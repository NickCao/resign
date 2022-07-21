use service_binding::Binding;
use service_binding::Listener;
use ssh::agent_client::AgentClient;
use ssh_agent_lib::Agent as SAgent;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tonic::transport::Channel;
use tonic::transport::Endpoint;
use tonic::{transport::Server, Request, Response, Status};

use openpgp::packet::Packet;
use openpgp::serialize::MarshalInto;
use openpgp_card::OpenPgp;
use sequoia::PublicResponse;
use sequoia_openpgp as openpgp;

pub mod ssh {
    tonic::include_proto!("ssh");
}

pub mod sequoia {
    tonic::include_proto!("sequoia");
}

#[derive(Default, Clone)]
struct Agent {
    backend: Arc<Mutex<resign::Backend>>,
}

#[tonic::async_trait]
impl sequoia::signer_server::Signer for Agent {
    async fn public(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<sequoia::PublicResponse>, Status> {
        let resp = || -> anyhow::Result<sequoia::PublicResponse> {
            let mut backend = self.backend.lock().unwrap();
            let mut card = backend.open()?;
            let mut card = OpenPgp::new(&mut card);
            let tx = card.transaction()?;
            let key = backend.public(tx)?;
            let key = Packet::from(key.role_as_primary().clone()).to_vec()?;
            Ok(PublicResponse { key })
        }()
        .map_err(|e| Status::unavailable(e.to_string()))?;
        Ok(Response::new(resp))
    }
    async fn sign(
        &self,
        request: tonic::Request<sequoia::SignRequest>,
    ) -> Result<Response<sequoia::SignResponse>, Status> {
        let resp = || -> anyhow::Result<sequoia::SignResponse> {
            let request = request.into_inner();
            let mut backend = self.backend.lock().unwrap();
            let mut card = backend.open()?;
            let mut card = OpenPgp::new(&mut card);
            let tx = card.transaction()?;
            let key = backend.public(tx)?;
            let tx = card.transaction()?;
            let hash_algo = request.hash_algo as u8;
            let sig = backend.sign(tx, key, hash_algo.into(), &request.digest, &|| {})?;
            Ok(sequoia::SignResponse {
                signature: sig.to_vec()?,
            })
        }()
        .map_err(|e| Status::unavailable(e.to_string()))?;
        Ok(Response::new(resp))
    }
    async fn acceptable_hashes(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<sequoia::AcceptableHashesResponse>, Status> {
        Err(Status::unimplemented("all hashes are accepted"))
    }
}

#[tonic::async_trait]
impl ssh::agent_server::Agent for Agent {
    async fn identities(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<ssh::IdentitiesResponse>, Status> {
        let resp = || -> anyhow::Result<ssh::IdentitiesResponse> {
            let mut backend = self.backend.lock().unwrap();
            let mut card = backend.open()?;
            let mut card = OpenPgp::new(&mut card);
            let tx = card.transaction()?;
            let (key_blob, comment) = backend.public_ssh(tx)?;
            Ok(ssh::IdentitiesResponse {
                identities: vec![ssh::Identity { key_blob, comment }],
            })
        }()
        .map_err(|e| Status::unavailable(e.to_string()))?;
        Ok(Response::new(resp))
    }
    async fn sign(
        &self,
        request: tonic::Request<ssh::SignRequest>,
    ) -> Result<Response<ssh::SignResponse>, Status> {
        let resp = || -> anyhow::Result<ssh::SignResponse> {
            let request = request.into_inner();
            let mut backend = self.backend.lock().unwrap();
            let mut card = backend.open()?;
            let mut card = OpenPgp::new(&mut card);
            let tx = card.transaction()?;
            let signature = backend.auth_ssh(tx, &request.data)?;
            Ok(ssh::SignResponse { signature })
        }()
        .map_err(|e| Status::unavailable(e.to_string()))?;
        Ok(Response::new(resp))
    }
}

struct SshAgent {
    client: Mutex<AgentClient<Channel>>,
}

impl ssh_agent_lib::Agent for SshAgent {
    type Error = anyhow::Error;
    fn handle(
        &self,
        request: ssh_agent_lib::proto::Message,
    ) -> Result<ssh_agent_lib::proto::Message, Self::Error> {
        match request {
            ssh_agent_lib::proto::Message::RequestIdentities => {
                let identities = futures::executor::block_on(async {
                    self.client
                        .lock()
                        .unwrap()
                        .identities(Request::new(()))
                        .await
                        .unwrap()
                });
                Ok(ssh_agent_lib::proto::Message::IdentitiesAnswer(
                    identities
                        .into_inner()
                        .identities
                        .iter()
                        .map(|v| ssh_agent_lib::proto::Identity {
                            comment: String::from_utf8(v.comment.clone()).unwrap(),
                            pubkey_blob: v.key_blob.clone(),
                        })
                        .collect(),
                ))
            }
            ssh_agent_lib::proto::Message::SignRequest(request) => {
                let signature = futures::executor::block_on(async {
                    self.client
                        .lock()
                        .unwrap()
                        .sign(Request::new(ssh::SignRequest {
                            key_blob: request.pubkey_blob,
                            flags: request.flags,
                            data: request.data,
                        }))
                        .await
                        .unwrap()
                });
                Ok(ssh_agent_lib::proto::Message::SignResponse(
                    signature.into_inner().signature,
                ))
            }
            _ => Ok(ssh_agent_lib::proto::Message::Failure),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;
    let agent = Agent::default();
    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(
        Server::builder()
            .add_service(ssh::agent_server::AgentServer::new(agent.clone()))
            .serve_with_incoming(futures::stream::iter(vec![Ok::<_, std::io::Error>(server)])),
    );
    tokio::spawn(
        Server::builder()
            .add_service(sequoia::signer_server::SignerServer::new(agent.clone()))
            .serve(addr),
    );

    let mut client = Some(client);
    let channel = Endpoint::try_from("http://127.0.0.1:0")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let client = client.take();
            async move {
                if let Some(client) = client {
                    Ok(client)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Client already taken",
                    ))
                }
            }
        }))
        .await
        .unwrap();
    let client = ssh::agent_client::AgentClient::new(channel);
    let agent = SshAgent {
        client: Mutex::new(client),
    };
    agent
        .listen(
            "unix:///tmp/test"
                .parse::<Binding>()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
    Ok(())
}
