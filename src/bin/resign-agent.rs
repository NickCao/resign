use service_binding::Binding;
use ssh_agent_lib::Agent as SAgent;
use std::sync::Mutex;
use tonic::transport::Channel;
use tonic::transport::Endpoint;
use tonic::{transport::Server, Request};

use resign::agent::ssh::agent_client::AgentClient;
use resign::agent::Agent;

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
                        .sign(Request::new(resign::agent::ssh::SignRequest {
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
            .add_service(resign::agent::ssh::agent_server::AgentServer::new(
                agent.clone(),
            ))
            .serve_with_incoming(futures::stream::iter(vec![Ok::<_, std::io::Error>(server)])),
    );
    tokio::spawn(
        Server::builder()
            .add_service(resign::agent::sequoia::signer_server::SignerServer::new(
                agent.clone(),
            ))
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
    let client = resign::agent::ssh::agent_client::AgentClient::new(channel);
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
