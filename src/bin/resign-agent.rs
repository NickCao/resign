use clap::Parser;
use ssh_agent_lib::Agent as _;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Channel;
use tonic::transport::Endpoint;
use tonic::{transport::Server, Request};

use resign::agent::ssh::agent_client::AgentClient;
use resign::agent::Agent;

struct SshAgent {
    client: tokio::sync::Mutex<AgentClient<Channel>>,
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
                    self.client.lock().await.identities(Request::new(())).await
                })?;
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
                        .await
                        .sign(Request::new(resign::agent::ssh::SignRequest {
                            key_blob: request.pubkey_blob,
                            flags: request.flags,
                            data: request.data,
                        }))
                        .await
                })?;
                Ok(ssh_agent_lib::proto::Message::SignResponse(
                    signature.into_inner().signature,
                ))
            }
            _ => Ok(ssh_agent_lib::proto::Message::Failure),
        }
    }
}

/// resign-agent
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// grpc listen address
    #[clap(long = "grpc")]
    grpc: String,
    /// ssh agent listen address
    #[clap(long = "ssh")]
    ssh: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use resign::agent::sequoia::decryptor_server::DecryptorServer;
    use resign::agent::sequoia::signer_server::SignerServer;
    use resign::agent::ssh::agent_client::AgentClient;
    use resign::agent::ssh::agent_server::AgentServer;

    let args = Args::parse();
    let agent = Agent::default();

    let (tx, rx) = tokio::io::duplex(1024);
    tokio::spawn(
        Server::builder()
            .add_service(AgentServer::new(agent.clone()))
            .serve_with_incoming(futures::stream::iter(vec![Ok::<_, std::io::Error>(rx)])),
    );

    drop(std::fs::remove_file(&args.grpc));
    let uds = UnixListener::bind(&args.grpc)?;
    tokio::spawn(
        Server::builder()
            .add_service(AgentServer::new(agent.clone()))
            .add_service(SignerServer::new(agent.clone()))
            .add_service(DecryptorServer::new(agent.clone()))
            .serve_with_incoming(UnixListenerStream::new(uds)),
    );

    let mut tx = Some(tx);
    let ch = Endpoint::try_from("http://localhost")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let client = tx.take();
            async move {
                client.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Client already taken")
                })
            }
        }))
        .await?;
    let agent = SshAgent {
        client: tokio::sync::Mutex::new(AgentClient::new(ch)),
    };
    drop(std::fs::remove_file(&args.ssh));
    agent.run_unix(&args.ssh).map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}
