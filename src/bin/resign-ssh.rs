use anyhow::{anyhow, Result};
use libsystemd::activation::IsType;

use rpc::SignRequest;
use service_binding::Binding;
use service_binding::Listener;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::{message::Identity, Message};
use std::net::TcpListener;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener;
use tokio::runtime::Runtime;
use tonic::Request;

use rpc::ssh_agent_client::SshAgentClient;

pub mod rpc {
    tonic::include_proto!("resign");
}

struct Backend {
    rt: Runtime,
}

impl Agent for Backend {
    type Error = BackendError;
    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        match request {
            Message::RequestIdentities => {
                let identities = self.rt.block_on(async {
                    let mut client = SshAgentClient::connect("http://127.0.0.1:50051")
                        .await
                        .unwrap();
                    client.identities(Request::new(())).await.unwrap()
                });
                Ok(Message::IdentitiesAnswer(
                    identities
                        .into_inner()
                        .identities
                        .iter()
                        .map(|v| Identity {
                            comment: String::from_utf8(v.comment.clone()).unwrap(),
                            pubkey_blob: v.key_blob.clone(),
                        })
                        .collect(),
                ))
            }
            Message::SignRequest(request) => {
                let signature = self.rt.block_on(async {
                    let mut client = SshAgentClient::connect("http://127.0.0.1:50051")
                        .await
                        .unwrap();
                    client
                        .sign(Request::new(SignRequest {
                            key_blob: request.pubkey_blob,
                            flags: request.flags,
                            data: request.data,
                        }))
                        .await
                        .unwrap()
                });
                Ok(Message::SignResponse(signature.into_inner().signature))
            }
            _ => Ok(Message::Failure),
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    Unknown(String),
}

fn main() -> Result<()> {
    let agent = Backend {
        rt: tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap(),
    };
    let binding: Listener = if let Ok(fds) = libsystemd::activation::receive_descriptors(false) {
        if fds.len() != 1 {
            return Err(anyhow!("exactly one file descriptor should be passed"));
        }
        let fd = fds.get(0).unwrap();
        unsafe {
            if fd.is_unix() {
                Listener::Unix(UnixListener::from_raw_fd(fd.clone().into_raw_fd()))
            } else if fd.is_inet() {
                Listener::Tcp(TcpListener::from_raw_fd(fd.clone().into_raw_fd()))
            } else {
                return Err(anyhow!("unsupported file descriptor type"));
            }
        }
    } else {
        let args = std::env::args();
        if args.len() != 2 {
            return Err(anyhow!("usage: resign_ssh <listen address>"));
        }
        args.skip(1)
            .next()
            .unwrap()
            .parse::<Binding>()?
            .try_into()?
    };
    agent.listen(binding).unwrap();
    Ok(())
}
