use tonic::{transport::Server, Request, Response, Status};

use rpc::ssh_agent_server::{SshAgent, SshAgentServer};
use rpc::{SignRequest, SignResponse, IdentitiesResponse};

pub mod rpc {
    tonic::include_proto!("resign");
}

#[derive(Default)]
pub struct SshAgentImpl {}

#[tonic::async_trait]
impl SshAgent for SshAgentImpl {
    async fn identities(&self, request: tonic::Request<()>) -> Result<Response<IdentitiesResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse> , Status> {
        Err(Status::unimplemented(""))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;
    let ssh_agent = SshAgentImpl::default();
    Server::builder()
        .add_service(SshAgentServer::new(ssh_agent))
        .serve(addr)
        .await?;
    Ok(())
}
