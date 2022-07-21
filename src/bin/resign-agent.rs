use std::sync::Arc;
use std::sync::Mutex;
use tonic::{transport::Server, Response, Status};

use openpgp::packet::Packet;
use openpgp::serialize::MarshalInto;
use openpgp_card::OpenPgp;
use sequoia::PublicResponse;
use sequoia_openpgp as openpgp;

pub mod rpc {
    tonic::include_proto!("resign");
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
        let mut backend = self.backend.lock().unwrap();
        let mut card = backend.open().unwrap();
        let mut card = OpenPgp::new(&mut card);
        let tx = card.transaction().unwrap();
        let key = backend.public(tx).unwrap();
        let key = Packet::from(key.role_as_primary().clone())
            .to_vec()
            .unwrap();
        Ok(Response::new(PublicResponse { key }))
    }
    async fn sign(
        &self,
        request: tonic::Request<sequoia::SignRequest>,
    ) -> Result<Response<sequoia::SignResponse>, Status> {
        let request = request.into_inner();
        let mut backend = self.backend.lock().unwrap();
        let mut card = backend.open().unwrap();
        let mut card = OpenPgp::new(&mut card);
        let tx = card.transaction().unwrap();
        let key = backend.public(tx).unwrap();
        let tx = card.transaction().unwrap();
        let hash_algo = request.hash_algo as u8;
        let sig = backend
            .sign(tx, key, hash_algo.into(), &request.digest, &|| {})
            .unwrap();
        Ok(Response::new(sequoia::SignResponse {
            signature: sig.to_vec().unwrap(),
        }))
    }
    async fn acceptable_hashes(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<sequoia::AcceptableHashesResponse>, Status> {
        Err(Status::unimplemented("all hashes are accepted"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;
    let ssh_agent = Agent::default();
    Server::builder()
        .add_service(sequoia::signer_server::SignerServer::new(ssh_agent.clone()))
        .serve(addr)
        .await?;
    Ok(())
}
