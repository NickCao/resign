use std::sync::Arc;
use std::sync::Mutex;
use tonic::{Request, Response, Status};

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
pub struct Agent {
    backend: Arc<Mutex<crate::Backend>>,
}

#[tonic::async_trait]
impl sequoia::signer_server::Signer for Agent {
    async fn public(
        &self,
        _request: Request<()>,
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
        request: Request<sequoia::SignRequest>,
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
        _request: Request<()>,
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
