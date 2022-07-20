use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;

use rpc::ssh_agent_server::{SshAgent, SshAgentServer};
use rpc::{IdentitiesResponse, Identity, SignRequest, SignResponse};
use tonic::{transport::Server, Request, Response, Status};

pub mod rpc {
    tonic::include_proto!("resign");
}

#[derive(Default)]
pub struct SshAgentImpl {}

#[tonic::async_trait]
impl SshAgent for SshAgentImpl {
    async fn identities(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<IdentitiesResponse>, Status> {
        let cards = openpgp_card_pcsc::PcscBackend::cards(None)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let mut response = IdentitiesResponse::default();
        for mut card in cards {
            let mut card = openpgp_card::OpenPgp::new(&mut card);
            let mut card_tx = card.transaction().unwrap();
            let comment = card_tx
                .application_related_data()
                .unwrap()
                .application_id()
                .unwrap()
                .ident()
                .into_bytes();
            let pub_key = card_tx.public_key(KeyType::Authentication).unwrap();
            let key_blob = match pub_key {
                PublicKeyMaterial::E(ecc) => match ecc.algo() {
                    Algo::Ecc(attrs) => match attrs.curve() {
                        Curve::Ed25519 => {
                            let mut blob = vec![0, 0, 0, 0xb];
                            blob.extend(b"ssh-ed25519");
                            blob.extend(vec![0, 0, 0, 0x20]);
                            blob.extend(ecc.data().to_vec());
                            blob
                        }
                        c => {
                            return Err(Status::unimplemented(format!(
                                "unsupported ecc curve {:?}",
                                c
                            )))
                        }
                    },
                    c => {
                        return Err(Status::unimplemented(format!(
                            "unsupported key type: {}",
                            c
                        )))
                    }
                },
                _ => panic!("Unsupported key type"),
            };
            response.identities.push(Identity { key_blob, comment });
        }
        Ok(Response::new(response))
    }
    async fn sign(&self, _request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
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
