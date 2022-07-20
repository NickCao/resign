use std::collections::HashMap;
use std::sync::Mutex;

use openpgp_card::algorithm::{Algo, Curve};

use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;

use rpc::ssh_agent_server::{SshAgent, SshAgentServer};
use rpc::{IdentitiesResponse, Identity, SignRequest, SignResponse};
use tonic::{transport::Server, Request, Response, Status};

pub mod rpc {
    tonic::include_proto!("resign");
}

struct Card {
    key_blob: Vec<u8>,
}

#[derive(Default)]
struct SshAgentInner {
    cards: HashMap<String, Card>,
}

#[derive(Default)]
pub struct SshAgentImpl {
    inner: Mutex<SshAgentInner>,
}

impl SshAgentImpl {
    fn refresh_cards(&self) -> anyhow::Result<()> {
        let cards = openpgp_card_pcsc::PcscBackend::cards(None)?;
        for mut card in cards {
            let mut card = openpgp_card::OpenPgp::new(&mut card);
            let mut tx = card.transaction()?;
            let aid = tx.application_related_data()?.application_id()?.ident();
            let auth_key = tx.public_key(KeyType::Authentication)?;
            let key_blob = match auth_key {
                PublicKeyMaterial::E(ecc) => match ecc.algo() {
                    Algo::Ecc(attrs) => match attrs.curve() {
                        Curve::Ed25519 => {
                            let mut blob = vec![0, 0, 0, 0xb];
                            blob.extend(b"ssh-ed25519");
                            blob.extend(vec![0, 0, 0, 0x20]);
                            blob.extend(ecc.data().to_vec());
                            blob
                        }
                        _c => unimplemented!(),
                    },
                    _c => unimplemented!(),
                },
                _ => unimplemented!(),
            };
            let mut inner = self.inner.lock().unwrap();
            inner.cards.insert(aid, Card { key_blob });
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl SshAgent for SshAgentImpl {
    async fn identities(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<IdentitiesResponse>, Status> {
        self.refresh_cards().unwrap();
        let identities = self
            .inner
            .lock()
            .unwrap()
            .cards
            .iter()
            .map(|(k, v)| Identity {
                comment: k.clone().into_bytes(),
                key_blob: v.key_blob.clone(),
            })
            .collect();
        let response = IdentitiesResponse { identities };
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
