use anyhow::anyhow;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::Signature;
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
    pin: Option<SecretString>,
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
            let old = inner.cards.insert(
                aid.clone(),
                Card {
                    key_blob,
                    pin: None,
                },
            );
            if let Some(old) = old {
                if let Some(mut oldc) = inner.cards.get_mut(&aid) {
                    oldc.pin = old.pin;
                }
            };
        }
        Ok(())
    }
    fn request_pin(&self, ident: &str) -> anyhow::Result<SecretString> {
        if let Some(Card { pin: Some(pin), .. }) = self.inner.lock().unwrap().cards.get(ident) {
            return Ok(pin.clone());
        }
        let mut input =
            PassphraseInput::with_default_binary().ok_or(anyhow!("pinentry binary not found"))?;
        let pin = input
            .with_description(&format!("Please unlock the card: {}", ident))
            .with_prompt("PIN")
            .interact()
            .map_err(|e| anyhow!("failed to get pin: {}", e))?;
        if let Some(mut card) = self.inner.lock().unwrap().cards.get_mut(ident) {
            card.pin = Some(pin.clone());
        }
        Ok(pin)
    }
    fn forget_pin(&self, ident: &str) {
        if let Some(mut card) = self.inner.lock().unwrap().cards.get_mut(ident) {
            card.pin = None;
        }
    }
}

#[tonic::async_trait]
impl SshAgent for SshAgentImpl {
    async fn identities(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<IdentitiesResponse>, Status> {
        self.refresh_cards()
            .map_err(|e| Status::unavailable(e.to_string()))?;
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
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let request = request.into_inner();
        assert!(request.flags == 0);
        let inner = self.inner.lock().unwrap();
        let ident = inner
            .cards
            .iter()
            .find(|(_k, v)| v.key_blob == request.key_blob)
            .ok_or(Status::unavailable("no card with matching key found"))?
            .0
            .clone();
        drop(inner);
        let mut card = openpgp_card_pcsc::PcscBackend::open_by_ident(&ident, None)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let mut card = openpgp_card::OpenPgp::new(&mut card);
        let mut tx = card
            .transaction()
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let pin = self
            .request_pin(&ident)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        tx.verify_pw1_user(pin.expose_secret().as_bytes())
            .map_err(|e| {
                self.forget_pin(&ident);
                Status::unavailable(e.to_string())
            })?;
        use openpgp_card::crypto_data::Hash;
        let hash = Hash::EdDSA(&request.data);
        let sig = tx
            .authenticate_for_hash(hash)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let signature = Signature {
            algorithm: "ssh-ed25519".to_string(),
            blob: sig,
        }
        .to_blob()
        .map_err(|e| Status::unavailable(e.to_string()))?;
        Ok(Response::new(SignResponse { signature }))
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
