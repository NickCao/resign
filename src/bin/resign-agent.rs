use anyhow::anyhow;

use openpgp::crypto::Signer as SequoiaSigner;
use openpgp::packet::key::Key4;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::packet::Packet;
use openpgp::serialize::Marshal;
use openpgp::serialize::MarshalInto;
use openpgp::types::HashAlgorithm;
use sequoia_openpgp as openpgp;

use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;
use openpgp_card::OpenPgpTransaction;

use openpgp_card_sequoia::card::Open;

use pinentry::PassphraseInput;

use secrecy::ExposeSecret;
use secrecy::SecretString;

use sequoia::PublicResponse;

use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::Signature;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use rpc::ssh_agent_server::{SshAgent, SshAgentServer};
use rpc::{IdentitiesResponse, Identity, SignRequest, SignResponse};
use tonic::{transport::Server, Request, Response, Status};

pub mod rpc {
    tonic::include_proto!("resign");
}

pub mod sequoia {
    tonic::include_proto!("sequoia");
}

#[derive(Clone)]
struct Card {
    key_blob: Vec<u8>,
    pin: Option<SecretString>,
}

#[derive(Default, Clone)]
struct SshAgentInner {
    cards: HashMap<String, Card>,
}

#[derive(Default, Clone)]
pub struct Agent {
    inner: Arc<Mutex<SshAgentInner>>,
}

impl Agent {
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
    fn verify_user<'a>(
        &self,
        mut tx: OpenPgpTransaction<'a>,
        signing: bool,
    ) -> anyhow::Result<OpenPgpTransaction<'a>> {
        let ident = tx.application_related_data()?.application_id()?.ident();

        let pin = match self.inner.lock().unwrap().cards.get(&ident) {
            Some(Card { pin: Some(pin), .. }) => pin.clone(),
            _ => {
                let mut input = PassphraseInput::with_default_binary()
                    .ok_or(anyhow!("pinentry binary not found"))?;
                let pin = input
                    .with_description(&format!("Please unlock the card: {}", ident))
                    .with_prompt("PIN")
                    .interact()
                    .map_err(|e| anyhow!(e))?;
                pin
            }
        };

        let verify = if signing {
            tx.verify_pw1_sign(pin.expose_secret().as_bytes())
        } else {
            tx.verify_pw1_user(pin.expose_secret().as_bytes())
        };
        match verify {
            Ok(()) => {
                if let Some(mut card) = self.inner.lock().unwrap().cards.get_mut(&ident) {
                    card.pin = Some(pin);
                }
                Ok(tx)
            }
            Err(e) => {
                if let Some(mut card) = self.inner.lock().unwrap().cards.get_mut(&ident) {
                    card.pin = None;
                }
                Err(e.into())
            }
        }
    }
    fn public(tx: OpenPgpTransaction) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        let mut open = Open::new(tx)?;
        let ctime = open.key_generation_times()?;
        let ctime: SystemTime = ctime
            .signature()
            .ok_or(anyhow!("ctime for signature subkey ununavailable"))?
            .to_datetime()
            .into();
        let key = open.public_key(KeyType::Signing)?;
        let key: Key<PublicParts, UnspecifiedRole> = match key {
            PublicKeyMaterial::E(k) => match k.algo() {
                Algo::Ecc(attrs) => match attrs.curve() {
                    Curve::Ed25519 => Key::V4(Key4::import_public_ed25519(k.data(), ctime)?),
                    _ => unimplemented!(),
                },
                _ => unimplemented!(),
            },
            PublicKeyMaterial::R(k) => Key::V4(Key4::import_public_rsa(k.v(), k.n(), ctime)?),
            _ => unimplemented!(),
        };
        Ok(key)
    }
    fn sign<'a>(
        &self,
        tx: OpenPgpTransaction,
        key: Key<PublicParts, UnspecifiedRole>,
        hash_algo: HashAlgorithm,
        digest: &[u8],
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<openpgp::crypto::mpi::Signature> {
        let tx = self.verify_user(tx, true)?;
        let mut open = Open::new(tx)?;
        let mut sign = open
            .signing_card()
            .ok_or(anyhow!("failed to open signing card"))?;
        let mut signer = sign.signer_from_pubkey(key, touch_prompt);
        signer
            .sign(hash_algo, digest)
            .map_err(|e| anyhow!("signing failed: {}", e))
    }
}

#[tonic::async_trait]
impl sequoia::signer_server::Signer for Agent {
    async fn public(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<sequoia::PublicResponse>, Status> {
        self.refresh_cards().unwrap();
        let inner = self.inner.lock().unwrap();
        let ident = inner
            .cards
            .iter()
            .next()
            .ok_or(Status::unavailable("no card found"))?
            .0
            .clone();
        drop(inner);
        let mut card = openpgp_card_pcsc::PcscBackend::open_by_ident(&ident, None)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let mut card = openpgp_card::OpenPgp::new(&mut card);
        let tx = card.transaction().unwrap();
        let key = Self::public(tx).map_err(|e| Status::unavailable(e.to_string()))?;
        let mut bytes = vec![];
        Packet::from(key.role_as_primary().clone())
            .serialize(&mut bytes)
            .unwrap();
        Ok(Response::new(PublicResponse { key: bytes }))
    }
    async fn sign(
        &self,
        request: tonic::Request<sequoia::SignRequest>,
    ) -> Result<Response<sequoia::SignResponse>, Status> {
        self.refresh_cards().unwrap();
        let request = request.into_inner();
        let inner = self.inner.lock().unwrap();
        let ident = inner
            .cards
            .iter()
            .next()
            .ok_or(Status::unavailable("no card found"))?
            .0
            .clone();
        drop(inner);
        let mut card = openpgp_card_pcsc::PcscBackend::open_by_ident(&ident, None)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let mut card = openpgp_card::OpenPgp::new(&mut card);
        let hash_algo = (request.hash_algo as u8).into();
        let tx = card
            .transaction()
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let tx = self
            .verify_user(tx, false)
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let key = Self::public(tx).unwrap();
        let tx = card
            .transaction()
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let sig = self
            .sign(tx, key, hash_algo, &request.digest, &|| {})
            .map_err(|e| Status::unavailable(e.to_string()))?;
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

#[tonic::async_trait]
impl SshAgent for Agent {
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
        let tx = card
            .transaction()
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let mut tx = self.verify_user(tx, true).unwrap();
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
    let ssh_agent = Agent::default();
    Server::builder()
        .add_service(SshAgentServer::new(ssh_agent.clone()))
        .add_service(sequoia::signer_server::SignerServer::new(ssh_agent.clone()))
        .serve(addr)
        .await?;
    Ok(())
}
