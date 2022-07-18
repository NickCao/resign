use anyhow::{anyhow, Result};
use clap::Parser;
use libsystemd::activation::IsType;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::MarshalInto;
use openpgp::Cert;
use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use sequoia_openpgp as openpgp;
use service_binding::Binding;
use service_binding::Listener;
use sha2::{Digest, Sha256, Sha512};
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::{message::Identity, Message};
use std::net::TcpListener;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener;

struct Backend {}

impl Agent for Backend {
    type Error = BackendError;
    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        match request {
            Message::RequestIdentities => {
                for mut pcsc in openpgp_card_pcsc::PcscBackend::cards(None).unwrap_or_default() {
                    let mut card = openpgp_card::OpenPgp::new(&mut pcsc);
                    let mut card_tx = card.transaction().unwrap();
                    let ard = card_tx.application_related_data().unwrap();
                    let pub_key = card_tx.public_key(KeyType::Authentication).unwrap();
                    let data = match pub_key {
                        PublicKeyMaterial::E(ref ecc) => {
                            (if let Algo::Ecc(ecc_attrs) = ecc.algo() {
                                match ecc_attrs.curve() {
                                    Curve::Ed25519 => ecc.data().to_vec(),
                                    c => panic!("Unsupported ECC Curve {:?}", c),
                                }
                            } else {
                                panic!("This should never happen");
                            })
                        }
                        _ => panic!("Unsupported key type"),
                    };
                    let mut pubkey_blob = vec![0, 0, 0, 0xb];
                    pubkey_blob.extend("ssh-ed25519".as_bytes());
                    pubkey_blob.extend(vec![0, 0, 0, 0x20]);
                    pubkey_blob.extend(data);
                    return Ok(Message::IdentitiesAnswer(vec![Identity {
                        pubkey_blob,
                        comment: ard.application_id().unwrap().ident(),
                    }]));
                }
                Ok(Message::Failure)
            }
            Message::SignRequest(request) => {
                assert!(request.flags == 0);
                let body = request.data;
                let mut pcsc = openpgp_card_pcsc::PcscBackend::cards(None)
                    .unwrap_or_default()
                    .into_iter()
                    .next()
                    .unwrap();
                let mut card = openpgp_card::OpenPgp::new(&mut pcsc);
                let mut card_tx = card.transaction().unwrap();

                let mut input = PassphraseInput::with_default_binary().unwrap();
                let pin = input
                    .with_description("enter pin for card")
                    .with_prompt("pin:")
                    .interact()
                    .unwrap();
                card_tx
                    .verify_pw1_user(pin.expose_secret().as_bytes())
                    .unwrap();
                use openpgp_card::crypto_data::Hash;
                let hash = Hash::EdDSA(&body);
                let sig = card_tx.authenticate_for_hash(hash).unwrap();
                Ok(Message::SignResponse(
                    (ssh_agent_lib::proto::signature::Signature {
                        algorithm: "ssh-ed25519".to_string(),
                        blob: sig,
                    })
                    .to_blob()
                    .unwrap(),
                ))
            }
            _ => Ok(Message::ExtensionFailure),
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    Unknown(String),
}

fn main() -> Result<()> {
    let agent = Backend {};
    let binding: Listener = if let Ok(fds) = libsystemd::activation::receive_descriptors(false) {
        if fds.len() != 1 {
            return Err(anyhow!("exactly one file descriptor should be passed"));
        }
        let fd = fds.iter().next().unwrap();
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
