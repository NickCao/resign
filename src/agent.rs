use openpgp_card::KeyType;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::crypto::mpi::PublicKey;
use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::types::Curve;
use sequoia_openpgp::types::HashAlgorithm;
use sequoia_openpgp::types::PublicKeyAlgorithm;
use sha2::Digest;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::{Identity, Message, Signature};
use std::sync::Mutex;

#[derive(Default)]
pub struct Agent {
    backend: Mutex<crate::Backend>,
}

impl ssh_agent_lib::Agent for Agent {
    type Error = anyhow::Error;
    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        match request {
            Message::RequestIdentities => {
                let ident = self
                    .backend
                    .lock()
                    .unwrap()
                    .transaction(None, &|backend, tx| {
                        let comment = tx.application_identifier()?.ident();
                        let pubkey = backend.public(tx, KeyType::Authentication)?;
                        Ok(Identity {
                            pubkey_blob: encode_pubkey(pubkey.mpis())?,
                            comment,
                        })
                    })?;
                Ok(Message::IdentitiesAnswer(vec![ident]))
            }
            Message::SignRequest(request) => {
                let sign = &|au: &mut dyn Signer| {
                    let sig = match au.public().pk_algo() {
                        PublicKeyAlgorithm::EdDSA => {
                            au.sign(HashAlgorithm::Unknown(0), &request.data)
                        }
                        PublicKeyAlgorithm::RSAEncryptSign => {
                            let mut hasher = sha2::Sha512::new();
                            hasher.update(&request.data);
                            au.sign(HashAlgorithm::SHA512, &hasher.finalize())
                        }
                        _ => unimplemented!(),
                    }?;
                    match sig {
                        mpi::Signature::EdDSA { r, s } => Ok(Signature {
                            algorithm: "ssh-ed25519".to_string(),
                            blob: [r.value(), s.value()].concat(),
                        }),
                        mpi::Signature::RSA { s } => Ok(Signature {
                            algorithm: "rsa-sha2-512".to_string(),
                            blob: s.value().to_vec(),
                        }),
                        _ => unimplemented!(),
                    }
                };
                let sig = self
                    .backend
                    .lock()
                    .unwrap()
                    .transaction(None, &|backend, tx| backend.auth(tx, sign, &|| {}))?;
                Ok(Message::SignResponse(sig.to_blob()?))
            }
            _ => Ok(Message::Failure),
        }
    }
}

pub fn encode_pubkey(key: &PublicKey) -> anyhow::Result<Vec<u8>> {
    let blob = match key {
        PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let points = q.decode_point(&Curve::Ed25519)?;
            openssh_keys::PublicKey {
                data: openssh_keys::Data::Ed25519 {
                    key: [points.0, points.1].concat(),
                },
                options: None,
                comment: None,
            }
            .data()
        }
        PublicKey::RSA { e, n } => {
            openssh_keys::PublicKey::from_rsa(e.value().to_vec(), n.value().to_vec()).data()
        }
        _ => unimplemented!(),
    };
    Ok(blob)
}
