use openpgp_card::KeyType;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::crypto::mpi::PublicKey;
use sequoia_openpgp::types::Curve;
use sequoia_openpgp::types::HashAlgorithm;
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
                let (pubkey, comment) =
                    self.backend
                        .lock()
                        .unwrap()
                        .transaction(None, &|backend, tx| {
                            let comment = tx.application_identifier()?.ident();
                            let pubkey = backend
                                .public(tx, KeyType::Authentication)?
                                .mpis()
                                .to_owned();
                            Ok((pubkey, comment))
                        })?;
                Ok(Message::IdentitiesAnswer(vec![Identity {
                    pubkey_blob: encode_pubkey(&pubkey).unwrap(),
                    comment,
                }]))
            }
            Message::SignRequest(request) => {
                let signature =
                    self.backend
                        .lock()
                        .unwrap()
                        .transaction(None, &|backend, tx| {
                            backend.auth(
                                tx,
                                &|au| {
                                    let sig = au.sign(HashAlgorithm::Unknown(0), &request.data)?;
                                    match sig {
                                        mpi::Signature::EdDSA { r, s } => {
                                            Ok([r.value(), s.value()].concat())
                                        }
                                        _ => unimplemented!(),
                                    }
                                },
                                &|| {},
                            )
                        })?;
                Ok(Message::SignResponse(
                    Signature {
                        algorithm: "ssh-ed25519".to_string(),
                        blob: signature,
                    }
                    .to_blob()?,
                ))
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
            let points = q.decode_point(&Curve::Ed25519).unwrap();
            let mut blob = vec![0, 0, 0, 0xb];
            blob.extend(b"ssh-ed25519");
            blob.extend(vec![0, 0, 0, 0x20]);
            blob.extend([points.0, points.1].concat());
            blob
        }
        _ => unimplemented!(),
    };
    Ok(blob)
}
