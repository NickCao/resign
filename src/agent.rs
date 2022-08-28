use openpgp_card::KeyType;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::crypto::mpi::PublicKey;
use sequoia_openpgp::crypto::Signer;
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
                    let sig = au.sign(HashAlgorithm::Unknown(0), &request.data)?;
                    match sig {
                        mpi::Signature::EdDSA { r, s } => Ok(Signature {
                            algorithm: "ssh-ed25519".to_string(),
                            blob: [r.value(), s.value()].concat(),
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
