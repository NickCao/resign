use openpgp_card::KeyType;
use sequoia_openpgp::crypto::mpi::PublicKey;
use sequoia_openpgp::types::Curve;
use ssh_agent_lib::proto::Identity;
use ssh_agent_lib::proto::Message;
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
                let signature = self
                    .backend
                    .lock()
                    .unwrap()
                    .transaction(None, &|backend, tx| backend.auth(tx, &request.data, &|| {}))?;
                Ok(Message::SignResponse(signature))
            }
            _ => Ok(Message::Failure),
        }
    }
}

pub fn encode_pubkey(key: &PublicKey) -> anyhow::Result<Vec<u8>> {
    let blob = match key {
        PublicKey::ECDSA { curve, q } => match curve {
            Curve::Ed25519 => {
                let mut blob = vec![0, 0, 0, 0xb];
                blob.extend(b"ssh-ed25519");
                blob.extend(vec![0, 0, 0, 0x20]);
                blob.extend(q.value());
                blob
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    };
    Ok(blob)
}
