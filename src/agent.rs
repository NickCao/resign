use ssh_agent_lib::proto::Identity;
use std::sync::Arc;
use std::sync::Mutex;

use openpgp_card::OpenPgp;
use sequoia_openpgp as openpgp;

#[derive(Default, Clone)]
pub struct Agent {
    backend: Arc<Mutex<crate::Backend>>,
}

impl ssh_agent_lib::Agent for Agent {
    type Error = anyhow::Error;
    fn handle(
        &self,
        request: ssh_agent_lib::proto::Message,
    ) -> Result<ssh_agent_lib::proto::Message, Self::Error> {
        match request {
            ssh_agent_lib::proto::Message::RequestIdentities => {
                let mut backend = self.backend.lock().unwrap();
                let mut card = backend.open()?;
                let mut card = OpenPgp::new(&mut card);
                let tx = card.transaction()?;
                let (pubkey_blob, comment) = backend.public_ssh(tx)?;
                Ok(ssh_agent_lib::proto::Message::IdentitiesAnswer(vec![
                    Identity {
                        pubkey_blob,
                        comment: String::from_utf8_lossy(&comment).to_string(),
                    },
                ]))
            }
            ssh_agent_lib::proto::Message::SignRequest(request) => {
                let mut backend = self.backend.lock().unwrap();
                let mut card = backend.open()?;
                let mut card = OpenPgp::new(&mut card);
                let tx = card.transaction()?;
                let signature = backend.auth_ssh(tx, &request.data)?;
                Ok(ssh_agent_lib::proto::Message::SignResponse(signature))
            }
            ssh_agent_lib::proto::Message::Extension(ext) => match ext.extension_type.as_str() {
                "decrypt@nichi.co" => {
                    let mut backend = self.backend.lock().unwrap();
                    let mut card = backend.open()?;
                    let mut card = OpenPgp::new(&mut card);
                    let tx = card.transaction()?;
                    let key = backend.public(tx, openpgp_card::KeyType::Decryption)?;
                    let tx = card.transaction()?;
                    let ciphertext = openpgp::crypto::mpi::Ciphertext::parse(
                        key.pk_algo(),
                        &*ext.extension_contents.0,
                    )?;
                    let plaintext = backend.decrypt(tx, &ciphertext, None, &|| {})?;
                    Ok(ssh_agent_lib::proto::Message::Extension(
                        ssh_agent_lib::proto::Extension {
                            extension_type: "decrypt@nichi.co".to_string(),
                            extension_contents: ssh_agent_lib::proto::ExtensionContents(
                                plaintext.to_vec(),
                            ),
                        },
                    ))
                }
                _ => Ok(ssh_agent_lib::proto::Message::Failure),
            },
            _ => Ok(ssh_agent_lib::proto::Message::Failure),
        }
    }
}
