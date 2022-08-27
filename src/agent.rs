use ssh_agent_lib::proto::Identity;
use std::sync::Arc;
use std::sync::Mutex;

use openpgp_card::OpenPgp;

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
            _ => Ok(ssh_agent_lib::proto::Message::Failure),
        }
    }
}
