use ssh_agent_lib::proto::*;
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
                let (pubkey_blob, comment) = self
                    .backend
                    .lock()
                    .unwrap()
                    .transaction(None, &|backend, tx| backend.public(tx))?;
                Ok(Message::IdentitiesAnswer(vec![Identity {
                    pubkey_blob,
                    comment: String::from_utf8_lossy(&comment).to_string(),
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
