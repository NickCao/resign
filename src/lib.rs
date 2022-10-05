use anyhow::anyhow;
use openpgp_card::{KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use sequoia_openpgp::{
    crypto::{Decryptor, Signer},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
};

pub mod agent;
pub mod pkesk;

#[derive(Default)]
pub struct Backend {
    pin: Option<SecretString>,
}

impl Backend {
    pub fn transaction<T>(
        &mut self,
        ident: Option<&str>,
        operation: &dyn Fn(&mut Self, Open) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let card = match ident {
            Some(ident) => PcscBackend::open_by_ident(ident, None)?,
            None => PcscBackend::cards(None)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no card available"))?,
        };
        let mut card = OpenPgp::new(card);
        let tx = card.transaction()?;
        let tx = Open::new(tx)?;
        operation(self, tx)
    }

    pub fn public(
        &mut self,
        mut tx: Open,
        key_type: KeyType,
    ) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        openpgp_card_sequoia::util::key_slot(&mut tx, key_type)?
            .ok_or_else(|| anyhow!("no key matching requested type"))
    }

    pub fn decrypt<'a, T>(
        &mut self,
        tx: Open,
        operation: &dyn Fn(&mut dyn Decryptor) -> anyhow::Result<T>,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<T> {
        let mut tx = self.verify_user(tx, false)?;
        let mut card = tx
            .user_card()
            .ok_or_else(|| anyhow!("failed to open user card"))?;
        let mut decryptor = card.decryptor(touch_prompt)?;
        operation(&mut decryptor)
    }

    pub fn auth<'a, T>(
        &mut self,
        tx: Open,
        operation: &dyn Fn(&mut dyn Signer) -> anyhow::Result<T>,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<T> {
        let mut tx = self.verify_user(tx, false)?;
        let mut card = tx
            .user_card()
            .ok_or_else(|| anyhow!("failed to open user card"))?;
        let mut authenticator = card.authenticator(touch_prompt)?;
        operation(&mut authenticator)
    }

    fn verify_user<'a>(&mut self, mut tx: Open<'a>, signing: bool) -> anyhow::Result<Open<'a>> {
        let ident = tx.application_identifier()?.ident();

        let pin = match &self.pin {
            Some(pin) => pin.clone(),
            _ => {
                let mut input = PassphraseInput::with_default_binary()
                    .ok_or_else(|| anyhow!("pinentry binary not found"))?;
                let pin = input
                    .with_description(&format!("Please unlock the card: {}", ident))
                    .with_prompt("PIN")
                    .interact()
                    .map_err(|e| anyhow!(e))?;
                pin
            }
        };

        let verify = if signing {
            tx.verify_user_for_signing(pin.expose_secret().as_bytes())
        } else {
            tx.verify_user(pin.expose_secret().as_bytes())
        };
        match verify {
            Ok(()) => {
                self.pin = Some(pin);
                Ok(tx)
            }
            Err(e) => {
                self.pin = None;
                Err(e.into())
            }
        }
    }
}
