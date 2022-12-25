use anyhow::anyhow;
use linux_keyutils::{KeyError, KeyRing, KeyRingIdentifier};
use openpgp_card::KeyType;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{state, Card};
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
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
pub struct Backend {}

impl Backend {
    pub fn transaction<T>(
        &mut self,
        ident: Option<&str>,
        operation: &dyn Fn(&mut Self, Card<state::Transaction>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let card = match ident {
            Some(ident) => PcscBackend::open_by_ident(ident, None)?,
            None => PcscBackend::cards(None)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no card available"))?,
        };
        let mut card: Card<state::Open> = card.into();
        let tx = card.transaction()?;
        operation(self, tx)
    }

    pub fn public<'a>(
        &mut self,
        mut tx: Card<state::Transaction<'a>>,
        key_type: KeyType,
    ) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        tx.public_key(key_type)?
            .ok_or_else(|| anyhow!("no key matching requested type"))
    }

    pub fn decrypt<'a, T>(
        &mut self,
        tx: Card<state::Transaction<'a>>,
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
        tx: Card<state::Transaction<'a>>,
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

    fn verify_user<'a>(
        &mut self,
        mut tx: Card<state::Transaction<'a>>,
        signing: bool,
    ) -> anyhow::Result<Card<state::Transaction<'a>>> {
        let keyring = KeyRing::from_special_id(KeyRingIdentifier::Process, true).unwrap();
        let ident = tx.application_identifier()?.ident();
        log::info!("search for key {} in keyring", ident);
        let key = keyring.search(&ident);

        let key = match key {
            Ok(key) => {
                log::info!("found key in keyring");
                key
            }
            Err(KeyError::KeyDoesNotExist) => {
                log::info!("failed to find key in keyring");
                let mut input = PassphraseInput::with_default_binary()
                    .ok_or_else(|| anyhow!("pinentry binary not found"))?;
                let pin = input
                    .with_description(&format!("Please unlock the card: {}", ident))
                    .with_prompt("PIN")
                    .interact()
                    .map_err(|e| anyhow!(e))?;
                keyring.add_key(&ident, pin.expose_secret()).unwrap()
            }
            Err(e) => {
                return Err(anyhow!("{:?}", e));
            }
        };

        let verify = if signing {
            tx.verify_user_for_signing(&key.read_to_vec().unwrap())
        } else {
            tx.verify_user(&key.read_to_vec().unwrap())
        };

        match verify {
            Ok(()) => Ok(tx),
            Err(e) => {
                keyring.unlink_key(key).unwrap();
                Err(e.into())
            }
        }
    }
}
