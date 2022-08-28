use age_core::format::FileKey;
use anyhow::anyhow;

use openpgp::crypto::mpi;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::prelude::Key;

use openpgp_card::OpenPgp;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use ssh_agent_lib::proto::Blob;

use openpgp::crypto::Signer as _;
use openpgp::types::HashAlgorithm;
use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;

use openpgp_card_sequoia::card::Open;
use sequoia_openpgp as openpgp;

pub mod agent;
pub mod pkesk;

#[derive(Default)]
pub struct Backend {
    pin: Option<SecretString>,
}

impl Backend {
    pub fn open<T>(
        &mut self,
        apply: &dyn Fn(&mut Self, Open) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let cards = openpgp_card_pcsc::PcscBackend::cards(None)?;
        let mut card = cards
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no card available"))?;
        let mut card = OpenPgp::new(&mut card);
        let tx = card.transaction()?;
        let tx = Open::new(tx)?;
        apply(self, tx)
    }

    pub fn public_raw(
        &mut self,
        mut tx: Open,
        key_type: KeyType,
    ) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        openpgp_card_sequoia::util::key_slot(&mut tx, key_type)?
            .ok_or_else(|| anyhow!("no key matching key type"))
    }

    pub fn public(&mut self, mut tx: Open) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let ident = tx.application_identifier()?.ident();
        let key = tx.public_key(KeyType::Authentication)?;
        let key_blob = match key {
            PublicKeyMaterial::E(ecc) => match ecc.algo() {
                Algo::Ecc(attrs) => match attrs.curve() {
                    Curve::Ed25519 => {
                        let mut blob = vec![0, 0, 0, 0xb];
                        blob.extend(b"ssh-ed25519");
                        blob.extend(vec![0, 0, 0, 0x20]);
                        blob.extend(ecc.data().to_vec());
                        blob
                    }
                    _ => unimplemented!(),
                },
                _ => unimplemented!(),
            },
            _ => unimplemented!(),
        };
        Ok((key_blob, ident.as_bytes().to_vec()))
    }

    pub fn decrypt<'a>(
        &mut self,
        tx: Open,
        pkesk: &crate::pkesk::PKESK,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<FileKey> {
        let mut tx = self.verify_user(tx, false)?;
        let mut decrypt = tx
            .user_card()
            .ok_or_else(|| anyhow!("failed to open user card"))?;
        let decryptor = decrypt.decryptor(touch_prompt)?;
        pkesk.unwrap(decryptor)
    }

    pub fn auth<'a>(
        &mut self,
        tx: Open,
        data: &[u8],
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<Vec<u8>> {
        let mut tx = self.verify_user(tx, false)?;
        let blob = tx
            .user_card()
            .unwrap()
            .authenticator(touch_prompt)?
            .sign(HashAlgorithm::Unknown(0), data)?;
        let blob = match blob {
            mpi::Signature::EdDSA { r, s } => [r.value(), s.value()].concat(),
            _ => unimplemented!(),
        };
        Ok(ssh_agent_lib::proto::Signature {
            algorithm: "ssh-ed25519".to_string(),
            blob,
        }
        .to_blob()?)
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
