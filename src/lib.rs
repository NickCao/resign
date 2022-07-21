use anyhow::anyhow;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use std::time::SystemTime;

use openpgp::crypto::Signer as SequoiaSigner;
use openpgp::packet::key::Key4;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::types::HashAlgorithm;
use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;
use openpgp_card::OpenPgpTransaction;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use sequoia_openpgp as openpgp;

#[derive(Default)]
pub struct Backend {
    pin: Option<SecretString>,
}

impl Backend {
    pub fn open(&mut self) -> anyhow::Result<PcscBackend> {
        let cards = openpgp_card_pcsc::PcscBackend::cards(None)?;
        cards
            .into_iter()
            .next()
            .ok_or(anyhow!("no card available"))
    }

    pub fn public(
        &mut self,
        tx: OpenPgpTransaction,
    ) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        let mut open = Open::new(tx)?;
        let ctime = open.key_generation_times()?;
        let ctime: SystemTime = ctime
            .signature()
            .ok_or(anyhow!("ctime for signature subkey ununavailable"))?
            .to_datetime()
            .into();
        let key = open.public_key(KeyType::Signing)?;
        let key: Key<PublicParts, UnspecifiedRole> = match key {
            PublicKeyMaterial::E(k) => match k.algo() {
                Algo::Ecc(attrs) => match attrs.curve() {
                    Curve::Ed25519 => Key::V4(Key4::import_public_ed25519(k.data(), ctime)?),
                    _ => unimplemented!(),
                },
                _ => unimplemented!(),
            },
            PublicKeyMaterial::R(k) => Key::V4(Key4::import_public_rsa(k.v(), k.n(), ctime)?),
            _ => unimplemented!(),
        };
        Ok(key)
    }

    pub fn sign<'a>(
        &mut self,
        tx: OpenPgpTransaction,
        key: Key<PublicParts, UnspecifiedRole>,
        hash_algo: HashAlgorithm,
        digest: &[u8],
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<openpgp::crypto::mpi::Signature> {
        let tx = self.verify_user(tx, true)?;
        let mut open = Open::new(tx)?;
        let mut sign = open
            .signing_card()
            .ok_or(anyhow!("failed to open signing card"))?;
        let mut signer = sign.signer_from_pubkey(key, touch_prompt);
        signer.sign(hash_algo, digest)
    }

    fn verify_user<'a>(
        &mut self,
        mut tx: OpenPgpTransaction<'a>,
        signing: bool,
    ) -> anyhow::Result<OpenPgpTransaction<'a>> {
        let ident = tx.application_related_data()?.application_id()?.ident();

        let pin = match &self.pin {
            Some(pin) => pin.clone(),
            _ => {
                let mut input = PassphraseInput::with_default_binary()
                    .ok_or(anyhow!("pinentry binary not found"))?;
                let pin = input
                    .with_description(&format!("Please unlock the card: {}", ident))
                    .with_prompt("PIN")
                    .interact()
                    .map_err(|e| anyhow!(e))?;
                pin
            }
        };

        let verify = if signing {
            tx.verify_pw1_sign(pin.expose_secret().as_bytes())
        } else {
            tx.verify_pw1_user(pin.expose_secret().as_bytes())
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
