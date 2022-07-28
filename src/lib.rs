use anyhow::anyhow;

use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use ssh_agent_lib::proto::Blob;
use std::time::SystemTime;

use openpgp::crypto::Decryptor as _;
use openpgp::crypto::Signer as _;
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

pub mod agent;

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
            .ok_or_else(|| anyhow!("no card available"))
    }

    pub fn public(
        &mut self,
        tx: OpenPgpTransaction,
        key_type: KeyType,
    ) -> anyhow::Result<Key<PublicParts, UnspecifiedRole>> {
        let mut open = Open::new(tx)?;
        let ctime = open.key_generation_times()?;
        let ctime = match key_type {
            KeyType::Signing => ctime.signature(),
            KeyType::Authentication => ctime.authentication(),
            KeyType::Decryption => ctime.decryption(),
            _ => unimplemented!(),
        };
        let ctime: SystemTime = ctime
            .ok_or_else(|| anyhow!("ctime for subkey ununavailable"))?
            .to_datetime()
            .into();
        let key = open.public_key(key_type)?;
        let key: Key<PublicParts, UnspecifiedRole> = match key {
            PublicKeyMaterial::E(k) => match k.algo() {
                Algo::Ecc(attrs) => match attrs.curve() {
                    Curve::Ed25519 => Key::V4(Key4::import_public_ed25519(k.data(), ctime)?),
                    Curve::Cv25519 => {
                        Key::V4(Key4::import_public_cv25519(k.data(), None, None, ctime)?)
                    }
                    _ => unimplemented!(),
                },
                _ => unimplemented!(),
            },
            PublicKeyMaterial::R(k) => Key::V4(Key4::import_public_rsa(k.v(), k.n(), ctime)?),
            _ => unimplemented!(),
        };
        Ok(key)
    }

    pub fn public_ssh(&mut self, mut tx: OpenPgpTransaction) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let ident = tx.application_related_data()?.application_id()?.ident();
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

    pub fn sign<'a>(
        &mut self,
        tx: OpenPgpTransaction,
        hash_algo: HashAlgorithm,
        digest: &[u8],
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<openpgp::crypto::mpi::Signature> {
        let tx = self.verify_user(tx, true)?;
        let mut open = Open::new(tx)?;
        let mut sign = open
            .signing_card()
            .ok_or_else(|| anyhow!("failed to open signing card"))?;
        let mut signer = sign.signer(touch_prompt)?;
        signer.sign(hash_algo, digest)
    }

    pub fn decrypt<'a>(
        &mut self,
        tx: OpenPgpTransaction,
        ciphertext: &openpgp::crypto::mpi::Ciphertext,
        plaintext_len: Option<usize>,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> anyhow::Result<openpgp::crypto::SessionKey> {
        let tx = self.verify_user(tx, false)?;
        let mut open = Open::new(tx)?;
        let mut decrypt = open
            .user_card()
            .ok_or_else(|| anyhow!("failed to open user card"))?;
        let mut decryptor = decrypt.decryptor(touch_prompt)?;
        decryptor.decrypt(ciphertext, plaintext_len)
    }

    pub fn auth_ssh(&mut self, tx: OpenPgpTransaction, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let hash = openpgp_card::crypto_data::Hash::EdDSA(data);
        let mut tx = self.verify_user(tx, false)?;
        let blob = tx.authenticate_for_hash(hash)?;
        Ok(ssh_agent_lib::proto::Signature {
            algorithm: "ssh-ed25519".to_string(),
            blob,
        }
        .to_blob()?)
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
