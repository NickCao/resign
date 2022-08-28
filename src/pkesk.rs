use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use anyhow::anyhow;
use secrecy::ExposeSecret;
use sequoia_openpgp::packet::prelude::PKESK3;
use sequoia_openpgp::packet::{key::UnspecifiedRole, Key};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{crypto::Decryptor, packet};
use sequoia_openpgp::{crypto::SessionKey, packet::key::PublicParts};
use std::io;

const STANZA_TAG: &str = "resign-pkesk-v1";

pub struct PKESK(packet::PKESK);

impl PKESK {
    pub fn encrypt(
        file_key: &FileKey,
        rcpt: &Key<PublicParts, UnspecifiedRole>,
    ) -> anyhow::Result<Self> {
        let data = SessionKey::from(file_key.expose_secret().as_slice());
        let pkesk = PKESK3::for_recipient(SymmetricAlgorithm::AES128, &data, rcpt)?;
        Ok(PKESK(packet::PKESK::V3(pkesk)))
    }
    pub fn decrypt(&self, decryptor: &mut dyn Decryptor) -> anyhow::Result<FileKey> {
        let session_key = self
            .0
            .decrypt(decryptor, None)
            .ok_or_else(|| anyhow!("decryption failed"))?
            .1;
        let mut file_key = [0u8; FILE_KEY_BYTES];
        file_key.copy_from_slice(&session_key);
        Ok(FileKey::from(file_key))
    }
}

impl TryFrom<Stanza> for PKESK {
    type Error = io::Error;
    fn try_from(value: Stanza) -> Result<Self, Self::Error> {
        if value.tag != STANZA_TAG || !value.args.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid stanza"));
        }
        Ok(Self(packet::PKESK::from_bytes(&value.body).map_err(
            |e| io::Error::new(io::ErrorKind::Other, e.to_string()),
        )?))
    }
}

impl TryInto<Stanza> for PKESK {
    type Error = io::Error;
    fn try_into(self) -> Result<Stanza, Self::Error> {
        let body = self
            .0
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![],
            body,
        })
    }
}
