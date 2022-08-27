use age_core::format::{FileKey, Stanza};
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
    pub fn wrap(
        file_key: &FileKey,
        rcpt: &Key<PublicParts, UnspecifiedRole>,
    ) -> anyhow::Result<Self> {
        let data = SessionKey::from(file_key.expose_secret().as_slice());
        let pkesk = PKESK3::for_recipient(SymmetricAlgorithm::AES128, &data, rcpt)?;
        Ok(PKESK(packet::PKESK::V3(pkesk)).try_into()?)
    }
    pub fn unwrap<T: Decryptor>(&self, mut decryptor: T) -> anyhow::Result<SessionKey> {
        Ok(self.0.decrypt(&mut decryptor, None).unwrap().1)
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
