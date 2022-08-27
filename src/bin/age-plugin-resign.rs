use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::Parser;
use openpgp_card::OpenPgp;
use secrecy::ExposeSecret;

use sequoia_openpgp::packet::{prelude::PKESK3, PKESK};
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{crypto::SessionKey, packet::key::PublicParts, parse::Parse};
use sequoia_openpgp::{
    packet::{key::UnspecifiedRole, Key},
    serialize::MarshalInto,
};
use std::io;
use std::{collections::HashMap, vec};

const PLUGIN_NAME: &str = "resign";
const STANZA_TAG: &str = "resign-pkesk-v1";

/// age-plugin-resign
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Run the given age plugin state machine. Internal use only.
    #[clap(long = "age-plugin", id = "STATE-MACHINE")]
    age_plugin: Option<String>,
}

struct Wrapped(PKESK);

impl TryFrom<Stanza> for Wrapped {
    type Error = io::Error;
    fn try_from(value: Stanza) -> Result<Self, Self::Error> {
        if value.tag != STANZA_TAG || value.args.len() != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid stanza"));
        }
        Ok(Self(PKESK::from_bytes(&value.body).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?))
    }
}

impl TryInto<Stanza> for Wrapped {
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

#[derive(Default)]
struct RecipientPlugin {
    recipients: Vec<Key<PublicParts, UnspecifiedRole>>,
    identities: Vec<Vec<u8>>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        _index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        let key = Key::from_bytes(&bytes)
            .unwrap()
            .parts_as_public()
            .to_owned();
        self.recipients.push(key);
        Ok(())
    }

    fn add_identity(
        &mut self,
        _index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        self.identities.push(bytes.to_vec());
        Ok(())
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        Ok(file_keys
            .into_iter()
            .map(|file_key| {
                self.recipients
                    .iter()
                    .map(|pk| {
                        let data = SessionKey::from(file_key.expose_secret().as_slice());
                        Ok(Wrapped(PKESK::V3(
                            PKESK3::for_recipient(SymmetricAlgorithm::AES128, &data, pk).unwrap(),
                        ))
                        .try_into()
                        .unwrap())
                    })
                    .collect()
            })
            .collect())
    }
}

#[derive(Default)]
struct IdentityPlugin {
    identities: Vec<Vec<u8>>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        _index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        self.identities.push(bytes.to_vec());
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut file_keys = HashMap::new();
        let mut backend = resign::Backend::default();
        let mut card = backend
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut card = OpenPgp::new(&mut card);
        for (index, file) in files.into_iter().enumerate() {
            for stanza in file {
                if stanza.tag != "resign" {
                    continue;
                }
                let tx = card.transaction().unwrap();
                let pkesk = Wrapped::try_from(stanza).unwrap().0;
                let sk = backend.decrypt_pkesk(tx, &pkesk, &|| {});
                let mut fk = [0u8; 16];
                fk.copy_from_slice(&sk.unwrap().1);
                file_keys.insert(index, Ok(FileKey::from(fk)));
                break;
            }
        }
        Ok(file_keys)
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    match args.age_plugin {
        Some(state_machine) => run_state_machine(
            &state_machine,
            RecipientPlugin::default,
            IdentityPlugin::default,
        ),
        None => {
            let mut backend = resign::Backend::default();
            let mut card = backend.open().unwrap();
            let mut card = OpenPgp::new(&mut card);
            let mut tx = card.transaction().unwrap();
            let ident = tx
                .application_related_data()
                .unwrap()
                .application_id()
                .unwrap()
                .ident();
            let pk = backend
                .public_raw(tx, openpgp_card::KeyType::Decryption)
                .unwrap();
            age_plugin::print_new_identity(PLUGIN_NAME, ident.as_bytes(), &pk.to_vec().unwrap());
            Ok(())
        }
    }
}
