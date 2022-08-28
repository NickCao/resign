use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::Parser;
use openpgp_card::OpenPgp;
use openpgp_card_sequoia::card::Open;
use resign::pkesk::PKESK;

use sequoia_openpgp::{packet::key::PublicParts, parse::Parse};
use sequoia_openpgp::{
    packet::{key::UnspecifiedRole, Key},
    serialize::MarshalInto,
};
use std::io;
use std::{collections::HashMap, vec};

const PLUGIN_NAME: &str = "resign";

/// age-plugin-resign
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Run the given age plugin state machine. Internal use only.
    #[clap(long = "age-plugin", id = "STATE-MACHINE")]
    age_plugin: Option<String>,
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
                        Ok(PKESK::wrap(&file_key, pk)
                            .map_err(|e| {
                                vec![recipient::Error::Internal {
                                    message: e.to_string(),
                                }]
                            })?
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let mut card = OpenPgp::new(&mut card);
        for (index, file) in files.into_iter().enumerate() {
            for stanza in file {
                PKESK::try_from(stanza)
                    .map(|s| -> anyhow::Result<()> {
                        let tx = card.transaction()?;
                        let tx = Open::new(tx)?;
                        let file_key = backend.decrypt_pkesk(tx, &s, &|| {})?;
                        file_keys.insert(index, Ok(file_key));
                        Ok(())
                    })
                    .unwrap()
                    .unwrap();

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
