use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::Parser;
use openpgp_card::KeyType;
use resign::{pkesk::PKESK, Backend};
use sequoia_openpgp::{
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    parse::Parse,
    serialize::MarshalInto,
};
use std::{collections::HashMap, io, vec};

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
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        let pubkey = Key::from_bytes(&bytes).map_err(|e| recipient::Error::Recipient {
            index,
            message: e.to_string(),
        })?;
        let pubkey = pubkey.parts_as_public().to_owned();
        self.recipients.push(pubkey);
        Ok(())
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        let ident = String::from_utf8(bytes.to_vec()).map_err(|e| recipient::Error::Identity {
            index,
            message: e.to_string(),
        })?;
        let pubkey = Backend::default().transaction(Some(&ident), &|backend, tx| {
            backend.public(tx, KeyType::Authentication)
        });
        let pubkey = pubkey.map_err(|e| recipient::Error::Identity {
            index,
            message: e.to_string(),
        })?;
        self.recipients.push(pubkey);
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
                        Ok(PKESK::encrypt(&file_key, pk)
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
        for (index, file) in files.into_iter().enumerate() {
            for stanza in file {
                PKESK::try_from(stanza)
                    .map(|s| -> anyhow::Result<()> {
                        let file_key = backend
                            .transaction(None, &|backend, tx| {
                                backend.decrypt(tx, &|de| s.decrypt(de), &|| {})
                            })
                            .unwrap();
                        file_keys.insert(index, Ok(file_key));
                        Ok(())
                    })
                    .unwrap()
                    .unwrap();
                // TODO: handle failures
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
            let (ident, pk) = resign::Backend::default()
                .transaction(None, &|backend, tx| {
                    let ident = tx.application_identifier()?.ident();
                    let pk = backend.public(tx, openpgp_card::KeyType::Decryption)?;
                    Ok((ident, pk))
                })
                .unwrap();
            age_plugin::print_new_identity(PLUGIN_NAME, ident.as_bytes(), &pk.to_vec().unwrap());
            Ok(())
        }
    }
}
