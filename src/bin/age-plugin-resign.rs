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
            backend.public(tx, KeyType::Decryption)
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
        let mut errors = vec![];
        let mut stanzas = vec![];
        for file_key in &file_keys {
            let mut wrapped = vec![];
            for recipient in &self.recipients {
                let stanza = PKESK::encrypt(file_key, recipient);
                match stanza {
                    Ok(stanza) => wrapped.push(stanza.try_into().unwrap()),
                    Err(err) => errors.push(recipient::Error::Internal {
                        message: err.to_string(),
                    }),
                }
            }
            stanzas.push(wrapped);
        }
        if !errors.is_empty() {
            Ok(Err(errors))
        } else {
            Ok(Ok(stanzas))
        }
    }
}

#[derive(Default)]
struct IdentityPlugin {
    identities: Vec<String>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        let ident = String::from_utf8(bytes.to_vec()).map_err(|e| identity::Error::Identity {
            index,
            message: e.to_string(),
        })?;
        self.identities.push(ident);
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut file_keys = HashMap::new();
        for identity in &self.identities {
            let mut backend = resign::Backend::default();
            for (index, file) in files.iter().enumerate() {
                for stanza in file {
                    if let Ok(pkesk) = PKESK::try_from(stanza) {
                        let file_key = backend.transaction(Some(identity), &|backend, tx| {
                            backend.decrypt(tx, &|de| pkesk.decrypt(de), &|| {})
                        });
                        if let Ok(file_key) = file_key {
                            file_keys.insert(index, Ok(file_key));
                        }
                    }
                }
            }
        }
        Ok(file_keys)
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.age_plugin {
        Some(state_machine) => Ok(run_state_machine(
            &state_machine,
            RecipientPlugin::default,
            IdentityPlugin::default,
        )?),
        None => resign::Backend::default().transaction(None, &|backend, tx| {
            let ident = tx.application_identifier()?.ident();
            let pk = backend.public(tx, openpgp_card::KeyType::Decryption)?;
            age_plugin::print_new_identity(PLUGIN_NAME, ident.as_bytes(), &pk.to_vec()?);
            Ok(())
        }),
    }
}
