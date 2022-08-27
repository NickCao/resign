use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::Parser;
use openpgp_card::OpenPgp;
use secrecy::ExposeSecret;
use sequoia_openpgp::{crypto::SessionKey, packet::key::PublicParts};
use sequoia_openpgp::{
    packet::{key::UnspecifiedRole, prelude::Key4, Key},
    serialize::MarshalInto,
};
use std::collections::HashMap;
use std::io;

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
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            unreachable!()
        }
        let key: Key<_, UnspecifiedRole> = Key::V4(
            Key4::import_public_cv25519(&bytes, None, None, None).map_err(|e| {
                recipient::Error::Recipient {
                    index,
                    message: e.to_string(),
                }
            })?,
        );
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
                        let ciphertext = pk.encrypt(&data).map_err(|e| {
                            vec![recipient::Error::Internal {
                                message: e.to_string(),
                            }]
                        })?;
                        Ok(Stanza {
                            tag: "resign".to_string(),
                            args: vec![],
                            body: ciphertext.to_vec().unwrap(),
                        })
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
        _files: Vec<Vec<Stanza>>,
        mut _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        todo!()
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    match args.age_plugin {
        Some(state_machine) => run_state_machine(
            &state_machine,
            || RecipientPlugin::default(),
            || IdentityPlugin::default(),
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
            let pk = backend.decryption_key(tx).unwrap();
            age_plugin::print_new_identity(PLUGIN_NAME, ident.as_bytes(), &pk);
            Ok(())
        }
    }
}
