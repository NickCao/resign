use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::Parser;
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
    recipients: Vec<Vec<u8>>,
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
        self.recipients.push(bytes.to_vec());
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
        _file_keys: Vec<FileKey>,
        mut _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
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
        None => Ok(()),
    }
}
