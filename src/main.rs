use anyhow::{anyhow, Result};
use clap::Parser;
use openpgp::armor;
use openpgp::packet::key::Key4;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::Cert;
use openpgp_card::algorithm::Algo;
use openpgp_card::algorithm::Curve;
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::KeyType;
use openpgp_card::OpenPgp;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use sequoia_openpgp as openpgp;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// resign
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// make a detached signature
    #[clap(short = 'b', long = "detach-sign")]
    detach_sign: bool,
    /// make a signature
    #[clap(short = 's', long = "sign")]
    sign: bool,
    /// verify a signature
    #[clap(long = "verify")]
    verify: bool,
    /// create ascii armored output
    #[clap(short = 'a', long = "armor")]
    armor: bool,
    /// use USER-ID to sign or decrypt (ignored, always uses signing subkey)
    #[clap(short = 'u', long = "local-user", name = "USER-ID")]
    local_user: Option<String>,
    /// write special status strings to the file descriptor n
    #[clap(long = "status-fd", name = "n")]
    status_fd: Option<i32>,
    /// select how to display key IDs
    #[clap(long = "keyid-format")]
    keyid_format: Option<String>,
    #[clap(value_parser)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    assert!(args.status_fd.is_some());
    let mut status_fd = unsafe { File::from_raw_fd(args.status_fd.unwrap()) };

    if args.sign {
        assert!(args.detach_sign);
        assert!(args.armor);
        for mut card in PcscBackend::cards(None)? {
            let mut pgp = OpenPgp::new(&mut card);
            let mut open = Open::new(pgp.transaction()?)?;

            let ctime = open.key_generation_times()?;
            let ctime: SystemTime = ctime.signature().unwrap().to_datetime().into();

            let key = open.public_key(KeyType::Signing)?;
            let key = match key {
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

            let mut input =
                PassphraseInput::with_default_binary().ok_or(anyhow!("pinentry not found"))?;
            let pin = input
                .with_description("Please unlock the card")
                .with_prompt("PIN")
                .interact()
                .map_err(|e| anyhow!(e.to_string()))?;
            open.verify_user_for_signing(pin.expose_secret().as_bytes())?;

            let mut sign = open
                .signing_card()
                .ok_or(anyhow!("failed to open signing card"))?;
            let singer = sign.signer_from_pubkey(key, &|| {});
            let message = Message::new(std::io::stdout());
            let armored = Armorer::new(message).kind(armor::Kind::Signature).build()?;
            let signer = Signer::new(armored, singer);
            let mut signer = signer.detached().build()?;
            std::io::copy(&mut std::io::stdin(), &mut signer)?;
            signer.finalize()?;
            status_fd.write(b"[GNUPG:] SIG_CREATED ")?;
            return Ok(());
        }
        Err(anyhow!("no card found"))
    } else if args.verify {
        status_fd.write(b"[GNUPG:] ERRSIG ")?;
        Ok(())
    } else {
        Err(anyhow!("no operation specified"))
    }
}
