use anyhow::{anyhow, Result};
use clap::Parser;
use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::Cert;
use openpgp_card::OpenPgp;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use sequoia_openpgp as openpgp;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;

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
    /// use USER-ID to sign or decrypt (path to certificate)
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
        assert!(args.local_user.is_some());
        for mut card in PcscBackend::cards(None)? {
            let mut pgp = OpenPgp::new(&mut card);
            let mut open = Open::new(pgp.transaction()?)?;
            let mut input =
                PassphraseInput::with_default_binary().ok_or(anyhow!("pinentry not found"))?;
            let pin = input
                .with_description("enter pin for card")
                .with_prompt("pin:")
                .interact()
                .map_err(|e| anyhow!(e.to_string()))?;
            open.verify_user_for_signing(pin.expose_secret().as_bytes())?;
            let mut sign = open
                .signing_card()
                .ok_or(anyhow!("failed to open signing card"))?;
            let cert = Cert::from_file(args.local_user.unwrap())?;
            let singer = sign.signer(&cert, &|| {})?;
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
