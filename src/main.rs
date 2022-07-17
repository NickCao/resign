use openpgp_card::OpenPgp;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;

use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::Cert;

use sequoia_openpgp as openpgp;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;

use clap::Parser;

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
    /// create ascii armored output
    #[clap(short = 'a', long = "armor")]
    armor: bool,
    /// use USER-ID to sign or decrypt
    #[clap(short = 'u', long = "local-user", name = "USER-ID")]
    local_user: Option<String>,
    /// write special status strings to the file descriptor n
    #[clap(long = "status-fd", name = "n")]
    status_fd: Option<i32>,
}

fn main() {
    let args = Args::parse();
    assert!(args.detach_sign);
    assert!(args.sign);
    assert!(args.armor);
    assert!(args.status_fd.is_some());

    let mut status_fd = unsafe { File::from_raw_fd(args.status_fd.unwrap()) };
    for mut card in PcscBackend::cards(None).unwrap() {
        let mut pgp = OpenPgp::new(&mut card);
        let mut open = Open::new(pgp.transaction().unwrap()).unwrap();
        let mut input = PassphraseInput::with_default_binary().unwrap();
        let pin = input
            .with_description("enter pin for card")
            .with_prompt("pin:")
            .interact()
            .unwrap();
        open.verify_user_for_signing(pin.expose_secret().as_bytes())
            .unwrap();
        let mut sign = open.signing_card().unwrap();
        let cert = Cert::from_file("/home/nickcao/Documents/cert").unwrap();
        let s = sign
            .signer(&cert, &|| println!("Touch confirmation needed for signing"))
            .unwrap();
        let stdout = std::io::stdout();
        let message = Message::new(stdout);
        let message = Armorer::new(message).kind(armor::Kind::Signature).build().unwrap();
        let signer = Signer::new(message, s);
        let mut signer = signer.detached().build().unwrap();
        std::io::copy(&mut std::io::stdin(), &mut signer).unwrap();
        signer.finalize().unwrap();
        status_fd.write(b"[GNUPG:] SIG_CREATED ").unwrap();
    }
}
