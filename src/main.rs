use anyhow::{anyhow, Result};
use chrono::prelude::*;
use clap::Parser;
use openpgp::armor;

use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::packet::Signature;
use openpgp::parse::Parse;

use openpgp::serialize::stream::{Armorer, Message, Signer};

use openpgp::Packet;
use openpgp::PacketPile;

use rpc::SignRequest;

use sequoia_openpgp as openpgp;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use tokio::runtime::Handle;

use tonic::transport::Channel;

use rpc::signer_client::SignerClient;

pub mod rpc {
    tonic::include_proto!("sequoia");
}

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

struct Remote {
    client: SignerClient<Channel>,
    key: Key<PublicParts, UnspecifiedRole>,
}

impl Remote {
    async fn new(mut client: SignerClient<Channel>) -> anyhow::Result<Self> {
        let resp = client.public(()).await?.into_inner();
        let packet = Packet::from_bytes(&resp.key)?;
        if let Packet::PublicKey(key) = packet {
            Ok(Self {
                client,
                key: key.role_as_unspecified().to_owned(),
            })
        } else {
            Err(anyhow!("failed to parse public key packet"))
        }
    }
}

impl openpgp::crypto::Signer for Remote {
    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
        let req = SignRequest {
            hash_algo: u8::from(hash_algo) as u32,
            digest: digest.to_vec(),
        };
        let resp = Handle::current().block_on(self.client.sign(req));
        openpgp::crypto::mpi::Signature::parse(self.key.pk_algo(), &*(resp?.into_inner().signature))
    }

    fn public(
        &self,
    ) -> &Key<openpgp::packet::key::PublicParts, openpgp::packet::key::UnspecifiedRole> {
        &self.key
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    assert!(args.status_fd.is_some());
    let mut status_fd = unsafe { File::from_raw_fd(args.status_fd.unwrap()) };

    if args.sign {
        assert!(args.detach_sign);
        assert!(args.armor);
        assert!(args.local_user.is_some());

        let channel = tonic::transport::Endpoint::try_from("http://localhost")?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                tokio::net::UnixStream::connect(args.local_user.clone().unwrap())
            }))
            .await?;
        let client = SignerClient::new(channel);
        let remote = Remote::new(client).await?;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let message = Message::new(std::io::stdout());
            let armored = Armorer::new(message).kind(armor::Kind::Signature).build()?;
            let signer = Signer::new(armored, remote);
            let mut signer = signer.detached().build()?;
            std::io::copy(&mut std::io::stdin(), &mut signer)?;
            signer.finalize()?;
            status_fd.write(b"[GNUPG:] SIG_CREATED \n")?;
            Ok(())
        })
        .await?
    } else if args.verify {
        if args.args.len() != 2 {
            return Err(anyhow!("unsupported number of arguments"));
        }
        let pile = PacketPile::from_file(&args.args[0])?;
        for packet in pile.descendants() {
            if let Packet::Signature(Signature::V4(sig)) = packet {
                status_fd.write(b"[GNUPG:] NEWSIG \n")?;
                status_fd.write(b"[GNUPG:] GOODSIG \n")?;
                eprintln!(
                    "resign: Signature made {}",
                    DateTime::<Utc>::from(
                        sig.signature_creation_time()
                            .ok_or_else(|| anyhow!("ctime for signature ununavailable"))?
                    )
                );
                for fp in sig.issuer_fingerprints() {
                    eprintln!(
                        "resign:                using {} key {}",
                        sig.pk_algo(),
                        fp.to_hex()
                    );
                }
            }
        }
        Ok(())
    } else {
        Err(anyhow!("no operation specified"))
    }
}
