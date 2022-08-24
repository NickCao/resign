use anyhow::{anyhow, Result};

use clap::Parser;


use openpgp::crypto::Decryptor;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;

use openpgp::parse::Parse;

use openpgp::parse::stream::DecryptorBuilder;
use openpgp::policy::StandardPolicy;

use openpgp::serialize::MarshalInto;

use openpgp::Packet;


use rpc::DecryptRequest;


use sequoia_openpgp as openpgp;



use tokio::runtime::Handle;

use tonic::transport::Channel;

use rpc::decryptor_client::DecryptorClient;


pub mod rpc {
    tonic::include_proto!("sequoia");
}

/// resign
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// decrypt data
    #[clap(short = 'd', long = "decrypt")]
    decrypt: bool,
    /// use USER-ID to sign or decrypt (ignored, always uses signing subkey)
    #[clap(short = 'u', long = "local-user", name = "USER-ID")]
    local_user: Option<String>,
    /// this is dummy option, gpg always requires the agent
    #[clap(long = "use-agent")]
    use_agent: bool,
    #[clap(value_parser)]
    args: Vec<String>,
}

struct RemoteDecryptor {
    client: DecryptorClient<Channel>,
    key: Key<PublicParts, UnspecifiedRole>,
}

impl RemoteDecryptor {
    async fn new(mut client: DecryptorClient<Channel>) -> anyhow::Result<Self> {
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

impl openpgp::crypto::Decryptor for RemoteDecryptor {
    fn decrypt(
        &mut self,
        ciphertext: &openpgp::crypto::mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> openpgp::Result<openpgp::crypto::SessionKey> {
        let req = DecryptRequest {
            ciphertext: ciphertext.to_vec()?,
            plaintext_len: plaintext_len.map(|x| x as u64),
        };
        let resp = Handle::current().block_on(self.client.decrypt(req));
        Ok(openpgp::crypto::SessionKey::from(
            resp?.into_inner().session_key,
        ))
    }

    fn public(
        &self,
    ) -> &Key<openpgp::packet::key::PublicParts, openpgp::packet::key::UnspecifiedRole> {
        &self.key
    }
}

impl openpgp::parse::stream::DecryptionHelper for RemoteDecryptor {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(openpgp::types::SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        for i in pkesks {
            if let Some((algo, sk)) = i.decrypt(self, sym_algo) {
                if decrypt(algo, &sk) {
                    return Ok(Some(self.public().fingerprint()));
                }
            };
        }
        Err(anyhow::anyhow!("no key to decrypt message"))
    }
}

impl openpgp::parse::stream::VerificationHelper for RemoteDecryptor {
    fn check(
        &mut self,
        _structure: openpgp::parse::stream::MessageStructure,
    ) -> openpgp::Result<()> {
        Ok(())
    }
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.decrypt {
        assert!(args.local_user.is_some());
        let channel = tonic::transport::Endpoint::try_from("http://localhost")?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                tokio::net::UnixStream::connect(args.local_user.clone().unwrap())
            }))
            .await?;
        let client = DecryptorClient::new(channel);
        let remote = RemoteDecryptor::new(client).await?;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let p = StandardPolicy::new();
            let mut decryptor =
                DecryptorBuilder::from_reader(std::io::stdin())?.with_policy(&p, None, remote)?;
            std::io::copy(&mut decryptor, &mut std::io::stdout())?;
            Ok(())
        })
        .await?
    } else {
        Err(anyhow!("no operation specified"))
    }
}
