use anyhow::anyhow;
use clap::Parser;
use openpgp_card::KeyType;
use sequoia_openpgp::{
    crypto::SessionKey,
    packet::{PKESK, SKESK},
    parse::{
        stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
        Parse,
    },
    policy::StandardPolicy,
    types::SymmetricAlgorithm,
    Cert, Fingerprint, KeyHandle, Result,
};

/// resign-gpg
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// decrypt data
    #[clap(short = 'd', long = "decrypt")]
    decrypt: bool,
    /// this is dummy option, gpg always requires the agent
    #[clap(long = "use-agent")]
    use_agent: bool,
    #[clap(value_parser)]
    args: Vec<String>,
}

#[derive(Default)]
pub struct Resign {
    backend: resign::Backend,
}

impl DecryptionHelper for Resign {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let fp = self.backend.transaction(None, &|backend, tx| {
            Ok(backend.public(tx, KeyType::Decryption)?.fingerprint())
        })?;
        for i in pkesks {
            let sk = self.backend.transaction(None, &|backend, tx| {
                Ok(backend.decrypt(tx, &|de| Ok(i.decrypt(de, sym_algo)), &|| {}))
            });
            if let Ok(Ok(Some((algo, sk)))) = sk {
                if decrypt(algo, &sk) {
                    return Ok(Some(fp));
                };
            }
        }
        Err(anyhow::anyhow!("no key to decrypt message"))
    }
}

impl VerificationHelper for Resign {
    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(vec![])
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.decrypt {
        let decryptor = Resign::default();
        let p = StandardPolicy::new();
        let r = std::io::stdin();
        let mut decryptor = DecryptorBuilder::from_reader(r)?.with_policy(&p, None, decryptor)?;
        std::io::copy(&mut decryptor, &mut std::io::stdout())?;
        Ok(())
    } else {
        Err(anyhow!("no operation specified"))
    }
}
