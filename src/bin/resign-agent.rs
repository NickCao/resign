use clap::Parser;
use resign::agent::Agent;
use ssh_agent_lib::Agent as _;

/// resign-agent
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// listen address
    #[clap(short = 'l', long = "listen")]
    listen: String,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let agent = Agent::default();

    drop(std::fs::remove_file(&args.listen));
    agent.run_unix(&args.listen)?;
    Ok(())
}
