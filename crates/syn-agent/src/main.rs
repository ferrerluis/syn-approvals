use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use syn_agent::Agent;
use syn_config::{AgentConfig, DEFAULT_AGENT_CONFIG};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "syn-agent", about = "Rootless Syn request relay")]
struct Arguments {
    /// Root-owned agent configuration.
    #[arg(long, default_value = DEFAULT_AGENT_CONFIG)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "syn_agent=info".into()),
        )
        .with_target(false)
        .init();
    let arguments = Arguments::parse();
    let config = AgentConfig::load(&arguments.config)?;
    config.validate()?;
    Agent::from_config(config).await?.run().await
}
