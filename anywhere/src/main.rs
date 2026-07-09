#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use anywhere::runner::{run, RunOptions};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// anywhere — a versatile proxy tool with multiple inbound/outbound protocols.
#[derive(Parser)]
#[command(
    name = "anywhere",
    version = concat!("v", env!("CARGO_PKG_VERSION"))
)]
struct Args {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "config.toml")]
    config: String,

    /// Command to restart the process (used by the UI).
    /// If set, `restart` is invoked as `<start_cmd> restart <service_name>`.
    /// If unset, the process re-executes itself via execve.
    #[arg(short = 's', long = "start-cmd")]
    start_cmd: Option<String>,
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let opts = RunOptions {
        config_path: Some(args.config.clone()),
        config_content: None,
        tun_fd: None,
        cache_dir: None, // desktop: use config's [common].cache_dir or CWD
        start_cmd: args.start_cmd,
    };

    run(opts).await
}
