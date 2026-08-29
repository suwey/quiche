#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anywhere::runner::{RunOptions, run};
use clap::Parser;

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

    /// Fetch a subscription URL and convert to sub.toml
    #[arg(long = "sub")]
    sub: Option<String>,

    /// User-Agent for subscription fetch.
    /// Default: `clash-verge/v{ver} Platform/{os}`.
    #[arg(long = "sub-ua")]
    sub_ua: Option<String>,

    /// Output path for `--sub` (default: `sub.toml`).
    #[arg(long = "sub-out", default_value = "sub.toml")]
    sub_out: String,

    /// Command to restart the process (used by the UI).
    /// If set, `restart` is invoked as `<start_cmd> restart <service_name>`.
    /// If unset, the process re-executes itself via execve.
    #[arg(short = 's', long = "start-cmd")]
    start_cmd: Option<String>,
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

/// Raise the file descriptor soft limit to the hard limit.
///
/// On macOS, launchd defaults to soft=256 regardless of `kern.maxfilesperproc`,
/// which is far too low for TUN transparent proxy (each TCP connection uses
/// ~2 fds). This is a no-op on platforms where the soft limit already equals
/// the hard limit.
fn raise_fd_limit() {
    #[cfg(unix)]
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
            log::warn!("getrlimit(RLIMIT_NOFILE) failed");
            return;
        }
        let soft = rlim.rlim_cur;
        let hard = rlim.rlim_max;
        if soft < hard {
            rlim.rlim_cur = hard;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
                log::warn!(
                    "setrlimit(RLIMIT_NOFILE, {hard}) failed, keeping soft={soft}"
                );
            } else {
                log::info!("Raised NOFILE soft limit from {soft} to {hard}");
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Raise fd limit before any I/O starts. Most critical on macOS (launchd
    // caps soft at 256), but harmless on other Unix platforms.
    raise_fd_limit();

    let args = Args::parse();

    // Handle subscription import mode.
    if let Some(sub_url) = &args.sub {
        let ua = args.sub_ua.clone().unwrap_or_else(|| {
            format!(
                "clash-verge/v{} Platform/{}",
                "20.0.0",
                std::env::consts::OS
            )
        });
        anywhere::subscription::run_subscription(sub_url, &ua, &args.sub_out)
            .await?;
        return Ok(());
    }

    let opts = RunOptions {
        config_path: Some(args.config.clone()),
        config_content: None,
        #[cfg(unix)]
        tun_fd: None,
        cache_dir: None, // desktop: use config's [common].cache_dir or CWD
        start_cmd: args.start_cmd,
    };

    loop {
        run(opts.clone()).await?;
        if !anywhere::runner::RESTART_REQUESTED
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            break;
        }
        log::info!("In-process restart: re-running run()");
    }
    Ok(())
}
