#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anywhere::openrung::DEFAULT_BROKER_URL;
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

    /// Fetch the signed OpenRung relay directory, verify its Ed25519
    /// signature, and convert to openrung.toml. Optional value: broker base
    /// URL (default: https://broker.openrung.org/), or a file:// URL / local
    /// path for offline import.
    #[arg(
        long = "sub-openrung",
        num_args = 0..=1,
        default_missing_value = DEFAULT_BROKER_URL
    )]
    sub_openrung: Option<String>,

    /// User-Agent for subscription fetch.
    /// Default: `clash-verge/v{ver} Platform/{os}`.
    #[arg(long = "sub-ua")]
    sub_ua: Option<String>,

    /// Output path for `--sub` (default: `sub.toml`) or `--sub-openrung`
    /// (default: `openrung.toml`).
    #[arg(long = "sub-out")]
    sub_out: Option<String>,

    /// Command to restart the process (used by the UI).
    /// If set, `restart` is invoked as `<start_cmd> restart <service_name>`.
    /// If unset, the process re-executes itself via execve.
    #[arg(short = 's', long = "start-cmd")]
    start_cmd: Option<String>,
}

// ---------------------------------------------------------------------------
// Import mode resolution
// ---------------------------------------------------------------------------

/// Which one-shot import `main` should perform, if any.
#[derive(Debug, PartialEq)]
enum ImportPlan {
    /// `--sub <url>`: plain subscription conversion.
    Subscription { url: String, out: String },
    /// `--sub-openrung [<source>]`: signed OpenRung relay directory.
    Openrung { source: String, out: String },
}

/// Resolve the import plan from the parsed args. `--sub` and
/// `--sub-openrung` are mutually exclusive (error, not a clap conflict, so
/// the ambiguity is reported the same way from scripts and the UI).
fn resolve_import_plan(
    sub: &Option<String>, sub_openrung: &Option<String>,
    sub_out: &Option<String>,
) -> Result<Option<ImportPlan>, String> {
    if sub.is_some() && sub_openrung.is_some() {
        return Err(
            "--sub and --sub-openrung are mutually exclusive; pass only one"
                .to_string(),
        );
    }
    if let Some(url) = sub {
        return Ok(Some(ImportPlan::Subscription {
            url: url.clone(),
            out: sub_out.clone().unwrap_or_else(|| "sub.toml".to_string()),
        }));
    }
    if let Some(source) = sub_openrung {
        return Ok(Some(ImportPlan::Openrung {
            source: source.clone(),
            out: sub_out
                .clone()
                .unwrap_or_else(|| "openrung.toml".to_string()),
        }));
    }
    Ok(None)
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

    // Handle one-shot import modes (subscription / OpenRung directory).
    let plan = match resolve_import_plan(
        &args.sub,
        &args.sub_openrung,
        &args.sub_out,
    ) {
        Ok(plan) => plan,
        Err(e) => return Err(e.into()),
    };
    if let Some(plan) = plan {
        let ua = args.sub_ua.clone().unwrap_or_else(|| {
            format!(
                "clash-verge/v{} Platform/{}",
                "20.0.0",
                std::env::consts::OS
            )
        });
        match plan {
            ImportPlan::Subscription { url, out } => {
                anywhere::subscription::run_subscription(&url, &ua, &out)
                    .await?;
            },
            ImportPlan::Openrung { source, out } => {
                anywhere::openrung::run_openrung_import(&source, &ua, &out)
                    .await?;
            },
        }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn sub_openrung_flag_without_value_uses_default_broker() {
        let args = Args::try_parse_from(["anywhere", "--sub-openrung"])
            .expect("--sub-openrung must work as a bare flag");
        assert_eq!(
            args.sub_openrung.as_deref(),
            Some(anywhere::openrung::DEFAULT_BROKER_URL)
        );
        assert_eq!(args.sub, None);
    }

    #[test]
    fn sub_openrung_flag_accepts_a_value() {
        let args = Args::try_parse_from([
            "anywhere",
            "--sub-openrung",
            "file:///tmp/relays.json",
        ])
        .expect("--sub-openrung must accept a value");
        assert_eq!(
            args.sub_openrung.as_deref(),
            Some("file:///tmp/relays.json")
        );

        let args = Args::try_parse_from([
            "anywhere",
            "--sub-openrung=https://broker.openrung.org/",
        ])
        .expect("--sub-openrung=<v> must work");
        assert_eq!(
            args.sub_openrung.as_deref(),
            Some("https://broker.openrung.org/")
        );
    }

    #[test]
    fn sub_openrung_flag_does_not_swallow_following_flags() {
        let args = Args::try_parse_from([
            "anywhere",
            "--sub-openrung",
            "--sub-out",
            "x.toml",
        ])
        .expect("flags after the bare flag must parse");
        assert!(args.sub_openrung.is_some());
        assert_eq!(args.sub_out.as_deref(), Some("x.toml"));
    }

    #[test]
    fn plan_subscription_regression() {
        // --sub keeps its previous behavior: default output sub.toml,
        // explicit --sub-out honored.
        let plan = resolve_import_plan(
            &Some("http://example.com/sub".to_string()),
            &None,
            &None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            plan,
            ImportPlan::Subscription {
                url: "http://example.com/sub".to_string(),
                out: "sub.toml".to_string()
            }
        );

        let plan = resolve_import_plan(
            &Some("http://example.com/sub".to_string()),
            &None,
            &Some("out.toml".to_string()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            plan,
            ImportPlan::Subscription {
                url: "http://example.com/sub".to_string(),
                out: "out.toml".to_string()
            }
        );
    }

    #[test]
    fn plan_openrung_defaults_to_openrung_toml() {
        let plan = resolve_import_plan(
            &None,
            &Some(anywhere::openrung::DEFAULT_BROKER_URL.to_string()),
            &None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            plan,
            ImportPlan::Openrung {
                source: anywhere::openrung::DEFAULT_BROKER_URL.to_string(),
                out: "openrung.toml".to_string()
            }
        );

        // explicit --sub-out wins in openrung mode too
        let plan = resolve_import_plan(
            &None,
            &Some("/tmp/relays.json".to_string()),
            &Some("custom.toml".to_string()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            plan,
            ImportPlan::Openrung {
                source: "/tmp/relays.json".to_string(),
                out: "custom.toml".to_string()
            }
        );
    }

    #[test]
    fn plan_mutually_exclusive() {
        let err = resolve_import_plan(
            &Some("http://example.com/sub".to_string()),
            &Some("https://broker.openrung.org/".to_string()),
            &None,
        )
        .unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn plan_none_when_no_import_flags() {
        assert!(
            resolve_import_plan(&None, &None, &None)
                .unwrap()
                .is_none()
        );
    }
}
