//! Core engine entry point — shared by desktop binary and Android JNI.
//!
//! The `run()` function is the single entry point that sets up logging,
//! loads config, creates outbounds/rules/TUN/inbounds, and runs the event
//! loop. Both `main.rs` (desktop) and `android/jni.rs` (Android) call this.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[allow(unused_imports)]
use crate::cache::{self, StatusSink};
use crate::config::Config;
use crate::context::AppContext;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::inbound::anytls::AnytlsInbound;
use crate::inbound::quic::QuicInbound;
use crate::inbound::socks5::Socks5Inbound;
use crate::outbound::registry::OutboundRegistry;
use crate::relay::CountedPacketRelay;
use crate::relay::CountedStreamRelay;
use crate::relay::FirstByteTimeoutRelay;
use crate::relay::PrependPacketRelay;
use crate::relay::PrependStreamRelay;
use crate::relay::bidirectional_packet_relay;
use crate::relay::bidirectional_relay;

/// Special outbound tag value that means "reject the connection".
/// When a rule's outbound is this value, the connection is refused:
/// - TCP: sends RST (via SO_LINGER=0) instead of FIN
/// - UDP: silently dropped
const REJECT_TAG: &str = "reject";

fn is_reject_tag(tag: &str) -> bool {
    tag == REJECT_TAG
}
use crate::rules::Rules;
use crate::rules::SniffInfo;
use crate::sniff;
use crate::ui::AppStats;
use crate::ui::state as ui_state;

/// Flag set by `trigger_restart` / `UiCommand::Reload` to signal that the
/// engine should restart after graceful shutdown (rather than stop completely).
/// Checked by `main()` (desktop) and `android/jni.rs` after `run()` returns.
pub static RESTART_REQUESTED: AtomicBool = AtomicBool::new(false);

use uuid::Uuid;

/// Options for the engine runner.
#[derive(Clone)]
pub struct RunOptions {
    /// Path to the configuration file (desktop) or inline config content
    /// (Android, when config_path is None).
    pub config_path: Option<String>,

    /// Inline config TOML content (used by Android when no file system path).
    pub config_content: Option<String>,

    /// TUN file descriptor from Android VpnService.
    /// On Linux/macOS this is None (TUN device is created internally).
    #[cfg(unix)]
    pub tun_fd: Option<std::os::fd::RawFd>,

    /// Cache directory for geo rule-set downloads.
    /// On desktop: defaults to config's `[common].cache_dir` or CWD.
    /// On Android: should be set to the app's `filesDir` path by JNI.
    pub cache_dir: Option<String>,

    /// Start command for UI restart functionality (desktop only).
    /// If set: `<start_cmd> restart <service_name>` is spawned.
    /// If None: the process re-executes itself via execve.
    pub start_cmd: Option<String>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            config_path: None,
            config_content: None,
            #[cfg(unix)]
            tun_fd: None,
            cache_dir: None,
            start_cmd: None,
        }
    }
}

/// Core engine entry point.
///
/// Sets up logging, loads config, creates outbounds/rules, starts TUN
/// (if configured), starts all inbounds, and runs until shutdown.
///
/// On desktop: called by `main.rs` with `tun_fd: None`.
/// On Android: called by `android/jni.rs` with `tun_fd: Some(fd)`.
pub async fn run(opts: RunOptions) -> Result<(), Box<dyn std::error::Error>> {
    // --- Cache store (persistent state + runtime status) ---
    let cache_dir_path = opts
        .cache_dir
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let db_path = cache_dir_path.join("cache.db");
    let json_dir = if cfg!(target_os = "android") {
        Some(cache_dir_path.clone())
    } else {
        None
    };
    let cache: Arc<cache::CacheStore> = Arc::new(
        cache::CacheStore::open(&db_path, json_dir).unwrap_or_else(|e| {
            log::warn!("Failed to open cache.db: {e}, using ephemeral store");
            cache::CacheStore::ephemeral()
        }),
    );
    let sink: cache::SharedSink = cache.clone();
    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::Starting));

    // Resolve the actual config file path as an absolute path.
    // This is stored in context so `PUT /configs` can always write back to
    // the correct file — regardless of how the config was loaded.
    let resolved_config_path: Option<String> =
        if let Some(path) = &opts.config_path {
            // config_path was provided — canonicalize it.
            let abs = std::path::Path::new(path)
                .canonicalize()
                .or_else(|_| {
                    // File may not exist yet (Android first run with inline content).
                    // Make it absolute relative to CWD.
                    let p = if std::path::Path::new(path).is_absolute() {
                        std::path::PathBuf::from(path)
                    } else {
                        std::env::current_dir().unwrap_or_default().join(path)
                    };
                    // Create parent dir if needed (Android filesDir should exist, but be safe).
                    if let Some(parent) = p.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    std::io::Result::Ok(p)
                })
                .map(|p| p.to_string_lossy().to_string())
                .ok();
            abs
        } else if opts.config_content.is_some() {
            // No config_path but we have inline content — we need a file to write
            // back to. Use a default path in CWD (desktop) or cache_dir (Android).
            #[cfg(target_os = "android")]
            {
                opts.cache_dir
                    .as_ref()
                    .map(|d| format!("{d}/anywhere.toml"))
            }
            #[cfg(not(target_os = "android"))]
            {
                Some(
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join("config.toml")
                        .to_string_lossy()
                        .to_string(),
                )
            }
        } else {
            None
        };

    // Load config from resolved path, or fall back to inline content.
    #[allow(unused_mut)]
    let mut config = if let Some(path) = &opts.config_path {
        if std::path::Path::new(path).exists() {
            Config::load(path)?
        } else if let Some(content) = &opts.config_content {
            // File doesn't exist yet — write inline content to the resolved path
            // for future reloads, then parse.
            if let Some(ref abs_path) = resolved_config_path {
                let _ = std::fs::write(abs_path, content);
            }
            Config::from_string(content)?
        } else {
            return Err(
                "config_path file does not exist and no inline content provided"
                    .into(),
            );
        }
    } else if let Some(content) = &opts.config_content {
        // No config_path — try to load from resolved path (may have been written
        // above), otherwise parse inline.
        if let Some(ref abs_path) = resolved_config_path {
            if std::path::Path::new(abs_path).exists() {
                Config::load(abs_path)?
            } else {
                Config::from_string(content)?
            }
        } else {
            Config::from_string(content)?
        }
    } else {
        return Err(
            "either config_path or config_content must be provided".into()
        );
    };

    // --- Android: force-override path-dependent config fields ---
    // Users may upload desktop configs with wrong paths. We override
    // these to ensure Android always uses the app's filesDir.
    #[cfg(target_os = "android")]
    {
        if let Some(ref cache_dir) = opts.cache_dir {
            // Override cache_dir so geo rule-sets download to the right place.
            config.common.cache_dir = Some(cache_dir.clone());
            // Force UI listen to 0.0.0.0 if not set (so it's reachable from LAN).
            // Keep user's port/secret if specified.
            if config.ui.listen.is_none() {
                config.ui.listen = Some("0.0.0.0:9090".to_string());
            }
            // Override UI serve_path so ServeDir looks in the right place.
            // Must come after listen check above so serve_path is always set
            // when listen is Some.
            config.ui.serve_path = Some(format!("{cache_dir}/ui"));
        }
        // Ensure config_path is set for reload support.
        if config.ui.listen.is_some() {
            log::info!(
                "Android config override: cache_dir={:?}, serve_path={:?}, listen={:?}",
                config.common.cache_dir,
                config.ui.serve_path,
                config.ui.listen
            );
        }
    }

    // --- Timezone detection (skip on Android — JNI layer handles it) ---
    #[cfg(not(target_os = "android"))]
    let tz_str = std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    #[cfg(target_os = "android")]
    let tz_str = String::new();

    // --- Logger initialization ---
    let logs_tx = if config.ui.listen.is_some() {
        #[cfg(not(target_os = "android"))]
        {
            Some(crate::ui::log::init())
        }
        #[cfg(target_os = "android")]
        {
            // On Android, android_logger is already initialized in JNI.
            // Just create the broadcast channel for WS log forwarding.
            Some(crate::ui::log::init_android())
        }
    } else {
        #[cfg(not(target_os = "android"))]
        {
            use std::io::Write;
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or("info"),
            )
            .format(|buf, record| {
                let ts = chrono::Local::now();
                let level = record.level().as_str();
                let target = record.target();
                writeln!(
                    buf,
                    "{} [{level:5} {target}] {}",
                    ts.format("%Y-%m-%d %H:%M:%S"),
                    record.args()
                )
            })
            .init();
        }
        #[cfg(target_os = "android")]
        {}
        None
    };

    // --- Stale routing cleanup (Linux + Windows) ---
    #[cfg(target_os = "linux")]
    {
        crate::inbound::tun::cleanup_stale_routing();
    }

    #[cfg(target_os = "windows")]
    {
        crate::inbound::tun::cleanup_stale_routing();
    }

    log::info!("Config loaded");
    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::LoadingRules));

    if !tz_str.is_empty() {
        log::info!("Detected system timezone: UTC{tz_str}");
    }

    let registry = Arc::new(OutboundRegistry::from_config(&config).await?);

    // Determine cache directory.
    // Priority: RunOptions.cache_dir (Android JNI) > config [common].cache_dir > CWD.
    let cache_dir = opts
        .cache_dir
        .as_ref()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            config
                .common
                .cache_dir
                .as_ref()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| {
            #[cfg(target_os = "android")]
            {
                // Android fallback: app's filesDir (should have been passed via JNI,
                // but just in case — use /data/data/com.anywhere.android/files).
                log::warn!("cache_dir not set, falling back to app data dir");
                std::path::PathBuf::from("/data/data/com.anywhere.android/files")
            }
            #[cfg(not(target_os = "android"))]
            {
                std::env::current_dir().unwrap_or_default()
            }
        });

    log::info!("Cache directory: {}", cache_dir.display());

    // Plain-IP DNS upstreams for geo-rule refresh. The refresh downloads rule
    // files over a bypass (TUN-protected) socket, but it must resolve the
    // download host the same way - the system resolver is hijacked by the
    // fake-ip DNS once the TUN is up and would return 198.18.x.x. Pick the
    // plain-IP entries from [dns].direct; fall back to 223.5.5.5 if none.
    let dns_plain: Vec<std::net::SocketAddr> = {
        let mut v: Vec<std::net::SocketAddr> = config
            .dns
            .direct
            .iter()
            .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| std::net::SocketAddr::new(ip, 53))
            .collect();
        if v.is_empty() {
            v.push(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(223, 5, 5, 5)),
                53,
            ));
        }
        v
    };
    log::info!("Geo refresh DNS upstreams: {:?}", dns_plain);
    log::info!("Loading rules...");
    let rules = Arc::new(
        Rules::from_config(
            &config.rules,
            &config.outbounds,
            &cache_dir,
            sink.as_ref(),
            &dns_plain,
        )
        .await
        .map_err(|e| {
            sink.emit(cache::StatusEvent::Notice {
                level: cache::NoticeLevel::Error,
                msg: format!("Failed to initialize rules: {e}"),
            });
            log::error!("Failed to initialize rules: {e}");
            e
        })?,
    );
    sink.emit(cache::StatusEvent::Phase(
        cache::EnginePhase::StartingInbound,
    ));
    log::info!("All rules initialized");

    let mut tasks = Vec::new();

    // --- Command bus and event bus ---
    let (cmd_tx, mut cmd_rx) =
        tokio::sync::mpsc::channel::<crate::command::UiCommand>(64);
    let (event_tx, _event_rx) =
        tokio::sync::broadcast::channel::<crate::command::StateEvent>(64);

    #[allow(unused_mut)]
    let mut ctx = if config.ui.listen.is_some() {
        let current_memory: fn() -> u64 =
            if cfg!(target_os = "linux") || cfg!(target_os = "android") {
                ui_state::read_linux_memory
            } else if cfg!(target_os = "macos") {
                ui_state::read_macos_memory
            } else if cfg!(target_os = "windows") {
                ui_state::read_windows_memory
            } else {
                || 0
            };
        let stats = AppStats::new(current_memory);
        let logs_tx = logs_tx.unwrap();
        let start_cmd = opts.start_cmd.clone();

        let outbound_tags: Vec<(String, String)> = config
            .outbounds
            .iter()
            .enumerate()
            .map(|(i, o)| (o.tag_or_default(i), o.type_.clone()))
            .chain(std::iter::once((
                "GLOBAL".to_string(),
                "urltest".to_string(),
            )))
            .collect();

        let urltest_states = registry.urltest_states.clone();

        // Restore persisted mode from cache.
        let saved_mode = cache.status().mode;
        let mode_idx = match saved_mode.as_str() {
            "direct" => Some(crate::rules::MODE_DIRECT),
            "global" => Some(crate::rules::MODE_GLOBAL),
            "rule" => Some(crate::rules::MODE_RULE),
            _ => None,
        };
        if let Some(idx) = mode_idx {
            rules.set_mode(idx);
            log::info!("restored mode from cache: {saved_mode}");
        }

        // Apply persisted group selections from cache.
        // All group types (select, urltest, GLOBAL) are unified into
        // urltest_states. For select-mode groups we use set_fixed_by_name
        // which sets both `fixed` and `current`, effectively restoring the
        // manual selection.
        let saved_selections = cache.get_group_selections();
        for (group, child) in &saved_selections {
            if let Some(state) = urltest_states.get(group) {
                if state.set_fixed_by_name(child) {
                    log::info!("restored selection for '{group}' -> '{child}'");
                }
            }
        }

        AppContext::new(
            registry.clone(),
            rules.clone(),
            stats.clone(),
            logs_tx,
            start_cmd,
            outbound_tags,
            urltest_states,
            cache.clone(),
            cmd_tx,
            event_tx,
        )
    } else {
        let (logs_tx, _) =
            tokio::sync::broadcast::channel::<crate::ui::log::LogMsg>(1);
        AppContext::new(
            registry.clone(),
            rules.clone(),
            AppStats::new(|| 0),
            logs_tx,
            None,
            Vec::new(),
            HashMap::new(),
            cache.clone(),
            cmd_tx,
            event_tx,
        )
    };

    // --- TUN inbounds ---
    // Linux: create TUN device internally via rtnetlink.
    // Android: receive fd from VpnService via JNI.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    ))]
    let (_tun_guard, tun_lifecycle): (
        Option<crate::inbound::tun::TunGuard>,
        Option<crate::inbound::tun::TunLifecycle>,
    ) = {
        use crate::dns::DnsHijack;
        use crate::inbound::tun::TunConfig;
        use crate::inbound::tun::TunInbound;
        use tokio_util::sync::CancellationToken;

        let dns_cfg = config.dns.clone();

        let mut last_guard = None;
        let mut last_lifecycle = None;

        for cfg in config.inbounds_by_type("tun") {
            let tun_config = match TunConfig::from_inbound_config(cfg) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Invalid TUN config: {e}");
                    continue;
                },
            };

            let local_direct = tun_config.local_direct;
            let fakeip_enabled = dns_cfg.fakeip.is_some();
            // Pass fakeip state to TunConfig so platform managers know
            // whether to set system DNS.
            let mut tun_config = tun_config;
            tun_config.fakeip_enabled = fakeip_enabled;
            let dns_cfg_for_builder = dns_cfg.clone();
            let rules_for_builder = rules.clone();
            let registry_clients = registry.clients_arc();
            let dns_builder: Box<
                dyn FnOnce(
                        crate::inbound::tun::TunWriter,
                        std::sync::Arc<
                            crate::inbound::tun::reverse_dns::ReverseDnsCache,
                        >,
                        CancellationToken,
                    ) -> DnsHijack
                    + Send,
            > = Box::new(move |writer, reverse_cache, shutdown| {
                DnsHijack::new(
                    &dns_cfg_for_builder,
                    local_direct,
                    rules_for_builder,
                    registry_clients,
                    writer,
                    reverse_cache,
                    shutdown,
                )
                .expect("invalid dns upstream")
            });

            #[cfg(target_os = "linux")]
            {
                match TunInbound::new(&tun_config, Some(dns_builder)).await {
                    Ok((inbound, guard, lifecycle)) => {
                        log::info!("Starting TUN inbound on {}", tun_config.addr);
                        log::info!(
                            "DNS hijack enabled (direct={:?}, remote={:?})",
                            dns_cfg.direct,
                            dns_cfg.remote
                        );
                        tasks.push(tokio::spawn(run_inbound(
                            inbound,
                            ctx.clone(),
                        )));
                        last_guard = Some(guard);
                        last_lifecycle = Some(lifecycle);
                    },
                    Err(e) => {
                        log::error!("Failed to start TUN inbound: {e}");
                    },
                }
            }

            #[cfg(target_os = "android")]
            {
                let fd = opts.tun_fd.ok_or_else(|| {
                    "TUN inbound configured but no fd provided from VpnService"
                })?;
                match TunInbound::new(&tun_config, Some(dns_builder), Some(fd))
                    .await
                {
                    Ok((inbound, guard, lifecycle)) => {
                        log::info!("Starting TUN inbound on Android (fd={})", fd);
                        log::info!(
                            "DNS hijack enabled (direct={:?}, remote={:?})",
                            dns_cfg.direct,
                            dns_cfg.remote
                        );
                        tasks.push(tokio::spawn(run_inbound(
                            inbound,
                            ctx.clone(),
                        )));
                        last_guard = Some(guard);
                        last_lifecycle = Some(lifecycle);
                    },
                    Err(e) => {
                        log::error!("Failed to start TUN inbound: {e}");
                    },
                }
            }

            #[cfg(target_os = "macos")]
            {
                match TunInbound::new(&tun_config, Some(dns_builder)).await {
                    Ok((inbound, guard, lifecycle)) => {
                        log::info!(
                            "Starting TUN inbound on {} (macOS)",
                            tun_config.addr
                        );
                        log::info!(
                            "DNS hijack enabled (direct={:?}, remote={:?})",
                            dns_cfg.direct,
                            dns_cfg.remote
                        );
                        tasks.push(tokio::spawn(run_inbound(
                            inbound,
                            ctx.clone(),
                        )));
                        last_guard = Some(guard);
                        last_lifecycle = Some(lifecycle);
                    },
                    Err(e) => {
                        log::error!("Failed to start TUN inbound: {e}");
                    },
                }
            }
            #[cfg(target_os = "windows")]
            {
                match TunInbound::new(&tun_config, Some(dns_builder)).await {
                    Ok((inbound, guard, lifecycle)) => {
                        log::info!(
                            "Starting TUN inbound on {} (Windows)",
                            tun_config.addr
                        );
                        log::info!(
                            "DNS hijack enabled (direct={:?}, remote={:?})",
                            dns_cfg.direct,
                            dns_cfg.remote
                        );
                        tasks.push(tokio::spawn(run_inbound(
                            inbound,
                            ctx.clone(),
                        )));
                        last_guard = Some(guard);
                        last_lifecycle = Some(lifecycle);
                    },
                    Err(e) => {
                        log::error!("Failed to start TUN inbound: {e}");
                    },
                }
            }
        }
        (last_guard, last_lifecycle)
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )))]
    let (_tun_guard, tun_lifecycle): (
        Option<crate::inbound::tun::TunGuard>,
        Option<crate::inbound::tun::TunLifecycle>,
    ) = (None, None);

    // Inject TUN manager into context (Linux/macOS/Windows - Android has no
    // route manager; its TUN routing is handled by VpnService).
    #[cfg(target_os = "linux")]
    if let Some(guard) = &_tun_guard {
        if let Some(mgr) = guard.tun_mgr() {
            ctx.set_tun_mgr(mgr);
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(guard) = &_tun_guard {
        if let Some(mgr) = guard.tun_mgr() {
            ctx.set_tun_mgr(mgr);
        }
    }
    #[cfg(target_os = "windows")]
    if let Some(guard) = &_tun_guard {
        if let Some(mgr) = guard.tun_mgr() {
            ctx.set_tun_mgr(mgr);
        }
    }

    // Store resolved absolute config path in context for reload support.
    ctx.set_config_path(resolved_config_path.clone());
    log::info!(
        "Config file: {}",
        resolved_config_path.as_deref().unwrap_or("<none>")
    );

    // --- UI server (optional) ---
    if config.ui.listen.is_some() {
        let ctx_for_ui = ctx.clone();
        let ui_config = config.ui.clone();
        tasks.push(tokio::spawn(async move {
            crate::ui::start(ui_config, ctx_for_ui).await;
        }));

        let stats = ctx.stats.clone();
        tasks.push(tokio::spawn(async move {
            stats_ticker_task(stats).await;
        }));
    }

    // --- Actor: process UiCommands from the UI ---
    {
        let ctx_for_actor = ctx.clone();
        tasks.push(tokio::spawn(async move {
            use crate::command::UiCommand;
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    UiCommand::SetMode(mode, tx) => {
                        let ok = ctx_for_actor.set_mode(mode);
                        let _ = tx.send(ok);
                    },
                    UiCommand::TunSetRouting(enable, tx) => {
                        let result = if enable {
                            ctx_for_actor.tun_routing_enable()
                        } else {
                            ctx_for_actor.tun_routing_disable()
                        };
                        let _ = tx.send(result);
                    },
                    UiCommand::Reload => {
                        ::log::info!(
                            "Reload command received - in-process restart"
                        );
                        #[cfg(not(target_os = "android"))]
                        {
                            RESTART_REQUESTED.store(true, Ordering::SeqCst);
                            ctx_for_actor.shutdown_signal.notify_waiters();
                        }
                        #[cfg(target_os = "android")]
                        {
                            crate::android::jni::request_restart();
                        }
                    },
                }
            }
        }));
    }

    // --- TUN mode check ---
    let has_tun = cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )) && !config.inbounds_by_type("tun").is_empty();

    // --- SOCKS5 inbounds ---
    for cfg in config.inbounds_by_type("socks5") {
        if has_tun {
            log::warn!(
                "TUN inbound active -- skipping SOCKS5 inbounds \
                 (all traffic already proxied via TUN)"
            );
            break;
        }
        let listen = cfg.listen.as_deref().unwrap_or("127.0.0.1:1080");

        match Socks5Inbound::new(listen).await {
            Ok(inbound) => {
                log::info!("Starting SOCKS5 inbound on {listen}");
                tasks.push(tokio::spawn(run_inbound(inbound, ctx.clone())));
            },
            Err(e) => {
                log::error!("Failed to bind SOCKS5 inbound on {listen}: {e}");
            },
        }
    }

    // --- QUIC inbounds ---
    for cfg in config.inbounds_by_type("quic") {
        if has_tun {
            log::warn!(
                "TUN inbound active -- skipping QUIC inbounds \
                 (all traffic already proxied via TUN)"
            );
            break;
        }
        match QuicInbound::from_config(cfg, config.passwords()) {
            Some(inbound) => {
                log::info!("Starting QUIC inbound");
                tasks.push(tokio::spawn(run_inbound(inbound, ctx.clone())));
            },
            None => {
                log::warn!("QuicInbound::from_config returned None");
            },
        }
    }

    // --- AnyTLS inbounds ---
    for cfg in config.inbounds_by_type("anytls") {
        if has_tun {
            log::warn!(
                "TUN inbound active -- skipping anytls inbounds \
                 (all traffic already proxied via TUN)"
            );
            break;
        }
        match AnytlsInbound::from_config(cfg, config.passwords()) {
            Some(inbound) => {
                log::info!("Starting anytls inbound");
                tasks.push(tokio::spawn(run_inbound(inbound, ctx.clone())));
            },
            None => {
                log::warn!("AnytlsInbound::from_config returned None");
            },
        }
    }

    if tasks.is_empty() {
        log::warn!("No inbounds configured; nothing to do.");
    }

    // --- Run until shutdown ---
    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::Ready));

    #[cfg(not(target_os = "android"))]
    {
        tokio::select! {
            _ = futures_util::future::join_all(tasks.iter_mut()) => {},
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutdown signal received, exiting...");
            },
            _ = ctx.shutdown_signal.notified() => {
                log::info!("In-process restart requested, shutting down...");
            },
        }
        // Abort spawned tasks so ports/resources are released before the
        // next run() iteration (in-process restart) or process exit.
        for handle in tasks {
            handle.abort();
        }
    }
    #[cfg(target_os = "android")]
    {
        // On Android, shutdown is triggered by the JNI layer (Kotlin calls
        // stopEngine). The run loop simply waits for all tasks to finish.
        futures_util::future::join_all(tasks).await;
    }

    // Abort per-connection relay tasks (spawned by run_inbound) so they
    // release their `Arc<dyn OutboundClient>` clones - especially the mless
    // multiplexer, whose WebSocket must close before the next run() reconnects.
    // Without this the old mless WS lingers and the proxy server throttles the
    // new connection (~100x slower after reload, refresh doesn't help).
    let drained_conns: Vec<tokio::task::JoinHandle<()>> = ctx
        .conn_handles
        .lock()
        .expect("conn_handles poisoned")
        .drain(..)
        .collect();
    for h in &drained_conns {
        h.abort();
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        futures_util::future::join_all(drained_conns),
    )
    .await;
    // Abort urltest background test loops so the outbound clients they hold
    // (esp. mless/vless mux persistent connections) are released. Together
    // with the per-connection task abort above and run() dropping the old
    // registry, this fully releases the old proxy WebSocket before the next
    // run() iteration reconnects.
    ctx.registry.shutdown_test_loops();

    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::Stopping));
    // Shut down TUN background tasks (reader, accept loop, NAT cleanup, DNS
    // listeners) and wait for them to release the `Arc<AsyncDevice>` before
    // the next run() iteration recreates the TUN device. Without this the
    // orphaned tasks keep the Wintun adapter/session open on Windows; the
    // reopened adapter then starts a second session that never receives
    // traffic, leaving the UI with no connections after an in-process reload.
    if let Some(tun_lifecycle) = tun_lifecycle {
        tun_lifecycle.shutdown().await;
    }
    drop(_tun_guard);
    log::info!("Shutdown complete.");
    Ok(())
}

/// Background task: snapshots atomics every 3s and broadcasts to WS channels.
async fn stats_ticker_task(stats: Arc<AppStats>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));

    let mut prev_upload = 0u64;
    let mut prev_download = 0u64;

    loop {
        interval.tick().await;

        let cur_upload = stats.upload_total.load(Ordering::Relaxed);
        let cur_download = stats.download_total.load(Ordering::Relaxed);

        let up = cur_upload.saturating_sub(prev_upload);
        let down = cur_download.saturating_sub(prev_download);
        prev_upload = cur_upload;
        prev_download = cur_download;

        let _ = stats.traffic_tx.send(ui_state::TrafficMsg { up, down });

        let inuse = (stats.current_memory)();
        let _ = stats.memory_tx.send(ui_state::MemoryMsg { inuse });

        let conns = stats.connections.read().await;
        let connections: Vec<_> = conns
            .values()
            .map(|cs| {
                let upload = cs.counters.upload.load(Ordering::Relaxed);
                let download = cs.counters.download.load(Ordering::Relaxed);
                let mut c = cs.info.clone();
                c.upload = upload;
                c.download = download;
                c
            })
            .collect();
        drop(conns);

        let _ = stats.connections_tx.send(ui_state::ConnectionsMsg {
            download_total: cur_download,
            upload_total: cur_upload,
            memory: inuse,
            connections,
        });
    }
}

// ---------------------------------------------------------------------------
// Per-inbound event loop
// ---------------------------------------------------------------------------

async fn run_inbound(mut inbound: impl Inbound + 'static, ctx: AppContext) {
    loop {
        let Some(conn) = inbound.accept().await else {
            log::warn!("Inbound accept returned None, retrying in 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        let ctx = ctx.clone();
        let conn_handles = ctx.conn_handles.clone();

        let handle = tokio::spawn(async move {
            let network = conn.network();
            let source = *conn.source();
            let type_name = conn.type_name().to_string();

            // --- Sniff phase (TUN TCP only) ---
            // In TUN mode the destination is an IP address. Read the first
            // bytes of the TCP stream to extract TLS SNI or HTTP Host,
            // then replace the destination domain so domain-based rules match.
            let (destination, mut stream, sniff_info) = match conn {
                InboundConn::Tcp {
                    destination,
                    mut stream,
                    sniff: true,
                    ..
                } => {
                    // Skip sniff for server-first protocols (SMTP/IMAP/POP3/FTP/SSH)
                    // where the server sends the first packet.
                    if sniff::is_server_first(destination.port) {
                        (destination, stream, None)
                    } else {
                        let mut buf = vec![0u8; 4096];
                        let mut total = 0;
                        while total < buf.len() {
                            // Check if we have a complete TLS record — if so, stop reading.
                            // TLS record header: type(1) + version(2) + length(2)
                            if total >= 5 && buf[0] == 0x16 {
                                let record_len =
                                    u16::from_be_bytes([buf[3], buf[4]]) as usize;
                                if total >= 5 + record_len {
                                    break; // full ClientHello received
                                }
                            }
                            // Also break early for HTTP (double CRLF marks end of headers)
                            if total >= 4
                                && buf[total - 4] == b'\r'
                                && buf[total - 3] == b'\n'
                                && buf[total - 2] == b'\r'
                                && buf[total - 1] == b'\n'
                            {
                                break;
                            }
                            // After the first read, check if the data looks like
                            // something we can sniff (TLS/HTTP/QUIC/DNS/etc.).
                            // If not, skip further sniff reads immediately to
                            // avoid adding latency to non-standard protocols
                            // (e.g. WeChat MMTLS).
                            if total > 0 && !sniff::looks_sniffable(&buf[..total])
                            {
                                break;
                            }
                            // Timeout to prevent sniff from blocking indefinitely on
                            // protocols where the client sends a small packet then
                            // waits for the server to respond (e.g. WeChat private
                            // protocol). Without this, the connection stalls.
                            match tokio::time::timeout(
                                Duration::from_millis(500),
                                stream.read(&mut buf[total..]),
                            )
                            .await
                            {
                                Ok(Ok(0)) => break,
                                Ok(Ok(n)) => total += n,
                                Ok(Err(e)) => {
                                    log::debug!("sniff: read error: {e}");
                                    let _ = stream.shutdown().await;
                                    return;
                                },
                                Err(_) => {
                                    // Sniff timeout — proceed with whatever we have.
                                    log::debug!(
                                        "sniff: timeout after reading {total} bytes from {destination}"
                                    );
                                    break;
                                },
                            }
                        }
                        let peeked = &buf[..total];
                        let sniffed = sniff::sniff(peeked);
                        let sniff_info = sniffed.as_ref().map(|r| {
                            SniffInfo::from_sniff_result(
                                r.domain.clone(),
                                r.protocol,
                            )
                        });

                        let new_dest = if let Some(ref domain) =
                            sniff_info.as_ref().and_then(|s| s.domain.as_ref())
                        {
                            let ip = destination.resolved_ip.or_else(|| {
                                match &destination.address {
                                    Address::Ipv4(o) => Some(
                                        std::net::IpAddr::V4(Ipv4Addr::from(*o)),
                                    ),
                                    Address::Ipv6(o) => Some(
                                        std::net::IpAddr::V6(Ipv6Addr::from(*o)),
                                    ),
                                    _ => None,
                                }
                            });
                            match ip {
                                Some(ip) => Destination::with_resolved(
                                    Address::Domain(domain.to_string()),
                                    destination.port,
                                    ip,
                                ),
                                None => Destination::new(
                                    Address::Domain(domain.to_string()),
                                    destination.port,
                                ),
                            }
                        } else {
                            destination
                        };

                        let boxed: Box<dyn crate::relay::StreamRelay> =
                            Box::new(PrependStreamRelay::new(
                                stream,
                                buf[..total].to_vec(),
                            ));
                        (new_dest, boxed, sniff_info)
                    } // end else (not server-first)
                },
                InboundConn::Tcp {
                    destination,
                    stream,
                    ..
                } => (destination, stream, None),
                InboundConn::Udp {
                    initial_destination,
                    mut packet,
                    type_,
                    ..
                } => {
                    // --- UDP path (with optional sniff) ---
                    // For TUN UDP, sniff the first datagram for QUIC SNI or DNS query name.
                    let mut sniff_info: Option<SniffInfo> = None;
                    let mut destination = initial_destination.clone();

                    let should_sniff_udp = type_ == "tun"
                        && matches!(
                            &initial_destination.address,
                            Address::Ipv4(_) | Address::Ipv6(_)
                        );

                    if should_sniff_udp {
                        let mut buf = vec![0u8; 4096];
                        match packet.read_packet(&mut buf).await {
                            Ok((n, dest)) if n > 0 => {
                                let payload = &buf[..n];
                                if let Some(result) = sniff::sniff(payload) {
                                    sniff_info =
                                        Some(SniffInfo::from_sniff_result(
                                            result.domain.clone(),
                                            result.protocol,
                                        ));
                                    if let Some(ref domain) = sniff_info
                                        .as_ref()
                                        .and_then(|s| s.domain.as_ref())
                                    {
                                        let ip = initial_destination
                                            .resolved_ip
                                            .or_else(
                                                || match &initial_destination
                                                    .address
                                                {
                                                    Address::Ipv4(o) => Some(
                                                        std::net::IpAddr::V4(
                                                            Ipv4Addr::from(*o),
                                                        ),
                                                    ),
                                                    Address::Ipv6(o) => Some(
                                                        std::net::IpAddr::V6(
                                                            Ipv6Addr::from(*o),
                                                        ),
                                                    ),
                                                    _ => None,
                                                },
                                            );
                                        destination = match ip {
                                            Some(ip) => {
                                                Destination::with_resolved(
                                                    Address::Domain(
                                                        domain.to_string(),
                                                    ),
                                                    initial_destination.port,
                                                    ip,
                                                )
                                            },
                                            None => Destination::new(
                                                Address::Domain(
                                                    domain.to_string(),
                                                ),
                                                initial_destination.port,
                                            ),
                                        };
                                    }
                                }
                                // Wrap packet relay to restore the consumed first datagram.
                                packet = Box::new(PrependPacketRelay::new(
                                    packet,
                                    payload.to_vec(),
                                    dest,
                                ));
                            },
                            _ => {
                                // Failed to read first packet — proceed without sniffing.
                            },
                        }
                    }

                    let host = if let Some(ref si) = sniff_info {
                        si.domain
                            .clone()
                            .unwrap_or_else(|| destination.address.to_string())
                    } else {
                        destination.address.to_string()
                    };
                    let dest_ip = destination.address.to_string();
                    let dest_port = destination.port.to_string();

                    let rule_match = match ctx.rules.match_conn(
                        &destination,
                        network,
                        sniff_info.as_ref(),
                    ) {
                        Some(m) => m,
                        None => {
                            log::warn!(
                                "No rule for {destination} ({network}), dropping"
                            );
                            return;
                        },
                    };
                    let tag = &rule_match.outbound_tag;
                    if is_reject_tag(tag) {
                        log::info!(
                            "Reject (udp) {destination} matched rule '{}'",
                            rule_match.description
                        );
                        // UDP: just drop the packet silently.
                        return;
                    }
                    let client = match ctx.registry.get(&tag) {
                        Some(c) => c,
                        None => {
                            log::warn!("No outbound tag '{tag}'");
                            return;
                        },
                    };

                    let conn_id = Uuid::new_v4().to_string();
                    let counters = ui_state::ConnCounters::new_arc();
                    let tag_stats = ctx.stats.get_or_create_tag(&tag).await;
                    let info = ui_state::Connection {
                        id: conn_id.clone(),
                        metadata: ui_state::ConnMetadata {
                            destination_ip: dest_ip,
                            destination_port: dest_port,
                            host,
                            network: network.to_string(),
                            type_: format!("{type_name}/{network}"),
                            source_ip: source.ip().to_string(),
                            source_port: source.port().to_string(),
                            process_path: String::new(),
                            dns_mode: "normal".to_string(),
                        },
                        upload: 0,
                        download: 0,
                        start: chrono::Local::now().to_rfc3339(),
                        chains: vec![tag.clone()],
                        rule: rule_match.description.clone(),
                    };
                    ctx.stats
                        .add_connection(
                            conn_id.clone(),
                            Arc::clone(&counters),
                            info,
                        )
                        .await;

                    let mut packet = packet;
                    let dial_result = {
                        client.dial_udp(&initial_destination).await.map_err(|e| {
                            format!(
                                "Failed to dial_udp {initial_destination} \
                                     via {tag}: {e}"
                            )
                        })
                    };
                    let out = match dial_result {
                        Ok(o) => o,
                        Err(msg) => {
                            log::error!("{msg}");
                            ctx.stats.remove_connection(&conn_id).await;
                            if msg.contains("No file descriptors") {
                                tokio::time::sleep(Duration::from_millis(100))
                                    .await;
                            }
                            return;
                        },
                    };
                    let mut counted_out = CountedPacketRelay {
                        inner: out,
                        stats: Arc::clone(&ctx.stats),
                        conn_counters: Arc::clone(&counters),
                        tag_stats: Arc::clone(&tag_stats),
                    };
                    log::info!("Relaying udp {initial_destination} via {tag}");
                    let udp_timeout = sniff_info
                        .as_ref()
                        .and_then(|si| si.protocol.as_deref())
                        .map(crate::relay::udp_timeout_for_protocol)
                        .unwrap_or(crate::relay::DEFAULT_UDP_TIMEOUT);
                    bidirectional_packet_relay(
                        &mut *packet,
                        &mut counted_out,
                        udp_timeout,
                    )
                    .await;
                    ctx.stats.remove_connection(&conn_id).await;
                    return;
                },
            };

            // --- TCP path (after sniff) ---
            let host = if let Some(ref si) = sniff_info {
                si.domain
                    .clone()
                    .unwrap_or_else(|| destination.address.to_string())
            } else {
                destination.address.to_string()
            };
            let dest_ip = destination.address.to_string();
            let dest_port = destination.port.to_string();

            let rule_match = match ctx.rules.match_conn(
                &destination,
                network,
                sniff_info.as_ref(),
            ) {
                Some(m) => m,
                None => {
                    log::warn!("No rule for {destination} ({network}), dropping");
                    return;
                },
            };
            let tag = &rule_match.outbound_tag;
            if is_reject_tag(tag) {
                log::info!(
                    "Reject (tcp) {destination} matched rule '{}'",
                    rule_match.description
                );
                // TCP: send RST by setting SO_LINGER=0 then dropping the stream.
                reset_tcp_stream(&mut stream).await;
                return;
            }
            let client = match ctx.registry.get(&tag) {
                Some(c) => c,
                None => {
                    log::warn!("No outbound tag '{tag}'");
                    return;
                },
            };

            let conn_id = Uuid::new_v4().to_string();
            let counters = ui_state::ConnCounters::new_arc();
            let tag_stats = ctx.stats.get_or_create_tag(&tag).await;
            let info = ui_state::Connection {
                id: conn_id.clone(),
                metadata: ui_state::ConnMetadata {
                    destination_ip: dest_ip,
                    destination_port: dest_port,
                    host,
                    network: network.to_string(),
                    type_: format!("{type_name}/{network}"),
                    source_ip: source.ip().to_string(),
                    source_port: source.port().to_string(),
                    process_path: String::new(),
                    dns_mode: "normal".to_string(),
                },
                upload: 0,
                download: 0,
                start: chrono::Local::now().to_rfc3339(),
                chains: vec![tag.clone()],
                rule: rule_match.description.clone(),
            };
            ctx.stats
                .add_connection(conn_id.clone(), Arc::clone(&counters), info)
                .await;

            let dial_result = {
                client.dial(&destination).await.map_err(|e| {
                    format!("Failed to dial {destination} via {tag}: {e}")
                })
            };
            let out = match dial_result {
                Ok(o) => o,
                Err(msg) => {
                    // macOS fallback: direct TCP connections fail because
                    // source IP (10.0.0.1) is not routable from gateway.
                    // Retry through the "auto" (proxy) outbound.
                    #[cfg(target_os = "macos")]
                    {
                        if tag == "direct"
                            && network == crate::inbound::Network::Tcp
                        {
                            if let Some(auto_client) =
                                ctx.registry.get("auto").cloned()
                            {
                                log::info!(
                                    "macOS direct failed, falling back to auto: {destination}"
                                );
                                let fallback_result = auto_client
                                    .dial(&destination)
                                    .await
                                    .map_err(|e| e.to_string());
                                match fallback_result {
                                    Ok(o) => {
                                        log::info!(
                                            "Fallback to auto succeeded for {destination}"
                                        );
                                        o
                                    },
                                    Err(e2_msg) => {
                                        log::error!(
                                            "{msg}; fallback to auto also failed: {e2_msg}"
                                        );
                                        let _ = stream.shutdown().await;
                                        ctx.stats
                                            .remove_connection(&conn_id)
                                            .await;
                                        return;
                                    },
                                }
                            } else {
                                log::error!("{msg}");
                                let _ = stream.shutdown().await;
                                ctx.stats.remove_connection(&conn_id).await;
                                return;
                            }
                        } else {
                            log::error!("{msg}");
                            let _ = stream.shutdown().await;
                            ctx.stats.remove_connection(&conn_id).await;
                            return;
                        }
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        log::error!("{msg}");
                        let _ = stream.shutdown().await;
                        ctx.stats.remove_connection(&conn_id).await;
                        return;
                    }
                },
            };

            let mut counted_out = CountedStreamRelay {
                // First-byte timeout: if the remote never answers (dead proxy
                // session, unreachable target) tear the relay down instead of
                // hanging until the client gives up.
                inner: Box::new(FirstByteTimeoutRelay::new(out)),
                stats: Arc::clone(&ctx.stats),
                conn_counters: Arc::clone(&counters),
                tag_stats: Arc::clone(&tag_stats),
            };

            if let Some(ref si) = sniff_info {
                if let Some(ref d) = si.domain {
                    log::info!(
                        "Relaying tcp {destination} (sniffed: {d}) via {tag}"
                    );
                } else {
                    log::info!("Relaying tcp {destination} via {tag}");
                }
            } else {
                log::info!("Relaying tcp {destination} via {tag}");
            }
            bidirectional_relay(&mut *stream, &mut counted_out).await;
            // After relay completes, gracefully finish the inbound stream to
            // release associated resources (e.g. TUN NAT table entries) and
            // close cleanly (FIN). RST (`reset()`) is reserved for the
            // `reject` rule only.
            stream.finish().await;
            ctx.stats.remove_connection(&conn_id).await;
        });
        conn_handles
            .lock()
            .expect("conn_handles poisoned")
            .push(handle);
    }
}

/// Set SO_LINGER=0 on the underlying TCP socket so that when the stream
/// is dropped, the kernel sends a RST instead of the normal FIN sequence.
async fn reset_tcp_stream(stream: &mut Box<dyn crate::relay::StreamRelay>) {
    // The StreamRelay trait has a `reset()` method (default: shutdown).
    // TcpRelay overrides it to set SO_LINGER=0 before closing, which
    // causes the kernel to send RST on drop.
    stream.reset().await;
}
