//! Core engine entry point — shared by desktop binary and Android JNI.
//!
//! The `run()` function is the single entry point that sets up logging,
//! loads config, creates outbounds/rules/TUN/inbounds, and runs the event
//! loop. Both `main.rs` (desktop) and `android/jni.rs` (Android) call this.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::Config;
use crate::context::AppContext;
#[allow(unused_imports)]
use crate::cache::{self, StatusSink};
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::inbound::anytls::AnytlsInbound;
use crate::inbound::quic::QuicInbound;
use crate::inbound::socks5::Socks5Inbound;
use crate::outbound::registry::OutboundRegistry;
use crate::relay::CountedPacketRelay;
use crate::relay::CountedStreamRelay;
use crate::relay::bidirectional_packet_relay;
use crate::relay::bidirectional_relay;
use crate::rules::Rules;
use crate::ui::AppStats;
use crate::ui::state as ui_state;

use uuid::Uuid;

/// Options for the engine runner.
pub struct RunOptions {
    /// Path to the configuration file (desktop) or inline config content
    /// (Android, when config_path is None).
    pub config_path: Option<String>,

    /// Inline config TOML content (used by Android when no file system path).
    pub config_content: Option<String>,

    /// TUN file descriptor from Android VpnService.
    /// On Linux/macOS this is None (TUN device is created internally).
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
    let cache_dir_path = opts.cache_dir
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
        cache::CacheStore::open(&db_path, json_dir)
            .unwrap_or_else(|e| {
                log::warn!("Failed to open cache.db: {e}, using ephemeral store");
                cache::CacheStore::ephemeral()
            }),
    );
    let sink: cache::SharedSink = cache.clone();
    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::Starting));

    // Resolve the actual config file path as an absolute path.
    // This is stored in context so `PUT /configs` can always write back to
    // the correct file — regardless of how the config was loaded.
    let resolved_config_path: Option<String> = if let Some(path) = &opts.config_path {
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
            opts.cache_dir.as_ref().map(|d| format!("{d}/anywhere.toml"))
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
            return Err("config_path file does not exist and no inline content provided".into());
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
        return Err("either config_path or config_content must be provided".into());
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

    // --- Stale routing cleanup (Linux only) ---
    #[cfg(target_os = "linux")]
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

    log::info!("Loading rules...");
    let rules = Arc::new(
        Rules::from_config(&config.rules, &config.outbounds, &cache_dir, sink.as_ref())
            .await
            .map_err(|e| {
                sink.emit(cache::StatusEvent::Notice { level: cache::NoticeLevel::Error, msg: format!("Failed to initialize rules: {e}") });
                log::error!("Failed to initialize rules: {e}");
                e
            })?,
    );
    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::StartingInbound));
    log::info!("All rules initialized");

    let mut tasks = Vec::new();

    // --- Command bus and event bus ---
    let (cmd_tx, mut cmd_rx) =
        tokio::sync::mpsc::channel::<crate::command::UiCommand>(64);
    let (event_tx, _event_rx) =
        tokio::sync::broadcast::channel::<crate::command::StateEvent>(64);

    #[allow(unused_mut)]
    let mut ctx = if config.ui.listen.is_some() {
        let current_memory: fn() -> u64 = if cfg!(target_os = "linux")
            || cfg!(target_os = "android")
        {
            ui_state::read_linux_memory
        } else if cfg!(target_os = "macos") {
            ui_state::read_macos_memory
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
            .collect();

        let urltest_states = registry.urltest_states.clone();

        AppContext::new(
            registry.clone(),
            rules.clone(),
            stats.clone(),
            logs_tx,
            start_cmd,
            outbound_tags,
            urltest_states,
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
            cmd_tx,
            event_tx,
        )
    };

    // --- TUN inbounds ---
    // Linux: create TUN device internally via rtnetlink.
    // Android: receive fd from VpnService via JNI.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _tun_guard: Option<crate::inbound::tun::TunGuard> = {
        use crate::dns::DnsHijack;
        use crate::inbound::tun::TunConfig;
        use crate::inbound::tun::TunInbound;

        let dns_cfg = config.dns.clone();

        let mut last_guard = None;

        for cfg in config.inbounds_by_type("tun") {
            let tun_config = match TunConfig::from_inbound_config(cfg) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Invalid TUN config: {e}");
                    continue;
                },
            };

            let local_direct = tun_config.local_direct;
            let dns_cfg_for_builder = dns_cfg.clone();
            let rules_for_builder = rules.clone();
            let registry_clients = registry.clients_arc();
            let dns_builder: Box<
                dyn FnOnce(
                        crate::inbound::tun::TunWriter,
                        std::sync::Arc<
                            crate::inbound::tun::reverse_dns::ReverseDnsCache,
                        >,
                    ) -> DnsHijack
                    + Send,
            > = Box::new(move |writer, reverse_cache| {
                DnsHijack::new(
                    &dns_cfg_for_builder,
                    local_direct,
                    rules_for_builder,
                    registry_clients,
                    writer,
                    reverse_cache,
                )
                .expect("invalid dns upstream")
            });

            #[cfg(target_os = "linux")]
            {
                match TunInbound::new(&tun_config, Some(dns_builder)).await {
                    Ok((inbound, guard)) => {
                        log::info!("Starting TUN inbound on {}", tun_config.addr);
                        log::info!(
                            "DNS hijack enabled (direct={:?}, remote={:?})",
                            dns_cfg.direct,
                            dns_cfg.remote
                        );
                        tasks.push(tokio::spawn(run_inbound(inbound, ctx.clone())));
                        last_guard = Some(guard);
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
                match TunInbound::new(&tun_config, Some(dns_builder), Some(fd)).await {
                    Ok((inbound, guard)) => {
                        log::info!("Starting TUN inbound on Android (fd={})", fd);
                        log::info!(
                            "DNS hijack enabled (direct={:?}, remote={:?})",
                            dns_cfg.direct,
                            dns_cfg.remote
                        );
                        tasks.push(tokio::spawn(run_inbound(inbound, ctx.clone())));
                        last_guard = Some(guard);
                    },
                    Err(e) => {
                        log::error!("Failed to start TUN inbound: {e}");
                    },
                }
            }
        }
        last_guard
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _tun_guard: Option<crate::inbound::tun::TunGuard> = None;

    // Inject TUN manager into context (Linux only — Android has no route manager).
    #[cfg(target_os = "linux")]
    if let Some(ref guard) = _tun_guard {
        if let Some(mgr) = guard.tun_mgr() {
            ctx.set_tun_mgr(mgr);
        }
    }

    // Store resolved absolute config path in context for reload support.
    ctx.set_config_path(resolved_config_path.clone());
    log::info!("Config file: {}", resolved_config_path.as_deref().unwrap_or("<none>"));

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
                            "Reload command received — requesting process restart"
                        );
                        #[cfg(not(target_os = "android"))]
                        {
                            let exe = match std::env::current_exe() {
                                Ok(p) => p,
                                Err(e) => {
                                    ::log::error!("Failed to get exe path: {e}");
                                    continue;
                                },
                            };
                            if let Some(ref start_cmd) = ctx_for_actor.start_cmd {
                                // External restart via `start_cmd restart <service_name>`.
                                // Do NOT exit ourselves — let the service manager
                                // send SIGTERM for graceful shutdown.
                                let service_name = exe
                                    .file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                match std::process::Command::new(start_cmd)
                                    .arg("restart")
                                    .arg(&service_name)
                                    .spawn()
                                {
                                    Ok(_) => {
                                        ::log::info!(
                                            "Restart requested via {start_cmd} restart {service_name}, waiting for SIGTERM..."
                                        );
                                    },
                                    Err(e) => {
                                        ::log::error!("Failed to restart: {e}");
                                    },
                                }
                            } else {
                                // Self re-exec via execve.
                                let exe_str = exe.to_string_lossy().to_string();
                                let args: Vec<String> = std::env::args().collect();
                                ::log::info!(
                                    "Restarting via execve: {exe_str} {:?}",
                                    args
                                );
                                tokio::spawn(async move {
                                    tokio::time::sleep(
                                        std::time::Duration::from_millis(200),
                                    )
                                    .await;
                                    use std::os::unix::process::CommandExt;
                                    let err = std::process::Command::new(&exe_str)
                                        .args(&args[1..])
                                        .exec();
                                    ::log::error!("execve failed: {err}");
                                    std::process::exit(1);
                                });
                            }
                        }
                        // Android: trigger_restart() in the UI handler calls
                        // process::exit(0) directly. This arm should not be
                        // reached on Android, but if it is, just log.
                        #[cfg(target_os = "android")]
                        ::log::warn!(
                            "Reload via command bus should not happen on Android"
                        );
                    },
                }
            }
        }));
    }

    // --- TUN mode check ---
    let has_tun = cfg!(any(target_os = "linux", target_os = "android"))
        && !config.inbounds_by_type("tun").is_empty();

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
            _ = futures_util::future::join_all(tasks) => {},
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutdown signal received, exiting...");
            },
        }
    }
    #[cfg(target_os = "android")]
    {
        // On Android, shutdown is triggered by the JNI layer (Kotlin calls
        // stopEngine). The run loop simply waits for all tasks to finish.
        futures_util::future::join_all(tasks).await;
    }

    sink.emit(cache::StatusEvent::Phase(cache::EnginePhase::Stopping));
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

        tokio::spawn(async move {
            let destination = conn.destination().clone();
            let network = conn.network();
            let host = destination.address.to_string();
            let dest_ip = destination.address.to_string();
            let dest_port = destination.port.to_string();
            let source = conn.source();

            let rule_match = match ctx.rules.match_conn(&destination, network) {
                Some(m) => m,
                None => {
                    log::warn!("No rule for {destination} ({network}), dropping");
                    return;
                },
            };
            let tag = &rule_match.outbound_tag;

            let client = match ctx.registry.get(&tag) {
                Some(c) => c,
                None => {
                    log::warn!("No outbound tag '{tag}'");
                    return;
                }
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
                    type_: format!("{}/{}", conn.type_name(), network),
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

            match conn {
                InboundConn::Tcp {
                    destination,
                    mut stream,
                    ..
                } => {
                    let dial_result = {
                        client.dial(&destination).await.map_err(|e| {
                            format!("Failed to dial {destination} via {tag}: {e}")
                        })
                    };
                    let out = match dial_result {
                        Ok(o) => o,
                        Err(msg) => {
                            log::error!("{msg}");
                            let _ = stream.shutdown().await;
                            ctx.stats.remove_connection(&conn_id).await;
                            return;
                        },
                    };

                    let mut counted_out = CountedStreamRelay {
                        inner: out,
                        stats: Arc::clone(&ctx.stats),
                        conn_counters: Arc::clone(&counters),
                        tag_stats: Arc::clone(&tag_stats),
                    };

                    log::info!("Relaying tcp {destination} via {tag}");
                    bidirectional_relay(&mut *stream, &mut counted_out).await;
                },
                InboundConn::Udp {
                    initial_destination,
                    mut packet,
                    ..
                } => {
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
                    bidirectional_packet_relay(&mut *packet, &mut counted_out)
                        .await;
                },
            }

            ctx.stats.remove_connection(&conn_id).await;
        });
    }
}
