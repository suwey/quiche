#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anywhere::config::Config;
use anywhere::inbound::Inbound;
use anywhere::inbound::InboundConn;
use anywhere::inbound::quic::QuicInbound;
use anywhere::inbound::socks5::Socks5Inbound;
use anywhere::outbound::registry::OutboundRegistry;
use anywhere::relay::CountedPacketRelay;
use anywhere::relay::CountedStreamRelay;
use anywhere::relay::bidirectional_packet_relay;
use anywhere::relay::bidirectional_relay;
use anywhere::rules::Rules;
use anywhere::ui::AppStats;
use anywhere::ui::state as ui_state;
use clap::Parser;
use uuid::Uuid;

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

    /// Command to restart the process (used by the UI)
    #[arg(short = 's', long = "start-cmd", default_value = "systemctl")]
    start_cmd: String,
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config = Config::load(&args.config)?;

    // Detect system timezone via `date +%z` before logger init.
    let tz_str = std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    // Initialize logger — use channel logger (UI-compatible) when [ui] is
    // configured, otherwise fall back to plain env_logger.
    let logs_tx = if config.ui.listen.is_some() {
        Some(anywhere::ui::log::init())
    } else {
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
        None
    };

    #[cfg(target_os = "linux")]
    {
        let has_tun_with_hijack =
            config.inbounds_by_type("tun").iter().any(|c| c.auto_hijack);
        if has_tun_with_hijack {
            anywhere::inbound::tun::cleanup_stale_routing();
        }
    }

    log::info!("Loaded config from {}", args.config);

    if !tz_str.is_empty() {
        log::info!("Detected system timezone: UTC{tz_str}");
    }

    let registry = Arc::new(OutboundRegistry::from_config(&config).await?);

    // Determine cache directory
    let cache_dir = config
        .common
        .cache_dir
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    log::info!("Loading rules...");
    let rules = Arc::new(
        Rules::from_config(&config.rules, &config.outbounds, &cache_dir)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Failed to initialize rules: {e}");
                std::process::exit(1);
            }),
    );
    log::info!("All rules initialized");

    let mut tasks = Vec::new();

    // --- UI server + stats ticker (only when [ui] is configured) ------------
    let stats = if config.ui.listen.is_some() {
        let current_memory: fn() -> u64 = if cfg!(target_os = "linux") {
            ui_state::read_linux_memory
        } else if cfg!(target_os = "macos") {
            ui_state::read_macos_memory
        } else {
            || 0
        };
        let stats = AppStats::new(current_memory);

        let ui_config = config.ui.clone();
        let logs_tx = logs_tx.unwrap();
        let start_cmd = args.start_cmd.clone();
        let stats_clone = Arc::clone(&stats);
        let rules_clone = rules.clone();

        let outbound_tags: Vec<(String, String)> = config
            .outbounds
            .iter()
            .enumerate()
            .map(|(i, o)| (o.tag_or_default(i), o.type_.clone()))
            .collect();

        let urltest_states = registry.urltest_states.clone();
        let registry_for_ui = Arc::clone(&registry);

        tasks.push(tokio::spawn(async move {
            anywhere::ui::start(
                ui_config,
                stats_clone,
                rules_clone,
                logs_tx,
                start_cmd,
                outbound_tags,
                urltest_states,
                registry_for_ui,
            )
            .await;
        }));

        let stats_ticker = Arc::clone(&stats);
        tasks.push(tokio::spawn(async move {
            stats_ticker_task(stats_ticker).await;
        }));

        stats
    } else {
        AppStats::new(|| 0)
    };

    // --- TUN mode check: when TUN is configured, skip other inbounds --------
    let has_tun =
        cfg!(target_os = "linux") && !config.inbounds_by_type("tun").is_empty();

    // --- SOCKS5 inbounds ---------------------------------------------------
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
                tasks.push(tokio::spawn(run_inbound(
                    inbound,
                    registry.clone(),
                    rules.clone(),
                    Arc::clone(&stats),
                )));
            },
            Err(e) => {
                log::error!("Failed to bind SOCKS5 inbound on {listen}: {e}");
            },
        }
    }

    // --- QUIC inbounds -----------------------------------------------------
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
                tasks.push(tokio::spawn(run_inbound(
                    inbound,
                    registry.clone(),
                    rules.clone(),
                    Arc::clone(&stats),
                )));
            },
            None => {
                log::warn!("QuicInbound::from_config returned None");
            },
        }
    }

    // --- TUN inbounds (Linux only) -----------------------------------------
    #[cfg(target_os = "linux")]
    let _tun_guard: Option<anywhere::inbound::tun::TunGuard> = {
        use anywhere::dns::DnsHijack;
        use anywhere::inbound::tun::TunConfig;
        use anywhere::inbound::tun::TunInbound;

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
                        anywhere::inbound::tun::TunWriter,
                        std::sync::Arc<
                            anywhere::inbound::tun::reverse_dns::ReverseDnsCache,
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

            match TunInbound::new(&tun_config, Some(dns_builder)).await {
                Ok((inbound, guard)) => {
                    log::info!("Starting TUN inbound on {}", tun_config.addr);
                    log::info!(
                        "DNS hijack enabled (direct={}, remote={})",
                        dns_cfg.direct,
                        dns_cfg.remote
                    );
                    tasks.push(tokio::spawn(run_inbound(
                        inbound,
                        registry.clone(),
                        rules.clone(),
                        Arc::clone(&stats),
                    )));
                    last_guard = Some(guard);
                },
                Err(e) => {
                    log::error!("Failed to start TUN inbound: {e}");
                },
            }
        }
        last_guard
    };
    #[cfg(not(target_os = "linux"))]
    let _tun_guard: Option<anywhere::inbound::tun::TunGuard> = None;

    if tasks.is_empty() {
        log::warn!("No inbounds configured; nothing to do.");
    }

    tokio::select! {
        _ = futures_util::future::join_all(tasks) => {},
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutdown signal received, exiting...");
        },
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

async fn run_inbound(
    mut inbound: impl Inbound + 'static, registry: Arc<OutboundRegistry>,
    rules: Arc<Rules>, stats: Arc<AppStats>,
) {
    loop {
        let Some(conn) = inbound.accept().await else {
            log::warn!("Inbound accept returned None, retrying in 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        let registry = Arc::clone(&registry);
        let rules = Arc::clone(&rules);
        let stats = Arc::clone(&stats);

        tokio::spawn(async move {
            let destination = conn.destination().clone();
            let network = conn.network();
            let host = destination.address.to_string();
            let dest_ip = destination.address.to_string();
            let dest_port = destination.port.to_string();
            let source = conn.source();

            let rule_match = match rules.match_conn(&destination, network) {
                Some(m) => m,
                None => {
                    log::warn!("No rule for {destination} ({network}), dropping");
                    return;
                },
            };
            let tag = &rule_match.outbound_tag;

            let client = match registry.get(&tag) {
                Some(c) => c,
                None => {
                    log::warn!("No outbound tag '{tag}'");
                    return;
                },
            };

            let conn_id = Uuid::new_v4().to_string();
            let counters = ui_state::ConnCounters::new_arc();
            let tag_stats = stats.get_or_create_tag(&tag).await;

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

            stats
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
                            stats.remove_connection(&conn_id).await;
                            return;
                        },
                    };

                    let mut counted_out = CountedStreamRelay {
                        inner: out,
                        stats: Arc::clone(&stats),
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
                            stats.remove_connection(&conn_id).await;
                            // If fd exhausted, sleep briefly to let the
                            // TUN handler's backpressure kick in.
                            if msg.contains("No file descriptors") {
                                tokio::time::sleep(Duration::from_millis(100))
                                    .await;
                            }
                            return;
                        },
                    };

                    let mut counted_out = CountedPacketRelay {
                        inner: out,
                        stats: Arc::clone(&stats),
                        conn_counters: Arc::clone(&counters),
                        tag_stats: Arc::clone(&tag_stats),
                    };

                    log::info!("Relaying udp {initial_destination} via {tag}");
                    bidirectional_packet_relay(&mut *packet, &mut counted_out)
                        .await;
                },
            }

            stats.remove_connection(&conn_id).await;
        });
    }
}
