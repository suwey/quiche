use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::Request;
use axum::extract::State;
use axum::extract::WebSocketUpgrade;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::middleware::{
    self,
};
use axum::response::IntoResponse;
use axum::response::Json;
use axum::routing::get;
use axum::routing::post;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use serde::Deserialize;

use crate::config::UiConfig;

pub mod log;
pub mod state;
pub mod ws;

pub use state::AppStats;

const MODE_LIST: &[&str] = &["rule", "direct", "global"];

fn mode_str(n: u8) -> &'static str {
    MODE_LIST[n as usize]
}

use crate::context::AppContext;

/// Shared application state for axum.
pub struct UiState {
    pub ctx: AppContext,
    pub config: UiConfig,
}

/// Start the UI HTTP server. Never returns (runs until SIGINT).
pub async fn start(config: UiConfig, ctx: AppContext) {
    let listen = config
        .listen
        .clone()
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());

    let ui_state = Arc::new(UiState {
        ctx,
        config: config.clone(),
    });

    let api_routes = Router::new()
        .route("/version", get(version_handler))
        .route(
            "/configs",
            get(configs_handler).patch(patch_configs_handler),
        )
        .route("/rules", get(rules_handler))
        .route("/proxies", get(proxies_handler))
        .route("/group/:tag/delay", get(group_delay_handler))
        .route("/providers/rules", get(providers_rules_handler))
        .route("/providers/proxies", get(providers_proxies_handler))
        .route("/logs", get(ws_logs_handler))
        .route("/restart", post(post_restart_handler))
        .route("/traffic", get(ws_traffic_handler))
        .route("/memory", get(ws_memory_handler))
        .route("/connections", get(ws_connections_handler))
        .layer(CorsLayer::permissive())
        .layer(middleware::from_fn_with_state(
            ui_state.clone(),
            auth_middleware,
        ))
        .with_state(ui_state);

    let app = if let Some(serve_path) = &config.serve_path {
        ::log::info!("UI: serving static files from {serve_path}");
        api_routes.fallback_service(ServeDir::new(serve_path))
    } else {
        api_routes
    };

    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            ::log::error!("UI server: failed to bind {listen}: {e}");
            return;
        },
    };

    ::log::info!("UI server listening on {listen}");

    if let Err(e) = axum::serve(listener, app).await {
        ::log::error!("UI server error: {e}");
    }
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<Arc<UiState>>, req: Request, next: Next,
) -> axum::response::Response {
    let secret = match &state.config.secret {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return next.run(req).await,
    };

    // Check Authorization: Bearer <secret> header
    let header_ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v == secret)
        .unwrap_or(false);

    if header_ok {
        return next.run(req).await;
    }

    // Check ?token=<secret> query param (metacubexd cookie fallback)
    let query_ok = req
        .uri()
        .query()
        .and_then(|q| {
            for pair in q.split('&') {
                if let Some(token) = pair.strip_prefix("token=") {
                    return Some(token == secret);
                }
            }
            None
        })
        .unwrap_or(false);

    if query_ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn version_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": concat!("anywhere/v", env!("CARGO_PKG_VERSION"))
    }))
}

#[derive(Deserialize)]
struct TunPatch {
    enable: Option<bool>,
}

#[derive(Deserialize)]
struct PatchConfigs {
    mode: Option<String>,
    tun: Option<TunPatch>,
}

async fn configs_handler(
    State(state): State<Arc<UiState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "allow-lan": false,
        "mode": mode_str(state.ctx.rules.current_mode()),
        "mode-list": MODE_LIST,
        "log-level": self::log::current_level(),
        "tun": {
            "enable": state.ctx.tun_routing_enabled(),
        },
    }))
}

async fn patch_configs_handler(
    State(state): State<Arc<UiState>>,
    axum::extract::Json(payload): axum::extract::Json<PatchConfigs>,
) -> impl IntoResponse {
    let mut handled = false;

    if let Some(tun) = payload.tun {
        if let Some(enable) = tun.enable {
            handled = true;
            let result = if enable {
                ::log::info!("Enabling TUN routing via API");
                state.ctx.tun_routing_enable()
            } else {
                ::log::info!("Disabling TUN routing via API");
                state.ctx.tun_routing_disable()
            };
            if let Err(e) = result {
                ::log::error!("Failed to toggle TUN routing: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, ());
            }
        }
    }

    if let Some(mode) = payload.mode {
        if let Some(idx) = MODE_LIST.iter().position(|m| *m == mode) {
            let idx = idx as u8;
            if state.ctx.set_mode(idx) {
                ::log::info!("Switched mode to {}", mode_str(idx));
                handled = true;
            }
        }
    }

    if handled {
        (StatusCode::NO_CONTENT, ())
    } else {
        (StatusCode::BAD_REQUEST, ())
    }
}

async fn post_restart_handler(
    State(state): State<Arc<UiState>>,
) -> impl IntoResponse {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, ()),
    };
    let service_name = exe
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    match std::process::Command::new(&state.ctx.start_cmd)
        .arg("restart")
        .arg(&service_name)
        .spawn()
    {
        Ok(_) => {
            ::log::info!(
                "Restarting via {} restart {}...",
                state.ctx.start_cmd,
                service_name
            );
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                std::process::exit(0);
            });
            (StatusCode::NO_CONTENT, ())
        },
        Err(e) => {
            ::log::error!("Failed to restart via {}: {e}", state.ctx.start_cmd);
            (StatusCode::INTERNAL_SERVER_ERROR, ())
        },
    }
}

async fn rules_handler(
    State(state): State<Arc<UiState>>,
) -> Json<serde_json::Value> {
    let rules: Vec<serde_json::Value> = state
        .ctx
        .rules
        .list()
        .iter()
        .map(|r| {
            serde_json::json!({
                "type": r.type_,
                "payload": r.payload(),
                "proxy": r.outbound_tag,
            })
        })
        .collect();

    Json(serde_json::json!({ "rules": rules }))
}

async fn providers_rules_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "providers": [] }))
}

async fn providers_proxies_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "providers": [] }))
}

async fn proxies_handler(
    State(state): State<Arc<UiState>>,
) -> Json<serde_json::Value> {
    let mut proxies = serde_json::Map::new();

    // Build the list of all user-configured outbound tags.
    let all_tags: Vec<&str> = state
        .ctx
        .outbound_tags
        .iter()
        .map(|(tag, _)| tag.as_str())
        .collect();

    // GLOBAL group
    let now_tag = state.ctx.rules.global_outbound().to_string();
    proxies.insert(
        "GLOBAL".into(),
        serde_json::json!({
            "all": all_tags,
            "history": [],
            "name": "GLOBAL",
            "now": now_tag,
            "type": "Fallback",
            "udp": true,
        }),
    );

    // Collect urltest child tags so we skip them at the top level.
    let mut urltest_child_tags: std::collections::HashSet<&str> =
        std::collections::HashSet::new();
    for (tag, type_) in &state.ctx.outbound_tags {
        if type_ == "urltest" {
            if let Some(ut_state) = state.ctx.urltest_states.get(tag.as_str()) {
                for child_tag in &ut_state.children {
                    urltest_child_tags.insert(child_tag.as_str());
                }
            }
        }
    }

    // Lookup map for outbound type by tag.
    let outbound_type_map: std::collections::HashMap<&str, &str> = state
        .ctx
        .outbound_tags
        .iter()
        .map(|(tag, type_)| (tag.as_str(), type_.as_str()))
        .collect();

    // Top-level entries: urltest nodes (with children embedded) +
    // non-urltest-children.
    for (tag, type_) in &state.ctx.outbound_tags {
        if type_ == "urltest" {
            if let Some(ut_state) = state.ctx.urltest_states.get(tag.as_str()) {
                let current_idx =
                    ut_state.current.load(std::sync::atomic::Ordering::Relaxed);
                let now = ut_state
                    .children
                    .get(current_idx)
                    .cloned()
                    .unwrap_or_default();

                // urltest own history = only the now child's record
                let mut history = Vec::new();
                if let Some(idx) =
                    ut_state.children.iter().position(|c| c == &now)
                {
                    let rec = ut_state.records[idx].read().await;
                    if let Some(ref r) = *rec {
                        history.push(serde_json::json!({
                            "time": r.time.to_rfc3339(),
                            "delay": r.delay,
                        }));
                    }
                }

                let mut obj = serde_json::json!({
                    "type": "URLTest",
                    "name": tag,
                    "udp": true,
                    "history": history,
                    "all": ut_state.children,
                    "now": now,
                });

                // Embed child proxy entries as sub-keys.
                if let Some(_obj_map) = obj.as_object_mut() {
                    for (i, child_tag) in ut_state.children.iter().enumerate() {
                        let child_type = outbound_type_map
                            .get(child_tag.as_str())
                            .unwrap_or(&"");
                        let rec = ut_state.records[i].read().await;
                        let child_history = if let Some(ref r) = *rec {
                            vec![serde_json::json!({
                                "time": r.time.to_rfc3339(),
                                "delay": r.delay,
                            })]
                        } else {
                            Vec::new()
                        };
                        proxies.insert(
                            child_tag.clone(),
                            serde_json::json!({
                                "type": child_type,
                                "name": child_tag,
                                "udp": true,
                                "history": child_history,
                            }),
                        );
                    }
                }

                proxies.insert(tag.clone(), obj);
            }
        }
    }

    Json(serde_json::json!({ "proxies": proxies }))
}

// ---------------------------------------------------------------------------
// Group delay handler (manual latency test)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GroupDelayParams {
    url: String,
    timeout: u64,
}

async fn group_delay_handler(
    State(state): State<Arc<UiState>>, Path(tag): Path<String>,
    Query(params): Query<GroupDelayParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Parse URL to extract host and port.
    let rest = params
        .url
        .strip_prefix("https://")
        .or_else(|| params.url.strip_prefix("http://"))
        .ok_or(StatusCode::BAD_REQUEST)?;

    let (host, port) = if let Some((h, rest)) = rest.split_once(':') {
        let port_str = rest.split('/').next().unwrap_or(rest);
        let port: u16 = port_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
        (h.to_string(), port)
    } else {
        let host = rest.split('/').next().unwrap_or(rest).to_string();
        let port = if params.url.starts_with("https") {
            443
        } else {
            80
        };
        (host, port)
    };
    let mut timeout_dur = std::time::Duration::from_millis(params.timeout);

    // For urltest nodes, each child gets the per-node timeout.
    if let Some(ut_state) = state.ctx.urltest_states.get(&tag) {
        let n = ut_state.children.len().max(1) as u32;
        timeout_dur *= n;
    }

    let client_arc = state
        .ctx
        .registry
        .get(&tag)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let mut result = serde_json::Map::new();
    let delay =
        tokio::time::timeout(timeout_dur, client_arc.test_latency(&host, port))
            .await
            .ok()
            .flatten();
    if let Some(d) = delay {
        result.insert(tag, serde_json::json!(d));
    }

    Ok(Json(serde_json::json!(result)))
}

async fn ws_traffic_handler(
    ws: WebSocketUpgrade, State(state): State<Arc<UiState>>,
) -> impl IntoResponse {
    let rx = state.ctx.stats.traffic_tx.subscribe();
    ws.on_upgrade(move |socket| ws::handle_traffic(socket, rx))
}

async fn ws_memory_handler(
    ws: WebSocketUpgrade, State(state): State<Arc<UiState>>,
) -> impl IntoResponse {
    let rx = state.ctx.stats.memory_tx.subscribe();
    ws.on_upgrade(move |socket| ws::handle_memory(socket, rx))
}

async fn ws_connections_handler(
    ws: WebSocketUpgrade, State(state): State<Arc<UiState>>,
) -> impl IntoResponse {
    let rx = state.ctx.stats.connections_tx.subscribe();
    ws.on_upgrade(move |socket| ws::handle_connections(socket, rx))
}

async fn ws_logs_handler(
    ws: WebSocketUpgrade, State(state): State<Arc<UiState>>,
) -> impl IntoResponse {
    let rx = state.ctx.logs_tx.subscribe();
    ws.on_upgrade(move |socket| ws::handle_logs(socket, rx))
}
