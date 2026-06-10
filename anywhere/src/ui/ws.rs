use axum::extract::ws::Message;
use axum::extract::ws::WebSocket;
use tokio::sync::broadcast;

use crate::ui::log::LogMsg;
use crate::ui::state::ConnectionsMsg;
use crate::ui::state::MemoryMsg;
use crate::ui::state::TrafficMsg;

/// Send a WebSocket ping every 30s to keep the connection alive through
/// proxies and load balancers that would otherwise drop idle connections.
const PING_INTERVAL_SECS: u64 = 30;

async fn keepalive_loop<T: Clone + Send + 'static>(
    mut socket: WebSocket, mut rx: broadcast::Receiver<T>,
    serialize: fn(T) -> String,
) {
    let mut ping_interval = tokio::time::interval(
        tokio::time::Duration::from_secs(PING_INTERVAL_SECS),
    );
    loop {
        tokio::select! {
            Ok(msg) = rx.recv() => {
                let text = serialize(msg);
                if socket
                    .send(Message::Text(text.into()))
                    .await
                    .is_err()
                { break; }
            }
            _ = ping_interval.tick() => {
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

/// Handle /traffic WS: subscribes to traffic_tx broadcast,
/// forwards pre-computed {up, down} delta every 3s.
pub async fn handle_traffic(
    socket: WebSocket, rx: broadcast::Receiver<TrafficMsg>,
) {
    keepalive_loop(socket, rx, |msg| {
        serde_json::to_string(
            &serde_json::json!({ "up": msg.up, "down": msg.down }),
        )
        .unwrap()
    })
    .await;
}

/// Handle /memory WS: subscribes to memory_tx broadcast,
/// forwards pre-computed {inuse} every 3s.
pub async fn handle_memory(
    socket: WebSocket, rx: broadcast::Receiver<MemoryMsg>,
) {
    keepalive_loop(socket, rx, |msg| {
        serde_json::to_string(&serde_json::json!({ "inuse": msg.inuse })).unwrap()
    })
    .await;
}

/// Handle /connections WS: subscribes to connections_tx broadcast,
/// forwards pre-computed full connections snapshot every 3s.
pub async fn handle_connections(
    socket: WebSocket, rx: broadcast::Receiver<ConnectionsMsg>,
) {
    keepalive_loop(socket, rx, |msg| serde_json::to_string(&msg).unwrap()).await;
}

/// Handle /logs WS: subscribes to the log broadcast channel,
/// forwards {"type": level, "payload": "[tid elapsed] target: message"}.
pub async fn handle_logs(socket: WebSocket, rx: broadcast::Receiver<LogMsg>) {
    keepalive_loop(socket, rx, |msg| serde_json::to_string(&msg).unwrap()).await;
}
