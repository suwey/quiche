pub mod config;
pub mod dns;
pub mod fingerprint;
pub mod inbound;
pub mod outbound;
pub mod protocol;
pub mod relay;
pub mod rules;
pub mod transport;
pub mod ui;

/// Send SIGINT to our own process so Drop handlers run before exit.
/// Call this instead of `std::process::exit()` when cleanup matters
/// (TUN interface deletion, route/DNS restoration, etc.).
pub fn graceful_shutdown() {
    use std::process::Command;
    let pid = std::process::id();
    let _ = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .output();
}
