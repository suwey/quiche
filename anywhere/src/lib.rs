pub mod android;
pub mod cache;
pub mod command;
pub mod config;
pub mod context;
pub mod dns;
pub mod fingerprint;
pub mod inbound;
pub mod outbound;
pub mod protocol;
pub mod relay;
pub mod runner;
pub mod rules;
pub mod transport;
pub mod ui;

// Re-export the core entry point so both the desktop binary (main.rs)
// and the Android JNI bridge (android/jni.rs) can call the same code.
pub use crate::runner::run;

/// Send SIGINT to our own process so Drop handlers run before exit.
/// Call this instead of `std::process::exit()` when cleanup matters
/// (TUN interface deletion, route/DNS restoration, etc.).
#[cfg(not(target_os = "android"))]
pub fn graceful_shutdown() {
    use std::process::Command;
    let pid = std::process::id();
    let _ = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .output();
}

/// On Android, graceful shutdown is handled by the JNI layer (Kotlin
/// VpnService destroys the TUN interface). This is a no-op stub.
#[cfg(target_os = "android")]
pub fn graceful_shutdown() {}
