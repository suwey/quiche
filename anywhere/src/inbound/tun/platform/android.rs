//! Android-specific TUN support.
//!
//! On Android, the TUN device is created by Kotlin's VpnService.establish()
//! and the file descriptor is passed to Rust via JNI. This module provides
//! the glue to open that fd as an async TUN device using the `tun` crate's
//! `Configuration::raw_fd()` API.
//!
//! Unlike Linux, Android does NOT need:
//!   - rtnetlink / policy routing (VpnService manages routes)
//!   - iptables rules (VpnService manages traffic routing)
//!   - fwmark bypass (VpnService.protect() handles this)

use std::os::fd::RawFd;
use std::sync::Arc;

use tun::AsyncDevice;

/// Open a TUN device from a raw file descriptor provided by Android
/// VpnService.establish().
///
/// Uses the `tun` crate's `Configuration::raw_fd()` API which is supported
/// on Linux/Android. The fd ownership is transferred to the device; by
/// default it will be closed when the device is dropped.
pub fn create_tun_from_fd(fd: RawFd) -> Result<AsyncDevice, std::io::Error> {
    let mut tun_config = tun::Configuration::default();
    tun_config.raw_fd(fd);
    // Do NOT close the fd on drop — VpnService owns the ParcelFileDescriptor
    // and will close it when the VPN is torn down.
    tun_config.close_fd_on_drop(false);
    tun_config.up();

    let device = tun::create_as_async(&tun_config).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("tun create failed: {e}"),
        )
    })?;

    log::info!("TUN device opened from fd={}", fd);

    Ok(device)
}

/// No-op route manager for Android.
///
/// Android's VpnService manages all routing. There is no need for
/// rtnetlink, iptables, or policy routing rules.
pub struct AndroidTunManager;

impl AndroidTunManager {
    pub fn new() -> Self {
        Self
    }
}

impl Drop for AndroidTunManager {
    fn drop(&mut self) {
        log::info!("Android TUN manager dropped (VpnService handles cleanup)");
    }
}

// ---------------------------------------------------------------------------
// Socket protection
// ---------------------------------------------------------------------------

/// Socket protection trait.
///
/// On Linux, outbound sockets bypass TUN via SO_MARK (fwmark).
/// On Android, outbound sockets bypass VPN via VpnService.protect(fd).
pub trait SocketProtect: Send + Sync {
    /// Protect a socket fd so it bypasses the VPN tunnel.
    fn protect(&self, fd: RawFd) -> bool;
}

/// No-op socket protector (desktop / TUN not active).
pub struct NoopProtect;

impl SocketProtect for NoopProtect {
    fn protect(&self, _fd: RawFd) -> bool {
        true
    }
}

use std::sync::RwLock;

static PROTECTOR: RwLock<Option<Arc<dyn SocketProtect>>> = RwLock::new(None);

/// Initialize the global socket protector. Called by the JNI layer
/// on Android during engine startup.
pub fn set_protector(p: Arc<dyn SocketProtect>) {
    let mut guard = PROTECTOR.write().unwrap();
    *guard = Some(p);
}

/// Get the global socket protector. Returns NoopProtect if not set.
pub fn get_protector() -> Arc<dyn SocketProtect> {
    PROTECTOR
        .read()
        .unwrap()
        .clone()
        .unwrap_or_else(|| Arc::new(NoopProtect))
}
