//! Android support module.
//!
//! This module is only compiled on `target_os = "android"`. It provides:
//!   - JNI bridge for Kotlin ↔ Rust interop
//!   - Socket protection via VpnService.protect()
//!   - TUN device creation from a VpnService fd
//!
//! See `android/jni.rs` for the JNI entry points.
//! See `inbound/tun/platform/android.rs` for TUN fd + protect infrastructure.

#[cfg(target_os = "android")]
pub mod jni;
