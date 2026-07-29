//! Platform-specific TUN operations.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::process::Command;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub(super) mod bypass_watcher;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

/// Run an arbitrary command, returning an error on non-zero exit.
/// All shell commands from TUN routing should go through this so
/// there is a single place with debug logging and error formatting.
///
/// Uses `status()` (not `output()`) so macOS uses `posix_spawn` instead of
/// `fork()+exec()`. `fork()` is O(RSS): it copies the entire page table even
/// though pages are copy-on-write. With hundreds of MB of RSS this makes each
/// command take 0.5-2s instead of ~1ms.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[allow(dead_code)]
pub(super) fn run_cmd(
    cmd: &str, args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!("{cmd} {}", args.join(" "));
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        return Err(format!(
            "{cmd} {} failed (exit {})",
            args.join(" "),
            status.code().unwrap_or(-1)
        )
        .into());
    }
    Ok(())
}
