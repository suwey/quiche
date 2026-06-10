//! Platform-specific TUN operations.

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub(super) mod bypass_watcher;

/// Run an arbitrary command, returning an error on non-zero exit.
/// All shell commands from TUN routing should go through this so
/// there is a single place with debug logging and error formatting.
#[cfg(target_os = "linux")]
pub(super) fn run_cmd(
    cmd: &str, args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!("{cmd} {}", args.join(" "));
    let output = Command::new(cmd).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{cmd} {} failed: {}",
            args.join(" "),
            stderr.trim()
        )
        .into());
    }
    Ok(())
}
