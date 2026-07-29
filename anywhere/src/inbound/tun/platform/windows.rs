//! Windows-specific TUN route management.
//!
//! The Wintun adapter itself is created by the `tun` crate (which loads
//! `wintun.dll` at runtime) in `TunInbound::new()`. This module handles only
//! routing, DNS hijacking, and cleanup - mirroring `macos.rs`.
//!
//! Routing uses the `route` command with the TUN address as the gateway (like
//! macOS), so no interface-index resolution is needed for route installation.

use std::net::IpAddr;
use std::process::Command;

use super::run_cmd;

/// Remove leftover TUN routes from a previous run that crashed without
/// cleaning up. Best-effort: a missing route is not an error.
pub fn cleanup_stale_routing() {
    let _ = run_cmd("route", &["DELETE", "0.0.0.0", "MASK", "128.0.0.0"]);
    let _ = run_cmd("route", &["DELETE", "128.0.0.0", "MASK", "128.0.0.0"]);
    let _ = run_cmd("route", &["-6", "DELETE", "::/1"]);
    let _ = run_cmd("route", &["-6", "DELETE", "8000::/1"]);
    log::info!("Windows: stale TUN routes cleaned up");
}

/// Route manager for the Windows TUN (Wintun) interface.
///
/// Manages:
/// - Default route via TUN (0.0.0.0/1 + 128.0.0.0/1 split trick)
/// - DNS hijacking by pointing the system DNS at the TUN address
/// - Cleanup of routes and DNS on drop
pub struct WindowsTunManager {
    pub iface_name: String,
    pub tun_addr: IpAddr,
    /// Whether split-default routes were installed (for cleanup).
    routes_installed: bool,
    /// Whether the system DNS was changed (for restore).
    dns_changed: bool,
    /// Backup of the original primary DNS server, restored on cleanup.
    original_dns: Option<String>,
    /// Whether DNS hijacking is active (copied from config at startup).
    auto_hijack: bool,
}

impl WindowsTunManager {
    pub fn new(iface_name: String, tun_addr: IpAddr, auto_hijack: bool) -> Self {
        Self {
            iface_name,
            tun_addr,
            routes_installed: false,
            dns_changed: false,
            original_dns: None,
            auto_hijack,
        }
    }

    /// The Wintun adapter (with address/MTU) is created by the `tun` crate in
    /// `TunInbound::new()`, so this is a no-op apart from logging.
    pub fn setup_interface(&self) -> Result<(), String> {
        log::info!(
            "Windows TUN interface {} configured at {}",
            self.iface_name,
            self.tun_addr
        );
        Ok(())
    }

    /// Install split-default routes to capture traffic via the TUN interface.
    ///
    /// Uses the 0.0.0.0/1 + 128.0.0.0/1 trick: two /1 routes are more specific
    /// than the default 0.0.0.0/0, so all traffic follows them through the TUN
    /// without touching the original default route. The TUN address is the
    /// gateway; Windows resolves the egress interface from it.
    pub fn setup_routing(
        &mut self, auto_hijack: bool, _bypass_ips: &[String],
    ) -> Result<(), String> {
        let tun_addr_str = self.tun_addr.to_string();

        match self.tun_addr {
            IpAddr::V4(_) => {
                run_cmd(
                    "route",
                    &["ADD", "0.0.0.0", "MASK", "128.0.0.0", &tun_addr_str],
                )
                .map_err(|e| e.to_string())?;
                run_cmd(
                    "route",
                    &["ADD", "128.0.0.0", "MASK", "128.0.0.0", &tun_addr_str],
                )
                .map_err(|e| e.to_string())?;
            },
            IpAddr::V6(_) => {
                run_cmd("route", &["-6", "ADD", "::/1", &tun_addr_str])
                    .map_err(|e| e.to_string())?;
                run_cmd("route", &["-6", "ADD", "8000::/1", &tun_addr_str])
                    .map_err(|e| e.to_string())?;
            },
        }

        self.routes_installed = true;
        log::info!(
            "Windows TUN split-default routes installed via {} (gateway {})",
            self.iface_name,
            self.tun_addr
        );

        // DNS hijacking: point the system DNS at the TUN address so all
        // queries reach our in-process resolver (which returns fake-IPs).
        if auto_hijack {
            if let Err(e) = self.setup_dns_hijack() {
                log::warn!("Windows DNS hijack failed (routing still active): {e}");
            }
        }

        Ok(())
    }

    /// Remove the split-default routes installed by `setup_routing`.
    ///
    /// Best-effort: a missing route (already cleaned up) is not an error.
    pub fn cleanup_routing(&mut self) {
        if self.routes_installed {
            let tun_addr_str = self.tun_addr.to_string();
            match self.tun_addr {
                IpAddr::V4(_) => {
                    let _ = run_cmd(
                        "route",
                        &["DELETE", "0.0.0.0", "MASK", "128.0.0.0", &tun_addr_str],
                    );
                    let _ = run_cmd(
                        "route",
                        &[
                            "DELETE", "128.0.0.0", "MASK", "128.0.0.0",
                            &tun_addr_str,
                        ],
                    );
                },
                IpAddr::V6(_) => {
                    let _ = run_cmd("route", &["-6", "DELETE", "::/1", &tun_addr_str]);
                    let _ =
                        run_cmd("route", &["-6", "DELETE", "8000::/1", &tun_addr_str]);
                },
            }
            self.routes_installed = false;
            log::info!("Windows TUN routes removed");
        }

        self.restore_dns();
    }

    /// Enable TUN routing (install split-default routes + DNS hijack).
    /// Idempotent: no-op if already enabled. Used by the runtime
    /// `tun_routing_enable` API; the TUN interface itself stays up.
    pub fn enable_routing(&mut self) -> Result<(), String> {
        if self.routes_installed {
            return Ok(());
        }
        self.setup_routing(self.auto_hijack, &[])
    }

    /// Disable TUN routing (remove routes + restore DNS).
    /// Idempotent: no-op if already disabled. The TUN interface stays up.
    pub fn disable_routing(&mut self) {
        if !self.routes_installed {
            return;
        }
        self.cleanup_routing()
    }

    /// Whether TUN routing (routes + DNS hijack) is currently active.
    pub fn is_routing_enabled(&self) -> bool {
        self.routes_installed
    }

    /// Point the system DNS at the TUN address.
    ///
    /// Uses `netsh interface ip set dns` on the primary interface. The original
    /// DNS is captured first so it can be restored on cleanup. This affects the
    /// whole system, so robust restore (and startup cleanup) is essential.
    fn setup_dns_hijack(&mut self) -> Result<(), String> {
        let iface = match primary_interface() {
            Some(i) => i,
            None => return Err("could not determine primary interface".into()),
        };

        // Back up the current DNS for restore on shutdown.
        self.original_dns = get_dns(&iface);
        let tun_addr_str = self.tun_addr.to_string();

        // Set the TUN address as the DNS server on the primary interface.
        let out = Command::new("netsh")
            .args([
                "interface", "ip", "set", "dns", &iface,
                "static", &tun_addr_str,
            ])
            .output()
            .map_err(|e| format!("netsh set dns failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "netsh set dns failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        self.dns_changed = true;
        log::info!(
            "Windows DNS hijack: set {} DNS to {} (was {:?})",
            iface,
            self.tun_addr,
            self.original_dns
        );
        Ok(())
    }

    /// Restore the original DNS settings if we changed them.
    fn restore_dns(&mut self) {
        if !self.dns_changed {
            return;
        }
        let iface = match primary_interface() {
            Some(i) => i,
            None => {
                log::warn!("Windows DNS restore: cannot find primary interface");
                return;
            },
        };
        match self.original_dns.take() {
            Some(dns) => {
                let _ = Command::new("netsh")
                    .args(["interface", "ip", "set", "dns", &iface, "static", &dns])
                    .output();
                log::info!("Windows DNS restored to {dns} on {iface}");
            },
            None => {
                // No backup recorded: reset to DHCP.
                let _ = Command::new("netsh")
                    .args(["interface", "ip", "set", "dns", &iface, "dhcp"])
                    .output();
                log::info!("Windows DNS reset to DHCP on {iface}");
            },
        }
        self.dns_changed = false;
    }
}

/// Find the primary (default-route) interface name via `route print`.
///
/// Returns the interface name suitable for `netsh interface ip set dns`.
fn primary_interface() -> Option<String> {
    // `route print 0.0.0.0` lists the default route; the trailing column is
    // the interface name. We take the first default route's interface.
    let out = Command::new("route").args(["print", "0.0.0.0"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        // Default route lines look like:
        //   0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>
        if line.starts_with("0.0.0.0") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // The interface name is the last-but-one or last field; interface
            // names can contain spaces, so rejoin from index 3 onward.
            if parts.len() >= 4 {
                return Some(parts[3..].join(" "));
            }
        }
    }
    None
}

/// Read the current DNS server of an interface via `netsh`.
fn get_dns(iface: &str) -> Option<String> {
    let out = Command::new("netsh")
        .args(["interface", "ip", "show", "dns", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Output contains lines like `    192.168.1.1` under the interface header.
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty()
            && line.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
        {
            return Some(line.split_whitespace().next().unwrap_or(line).to_string());
        }
    }
    None
}
