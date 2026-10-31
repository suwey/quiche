//! Windows-specific TUN route management.
//!
//! The Wintun adapter itself is created by the `tun` crate (which loads
//! `wintun.dll` at runtime) in `TunInbound::new()`. This module handles only
//! routing and cleanup - mirroring `macos.rs`.
//!
//! Routing is pure iphlpapi v2 via `windows_route.rs`
//! (`MIB_IPFORWARD_ROW2` + `CreateIpForwardEntry2`/`DeleteIpForwardEntry2`):
//! no child processes, no text parsing, no OEM code-page garbage.
//!
//! DNS is intentionally NOT hijacked via `netsh`: the split-default routes
//! already pull every udp/53 packet (whatever resolver the system uses) into
//! the TUN, where the handler intercepts it by port. Pointing the system DNS
//! at the TUN's own address would send queries down the Windows loopback
//! path - packets to a local IP never traverse the adapter, so they would
//! never reach the TUN handler at all (and a crash without cleanup would
//! leave the system with a dead resolver).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::windows_route;

/// Remove leftover TUN routes from a previous run that crashed without
/// cleaning up. Best-effort: a missing route is not an error. Scans the whole
/// forwarding table by prefix (same global semantics as the old
/// `route DELETE` calls), so no manager state is needed at startup.
pub fn cleanup_stale_routing() {
    let v4 = windows_route::routes_delete_by_prefix(
        AF_INET,
        &[
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1), // 0.0.0.0/1
            (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1), // 128.0.0.0/1
        ],
    );
    let v6 = windows_route::routes_delete_by_prefix(
        AF_INET6,
        &[
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1), // ::/1
            // 8000::/1: the top half of the IPv6 space.
            (IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
        ],
    );
    log::info!(
        "Windows: stale TUN routes cleaned up ({v4} IPv4 + {v6} IPv6 entries removed)"
    );
}

/// One installed split-default route, remembered for exact cleanup.
#[derive(Clone, Copy)]
struct InstalledRoute {
    prefix: IpAddr,
    prefix_len: u8,
    iface_index: u32,
    next_hop: IpAddr,
}

/// Route manager for the Windows TUN (Wintun) interface.
///
/// Manages:
/// - Default route via TUN (0.0.0.0/1 + 128.0.0.0/1 split trick)
/// - Cleanup of routes on drop
///
/// DNS is deliberately left to the system: the split routes funnel all
/// udp/53 into the TUN handler regardless of the configured resolver, so
/// there is nothing to hijack (see the module docs for why `netsh` was
/// removed).
pub struct WindowsTunManager {
    pub iface_name: String,
    pub tun_addr: IpAddr,
    /// Split-default routes installed by `setup_routing` (exact cleanup).
    installed_routes: Vec<InstalledRoute>,
}

impl WindowsTunManager {
    pub fn new(iface_name: String, tun_addr: IpAddr) -> Self {
        Self {
            iface_name,
            tun_addr,
            installed_routes: Vec::new(),
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
    /// without touching the original default route. Routes are keyed to the
    /// Wintun adapter's IfIndex (resolved once via `GetAdaptersAddresses`)
    /// with the TUN address as next hop; only the TUN address family is
    /// touched, same as the old route.exe behavior.
    pub fn setup_routing(
        &mut self, _bypass_ips: &[String],
    ) -> Result<(), String> {
        // The Wintun adapter is created by the `tun` crate without a
        // configured name, so its FriendlyName is the crate default
        // ("wintun") - NOT the internal "tun0" label this manager holds.
        // Anchor on the adapter's own unicast address (we assigned it),
        // falling back to a name match.
        let tun_addr = self.tun_addr;
        let (iface_index, matched_by) =
            windows_route::find_tun_adapter(tun_addr, &self.iface_name)
                .ok_or_else(|| {
                    format!(
                        "TUN adapter not found via GetAdaptersAddresses by \
                         address {tun_addr} or name '{}' (routing not installed)",
                        self.iface_name
                    )
                })?;

        let prefixes: [(IpAddr, u8); 2] = match self.tun_addr {
            IpAddr::V4(_) => [
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1), // 0.0.0.0/1
                (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1), // 128.0.0.0/1
            ],
            IpAddr::V6(_) => [
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1), // ::/1
                (IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1), // 8000::/1
            ],
        };

        for (prefix, prefix_len) in prefixes {
            windows_route::route_add(
                prefix,
                prefix_len,
                iface_index,
                self.tun_addr,
            )
            .map_err(|e| {
                format!(
                    "route add {prefix}/{prefix_len} failed (Win32 error {e})"
                )
            })?;
            // Record only after a successful install so cleanup stays exact.
            self.installed_routes.push(InstalledRoute {
                prefix,
                prefix_len,
                iface_index,
                next_hop: self.tun_addr,
            });
        }

        log::info!(
            "Windows TUN split-default routes installed on {} (matched by {matched_by}, \
             ifindex {iface_index}, gateway {})",
            self.iface_name,
            self.tun_addr
        );

        // No system-DNS change: the split routes already funnel every
        // udp/53 packet into the TUN, where the handler intercepts it by
        // port (see module docs for why pointing the system resolver at the
        // TUN's own address is broken on Windows).

        Ok(())
    }

    /// Remove the split-default routes installed by `setup_routing`, using the
    /// remembered prefix/iface/next-hop parameters for exact deletion
    /// (`route_delete` treats a missing route as success).
    pub fn cleanup_routing(&mut self) {
        if !self.installed_routes.is_empty() {
            for route in self.installed_routes.drain(..) {
                if let Err(e) = windows_route::route_delete(
                    route.prefix,
                    route.prefix_len,
                    route.iface_index,
                    route.next_hop,
                ) {
                    log::warn!(
                        "Windows TUN route delete {}/{} failed (Win32 error {})",
                        route.prefix,
                        route.prefix_len,
                        e
                    );
                }
            }
            log::info!("Windows TUN routes removed");
        }
    }

    /// Enable TUN routing (install split-default routes).
    /// Idempotent: no-op if already enabled. Used by the runtime
    /// `tun_routing_enable` API; the TUN interface itself stays up.
    pub fn enable_routing(&mut self) -> Result<(), String> {
        if !self.installed_routes.is_empty() {
            return Ok(());
        }
        self.setup_routing(&[])
    }

    /// Disable TUN routing (remove routes + restore DNS).
    /// Idempotent: no-op if already disabled. The TUN interface stays up.
    pub fn disable_routing(&mut self) {
        if self.installed_routes.is_empty() {
            return;
        }
        self.cleanup_routing()
    }

    /// Whether TUN routing (split-default routes) is currently active.
    pub fn is_routing_enabled(&self) -> bool {
        !self.installed_routes.is_empty()
    }
}
