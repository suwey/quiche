//! macOS-specific TUN route management.
//!
//! Uses `route` and `pfctl` commands to manage routing and DNS hijacking.
//! Unlike Linux's rtnetlink approach, macOS keeps it simple with shell commands.

use std::net::IpAddr;
use std::process::Command;

/// Route manager for macOS TUN interface.
///
/// Manages:
/// - Default route via TUN (using 0.0.0.0/1 + 128.0.0.0/1 split trick)
/// - DNS hijacking via pfctl rdr (port 53 → 1053)
/// - Bypass for the TUN's own outbound traffic
pub struct MacosTunManager {
    pub iface_name: String,
    pub tun_addr: IpAddr,
    /// Whether we installed pf bypass rules (for cleanup).
    pf_bypass_installed: bool,
    /// Whether we installed pf DNS hijack rules (for cleanup).
    pf_rules_installed: bool,
    /// Whether we installed routes.
    routes_installed: bool,
    /// Original default gateway (if captured).
    original_gateway: Option<IpAddr>,
    /// Whether DNS hijacking is active (copied from config at startup).
    auto_hijack: bool,
}

impl MacosTunManager {
    pub fn new(
        iface_name: String,
        tun_addr: IpAddr,
        auto_hijack: bool,
    ) -> Self {
        Self {
            iface_name,
            tun_addr,
            pf_bypass_installed: false,
            pf_rules_installed: false,
            routes_installed: false,
            original_gateway: None,
            auto_hijack,
        }
    }

    /// Set up the TUN interface address and MTU.
    /// The `tun` crate already configures address/netmask on creation
    /// (via `set_alias`), so this is mostly a no-op. We just log.
    pub fn setup_interface(&self) -> Result<(), String> {
        log::info!(
            "macOS TUN interface {} configured at {}",
            self.iface_name,
            self.tun_addr
        );
        Ok(())
    }

    /// Install routes to capture traffic via the TUN interface.
    ///
    /// Uses the split-default-route trick: install two /1 routes
    /// (0.0.0.0/1 and 128.0.0.0/1) that are more specific than the
    /// default 0.0.0.0/0 route, so all traffic goes through TUN without
    /// touching the original default route.
    pub fn setup_routing(
        &mut self,
        auto_hijack: bool,
        _bypass_ips: &[String],
    ) -> Result<(), String> {
        // Save original default gateway for reference.
        self.original_gateway = get_default_gateway();

        // Find the actual TUN interface name for -ifscope.
        let tun_iface = find_tun_interface_name();
        log::info!("TUN interface for ifscope: {tun_iface}");

        // Install split default routes for IPv4.
        // NO -ifscope: scoped routes are only used for IP_BOUND_IF traffic,
        // general traffic would bypass TUN entirely. Instead, rely on the
        // host route for TUN address (below) to make IP_BOUND_IF work:
        // the host route makes the gateway (10.0.0.1) resolve to utun4,
        // so IP_BOUND_IF=en0 ignores split routes (output=utun4).
        let tun_addr_str = self.tun_addr.to_string();
        run_route_cmd(&[
            "-n", "add",
            "-net", "0.0.0.0/1",
            &tun_addr_str,
        ])?;

        run_route_cmd(&[
            "-n", "add",
            "-net", "128.0.0.0/1",
            &tun_addr_str,
        ])?;

        // IPv6 split routes (if applicable).
        if let IpAddr::V6(_) = self.tun_addr {
            run_route_cmd(&[
                "-n", "add",
                "-net", "::/1",
                &tun_addr_str,
            ])?;
            run_route_cmd(&[
                "-n", "add",
                "-net", "8000::/1",
                &tun_addr_str,
            ])?;
        }

        // Bypass routes for private networks so LAN traffic doesn't
        // go through TUN. Without this, local discovery protocols (mDNS,
        // SSDP, NetBIOS) and direct LAN access get proxied unnecessarily.
        for subnet in &[
            // NOTE: 10.0.0.0/8 is excluded because the TUN address (10.0.0.1)
            // is in this range. If we add a bypass route for it, IP_BOUND_IF
            // can't bypass the split routes (gateway 10.0.0.1 resolves via
            // en0 instead of utun4). LAN traffic to 10.x.x.x will go through
            // TUN, which is acceptable for most setups.
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
        ] {
            // Use the original gateway as the next-hop for private subnets.
            if let Some(gw) = self.original_gateway {
                let _ = run_route_cmd(&[
                    "-n", "add",
                    "-net", subnet,
                    &gw.to_string(),
                ]);
            } else {
                // No gateway found — add direct interface route via default route.
                let _ = run_route_cmd(&[
                    "-n", "add",
                    "-net", subnet,
                    "-interface", "en0",
                ]);
            }
        }

        // Add a host route for the TUN address via the TUN interface.
        // Without this, the bypass route for 10.0.0.0/8 routes the TUN
        // address (10.0.0.1) via en0, making IP_BOUND_IF ineffective
        // (split routes' gateway resolves via en0, not utun).
        // The host route (/32) is more specific than the /8 bypass route.
        let _ = run_route_cmd(&[
            "-n", "add",
            "-host", &self.tun_addr.to_string(),
            "-interface", &tun_iface,
        ]);
        log::info!("Added host route {} via {}", self.tun_addr, tun_iface);
        // Add default routes scoped to en0 for IP_BOUND_IF.
        // macOS IP_BOUND_IF may require scoped routes to find a path.
        if let Some(gw) = self.original_gateway {
            let gw_s = gw.to_string();
            let _ = run_route_cmd(&["-n", "add", "-net", "0.0.0.0/1", "-ifscope", "en0", &gw_s]);
            let _ = run_route_cmd(&["-n", "add", "-net", "128.0.0.0/1", "-ifscope", "en0", &gw_s]);
            log::info!("Added en0-scoped default routes via {gw_s}");
        }

        self.routes_installed = true;
        log::info!(
            "macOS TUN routes installed via {} (gateway was {:?})",
            self.iface_name,
            self.original_gateway
        );

        // Install pf route-to bypass rules so direct outbound traffic
        // bypasses TUN. Direct outbound sockets bind to en0 source IP;
        // pf matches `from <en0_ip>` and redirects to original gateway.
        // IP_BOUND_IF does NOT work (gateway unreachable → ENETUNREACH).
        self.setup_bypass_pf()?;

        // DNS hijacking via pfctl.
        if auto_hijack {
            self.setup_dns_hijack()?;
        }

        Ok(())
    }

    /// Install pf `route-to` rules to bypass TUN for direct outbound traffic.
    ///
    /// On macOS, split routes (0.0.0.0/1 + 128.0.0.0/1) capture ALL traffic.
    /// IP_BOUND_IF doesn't work because the route gateway (TUN address) is
    /// unreachable via the bound physical interface → ENETUNREACH.
    ///
    /// Solution: pf `route-to` operates at the packet level AFTER route
    /// lookup. Direct outbound sockets bind to the en0 source IP; pf
    /// matches `from <en0_ip>` and redirects the packet to the original
    /// gateway via en0, bypassing TUN entirely.
    fn setup_bypass_pf(&mut self) -> Result<(), String> {

        let en0_ip = match get_en0_ipv4() {
            Some(ip) => ip,
            None => {
                log::warn!("No en0 IPv4 found; skipping pf bypass");
                return Ok(());
            }
        };
        let gw_str = match &self.original_gateway {
            Some(gw) => gw.to_string(),
            None => {
                log::warn!("No default gateway found; skipping pf bypass");
                return Ok(());
            }
        };

        let iface = default_physical_iface().unwrap_or_else(|| "en0".to_string());

        // Read existing /etc/pf.conf and insert our rules directly
        // into the main ruleset (not via anchor). Anchor-based route-to
        // doesn't work reliably for route-to rules — the rule loads but
        // packets don't get redirected. Direct main-ruleset rules work.
        let existing_pf = std::fs::read_to_string("/etc/pf.conf")
            .unwrap_or_else(|_| String::new());

        // Find the actual TUN interface name. The tun crate creates a utun
        // device but doesn't expose the name. Reuse find_tun_interface_name
        // to avoid a duplicate ifconfig fork.
        let tun_iface = find_tun_interface_name();
        log::info!("TUN interface detected: {tun_iface}");
        log::info!("setup_bypass_pf: tun_iface={tun_iface}, en0_ip={en0_ip}, gw={gw_str}, iface={iface}");

        // With IP_BOUND_IF + host route, no pf route-to/nat rules needed.
        // pf is only used for DNS hijack (rdr) and lo0 protection.
        let nat_rule = "";
        let filter_rules = format!(
            "pass out quick on lo0 inet proto {{ tcp udp }} keep state\n",
        );

        // Insert nat rule before filtering section, filter rules after load anchor.
        let mut combined = String::new();
        for line in existing_pf.lines() {
            if line == "anchor \"com.apple/*\"" && !existing_pf.contains("anywhere_nat") {
                combined.push_str("# anywhere nat rule (translation)\n");
                combined.push_str(&nat_rule);
            }
            combined.push_str(line);
            combined.push('\n');
            if line.starts_with("load anchor \"com.apple\"") {
                if !existing_pf.contains("anywhere_bypass") {
                    combined.push_str("# anywhere bypass rules (filtering)\n");
                    combined.push_str(&filter_rules);
                }
            }
        }

        std::fs::write("/tmp/anywhere_bypass.pf", &format!("{nat_rule}{filter_rules}"))
            .map_err(|e| format!("Failed to write bypass rules: {e}"))?;

        // Write the combined pf.conf and load it.
        std::fs::write("/tmp/anywhere_combined.pf", &combined)
            .map_err(|e| format!("Failed to write combined pf.conf: {e}"))?;

        // Disable pf first to avoid "DIOCADDRULE: Resource busy".
        let _ = run_pfctl_cmd(&["-d"]);

        log::debug!("Loading pf ruleset (combined with bypass + DNS anchors)");
        run_pfctl_cmd(&["-f", "/tmp/anywhere_combined.pf"])?;

        // Ensure pf is enabled.
        let _ = run_pfctl_cmd(&["-E"]);

        self.pf_bypass_installed = true;
        log::info!(
            "macOS pf bypass installed: nat on {tun_iface} + route-to {iface} via {gw_str} (en0_ip={en0_ip})"
        );
        Ok(())
    }

    /// Set up DNS hijacking: redirect all UDP port 53 traffic to 1053
    /// using pfctl rdr rules.
    fn setup_dns_hijack(&mut self) -> Result<(), String> {
        // Build DNS rdr rules.
        // Don't bind to a specific interface - the TUN interface name is
        // assigned dynamically by the kernel (utunN) and may not be
        // resolved correctly at this point. A global rdr catches all
        // DNS traffic regardless of which interface it arrives on.
        //
        // CRITICAL: add a `no rdr` exclusion for traffic from the physical
        // interface IP. The DNS resolver (resolve_direct_udp) binds to the
        // en0 IP via bind_udp_bypass and sends queries to upstream DNS
        // servers (e.g. 223.5.5.5:53). Without the exclusion, the rdr rule
        // redirects the resolver's own queries back to the listener,
        // creating an infinite loop. On Linux this is handled by SO_MARK +
        // iptables `! --mark`; macOS has no SO_MARK, so we exclude by
        // source IP instead.
        let en0_ip = get_en0_ipv4().unwrap_or_else(|| "0.0.0.0".to_string());
        let dns_rules = format!(
            "no rdr inet proto udp from {en0_ip} to any port 53\n\
             rdr pass inet proto udp from any to any port 53 -> 127.0.0.1 port {hijack_port}\n\
             rdr pass inet6 proto udp from any to any port 53 -> ::1 port {hijack_port}\n",
            en0_ip = en0_ip,
            hijack_port = crate::dns::DNS_REDIRECT_PORT,
        );

        // Read the current combined pf.conf and insert DNS rdr rules.
        // rdr is a translation rule — must come BEFORE filter rules (pass).
        // pf order: options, normalization, queueing, translation, filtering.
        // We insert rdr rules after the com.apple rdr-anchor line and before
        // the anchor (filtering) line.
        let combined = std::fs::read_to_string("/tmp/anywhere_combined.pf")
            .unwrap_or_else(|_| {
                std::fs::read_to_string("/etc/pf.conf").unwrap_or_default()
            });

        let mut updated = String::new();
        let mut inserted = false;
        for line in combined.lines() {
            // Insert DNS rdr rules right before the filtering section
            // (anchor "com.apple/*" is the first filtering rule).
            if !inserted && line == "anchor \"com.apple/*\"" {
                updated.push_str(&dns_rules);
                inserted = true;
            }
            updated.push_str(line);
            updated.push('\n');
        }
        if !inserted {
            // Fallback: prepend before pass rules.
            let mut done = false;
            let mut tmp = String::new();
            for line in updated.lines() {
                if !done && line.starts_with("pass ") {
                    tmp.push_str(&dns_rules);
                    done = true;
                }
                tmp.push_str(line);
                tmp.push('\n');
            }
            updated = tmp;
        }

        std::fs::write("/tmp/anywhere_combined.pf", &updated)
            .map_err(|e| format!("Failed to write combined pf.conf: {e}"))?;

        // Disable pf, reload, re-enable.
        let _ = run_pfctl_cmd(&["-d"]);
        run_pfctl_cmd(&["-f", "/tmp/anywhere_combined.pf"])?;
        let _ = run_pfctl_cmd(&["-E"]);

        self.pf_rules_installed = true;
        log::info!("macOS DNS hijack installed via pfctl");
        Ok(())
    }

    /// Remove all installed routes and pf rules.
    pub fn cleanup_routing(&mut self) {
        // Remove pf bypass: reload original /etc/pf.conf to flush our rules.
        // Guarded by `pf_bypass_installed` so the second cleanup (from Drop)
        // doesn't run pfctl again — `fork()` is O(RSS) and the double call
        // was a major source of shutdown latency.
        if self.pf_bypass_installed {
            let _ = run_pfctl_cmd(&["-f", "/etc/pf.conf"]);
            let _ = std::fs::remove_file("/tmp/anywhere_bypass.pf");
            let _ = std::fs::remove_file("/tmp/anywhere_dns.pf");
            let _ = std::fs::remove_file("/tmp/anywhere_combined.pf");
            log::info!("macOS pf bypass removed (restored /etc/pf.conf)");
            self.pf_bypass_installed = false;
        }

        if self.pf_rules_installed {
            log::info!("macOS DNS hijack rules removed");
            self.pf_rules_installed = false;
        }

        if self.routes_installed {
            let tun_addr_str = self.tun_addr.to_string();

            // Delete split routes.
            let _ = run_route_cmd(&["-n", "delete", "-net", "0.0.0.0/1", &tun_addr_str]);
            let _ = run_route_cmd(&["-n", "delete", "-net", "128.0.0.0/1", &tun_addr_str]);

            if let IpAddr::V6(_) = self.tun_addr {
                let _ = run_route_cmd(&["-n", "delete", "-net", "::/1", &tun_addr_str]);
                let _ = run_route_cmd(&["-n", "delete", "-net", "8000::/1", &tun_addr_str]);
            }

            // Delete host route for TUN address.
            let _ = run_route_cmd(&["-n", "delete", "-host", &tun_addr_str]);

            // Delete en0-scoped default routes (added for IP_BOUND_IF).
            if let Some(gw) = &self.original_gateway {
                let gw_s = gw.to_string();
                let _ = run_route_cmd(&["-n", "delete", "-net", "0.0.0.0/1", "-ifscope", "en0", &gw_s]);
                let _ = run_route_cmd(&["-n", "delete", "-net", "128.0.0.0/1", "-ifscope", "en0", &gw_s]);
            }

            // Delete bypass routes (only the ones we actually install).
            for subnet in &[
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "224.0.0.0/4",
            ] {
                let _ = run_route_cmd(&["-n", "delete", "-net", subnet]);
            }

            log::info!("macOS TUN routes removed");
            self.routes_installed = false;
        }
    }

    /// Enable TUN routing (install routes + pf rules + DNS hijack).
    /// Idempotent: no-op if already enabled. Used by the runtime
    /// `tun_routing_enable` API; the TUN interface itself stays up.
    pub fn enable_routing(&mut self) -> Result<(), String> {
        if self.routes_installed {
            return Ok(());
        }
        self.setup_routing(self.auto_hijack, &[])
    }

    /// Disable TUN routing (remove routes + pf rules + DNS).
    /// Idempotent: no-op if already disabled. The TUN interface stays up.
    pub fn disable_routing(&mut self) {
        if !self.routes_installed {
            return;
        }
        self.cleanup_routing()
    }

    /// Whether TUN routing (routes + pf rules + DNS) is currently active.
    pub fn is_routing_enabled(&self) -> bool {
        self.routes_installed
    }
}

impl Drop for MacosTunManager {
    fn drop(&mut self) {
        self.cleanup_routing();
    }
}

/// Find the TUN interface name by listing all interfaces and picking
/// the highest-numbered utun (most recently created).
fn find_tun_interface_name() -> String {
    let output = Command::new("ifconfig")
        .arg("-l")
        .output();
    if let Ok(o) = output {
        let s = String::from_utf8_lossy(&o.stdout);
        let mut utun_ifaces: Vec<&str> = s
            .split_whitespace()
            .filter(|n| n.starts_with("utun"))
            .collect();
        utun_ifaces.sort();
        if let Some(name) = utun_ifaces.last() {
            return name.to_string();
        }
    }
    "utun0".to_string()
}

/// Get the current default gateway by parsing `route -n get default`.
fn get_default_gateway() -> Option<IpAddr> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(gateway_str) = line.strip_prefix("gateway:") {
            let gateway_str = gateway_str.trim();
            if let Ok(ip) = gateway_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Run a `route` command, returning an error on non-zero exit.
///
/// Uses `status()` (not `output()`) so macOS uses `posix_spawn` instead of
/// `fork()+exec()`. `fork()` is O(RSS): it copies the entire page table even
/// though pages are copy-on-write. With hundreds of MB of RSS this makes each
/// command take 0.5-2s instead of ~1ms.
fn run_route_cmd(args: &[&str]) -> Result<(), String> {
    log::debug!("route {}", args.join(" "));
    let status = Command::new("route").args(args).status().map_err(|e| e.to_string())?;
    if !status.success() {
        // "route delete" may fail if route doesn't exist; log but don't error.
        if args.iter().any(|&a| a == "delete") {
            log::debug!("route delete (may be already gone)");
            return Ok(());
        }
        return Err(format!(
            "route {} failed (exit {})",
            args.join(" "),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}
/// Run a `pfctl` command, returning an error on non-zero exit.
///
/// Uses `status()` (not `output()`) so macOS uses `posix_spawn` instead of
/// `fork()+exec()`. See [`run_route_cmd`] for rationale.
fn run_pfctl_cmd(args: &[&str]) -> Result<(), String> {
    log::debug!("pfctl {}", args.join(" "));
    let status = Command::new("pfctl").args(args).status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!(
            "pfctl {} failed (exit {})",
            args.join(" "),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Get the IPv4 address of the primary physical interface (en0/en1/...).
fn get_en0_ipv4() -> Option<String> {
    let iface = default_physical_iface()?;
    let output = Command::new("ifconfig")
        .args([&iface])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(ip) = rest.split_whitespace().next() {
                return Some(ip.to_string());
            }
        }
    }
    None
}

/// Find the default physical interface by looking up the default route.
fn default_physical_iface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(iface) = line.strip_prefix("interface:") {
            let iface = iface.trim();
            if !iface.is_empty() {
                return Some(iface.to_string());
            }
        }
    }
    None
}


