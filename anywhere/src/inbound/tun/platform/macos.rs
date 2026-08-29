//! macOS-specific TUN route management.
//!
//! Uses `route` and `pfctl` commands to manage routing and DNS hijacking.
//! Unlike Linux's rtnetlink approach, macOS keeps it simple with shell commands.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
use tokio::io::AsyncBufReadExt;

const ROUTE_ECHO_SUPPRESSION: Duration = Duration::from_secs(10);
static RECENT_ROUTE_COMMAND_PIDS: std::sync::Mutex<Vec<(u32, Instant)>> =
    std::sync::Mutex::new(Vec::new());
static NETWORK_DIAGNOSTICS_LAST: std::sync::Mutex<Option<Instant>> =
    std::sync::Mutex::new(None);

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
    /// Original physical interface (en0/en1/…, if captured).
    physical_iface: Option<String>,
    /// Whether DNS hijacking is active (copied from config at startup).
    auto_hijack: bool,
    /// Whether fake-ip mode is enabled (only set system DNS when fakeip is on).
    fakeip_enabled: bool,
    /// Original system DNS servers (saved for cleanup).
    original_dns: Option<Vec<String>>,
    /// Network service name (e.g. "Wi-Fi") for DNS restore.
    network_service: Option<String>,
    /// Whether system DNS was modified and still needs restoration.
    system_dns_modified: bool,
}

impl MacosTunManager {
    pub fn new(iface_name: String, tun_addr: IpAddr, auto_hijack: bool) -> Self {
        Self {
            iface_name,
            tun_addr,
            pf_bypass_installed: false,
            pf_rules_installed: false,
            routes_installed: false,
            original_gateway: None,
            physical_iface: None,
            auto_hijack,
            fakeip_enabled: false,
            original_dns: None,
            network_service: None,
            system_dns_modified: false,
        }
    }

    /// Set whether fake-ip DNS mode is enabled.
    /// When true, setup_routing will set system DNS to public IPs so that
    /// DNS queries go through TUN and get fake-ip responses.
    /// When false, system DNS is left untouched (DNS may leak but this is
    /// expected when fake-ip is disabled).
    pub fn set_fakeip_enabled(&mut self, enabled: bool) {
        self.fakeip_enabled = enabled;
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
        &mut self, auto_hijack: bool, _bypass_ips: &[String],
    ) -> Result<(), String> {
        // Save original default gateway for reference.
        self.original_gateway = get_default_gateway();
        self.physical_iface = default_physical_iface();

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
        run_route_cmd(&["-n", "add", "-net", "0.0.0.0/1", &tun_addr_str])?;

        run_route_cmd(&["-n", "add", "-net", "128.0.0.0/1", &tun_addr_str])?;

        // IPv6 split routes (if applicable).
        if let IpAddr::V6(_) = self.tun_addr {
            run_route_cmd(&["-n", "add", "-net", "::/1", &tun_addr_str])?;
            run_route_cmd(&["-n", "add", "-net", "8000::/1", &tun_addr_str])?;
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
                    "-n",
                    "add",
                    "-net",
                    subnet,
                    &gw.to_string(),
                ]);
            } else {
                // No gateway found - add direct interface route via default route.
                let _ = run_route_cmd(&[
                    "-n",
                    "add",
                    "-net",
                    subnet,
                    "-interface",
                    self.physical_iface.as_deref().unwrap_or("en0"),
                ]);
            }
        }

        // Add a host route for the TUN address via the TUN interface.
        // Without this, the bypass route for 10.0.0.0/8 routes the TUN
        // address (10.0.0.1) via en0, making IP_BOUND_IF ineffective
        // (split routes' gateway resolves via en0, not utun).
        // The host route (/32) is more specific than the /8 bypass route.
        let _ = run_route_cmd(&[
            "-n",
            "add",
            "-host",
            &self.tun_addr.to_string(),
            "-interface",
            &tun_iface,
        ]);
        log::info!("Added host route {} via {}", self.tun_addr, tun_iface);
        // Add default routes scoped to en0 for IP_BOUND_IF.
        // macOS IP_BOUND_IF may require scoped routes to find a path.
        if let Some(gw) = self.original_gateway {
            let gw_s = gw.to_string();
            let iface = self.physical_iface.as_deref().unwrap_or("en0");
            let _ = run_route_cmd(&[
                "-n",
                "add",
                "-net",
                "0.0.0.0/1",
                "-ifscope",
                iface,
                &gw_s,
            ]);
            let _ = run_route_cmd(&[
                "-n",
                "add",
                "-net",
                "128.0.0.0/1",
                "-ifscope",
                iface,
                &gw_s,
            ]);
            log::info!("Added {iface}-scoped default routes via {gw_s}");
        }

        crate::outbound::common::refresh_macos_physical_iface_cache();

        self.routes_installed = true;
        log::info!(
            "macOS TUN routes installed via {} (gateway was {:?})",
            self.iface_name,
            self.original_gateway
        );

        // Install the minimal PF rules required by TUN mode.
        // Direct outbound traffic uses IP_BOUND_IF with scoped routes.
        self.setup_bypass_pf()?;

        // DNS hijacking: set system DNS to a public IP so mDNSResponder
        // sends queries to a public address (not the router). These queries
        // flow through TUN split routes and are intercepted by the TUN
        // handler's dst_port==53 check. Also install pf rdr for LAN DNS as
        // a fallback for apps that hardcode router DNS.
        if auto_hijack {
            // Only set system DNS when fake-ip is enabled. In fake-ip mode,
            // DNS queries are answered locally (fake IP allocated), so
            // redirecting system DNS through TUN is safe and prevents leaks.
            // When fake-ip is disabled, DNS queries need real upstream
            // resolution — setting system DNS to a public IP would force
            // all DNS through TUN, which breaks if the proxy outbound
            // doesn't support UDP relay (e.g. SS with obfs plugin).
            if self.fakeip_enabled {
                self.setup_system_dns()?;
            }
            self.setup_dns_hijack()?;
        }

        Ok(())
    }

    /// Set system DNS servers to public IPs so DNS queries route through
    /// TUN instead of the LAN bypass route to the router.
    ///
    /// macOS `mDNSResponder` sends DNS queries to the configured system DNS
    /// server. When the system DNS is the router (e.g. 192.168.50.1), the
    /// LAN bypass route (192.168.0.0/16 → physical gateway) takes precedence
    /// over TUN split routes, so DNS queries never reach TUN.
    ///
    /// By setting the system DNS to a public IP (e.g. 223.5.5.5), DNS queries
    /// match the TUN split route (0.0.0.0/1 or 128.0.0.0/1 → 10.0.0.1) and
    /// are intercepted by the TUN handler's dst_port==53 check.
    ///
    /// The proxy's own DNS queries use IP_BOUND_IF to bypass TUN, so they
    /// are not affected.
    fn setup_system_dns(&mut self) -> Result<(), String> {
        // Find the active network service (e.g. "Wi-Fi").
        //
        // Strategy: use `route -n get default` to find the default interface
        // (e.g. en0), then map it to a network service name via
        // `networksetup -listallhardwareports`. This reliably picks the
        // primary interface regardless of connection type (Wi-Fi, Ethernet,
        // USB tethering, etc.). Falls back to iterating services by IPv4.
        let service = self.find_primary_network_service();

        let Some(service) = service else {
            log::warn!("DNS hijack: could not find active network service");
            return Ok(());
        };
        log::info!("DNS hijack: active network service: {service}");

        // Save original DNS servers.
        let original = run_networksetup_cmd(&["-getdnsservers", &service]);
        let original_dns: Vec<String> =
            if original.contains("There aren't any DNS Servers set") {
                Vec::new()
            } else {
                original
                    .lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
        self.original_dns = Some(original_dns.clone());
        self.network_service = Some(service.clone());

        // Set system DNS to public IPs. These addresses will route through
        // TUN split routes and be intercepted by the TUN handler.
        // Using 223.5.5.5 and 114.114.114.114 (Alibaba DNS) as they are
        // fast public resolvers in China. The actual resolution is handled
        // by anywhere's DNS engine (direct upstream), not these IPs directly.
        let set_dns_result = Command::new("networksetup")
            .args(["-setdnsservers", &service, "223.5.5.5", "114.114.114.114"])
            .output();
        let set_dns_success = set_dns_result
            .as_ref()
            .is_ok_and(|output| output.status.success());
        if set_dns_success {
            self.system_dns_modified = true;
        } else {
            log::warn!("DNS hijack: failed to set system DNS servers");
        }
        log::info!(
            "DNS hijack: system DNS set to 223.5.5.5, 114.114.114.114 (was {:?})",
            original_dns
        );

        // Flush DNS cache so mDNSResponder picks up the new servers.
        let _ = Command::new("dscacheutil").arg("-flushcache").output();
        let _ = Command::new("killall")
            .arg("-HUP")
            .arg("mDNSResponder")
            .output();

        Ok(())
    }

    /// Restore original system DNS servers.
    fn restore_system_dns(&mut self) {
        if !self.system_dns_modified {
            return;
        }
        let Some(ref service) = self.network_service else {
            return;
        };
        let Some(ref original) = self.original_dns else {
            return;
        };

        if original.is_empty() {
            // Clear DNS (back to DHCP-assigned): pass no server args.
            let _ = Command::new("networksetup")
                .args(["-setdnsservers", service])
                .output();
        } else {
            let mut args = vec!["-setdnsservers".to_string(), service.clone()];
            args.extend(original.iter().cloned());
            let _ = Command::new("networksetup").args(&args).output();
        }
        log::info!("DNS hijack: system DNS restored to {:?}", original);
        self.system_dns_modified = false;

        // Flush DNS cache.
        let _ = Command::new("dscacheutil").arg("-flushcache").output();
        let _ = Command::new("killall")
            .arg("-HUP")
            .arg("mDNSResponder")
            .output();
    }

    /// Find the primary network service name by looking up the default
    /// route's interface and mapping it via `networksetup -listallhardwareports`.
    /// Falls back to iterating services for one with a real IPv4 address.
    fn find_primary_network_service(&self) -> Option<String> {
        // 1. Get the default route's interface (e.g. "en0").
        let route_output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let route_str = String::from_utf8_lossy(&route_output.stdout);
        let iface: Option<&str> = route_str
            .lines()
            .map(|l| l.trim())
            .find_map(|l| l.strip_prefix("interface:").map(|s| s.trim()));

        if let Some(iface) = iface {
            log::debug!("DNS hijack: default route interface: {iface}");
            // 2. Map interface (en0) → hardware port name (Wi-Fi) via
            // `networksetup -listallhardwareports` which outputs:
            //   Hardware Port: Wi-Fi
            //   Device: en0
            //   Ethernet Address: ...
            let hw_output = run_networksetup_cmd(&["-listallhardwareports"]);
            let mut last_port: Option<String> = None;
            for line in hw_output.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("Hardware Port:") {
                    last_port = Some(rest.trim().to_string());
                } else if line.strip_prefix("Device:").map(|s| s.trim())
                    == Some(iface)
                {
                    if let Some(port) = &last_port {
                        // Verify this service has a real IPv4 address.
                        let info = run_networksetup_cmd(&["-getinfo", port]);
                        let has_ipv4 = info.lines().any(|l| {
                            l.trim().starts_with("IP address")
                                && !l.contains("none")
                        });
                        if has_ipv4 {
                            return Some(port.clone());
                        }
                    }
                }
            }
        }

        // 3. Fallback: iterate services, find first with real IPv4.
        log::debug!("DNS hijack: falling back to service iteration");
        run_networksetup_cmd(&["-listallnetworkservices"])
            .lines()
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with('*')
                    && !l.starts_with("An asterisk")
            })
            .find(|l| {
                let info = run_networksetup_cmd(&["-getinfo", l]);
                info.lines().any(|line| {
                    line.trim().starts_with("IP address")
                        && !line.contains("none")
                })
            })
            .map(|s| s.trim().to_string())
    }

    /// Install the minimal PF rules required by TUN mode.
    ///
    /// Direct outbound traffic uses IP_BOUND_IF with scoped physical routes.
    /// PF `route-to` is deliberately avoided because it can black-hole after
    /// macOS Deep Idle reinitializes the physical interface.
    ///
    fn setup_bypass_pf(&mut self) -> Result<(), String> {
        let en0_ip = match get_en0_ipv4() {
            Some(ip) => ip,
            None => {
                log::warn!("No en0 IPv4 found; skipping pf bypass");
                return Ok(());
            },
        };
        let gw_str = match &self.original_gateway {
            Some(gw) => gw.to_string(),
            None => {
                log::warn!("No default gateway found; skipping pf bypass");
                return Ok(());
            },
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
        log::info!(
            "setup_bypass_pf: tun_iface={tun_iface}, en0_ip={en0_ip}, gw={gw_str}, iface={iface}"
        );

        // Keep PF free of route-to rules. Direct sockets use IP_BOUND_IF and
        // scoped physical routes instead; route-to can black-hole after deep
        // idle when macOS reinitializes the physical interface.
        let nat_rule = "";
        let filter_rules = format!(
            "pass out quick on lo0 inet proto {{ tcp udp }} keep state\n",
        );

        // Insert nat rule before filtering section, filter rules after load anchor.
        let mut combined = String::new();
        for line in existing_pf.lines() {
            if line == "anchor \"com.apple/*\""
                && !existing_pf.contains("anywhere_nat")
            {
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

        std::fs::write(
            "/tmp/anywhere_bypass.pf",
            &format!("{nat_rule}{filter_rules}"),
        )
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
            "macOS PF bypass installed: lo0 state rules only (tun_iface={tun_iface})"
        );
        Ok(())
    }

    /// Set up DNS hijacking: redirect LAN DNS traffic to the loopback
    /// listener using pfctl rdr rules.
    ///
    /// Only redirect UDP port 53 traffic destined to private/LAN ranges
    /// (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8). This covers the common
    /// case where the system DNS server is the router (e.g. 192.168.50.1)
    /// and that traffic bypasses TUN via LAN bypass routes.
    ///
    /// DNS queries to public IPs (e.g. 223.5.5.5) are NOT redirected here —
    /// they flow through TUN split routes and are intercepted by the TUN
    /// handler's `dst_port == 53` check.
    ///
    /// The proxy's own DNS queries (resolve_direct_udp) target public IPs
    /// (223.5.5.5, 114.114.114.114) and use IP_BOUND_IF to bypass TUN, so
    /// they are not caught by this rdr (not in LAN ranges).
    ///
    /// This avoids the need for `no rdr from <en0_ip>` which was too broad
    /// and exempted ALL local DNS traffic, causing DNS leaks.
    fn setup_dns_hijack(&mut self) -> Result<(), String> {
        let dns_rules = format!(
            "rdr pass inet proto udp from any to 192.168.0.0/16 port 53 -> 127.0.0.1 port {hijack_port}\n\
             rdr pass inet proto udp from any to 172.16.0.0/12 port 53 -> 127.0.0.1 port {hijack_port}\n\
             rdr pass inet proto udp from any to 10.0.0.0/8 port 53 -> 127.0.0.1 port {hijack_port}\n",
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
            let _ = run_route_cmd(&[
                "-n",
                "delete",
                "-net",
                "0.0.0.0/1",
                &tun_addr_str,
            ]);
            let _ = run_route_cmd(&[
                "-n",
                "delete",
                "-net",
                "128.0.0.0/1",
                &tun_addr_str,
            ]);

            if let IpAddr::V6(_) = self.tun_addr {
                let _ = run_route_cmd(&[
                    "-n",
                    "delete",
                    "-net",
                    "::/1",
                    &tun_addr_str,
                ]);
                let _ = run_route_cmd(&[
                    "-n",
                    "delete",
                    "-net",
                    "8000::/1",
                    &tun_addr_str,
                ]);
            }

            // Delete host route for TUN address.
            let _ = run_route_cmd(&["-n", "delete", "-host", &tun_addr_str]);

            // Delete physical-interface-scoped default routes (added for
            // IP_BOUND_IF).
            if let Some(gw) = &self.original_gateway {
                let gw_s = gw.to_string();
                let iface = self.physical_iface.as_deref().unwrap_or("en0");
                let _ = run_route_cmd(&[
                    "-n",
                    "delete",
                    "-net",
                    "0.0.0.0/1",
                    "-ifscope",
                    iface,
                    &gw_s,
                ]);
                let _ = run_route_cmd(&[
                    "-n",
                    "delete",
                    "-net",
                    "128.0.0.0/1",
                    "-ifscope",
                    iface,
                    &gw_s,
                ]);
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

        // Restore original system DNS servers.
        self.restore_system_dns();
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

    /// Reinstall missing TUN routes after a wake and replace old physical
    /// bypass routes when the default gateway or interface changes.
    ///
    /// Returns false while the physical network has not become ready yet.
    fn reconcile_routes(&mut self) -> bool {
        let Some(gateway) = get_default_gateway() else {
            return false;
        };
        let Some(iface) = default_physical_iface() else {
            return false;
        };
        if !physical_iface_is_ready(&iface, gateway.is_ipv4()) {
            log::debug!("macOS physical interface {iface} is not ready");
            return false;
        }

        let network_changed = self.original_gateway != Some(gateway)
            || self.physical_iface.as_deref() != Some(iface.as_str());
        if network_changed {
            log::info!(
                "macOS physical network changed: gateway {:?} -> {gateway}, iface {:?} -> {iface}",
                self.original_gateway,
                self.physical_iface
            );
            self.remove_physical_bypass_routes();
        }

        self.original_gateway = Some(gateway);
        self.physical_iface = Some(iface.clone());

        let tun_iface = find_tun_interface_name();
        let tun_addr = self.tun_addr.to_string();
        let gateway_s = gateway.to_string();

        if replace_route(&["-net", "0.0.0.0/1", &tun_addr]).is_err() {
            return false;
        }
        if replace_route(&["-net", "128.0.0.0/1", &tun_addr]).is_err() {
            return false;
        }

        if let IpAddr::V6(_) = self.tun_addr {
            if replace_route(&["-net", "::/1", &tun_addr]).is_err() {
                return false;
            }
            if replace_route(&["-net", "8000::/1", &tun_addr]).is_err() {
                return false;
            }
        }

        if network_changed {
            for subnet in &[
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "224.0.0.0/4",
            ] {
                if run_route_cmd(&["-n", "add", "-net", subnet, &gateway_s])
                    .is_err()
                {
                    return false;
                }
            }
        }

        if replace_route(&["-host", &tun_addr, "-interface", &tun_iface]).is_err()
        {
            return false;
        }
        if recreate_scoped_route(&[
            "-net",
            "0.0.0.0/1",
            "-ifscope",
            &iface,
            &gateway_s,
        ])
        .is_err()
        {
            return false;
        }
        if recreate_scoped_route(&[
            "-net",
            "128.0.0.0/1",
            "-ifscope",
            &iface,
            &gateway_s,
        ])
        .is_err()
        {
            return false;
        }

        self.routes_installed = true;
        crate::outbound::common::refresh_macos_physical_iface_cache();
        if network_changed {
            log::info!(
                "macOS TUN routes reconciled for gateway {gateway_s} via {iface}"
            );
        } else {
            log::info!("macOS TUN routes reconciled after route/interface event");
        }
        true
    }

    fn remove_physical_bypass_routes(&self) {
        for subnet in &[
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
        ] {
            let _ = run_route_cmd(&["-n", "delete", "-net", subnet]);
        }

        if let Some(gateway) = self.original_gateway {
            let gateway_s = gateway.to_string();
            let iface = self.physical_iface.as_deref().unwrap_or("en0");
            let _ = run_route_cmd(&[
                "-n",
                "delete",
                "-net",
                "0.0.0.0/1",
                "-ifscope",
                iface,
                &gateway_s,
            ]);
            let _ = run_route_cmd(&[
                "-n",
                "delete",
                "-net",
                "128.0.0.0/1",
                "-ifscope",
                iface,
                &gateway_s,
            ]);
        }
    }
}

impl Drop for MacosTunManager {
    fn drop(&mut self) {
        self.cleanup_routing();
    }
}

/// Watch for route loss after sleep and gateway/interface changes while TUN
/// routing is enabled.
pub async fn run_route_watcher(
    manager: std::sync::Arc<std::sync::Mutex<MacosTunManager>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut restart_delay = Duration::from_secs(1);
    loop {
        let mut monitor = match tokio::process::Command::new("route")
            .args(["-n", "monitor"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(monitor) => monitor,
            Err(e) => {
                log::warn!(
                    "macOS route watcher: failed to start route monitor: {e}"
                );
                if shutdown.is_cancelled() {
                    return;
                }
                tokio::time::sleep(restart_delay).await;
                restart_delay = (restart_delay * 2).min(Duration::from_secs(30));
                continue;
            },
        };

        let stdout = match monitor.stdout.take() {
            Some(stdout) => stdout,
            None => {
                log::warn!("macOS route watcher: route monitor has no stdout");
                let _ = monitor.kill().await;
                if shutdown.is_cancelled() {
                    return;
                }
                tokio::time::sleep(restart_delay).await;
                continue;
            },
        };

        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let mut last_reconcile = Instant::now();
        let mut gateway_probe_interval =
            tokio::time::interval(Duration::from_secs(5));
        gateway_probe_interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        log::info!("macOS route watcher: route monitor started");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = monitor.kill().await;
                    return;
                },
                line = lines.next_line() => {
                    let line = match line {
                        Ok(Some(line)) => line,
                        Err(e) => {
                            log::warn!("macOS route watcher: read failed: {e}");
                            break;
                        },
                        Ok(None) => {
                            log::warn!("macOS route watcher: route monitor exited");
                            break;
                        },
                    };

                    if !route_event_requires_reconciliation(&line) {
                        continue;
                    }
                    if route_event_is_from_own_command(&line) {
                        continue;
                    }
                    if last_reconcile.elapsed() < Duration::from_secs(5) {
                        continue;
                    }

                    log::debug!("macOS route watcher: {line}");
                    last_reconcile = Instant::now();
                    reconcile_routes_with_retries(&manager, &shutdown).await;
                },
                _ = gateway_probe_interval.tick() => {
                    let (gateway, routes_installed) = {
                        let Ok(manager) = manager.lock() else {
                            continue;
                        };
                        (manager.original_gateway, manager.routes_installed)
                    };
                    if !routes_installed {
                        continue;
                    }
                    let Some(gateway) = gateway else {
                        continue;
                    };
                    if physical_gateway_probe(gateway).await {
                        continue;
                    }

                    log::warn!("macOS physical gateway probe failed: {gateway}");
                    last_reconcile = Instant::now();
                    reconcile_routes_with_retries(&manager, &shutdown).await;
                },
            }
        }

        let _ = monitor.wait().await;
        if shutdown.is_cancelled() {
            return;
        }

        tokio::time::sleep(restart_delay).await;
        restart_delay = (restart_delay * 2).min(Duration::from_secs(30));
    }
}

async fn physical_gateway_probe(gateway: IpAddr) -> bool {
    if gateway.is_ipv6() {
        return true;
    }

    let bind_addr = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0);
    let probe_addr = SocketAddr::new(gateway, 9);
    let socket = match crate::outbound::common::bind_udp_bypass(bind_addr).await {
        Ok(socket) => socket,
        Err(e) => {
            log::debug!("macOS gateway probe bind failed: {e}");
            return false;
        },
    };
    if let Err(e) = socket.connect(probe_addr).await {
        log::debug!("macOS gateway probe connect failed: {e}");
        return false;
    }
    match socket.send(&[0]).await {
        Ok(_) => true,
        Err(e) => {
            log::debug!("macOS gateway probe send failed: {e}");
            false
        },
    }
}

async fn reconcile_routes_with_retries(
    manager: &std::sync::Arc<std::sync::Mutex<MacosTunManager>>,
    shutdown: &tokio_util::sync::CancellationToken,
) {
    let mut retry_delay = Duration::from_millis(250);
    for _ in 0..20 {
        tokio::time::sleep(retry_delay).await;
        if shutdown.is_cancelled() {
            return;
        }
        retry_delay = (retry_delay * 2).min(Duration::from_secs(1));

        let reconciled = match manager.lock() {
            Ok(mut manager) => manager.reconcile_routes(),
            Err(_) => false,
        };
        if reconciled {
            return;
        }
        log::warn!("macOS physical network not ready after wake; retrying");
    }
}

fn route_event_requires_reconciliation(line: &str) -> bool {
    line.starts_with("RTM_DELETE:")
        || line.starts_with("RTM_CHANGE:")
        || line.starts_with("RTM_IFINFO:")
        || line.starts_with("RTM_IFANNOUNCE:")
        || line.starts_with("RTM_NEWADDR:")
        || line.starts_with("RTM_DELADDR:")
}

fn replace_route(route_args: &[&str]) -> Result<(), String> {
    let mut change_args = vec!["-n", "change"];
    change_args.extend_from_slice(route_args);
    if let Err(e) = run_route_cmd(&change_args) {
        log::debug!("route change failed, adding instead: {e}");
        let mut add_args = vec!["-n", "add"];
        add_args.extend_from_slice(route_args);
        return run_route_cmd(&add_args);
    }
    Ok(())
}

fn recreate_scoped_route(route_args: &[&str]) -> Result<(), String> {
    let mut delete_args = vec!["-n", "delete"];
    delete_args.extend_from_slice(route_args);
    let _ = run_route_cmd(&delete_args);

    let mut add_args = vec!["-n", "add"];
    add_args.extend_from_slice(route_args);
    run_route_cmd(&add_args)
}

fn route_event_pid(line: &str) -> Option<u32> {
    let pid_section = line.split("pid:").nth(1)?;
    let pid = pid_section.split(',').next()?.trim();
    pid.parse().ok()
}

fn record_route_command_pid(pid: u32) {
    if let Ok(mut recent_pids) = RECENT_ROUTE_COMMAND_PIDS.lock() {
        recent_pids.retain(|(_, recorded_at)| {
            recorded_at.elapsed() < ROUTE_ECHO_SUPPRESSION
        });
        recent_pids.push((pid, Instant::now()));
    }
}

fn route_event_is_from_own_command(line: &str) -> bool {
    let Some(pid) = route_event_pid(line) else {
        return false;
    };

    let Ok(mut recent_pids) = RECENT_ROUTE_COMMAND_PIDS.lock() else {
        return false;
    };
    recent_pids.retain(|(_, recorded_at)| {
        recorded_at.elapsed() < ROUTE_ECHO_SUPPRESSION
    });
    recent_pids.iter().any(|(recent_pid, _)| *recent_pid == pid)
}

pub fn log_network_diagnostics(destination: IpAddr) {
    let Ok(mut last_diagnostics) = NETWORK_DIAGNOSTICS_LAST.lock() else {
        return;
    };
    let now = Instant::now();
    if last_diagnostics
        .is_some_and(|last| now.duration_since(last) < Duration::from_secs(10))
    {
        return;
    }
    *last_diagnostics = Some(now);

    let default_route = run_diagnostic_cmd("route", &["-n", "get", "default"]);
    log::warn!("macOS network diagnostics: default route\n{default_route}");

    let gateway = default_route
        .lines()
        .find_map(|line| line.trim().strip_prefix("gateway:"))
        .map(str::trim);
    let iface = default_route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(str::trim);

    if let Some(iface) = iface {
        let interface = run_diagnostic_cmd("ifconfig", &[iface]);
        log::warn!("macOS network diagnostics: ifconfig {iface}\n{interface}");

        let destination_str = destination.to_string();
        let scoped_route = run_diagnostic_cmd(
            "route",
            &["-n", "get", "-ifscope", iface, &destination_str],
        );
        log::warn!(
            "macOS network diagnostics: {iface}-scoped route to {destination}\n{scoped_route}"
        );
    }

    let destination_str = destination.to_string();
    let destination_route =
        run_diagnostic_cmd("route", &["-n", "get", &destination_str]);
    log::warn!(
        "macOS network diagnostics: route to {destination}\n{destination_route}"
    );

    let routing_table = run_diagnostic_cmd("netstat", &["-rn", "-f", "inet"]);
    log::warn!("macOS network diagnostics: IPv4 routes\n{routing_table}");

    if let Some(gateway) = gateway {
        let arp = run_diagnostic_cmd("arp", &["-n", gateway]);
        log::warn!("macOS network diagnostics: ARP {gateway}\n{arp}");
        let ping =
            run_diagnostic_cmd("ping", &["-c", "1", "-W", "1000", gateway]);
        log::warn!("macOS network diagnostics: ping {gateway}\n{ping}");
    }
}

fn run_diagnostic_cmd(command: &str, args: &[&str]) -> String {
    match Command::new(command).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("{stdout}{stderr}").trim().to_string()
        },
        Err(e) => format!("failed to run {command}: {e}"),
    }
}

fn physical_iface_is_ready(iface: &str, require_ipv4: bool) -> bool {
    let output = Command::new("ifconfig").arg(iface).output();
    let stdout = match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(_) => return false,
    };
    interface_output_is_ready(&stdout, require_ipv4)
}

fn interface_output_is_ready(stdout: &str, require_ipv4: bool) -> bool {
    let Some(status_line) = stdout.lines().next() else {
        return false;
    };
    let Some(flags_section) = status_line.split("flags=").nth(1) else {
        return false;
    };
    let Some(flags) = flags_section
        .split('<')
        .nth(1)
        .and_then(|section| section.split('>').next())
    else {
        return false;
    };
    let flags: Vec<&str> = flags.split(',').map(str::trim).collect();
    let is_up = flags.contains(&"UP");
    let is_running = flags.contains(&"RUNNING");
    let status = stdout.lines().find_map(|line| {
        let line = line.trim_start();
        line.strip_prefix("status:").map(str::trim)
    });
    let status_is_ready = match status {
        Some("active") | Some("associated") => true,
        Some(_) => false,
        None => true,
    };
    let has_ipv4 = stdout
        .lines()
        .any(|line| line.trim_start().starts_with("inet "));

    is_up && is_running && status_is_ready && (!require_ipv4 || has_ipv4)
}

/// Find the TUN interface name by listing all interfaces and picking
/// the highest-numbered utun (most recently created).
fn find_tun_interface_name() -> String {
    let output = Command::new("ifconfig").arg("-l").output();
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

#[cfg(test)]
mod tests {
    use super::interface_output_is_ready;
    use super::route_event_pid;
    use super::route_event_requires_reconciliation;

    #[test]
    fn route_and_interface_changes_trigger_reconciliation() {
        assert!(route_event_requires_reconciliation(
            "RTM_DELETE: Delete Route: len 128, pid: 0, seq 0, errno 0, flags:<DONE>"
        ));
        assert!(route_event_requires_reconciliation(
            "RTM_CHANGE: Change Route: len 128, pid: 0, seq 0, errno 0, flags:<DONE>"
        ));
        assert!(route_event_requires_reconciliation(
            "RTM_IFINFO: Interface Status Changed: len 168, if# 6, flags:<UP,RUNNING>"
        ));
        assert!(route_event_requires_reconciliation(
            "RTM_IFANNOUNCE: Interface announce: len 96, if# 6, what: 0"
        ));
        assert!(route_event_requires_reconciliation(
            "RTM_NEWADDR: Interface address added: len 0"
        ));
        assert!(route_event_requires_reconciliation(
            "RTM_DELADDR: Interface address deleted: len 0"
        ));
        assert!(!route_event_requires_reconciliation(
            "RTM_MISS: Lookup failed on this address: len 120, pid: 0, seq 0"
        ));
        assert!(!route_event_requires_reconciliation(
            "got message of size 120"
        ));
    }

    #[test]
    fn route_event_pid_is_parsed() {
        assert_eq!(
            route_event_pid(
                "RTM_CHANGE: Change Route: len 132, pid: 86790, seq 1, errno 0"
            ),
            Some(86790)
        );
        assert_eq!(route_event_pid("RTM_CHANGE: no pid"), None);
    }

    #[test]
    fn physical_interface_requires_up_running_and_ipv4_when_required() {
        let ready = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet 192.168.50.30 netmask 0xffffff00 broadcast 192.168.50.255\n";
        let not_up = "en0: flags=863<BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet 192.168.50.30 netmask 0xffffff00 broadcast 192.168.50.255\n";
        let no_ipv4 = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n";

        assert!(interface_output_is_ready(ready, true));
        assert!(!interface_output_is_ready(not_up, false));
        assert!(interface_output_is_ready(no_ipv4, false));
        assert!(!interface_output_is_ready(no_ipv4, true));
        let not_associated = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLE,MULTICAST>\n\tstatus: associating\n\tinet 192.168.50.30\n";
        assert!(!interface_output_is_ready(not_associated, true));
    }
}

/// Run a `route` command, returning an error on non-zero exit.
///
/// Uses `status()` (not `output()`) so macOS uses `posix_spawn` instead of
/// `fork()+exec()`. `fork()` is O(RSS): it copies the entire page table even
/// though pages are copy-on-write. With hundreds of MB of RSS this makes each
/// command take 0.5-2s instead of ~1ms.
fn run_route_cmd(args: &[&str]) -> Result<(), String> {
    log::debug!("route {}", args.join(" "));
    let mut command = Command::new("route");
    command.args(args);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    record_route_command_pid(child.id());
    let status = child.wait().map_err(|e| e.to_string())?;
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
    let status = Command::new("pfctl")
        .args(args)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!(
            "pfctl {} failed (exit {})",
            args.join(" "),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Run a `networksetup` command and return stdout as a string.
fn run_networksetup_cmd(args: &[&str]) -> String {
    log::debug!("networksetup {}", args.join(" "));
    let output = Command::new("networksetup").args(args).output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => {
            log::warn!("networksetup {} failed: {e}", args.join(" "));
            String::new()
        },
    }
}

/// Get the IPv4 address of the primary physical interface (en0/en1/...).
fn get_en0_ipv4() -> Option<String> {
    let iface = default_physical_iface()?;
    let output = Command::new("ifconfig").args([&iface]).output().ok()?;
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
