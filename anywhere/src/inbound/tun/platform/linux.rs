//! Linux-specific TUN route management via rtnetlink.

use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dns::DNS_REDIRECT_PORT;

use super::bypass_watcher::BypassWatcherHandle;
use super::bypass_watcher::{self};
use super::run_cmd;

use rtnetlink::Handle;

/// Sentinel fwmark used on outbound sockets to bypass the TUN routing table.
/// Must match the value used in `setup_bypass_routing`.
pub const BYPASS_FWMARK: u32 = 0x1;

/// Routing table that holds the default route via the TUN interface for
/// policy-routed traffic. The kernel's main table is left untouched so
/// router daemons like wanduck (Asuswrt) don't trigger captive portal.
pub const TUN_ROUTING_TABLE: u32 = 200;

/// Priority of the catch-all policy rule that steers all traffic to the TUN
/// routing table. Must be above the kernel's default (32766 / main) and below
/// the DNS hijack rule (2500) and the bypass rule (100).
const TUN_CATCH_ALL_PRIO: u32 = 3000;

/// Priority of the exception rule that lets TUN handler responses (arriving
/// on the TUN interface) use the main routing table so they reach LAN.
const TUN_IIF_EXCEPTION_PRIO: u32 = 400;

/// Common teardown for routing rules. Used on normal shutdown (Drop).
///
/// WAN/LAN bypass rules are NOT touched here: the
/// `BypassWatcherHandle::shutdown_blocking` in `TunRouteManager::drop` removes
/// them precisely before this function runs.
/// When `iface_name` is `None`, interface-specific iptables rules are skipped.
fn teardown_routing(iface_name: Option<&str>) {
    // Policy routing rules & bypass — both families (the v6 deletes fail
    // harmlessly when the tunnel never had a v6 address).
    if let Err(e) =
        run_ip(&["rule", "del", "priority", &TUN_CATCH_ALL_PRIO.to_string()])
    {
        log::debug!("teardown: del catch-all rule failed: {e}");
    }
    if let Err(e) = run_ip(&[
        "rule",
        "del",
        "priority",
        &TUN_IIF_EXCEPTION_PRIO.to_string(),
    ]) {
        log::debug!("teardown: del iif exception rule failed: {e}");
    }
    if let Err(e) = run_ip(&[
        "-6",
        "rule",
        "del",
        "priority",
        &TUN_CATCH_ALL_PRIO.to_string(),
    ]) {
        log::debug!("teardown: del v6 catch-all rule failed: {e}");
    }
    if let Err(e) = run_ip(&[
        "-6",
        "rule",
        "del",
        "priority",
        &TUN_IIF_EXCEPTION_PRIO.to_string(),
    ]) {
        log::debug!("teardown: del v6 iif exception rule failed: {e}");
    }

    // Bypass fwmark rule & table 200 — only safe when the TUN device is about
    // to be deleted (Drop) or doesn't exist yet (startup cleanup).
    if let Err(e) = run_ip(&[
        "rule", "del", "fwmark", "1", "table", "100", "priority", "100",
    ]) {
        log::debug!("teardown: del fwmark rule failed: {e}");
    }
    if let Err(e) = run_ip(&[
        "-6",
        "rule",
        "del",
        "fwmark",
        "1",
        "table",
        "100",
        "priority",
        "100",
    ]) {
        log::debug!("teardown: del v6 fwmark rule failed: {e}");
    }
    if let Err(e) =
        run_ip(&["route", "flush", "table", &TUN_ROUTING_TABLE.to_string()])
    {
        log::debug!("teardown: flush table 200 failed: {e}");
    }
    if let Err(e) = run_ip(&[
        "-6",
        "route",
        "flush",
        "table",
        &TUN_ROUTING_TABLE.to_string(),
    ]) {
        log::debug!("teardown: flush v6 table 200 failed: {e}");
    }

    // Note: LAN mangle DNAT mark rules are removed by the BypassWatcher on
    // normal shutdown. On stale cleanup we cannot enumerate which LAN
    // interfaces were marked previously, so any leftover mangle rules from a
    // crash will accumulate -- they only fire on DNAT'd packets so duplicates
    // are harmless but should be cleaned manually if seen.

    // Interface-specific iptables (INPUT/FORWARD ACCEPT, POSTROUTING).
    if let Some(name) = iface_name {
        for chain in &["INPUT", "FORWARD"] {
            if let Err(e) =
                run_cmd("iptables", &["-D", chain, "-i", name, "-j", "ACCEPT"])
            {
                log::debug!(
                    "teardown: iptables -D {chain} -i {name} ACCEPT failed: {e}"
                );
            }
            if let Err(e) = run_cmd(
                "ip6tables",
                &["-D", chain, "-i", name, "-j", "ACCEPT"],
            ) {
                log::debug!(
                    "teardown: ip6tables -D {chain} -i {name} ACCEPT failed: {e}"
                );
            }
        }
        if let Err(e) =
            run_cmd("iptables", &["-D", "FORWARD", "-o", name, "-j", "ACCEPT"])
        {
            log::debug!(
                "teardown: iptables -D FORWARD -o {name} ACCEPT failed: {e}"
            );
        }
        if let Err(e) = run_cmd(
            "ip6tables",
            &["-D", "FORWARD", "-o", name, "-j", "ACCEPT"],
        ) {
            log::debug!(
                "teardown: ip6tables -D FORWARD -o {name} ACCEPT failed: {e}"
            );
        }
        if let Err(e) = run_cmd(
            "iptables",
            &["-t", "nat", "-D", "POSTROUTING", "-o", name, "-j", "ACCEPT"],
        ) {
            log::debug!(
                "teardown: iptables -t nat -D POSTROUTING -o {name} ACCEPT failed: {e}"
            );
        }
    }

    // IPv6 DNS REDIRECT rule (OUTPUT — local processes).
    if let Err(e) = run_cmd_args("ip6tables", &dns_redirect_args6(false)) {
        log::debug!("teardown: del v6 DNS OUTPUT redirect failed: {e}");
    }

    // DNS REDIRECT rules.
    if let Err(e) = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "mark",
            "!",
            "--mark",
            &BYPASS_FWMARK.to_string(),
            "-j",
            "REDIRECT",
            "--to-port",
            &DNS_REDIRECT_PORT.to_string(),
        ],
    ) {
        log::debug!("teardown: del DNS OUTPUT redirect failed: {e}");
    }
    if let Err(e) = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "REDIRECT",
            "--to-port",
            &DNS_REDIRECT_PORT.to_string(),
        ],
    ) {
        log::debug!("teardown: del DNS PREROUTING redirect failed: {e}");
    }
}

/// Clean up stale routing rules from a previous crash.
///
/// Must be called before any outbound DNS resolution happens (i.e. before
/// OutboundRegistry::from_config), so that DNS requests don't get routed
/// into a TUN device that isn't running yet.
///
/// This does a brute-force sweep of the priority ranges used by the watcher
/// (WAN/LAN from-rules: 150..180, LAN to-rules: 200..280) because after a crash
/// there is no watcher state to enumerate which interfaces had rules installed.
pub fn cleanup_stale_routing() {
    // Clean up bypass from-rules (priorities 150-179).
    for prio in 150u32..180u32 {
        let _ = run_ip(&["rule", "del", "priority", &prio.to_string()]);
    }
    // Clean up bypass to-rules (priorities 200-279).
    for prio in 200u32..280u32 {
        let _ = run_ip(&["rule", "del", "priority", &prio.to_string()]);
    }

    teardown_routing(None);
}

/// Manages Linux routing table entries for the TUN interface.
pub struct TunRouteManager {
    pub handle: Handle,
    pub link_index: u32,
    pub tun_addr: IpAddr,
    /// Secondary IPv6 address (`tun.addr6`, or `tun_addr` itself when it is
    /// an IPv6 CIDR). `None` keeps the tunnel v4-only — no v6 policy rules,
    /// so v6 traffic keeps using the main table and cannot leak into a TUN
    /// that would not carry it.
    pub v6_addr: Option<Ipv6Addr>,
    /// Prefix length for `v6_addr`.
    pub v6_prefix: u8,
    pub iface_name: String,
    /// Whether to install iptables rules and DNS redirect (auto-hijack mode).
    pub auto_hijack: bool,
    /// WAN interfaces to monitor dynamically. Only `from <wan_ip>` rules are
    /// installed for these interfaces.
    monitor_wan_ifaces: Vec<String>,
    /// LAN interfaces to install startup bypass rules for. These get `from`,
    /// `to <subnet>`, and mangle DNAT mark rules.
    bypass_lan_ifaces: Vec<String>,
    /// Handle to the bypass watcher task. Owns the lifecycle of all WAN/LAN
    /// bypass rules. `None` until `setup_routing` runs, or when both lists are
    /// empty.
    bypass_watcher: Option<BypassWatcherHandle>,
    /// Whether TUN capture rules (catch-all + iif exception) are installed.
    pub tun_capture: AtomicBool,
}

impl TunRouteManager {
    pub fn new(
        handle: Handle, link_index: u32, tun_addr: IpAddr,
        v6_addr: Option<Ipv6Addr>, v6_prefix: u8, iface_name: String,
        auto_hijack: bool, monitor_wan_ifaces: Vec<String>,
        bypass_lan_ifaces: Vec<String>,
    ) -> Self {
        Self {
            handle,
            link_index,
            tun_addr,
            v6_addr,
            v6_prefix,
            iface_name,
            auto_hijack,
            monitor_wan_ifaces,
            bypass_lan_ifaces,
            bypass_watcher: None,
            tun_capture: AtomicBool::new(false),
        }
    }

    /// Add the TUN IP address(es) to the interface and bring it up.
    pub async fn setup_interface(
        &self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prefix_len = if self.tun_addr.is_ipv4() { 24 } else { 64 };

        self.handle
            .address()
            .add(self.link_index, self.tun_addr, prefix_len)
            .replace()
            .execute()
            .await?;

        // Dual-stack: the v6 address comes from `tun.addr6` and is added as
        // a second interface address (the kernel then has an on-link route
        // for the fake-ip v6 pool's /64).
        if let Some(v6) = self.v6_addr {
            self.handle
                .address()
                .add(self.link_index, IpAddr::V6(v6), self.v6_prefix)
                .replace()
                .execute()
                .await?;
        }

        let msg = rtnetlink::LinkUnspec::new_with_index(self.link_index)
            .up()
            .build();
        self.handle.link().set(msg).execute().await?;

        // Set rp_filter to loose mode (2) globally. After setup_policy_routing
        // adds a default route via tun0 in the TUN routing table, strict mode (1)
        // would drop incoming packets on ppp0/eth0 because their source IPs
        // are no longer reachable via the receiving interface specifically.
        // Loose mode only requires reachability via ANY interface, which the
        // default route through tun0 satisfies.
        //
        // Mode 2 is the standard approach used by VPN/TUN software — it
        // prevents IP spoofing while tolerating asymmetric routing.
        // Setting conf/all is sufficient — the kernel uses max(conf/all, iface)
        // as the effective value for each interface.
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "2");

        match self.v6_addr {
            Some(v6) => {
                log::info!(
                    "TUN interface is up with addresses {} and [{v6}]",
                    self.tun_addr
                );
            },
            None => {
                log::info!("TUN interface is up with address {}", self.tun_addr);
            },
        }
        Ok(())
    }

    /// Configure all routing: bypass fwmark, policy routing, and optional
    /// router-specific iptables hacks. Both address families when the
    /// tunnel is dual-stack (`v6_addr` set); policy rules on Linux are
    /// family-scoped, so every rule exists twice (`ip rule` / `ip -6 rule`).
    ///
    /// When `auto_hijack` is true (default), also:
    ///   - Starts a DNS loopback listener (port 1053, redirected from 53 via
    ///     iptables so dnsmasq DHCP is untouched)
    ///   - Adds iptables ACCEPT rules so TUN traffic passes through the
    ///   - For each WAN interface in `monitor_wan_ifaces`, auto-discovers its
    ///     local IP and adds `from <wan_ip> lookup main`; these interfaces are
    ///     monitored for PPPoE redial/address changes
    ///   - For each LAN interface in `bypass_lan_ifaces`, auto-discovers its
    ///     IP/subnet at startup and adds `from <ip>` / `to <subnet>` rules plus
    ///     mangle DNAT mark so port-forwarded traffic bypasses TUN
    ///
    /// Set `auto_hijack = false` to leave routing completely unmodified
    /// (useful when the user manages routing externally).
    ///
    /// Rules installed (per enabled family):
    ///   priority  match              action
    ///      100    fwmark 0x1         lookup 100  (anywhere's own sockets)
    ///      150+   from <wan_ip>      lookup main (WAN monitor, v4 only)
    ///      150+   from <lan_ip>      lookup main (LAN bypass, v4 only)
    ///      200+   to <lan_subnet>    lookup main (LAN bypass, v4 only)
    ///      400    iif tun0           lookup main (TUN responses reach LAN)
    ///     3000    from all           lookup 200  (everything else → TUN)
    ///    32766    (built-in)         lookup main
    pub fn setup_routing(
        &mut self, auto_hijack: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // v4 half — only meaningful when the tunnel has a v4 address
        // (`refresh_policy_tables` builds table 200 from the TUN address's
        // family and would fail on a v6 destination under plain `ip route`).
        if self.tun_addr.is_ipv4() {
            run_ip(&[
                "rule", "add", "fwmark", "1", "table", "100", "priority", "100",
            ])?;

            refresh_policy_tables(self.tun_addr, &self.iface_name)?;

            log::info!("Bypass routing configured (fwmark 1 → table 100, v4)");
        }

        // v6 half — mirror of the v4 policy routing. Only installed when the
        // tunnel has a v6 address: without it the v6 catch-all rule would
        // steer v6 traffic into a tunnel that cannot carry it.
        if let Some(v6) = self.v6_addr {
            run_ip_args(&v6_rule_args(100, &["fwmark", "1", "table", "100"]))?;

            refresh_v6_policy_tables(v6, self.v6_prefix, &self.iface_name)?;

            log::info!("Bypass routing configured (fwmark 1 → table 100, v6)");
        }

        // --- policy routing: table 200 + rules ---
        log::info!(
            "Policy routing tables refreshed (table 100 bypass, table {} via {})",
            TUN_ROUTING_TABLE,
            self.iface_name
        );

        self.enable_tun_capture(auto_hijack)?;

        // --- router hacks (only when auto_hijack is true) ---
        if auto_hijack {
            // ACCEPT rules for the TUN interface — iptables always, ip6tables
            // when the tunnel carries v6 (otherwise the rules would never
            // match and only accumulate).
            let mut binaries: Vec<&str> = vec!["iptables"];
            if self.v6_addr.is_some() {
                binaries.push("ip6tables");
            }
            for binary in binaries {
                for chain in &["INPUT", "FORWARD"] {
                    if let Err(e) = run_cmd(
                        binary,
                        &[
                            "-I",
                            chain,
                            "1",
                            "-i",
                            &self.iface_name,
                            "-j",
                            "ACCEPT",
                        ],
                    ) {
                        log::error!(
                            "Failed to add {binary} -I {chain} ACCEPT for TUN interface {}: {e}. TUN traffic may be dropped by firewall.",
                            self.iface_name
                        );
                    }
                }
                if let Err(e) = run_cmd(
                    binary,
                    &[
                        "-I",
                        "FORWARD",
                        "1",
                        "-o",
                        &self.iface_name,
                        "-j",
                        "ACCEPT",
                    ],
                ) {
                    log::error!(
                        "Failed to add {binary} -I FORWARD -o {} ACCEPT: {e}. TUN outbound traffic may be dropped by firewall.",
                        self.iface_name
                    );
                }
            }
            if let Err(e) = run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-I",
                    "POSTROUTING",
                    "1",
                    "-o",
                    &self.iface_name,
                    "-j",
                    "ACCEPT",
                ],
            ) {
                log::error!(
                    "Failed to add iptables -t nat -I POSTROUTING ACCEPT for TUN interface {}: {e}. TUN traffic may not reach external networks.",
                    self.iface_name
                );
            }

            // --- Interface-based bypass routes ---
            // Spawn the BypassIfaceWatcher: it owns the lifecycle of all WAN
            // source-address rules and LAN bypass rules. WAN interfaces are
            // monitored dynamically (PPPoE redial/address changes); LAN rules
            // are installed during the initial snapshot and removed on
            // shutdown.
            //
            // Storing the handle on `self` (rather than spawning detached)
            // ensures Drop can synchronously block on rule cleanup.
            if !self.monitor_wan_ifaces.is_empty()
                || !self.bypass_lan_ifaces.is_empty()
            {
                let watcher_handle = bypass_watcher::spawn(
                    self.handle.clone(),
                    self.monitor_wan_ifaces.clone(),
                    self.bypass_lan_ifaces.clone(),
                    self.tun_addr,
                    self.iface_name.clone(),
                );
                self.bypass_watcher = Some(watcher_handle);
            }
        }

        Ok(())
    }

    /// Re-enable only the rules disabled by `disable_tun_capture`.
    /// Used when switching from direct mode back to rule/global mode.
    pub fn enable_tun_capture(
        &mut self, auto_hijack: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.tun_capture.load(Ordering::Acquire) {
            log::debug!("TUN capture already enabled, skipping");
            return Ok(());
        }

        // Delete first to make this robust against partial previous toggles.
        let _ = run_ip(&[
            "rule",
            "del",
            "priority",
            &TUN_IIF_EXCEPTION_PRIO.to_string(),
        ]);
        run_ip(&[
            "rule",
            "add",
            "priority",
            &TUN_IIF_EXCEPTION_PRIO.to_string(),
            "iif",
            &self.iface_name,
            "lookup",
            "main",
        ])?;

        let _ =
            run_ip(&["rule", "del", "priority", &TUN_CATCH_ALL_PRIO.to_string()]);
        run_ip(&[
            "rule",
            "add",
            "priority",
            &TUN_CATCH_ALL_PRIO.to_string(),
            "from",
            "all",
            "lookup",
            &TUN_ROUTING_TABLE.to_string(),
        ])?;

        // v6 mirror of the two capture rules — only when the tunnel carries
        // v6 (otherwise v6 traffic must keep using the main table).
        if self.v6_addr.is_some() {
            let _ = run_ip(&[
                "-6",
                "rule",
                "del",
                "priority",
                &TUN_IIF_EXCEPTION_PRIO.to_string(),
            ]);
            run_ip_args(&v6_rule_args(
                TUN_IIF_EXCEPTION_PRIO,
                &["iif", &self.iface_name, "lookup", "main"],
            ))?;

            let _ = run_ip(&[
                "-6",
                "rule",
                "del",
                "priority",
                &TUN_CATCH_ALL_PRIO.to_string(),
            ]);
            run_ip_args(&v6_rule_args(
                TUN_CATCH_ALL_PRIO,
                &["from", "all", "lookup", &TUN_ROUTING_TABLE.to_string()],
            ))?;
        }

        if auto_hijack {
            let _ = run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "OUTPUT",
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-m",
                    "mark",
                    "!",
                    "--mark",
                    &BYPASS_FWMARK.to_string(),
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    &DNS_REDIRECT_PORT.to_string(),
                ],
            );
            if let Err(e) = run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-I",
                    "OUTPUT",
                    "1",
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-m",
                    "mark",
                    "!",
                    "--mark",
                    &BYPASS_FWMARK.to_string(),
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    &DNS_REDIRECT_PORT.to_string(),
                ],
            ) {
                log::error!(
                    "Failed to redirect local DNS (53→{}): {e}",
                    DNS_REDIRECT_PORT
                );
            }

            // v6 mirror of the local DNS redirect. The REDIRECT lands on
            // ::1:1053, which is where `start_hijack_listener` binds a
            // dedicated listener on Linux. LAN-client v6 DNS is NOT
            // redirected (no PREROUTING rule): it flows into the TUN via
            // the policy rules above and is hijacked there by the
            // dst_port==53 check — same as queries to public v6 resolvers.
            if self.v6_addr.is_some() {
                let _ = run_cmd_args("ip6tables", &dns_redirect_args6(false));
                if let Err(e) =
                    run_cmd_args("ip6tables", &dns_redirect_args6(true))
                {
                    log::error!(
                        "Failed to redirect local v6 DNS (53→{}): {e}",
                        DNS_REDIRECT_PORT
                    );
                }
            }

            let _ = run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-m",
                    "addrtype",
                    "--dst-type",
                    "LOCAL",
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    &DNS_REDIRECT_PORT.to_string(),
                ],
            );
            if let Err(e) = run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-I",
                    "PREROUTING",
                    "1",
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-m",
                    "addrtype",
                    "--dst-type",
                    "LOCAL",
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    &DNS_REDIRECT_PORT.to_string(),
                ],
            ) {
                log::error!(
                    "Failed to redirect LAN client DNS (53→{}): {e}",
                    DNS_REDIRECT_PORT
                );
            }
        }

        self.tun_capture.store(true, Ordering::Release);
        Ok(())
    }

    /// Remove rules that direct traffic into the TUN interface.
    /// Safe to call when switching to direct mode — does NOT touch:
    ///   - fwmark bypass rule (outbound sockets still need table 100)
    ///   - table 100 / table 200 route contents
    ///   - iptables ACCEPT rules (INPUT/FORWARD, POSTROUTING)
    ///
    /// Rules removed:
    ///   priority 400  iif tun0           lookup main
    ///   priority 3000  from all           lookup 200
    ///   iptables -t nat -I OUTPUT ... DNS REDIRECT
    ///   iptables -t nat -I PREROUTING ... DNS REDIRECT
    pub fn disable_tun_capture(&mut self) {
        if !self.tun_capture.load(Ordering::Acquire) {
            log::debug!("TUN capture already disabled, skipping");
            return;
        }
        if let Err(e) =
            run_ip(&["rule", "del", "priority", &TUN_CATCH_ALL_PRIO.to_string()])
        {
            log::debug!("disable_tun_capture: del catch-all rule failed: {e}");
        }
        if let Err(e) = run_ip(&[
            "rule",
            "del",
            "priority",
            &TUN_IIF_EXCEPTION_PRIO.to_string(),
        ]) {
            log::debug!(
                "disable_tun_capture: del iif exception rule failed: {e}"
            );
        }

        // v6 mirror of the capture-rule deletes (harmless when absent).
        if let Err(e) = run_ip(&[
            "-6",
            "rule",
            "del",
            "priority",
            &TUN_CATCH_ALL_PRIO.to_string(),
        ]) {
            log::debug!(
                "disable_tun_capture: del v6 catch-all rule failed: {e}"
            );
        }
        if let Err(e) = run_ip(&[
            "-6",
            "rule",
            "del",
            "priority",
            &TUN_IIF_EXCEPTION_PRIO.to_string(),
        ]) {
            log::debug!(
                "disable_tun_capture: del v6 iif exception rule failed: {e}"
            );
        }

        // Remove DNS redirect so local processes can resolve directly.
        if let Err(e) = run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                "53",
                "-m",
                "mark",
                "!",
                "--mark",
                &BYPASS_FWMARK.to_string(),
                "-j",
                "REDIRECT",
                "--to-port",
                &DNS_REDIRECT_PORT.to_string(),
            ],
        ) {
            log::debug!(
                "disable_tun_capture: del DNS OUTPUT redirect failed: {e}"
            );
        }
        if let Err(e) = run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                "53",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "REDIRECT",
                "--to-port",
                &DNS_REDIRECT_PORT.to_string(),
            ],
        ) {
            log::debug!(
                "disable_tun_capture: del DNS PREROUTING redirect failed: {e}"
            );
        }
        // v6 mirror of the OUTPUT redirect delete (harmless when absent).
        if let Err(e) = run_cmd_args("ip6tables", &dns_redirect_args6(false)) {
            log::debug!(
                "disable_tun_capture: del v6 DNS OUTPUT redirect failed: {e}"
            );
        }
        self.tun_capture.store(false, Ordering::Release);
    }

    pub fn cleanup_routing(&mut self) {
        // Stop the bypass watcher first and synchronously wait for it to
        // remove every rule it installed.
        if let Some(mut watcher) = self.bypass_watcher.take() {
            watcher.shutdown_blocking();
        }
        self.disable_tun_capture();
    }
}

impl Drop for TunRouteManager {
    fn drop(&mut self) {
        self.cleanup_routing();
        // Full teardown including fwmark/DNS/table 200 — safe here because
        // the TUN device is about to be deleted, so no traffic can loop.
        teardown_routing(Some(&self.iface_name));

        let status = Command::new("ip")
            .args(["link", "delete", &self.iface_name])
            .status();
        match status {
            Ok(s) if s.success() => {
                log::info!("TUN interface {} deleted", self.iface_name);
            },
            Ok(s) => {
                log::warn!(
                    "Failed to delete TUN interface {} (exit {})",
                    self.iface_name,
                    s.code().unwrap_or(-1)
                );
            },
            Err(e) => {
                log::warn!("Failed to run ip link delete: {e}");
            },
        }
    }
}

/// Run an `ip` command, returning an error on non-zero exit.
pub(super) fn run_ip(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    super::run_cmd("ip", args)
}

/// Rebuild routing tables derived from the current main table.
///
/// Table 100 is used by fwmark-bypassed sockets and needs current main default
/// routes plus connected/special routes. Table 200 is the catch-all TUN table:
/// it keeps current non-default main routes so LAN/peer/special routes are not
/// swallowed by its `default dev tun0` route.
pub(super) fn refresh_policy_tables(
    tun_addr: IpAddr, tun_iface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = run_ip(&["route", "flush", "table", "100"]);
    let _ = run_ip(&["route", "flush", "table", &TUN_ROUTING_TABLE.to_string()]);

    // Copy default routes into table 100 for bypass.
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let mut found_default = false;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        found_default = true;
        let spec = line.strip_prefix("default ").unwrap_or(line);
        log::info!("Adding bypass route: default {spec} → table 100");
        add_default_route_for_table(spec, Some("100"))?;
    }
    if !found_default {
        log::warn!(
            "No default route in main table — bypass routing (table 100) \
             will NOT work. DoH and other bypass sockets will fail. \
             Ensure WAN interface is up before starting anywhere."
        );
    }

    copy_main_non_default_routes("100", false)?;

    let prefix_len = if tun_addr.is_ipv4() { 24 } else { 64 };
    let tun_net = match tun_addr {
        IpAddr::V4(a) => {
            let net = u32::from(a) & (!0u32 << (32 - prefix_len));
            IpAddr::V4(std::net::Ipv4Addr::from(net))
        },
        IpAddr::V6(a) => {
            let net = u128::from(a) & (!0u128 << (128 - prefix_len));
            IpAddr::V6(std::net::Ipv6Addr::from(net))
        },
    };

    let table = TUN_ROUTING_TABLE.to_string();
    run_ip(&[
        "route",
        "replace",
        &tun_net.to_string(),
        "dev",
        tun_iface,
        "table",
        &table,
    ])?;

    copy_main_non_default_routes(&table, false)?;

    run_ip(&[
        "route", "replace", "default", "dev", tun_iface, "table", &table,
    ])?;

    Ok(())
}

fn copy_main_non_default_routes(
    table: &str, v6: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let show_args: Vec<&str> = if v6 {
        vec!["-6", "route", "show", "table", "main"]
    } else {
        vec!["route", "show", "table", "main"]
    };
    let output = Command::new("ip").args(&show_args).output()?;
    let stdout = String::from_utf8(output.stdout)?;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("default ") {
            continue;
        }
        // `ip route show` flags a route whose nexthop device has no carrier
        // (a stopped docker0, a disconnected ethernet) with `linkdown`, and
        // `ip route replace` refuses to install it — skip instead of failing.
        if line.split_whitespace().any(|token| token == "linkdown") {
            log::debug!(
                "Skipping linkdown route for table {table}: {line}"
            );
            continue;
        }
        log::debug!("Copying route to table {table}: {line}");
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut args: Vec<&str> = if v6 {
            vec!["-6", "route", "replace", "table", table]
        } else {
            vec!["route", "replace", "table", table]
        };
        args.extend_from_slice(&tokens);
        if let Err(e) = run_ip(&args) {
            log::error!("Failed to copy route to table {table} (non-fatal): {e}");
        }
    }

    Ok(())
}

/// Add a default route with the given spec to a specific routing table.
///
/// `spec` is the part after "default " from `ip route show default`,
/// e.g. "via 125.121.62.193 dev ppp0". We split it by whitespace so each
/// token becomes a separate argument to `ip route`.
fn add_default_route_for_table(
    spec: &str, table: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    let mut args = vec!["route", "replace"];
    if let Some(t) = table {
        args.push("table");
        args.push(t);
    }
    args.push("default");
    args.extend_from_slice(&tokens);
    run_ip(&args)
}

/// [`run_ip`] for owned (String) argument lists.
fn run_ip_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ip(&refs)
}

/// [`super::run_cmd`] for owned (String) argument lists.
fn run_cmd_args(
    cmd: &str, args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    super::run_cmd(cmd, &refs)
}

/// `ip -6 rule add ... priority <prio> <spec…>` arguments — Linux policy
/// rules are family-scoped, so the v6 capture rules mirror the v4 ones with
/// the `-6` flag. Shared by setup/enable/teardown paths; unit tests pin the
/// exact shape.
fn v6_rule_args(priority: u32, spec: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = vec!["-6".into(), "rule".into(), "add".into()];
    args.extend(spec.iter().map(|s| s.to_string()));
    args.push("priority".into());
    args.push(priority.to_string());
    args
}

/// ip6tables arguments for the local-process DNS REDIRECT (OUTPUT: udp/53 →
/// `DNS_REDIRECT_PORT`, engine sockets excluded via the bypass fwmark).
/// `insert` picks `-I OUTPUT 1` (install) vs `-D OUTPUT` (remove); shared by
/// enable/disable paths so the two shapes stay in sync.
fn dns_redirect_args6(insert: bool) -> Vec<String> {
    let mut args: Vec<String> = vec!["-t".into(), "nat".into()];
    if insert {
        args.extend(["-I".into(), "OUTPUT".into(), "1".into()]);
    } else {
        args.extend(["-D".into(), "OUTPUT".into()]);
    }
    for token in [
        "-p", "udp", "--dport", "53", "-m", "mark", "!", "--mark",
    ] {
        args.push(token.to_string());
    }
    args.push(BYPASS_FWMARK.to_string());
    args.extend(["-j", "REDIRECT", "--to-port"].iter().map(|s| s.to_string()));
    args.push(DNS_REDIRECT_PORT.to_string());
    args
}

/// v6 mirror of [`refresh_policy_tables`]: table 100 gets the main table's
/// v6 defaults (for fwmark-bypassed sockets), table 200 gets the TUN subnet,
/// the main table's non-default v6 routes (so LAN/peer v6 subnets stay
/// reachable directly) and the default via the TUN device.
fn refresh_v6_policy_tables(
    v6_addr: Ipv6Addr, v6_prefix: u8, tun_iface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = run_ip(&["-6", "route", "flush", "table", "100"]);
    let _ = run_ip(&[
        "-6",
        "route",
        "flush",
        "table",
        &TUN_ROUTING_TABLE.to_string(),
    ]);

    // Copy v6 default routes into table 100 for bypass.
    let output =
        Command::new("ip").args(["-6", "route", "show", "default"]).output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let mut found_default = false;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        found_default = true;
        let spec = line.strip_prefix("default ").unwrap_or(line);
        log::info!("Adding v6 bypass route: default {spec} → table 100");
        let mut args = vec!["-6", "route", "replace", "table", "100"];
        args.push("default");
        args.extend(spec.split_whitespace());
        run_ip(&args)?;
    }
    if !found_default {
        log::warn!(
            "No v6 default route in main table — v6 bypass routing (table 100) \
             will NOT work. v6 outbound connections will fail. Ensure the WAN \
             interface has v6 connectivity before starting anywhere."
        );
    }

    copy_main_non_default_routes("100", true)?;

    let net = u128::from(v6_addr) & (!0u128 << (128 - v6_prefix));
    let tun_net = IpAddr::V6(std::net::Ipv6Addr::from(net));

    let table = TUN_ROUTING_TABLE.to_string();
    run_ip(&[
        "-6",
        "route",
        "replace",
        &tun_net.to_string(),
        "dev",
        tun_iface,
        "table",
        &table,
    ])?;

    copy_main_non_default_routes(&table, true)?;

    run_ip(&[
        "-6",
        "route",
        "replace",
        "default",
        "dev",
        tun_iface,
        "table",
        &table,
    ])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v6_rule_args_mirror_the_v4_capture_rules() {
        // The v6 policy rules are the v4 ones with `-6` prepended; the
        // priorities must stay identical so teardown by priority works for
        // both families.
        assert_eq!(
            v6_rule_args(
                TUN_CATCH_ALL_PRIO,
                &["from", "all", "lookup", &TUN_ROUTING_TABLE.to_string()],
            ),
            vec![
                "-6".to_string(),
                "rule".to_string(),
                "add".to_string(),
                "from".to_string(),
                "all".to_string(),
                "lookup".to_string(),
                "200".to_string(),
                "priority".to_string(),
                "3000".to_string(),
            ]
        );
        assert_eq!(
            v6_rule_args(TUN_IIF_EXCEPTION_PRIO, &["iif", "tun0", "lookup", "main"]),
            vec![
                "-6".to_string(),
                "rule".to_string(),
                "add".to_string(),
                "iif".to_string(),
                "tun0".to_string(),
                "lookup".to_string(),
                "main".to_string(),
                "priority".to_string(),
                "400".to_string(),
            ]
        );
    }

    #[test]
    fn v6_dns_redirect_args_are_symmetric_for_install_and_remove() {
        let install = dns_redirect_args6(true);
        let remove = dns_redirect_args6(false);

        // Install: ip6tables -t nat -I OUTPUT 1 <match> -j REDIRECT --to-port N
        // Remove:  ip6tables -t nat -D OUTPUT    <match> -j REDIRECT --to-port N
        // Identical apart from the operation — the delete must reference the
        // exact rule the insert created, otherwise stale rules accumulate.
        assert_eq!(install[2], "-I");
        assert_eq!(install[3], "OUTPUT");
        assert_eq!(install[4], "1");
        assert_eq!(&install[5..], &remove[3..]);

        // The match section mirrors the v4 rule: udp/53, fwmark bypass
        // excluded, REDIRECT to the loopback DNS port.
        let match_part = &remove[3..];
        let expected: Vec<String> = [
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "mark",
            "!",
            "--mark",
            "1",
            "-j",
            "REDIRECT",
            "--to-port",
            "1053",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(match_part, expected);
    }
}
