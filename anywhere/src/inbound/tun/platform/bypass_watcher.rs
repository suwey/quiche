//! Bypass interface watcher: owns the lifecycle of WAN/LAN bypass rules.
//!
//! For each WAN interface in `monitor_wan_ifaces`, installs and maintains:
//!   - `ip rule add from <wan_ip> lookup main priority 150+slot`
//!
//! For each LAN interface in `bypass_lan_ifaces`, installs at startup:
//!   - `ip rule add from <lan_ip> lookup main priority 150+slot`
//!   - `ip rule add to <lan_subnet> lookup main priority 200+slot`
//!   - `iptables -t mangle -I PREROUTING -i <iface> -m conntrack --ctstate DNAT
//!     -j MARK --set-mark 1`
//!
//! WAN interfaces are monitored dynamically because PPPoE interfaces (`ppp0`)
//! may come up long after `anywhere` starts or change address after redial.
//! LAN bypass rules are installed from the startup snapshot and cleaned up on
//! shutdown; LAN interface address changes are intentionally not monitored.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{
    self,
};

use futures_util::stream::StreamExt;
use rtnetlink::Handle;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::link::LinkFlags;
use rtnetlink::packet_route::link::LinkMessage;
use tokio::sync::oneshot;

use super::linux::BYPASS_FWMARK;
use super::linux::refresh_policy_tables;
use super::linux::run_ip;
use super::run_cmd;

/// Priority base for the per-interface `from <ip> lookup main` rules.
/// Slot `i` uses `FROM_PRIO_BASE + i`. Must match the range cleaned up by
/// `cleanup_stale_routing` (150..180) in `linux.rs`.
const FROM_PRIO_BASE: u32 = 150;
/// Priority base for the per-interface `to <subnet> lookup main` rules.
/// Slot `i` uses `TO_PRIO_BASE + i`. Must match the range cleaned up by
/// `cleanup_stale_routing` (200..280) in `linux.rs`.
const TO_PRIO_BASE: u32 = 200;

/// Maximum number of source-rule slots supported. WAN slots come first,
/// followed by LAN slots, so priorities stay deterministic across restarts.
const MAX_FROM_SLOTS: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Wan,
    Lan,
}

#[derive(Debug, Clone)]
struct InstalledRule {
    /// Interface name (e.g. "ppp0" or "br0").
    iface: String,
    /// Rule kind controls which kernel rules were installed.
    kind: RuleKind,
    /// IPv4 address used in the `from <ip>` rule.
    ip: Ipv4Addr,
    /// Subnet CIDR used in the `to <subnet>` rule for LAN rules.
    subnet: Option<String>,
    /// Priority of the `from` rule.
    from_prio: u32,
    /// Priority of the `to` rule for LAN rules.
    to_prio: Option<u32>,
}

/// Handle used to stop the watcher and wait for it to clean up.
pub struct BypassWatcherHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    done_rx: Option<Receiver<()>>,
}

impl BypassWatcherHandle {
    /// Signal the watcher to shut down and synchronously wait for it to
    /// finish removing all installed rules. Safe to call from `Drop` even
    /// when inside a tokio runtime, because the done channel uses
    /// `std::sync::mpsc` (true OS-level blocking, not tokio's fake one).
    pub fn shutdown_blocking(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(rx) = self.done_rx.take() {
            let _ = rx.recv();
        }
    }
}

/// Spawn the bypass interface watcher task.
///
/// `monitor_wan_ifaces` are watched for IPv4 address changes and get only
/// `from <wan_ip>` rules. `bypass_lan_ifaces` are installed from the startup
/// snapshot and get full LAN bypass rules.
pub fn spawn(
    handle: Handle, monitor_wan_ifaces: Vec<String>,
    bypass_lan_ifaces: Vec<String>, tun_addr: IpAddr, tun_iface: String,
) -> BypassWatcherHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    if monitor_wan_ifaces.is_empty() && bypass_lan_ifaces.is_empty() {
        let _ = done_tx.send(());
        return BypassWatcherHandle {
            shutdown_tx: Some(shutdown_tx),
            done_rx: Some(done_rx),
        };
    }

    let from_slots = monitor_wan_ifaces.len() + bypass_lan_ifaces.len();
    if from_slots as u32 > MAX_FROM_SLOTS {
        log::error!(
            "monitor_wan_ifaces + bypass_lan_ifaces has {from_slots} entries \
             but MAX_FROM_SLOTS is {MAX_FROM_SLOTS}; extra entries will be \
             ignored",
        );
    }

    tokio::spawn(async move {
        let mut state = WatcherState::new(
            monitor_wan_ifaces,
            bypass_lan_ifaces,
            tun_addr,
            tun_iface,
        );
        if let Err(e) = state.run(handle, shutdown_rx).await {
            log::error!("bypass iface watcher exited with error: {e}");
        }
        state.remove_all();
        let _ = done_tx.send(());
    });

    BypassWatcherHandle {
        shutdown_tx: Some(shutdown_tx),
        done_rx: Some(done_rx),
    }
}

// ---------------------------------------------------------------------------
// WatcherState — internal book-keeping
// ---------------------------------------------------------------------------

struct WatcherState {
    /// WAN interface names from config, indexed by WAN slot.
    monitor_wan_ifaces: Vec<String>,
    /// LAN interface names from config, indexed by LAN slot.
    bypass_lan_ifaces: Vec<String>,
    /// TUN address used when refreshing table 200.
    tun_addr: IpAddr,
    /// TUN interface name used when refreshing table 200.
    tun_iface: String,
    /// Currently installed rules, keyed by `kind:iface`. Updated whenever we
    /// install/remove rules so `remove_all` on shutdown is exact.
    installed: HashMap<String, InstalledRule>,
}

impl WatcherState {
    fn new(
        monitor_wan_ifaces: Vec<String>, bypass_lan_ifaces: Vec<String>,
        tun_addr: IpAddr, tun_iface: String,
    ) -> Self {
        Self {
            monitor_wan_ifaces,
            bypass_lan_ifaces,
            tun_addr,
            tun_iface,
            installed: HashMap::new(),
        }
    }

    fn key(kind: RuleKind, iface: &str) -> String {
        match kind {
            RuleKind::Wan => format!("wan:{iface}"),
            RuleKind::Lan => format!("lan:{iface}"),
        }
    }

    /// Return the source-rule slot (= priority offset) for an interface.
    fn from_slot_of(&self, kind: RuleKind, iface: &str) -> Option<u32> {
        match kind {
            RuleKind::Wan =>
                self.monitor_wan_ifaces.iter().position(|x| x == iface),
            RuleKind::Lan => self
                .bypass_lan_ifaces
                .iter()
                .position(|x| x == iface)
                .map(|pos| self.monitor_wan_ifaces.len() + pos),
        }
        .and_then(|pos| {
            let slot = pos as u32;
            if slot < MAX_FROM_SLOTS {
                Some(slot)
            } else {
                None
            }
        })
    }

    fn refresh_policy_tables(&self) {
        if let Err(e) = refresh_policy_tables(self.tun_addr, &self.tun_iface) {
            log::error!("failed to refresh policy routing tables: {e}");
        }
    }

    fn lan_to_slot_of(&self, iface: &str) -> Option<u32> {
        self.bypass_lan_ifaces
            .iter()
            .position(|x| x == iface)
            .map(|pos| pos as u32)
    }

    fn is_wan_iface(&self, iface: &str) -> bool {
        self.from_slot_of(RuleKind::Wan, iface).is_some()
    }

    /// Drive the snapshot + event loop. Returns when the shutdown channel
    /// fires or when the netlink connection terminates.
    async fn run(
        &mut self, handle: Handle, mut shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Snapshot existing links via shell commands (reliable on all
        //    kernels).
        self.snapshot().await;

        // 2. Open a multicast connection subscribed to link + IPv4 address
        //    events.
        let (conn, _evt_handle, mut messages) =
            rtnetlink::new_multicast_connection(&[
                MulticastGroup::Link,
                MulticastGroup::Ipv4Ifaddr,
            ])
            .map_err(|e| format!("netlink multicast bind failed: {e}"))?;
        tokio::spawn(conn);

        // 3. Event loop: re-evaluate state on every relevant rtnetlink event.
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    log::debug!("bypass watcher: shutdown signal received");
                    return Ok(());
                }
                msg = messages.next() => {
                    let Some((msg, _addr)) = msg else {
                        log::warn!(
                            "bypass watcher: netlink stream ended unexpectedly"
                        );
                        return Ok(());
                    };
                    self.handle_event(&handle, msg).await;
                }
            }
        }
    }

    /// Scan configured interfaces and reconcile installed rules with current
    /// state. Uses shell commands (`ip -o addr show dev`) for reliable
    /// operation on all kernels.
    async fn snapshot(&mut self) {
        let wan_ifaces = self.monitor_wan_ifaces.clone();
        for iface in wan_ifaces {
            self.snapshot_iface(RuleKind::Wan, &iface).await;
        }

        let lan_ifaces = self.bypass_lan_ifaces.clone();
        for iface in lan_ifaces {
            self.snapshot_iface(RuleKind::Lan, &iface).await;
        }
    }

    async fn snapshot_iface(&mut self, kind: RuleKind, iface: &str) {
        if self.from_slot_of(kind, iface).is_none() {
            return;
        }

        let output = match std::process::Command::new("ip")
            .args(["-o", "addr", "show", "dev", iface])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                log::error!(
                    "bypass_iface '{iface}': failed to run ip command: {e}"
                );
                return;
            },
        };

        let key = Self::key(kind, iface);
        if !output.status.success() {
            if self.installed.contains_key(&key) {
                log::error!(
                    "bypass_iface '{iface}': interface does not exist \
                     (check your config; common typo: 'wan0' is not a Linux \
                     interface name on Asuswrt -- use 'ppp0' or 'eth0' instead)"
                );
                self.remove_for(kind, iface);
            }
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut found_ip = None;
        for line in stdout.lines() {
            if let Some((ip, prefix)) = parse_inet_addr_line(line) {
                found_ip = Some((ip, prefix));
                break;
            }
        }

        match found_ip {
            Some((ip, prefix_len)) => {
                self.reconcile_iface(kind, iface, ip, prefix_len);
            },
            None =>
                if self.installed.contains_key(&key) {
                    log::info!(
                        "bypass_iface '{iface}': IPv4 address removed; \
                         removing bypass rules"
                    );
                    self.remove_for(kind, iface);
                    if kind == RuleKind::Wan {
                        self.refresh_policy_tables();
                    }
                },
        }
    }

    /// Process one rtnetlink event.
    async fn handle_event(
        &mut self, handle: &Handle, msg: NetlinkMessage<RouteNetlinkMessage>,
    ) {
        let NetlinkMessage { payload, .. } = msg;
        let inner = match payload {
            NetlinkPayload::InnerMessage(m) => m,
            _ => return,
        };
        match inner {
            RouteNetlinkMessage::NewAddress(m) => {
                self.on_addr_change(handle, m, true).await;
            },
            RouteNetlinkMessage::DelAddress(m) => {
                self.on_addr_change(handle, m, false).await;
            },
            RouteNetlinkMessage::NewLink(m) => {
                self.on_link_change(handle, m).await;
            },
            RouteNetlinkMessage::DelLink(m) => {
                let ifindex = m.header.index;
                let name = ifname_from_link(&m);
                if let Some(name) = name {
                    let key = Self::key(RuleKind::Wan, &name);
                    if self.installed.contains_key(&key) {
                        log::info!(
                            "bypass_iface '{name}' (ifindex {ifindex}): link \
                             removed; removing bypass rules"
                        );
                        self.remove_for(RuleKind::Wan, &name);
                        self.refresh_policy_tables();
                    }
                }
            },
            _ => {},
        }
    }

    /// Handle a NewAddress / DelAddress event. Only WAN interfaces are dynamic;
    /// LAN rules are snapshot-only.
    async fn on_addr_change(
        &mut self, handle: &Handle, m: AddressMessage, is_new: bool,
    ) {
        let family: u8 = m.header.family.into();
        if family != 2 {
            return;
        }

        let ifindex = m.header.index;
        let Some(name) = ifname_for_ifindex(handle, ifindex).await else {
            return;
        };
        if !self.is_wan_iface(&name) {
            return;
        }

        let mut new_ip: Option<Ipv4Addr> = None;
        for attr in &m.attributes {
            if let AddressAttribute::Address(IpAddr::V4(v4)) = attr {
                new_ip = Some(*v4);
                break;
            }
        }

        if is_new {
            let Some(ip) = new_ip else { return };
            self.reconcile_iface(RuleKind::Wan, &name, ip, m.header.prefix_len);
        } else {
            let key = Self::key(RuleKind::Wan, &name);
            if let Some(cur) = self.installed.get(&key) &&
                let Some(removed) = new_ip &&
                cur.ip == removed
            {
                log::info!(
                    "bypass_iface '{name}': address {removed} removed; \
                     removing bypass rules"
                );
                self.remove_for(RuleKind::Wan, &name);
                self.refresh_policy_tables();
            }
        }
    }

    /// Handle a NewLink event. Only WAN interfaces are dynamic.
    async fn on_link_change(&mut self, _handle: &Handle, m: LinkMessage) {
        let ifindex = m.header.index;
        let Some(name) = ifname_from_link(&m) else {
            return;
        };
        if !self.is_wan_iface(&name) {
            return;
        }

        let key = Self::key(RuleKind::Wan, &name);
        let is_up = m.header.flags.contains(LinkFlags::Up);
        if !is_up && self.installed.contains_key(&key) {
            log::info!(
                "bypass_iface '{name}' (ifindex {ifindex}): interface went \
                 down; removing bypass rules"
            );
            self.remove_for(RuleKind::Wan, &name);
            self.refresh_policy_tables();
        }
    }

    /// Idempotently install rules for `iface` with the given address. If the
    /// iface already has rules with a different IP/subnet, remove the old ones
    /// first.
    fn reconcile_iface(
        &mut self, kind: RuleKind, iface: &str, ip: Ipv4Addr, prefix_len: u8,
    ) {
        let Some(from_slot) = self.from_slot_of(kind, iface) else {
            return;
        };
        let key = Self::key(kind, iface);
        let subnet = (kind == RuleKind::Lan).then(|| subnet_cidr(ip, prefix_len));
        let from_prio = FROM_PRIO_BASE + from_slot;
        let to_prio = match kind {
            RuleKind::Wan => None,
            RuleKind::Lan =>
                self.lan_to_slot_of(iface).map(|slot| TO_PRIO_BASE + slot),
        };

        if let Some(cur) = self.installed.get(&key) &&
            cur.ip == ip &&
            cur.subnet == subnet
        {
            return;
        }

        if self.installed.contains_key(&key) {
            self.remove_for(kind, iface);
        }

        if let Err(e) = install_from_rule(ip, from_prio) {
            log::error!(
                "bypass_iface '{iface}': failed to add from-rule for {ip} \
                 (prio {from_prio}): {e}"
            );
            return;
        }

        if let RuleKind::Lan = kind {
            let Some(ref subnet) = subnet else {
                let _ = uninstall_rule(from_prio);
                return;
            };
            let Some(to_prio) = to_prio else {
                let _ = uninstall_rule(from_prio);
                return;
            };
            if let Err(e) = install_to_rule(subnet, to_prio) {
                log::error!(
                    "bypass_iface '{iface}': failed to add to-rule for {subnet} \
                     (prio {to_prio}): {e}"
                );
                let _ = uninstall_rule(from_prio);
                return;
            }
            if let Err(e) = install_mangle_rule(iface) {
                log::error!(
                    "bypass_iface '{iface}': failed to add mangle DNAT mark \
                     rule: {e}"
                );
                let _ = uninstall_rule(from_prio);
                let _ = uninstall_rule(to_prio);
                return;
            }
            log::info!(
                "bypass_lan_iface '{iface}': installed rules (from {ip} prio \
                 {from_prio}, to {subnet} prio {to_prio}, mangle -i {iface} \
                 ctstate DNAT)"
            );
        } else {
            log::info!(
                "monitor_wan_iface '{iface}': installed from-rule for {ip} \
                 prio {from_prio}"
            );
            self.refresh_policy_tables();
        }

        self.installed.insert(key, InstalledRule {
            iface: iface.to_string(),
            kind,
            ip,
            subnet,
            from_prio,
            to_prio,
        });
    }

    /// Remove the rules currently installed for `iface` (if any).
    fn remove_for(&mut self, kind: RuleKind, iface: &str) {
        let key = Self::key(kind, iface);
        let Some(rule) = self.installed.remove(&key) else {
            return;
        };
        let _ = uninstall_rule(rule.from_prio);
        if let Some(to_prio) = rule.to_prio {
            let _ = uninstall_rule(to_prio);
        }
        if rule.kind == RuleKind::Lan {
            let _ = uninstall_mangle_rule(&rule.iface);
        }
    }

    /// Remove every rule we installed. Called on shutdown so that the kernel
    /// state is left clean even if the broader teardown skips us.
    fn remove_all(&mut self) {
        let installed: Vec<(RuleKind, String)> = self
            .installed
            .values()
            .map(|rule| (rule.kind, rule.iface.clone()))
            .collect();
        for (kind, iface) in installed {
            self.remove_for(kind, &iface);
        }
    }
}

// ---------------------------------------------------------------------------
// Rule install / uninstall helpers — thin wrappers over `ip` and `iptables`
// ---------------------------------------------------------------------------

fn install_from_rule(
    ip: Ipv4Addr, prio: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip_s = ip.to_string();
    let prio_s = prio.to_string();
    run_ip(&[
        "rule", "add", "from", &ip_s, "lookup", "main", "priority", &prio_s,
    ])
}

fn install_to_rule(
    subnet: &str, prio: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let prio_s = prio.to_string();
    run_ip(&[
        "rule", "add", "to", subnet, "lookup", "main", "priority", &prio_s,
    ])
}

fn install_mangle_rule(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    let fwmark = BYPASS_FWMARK.to_string();
    run_cmd("iptables", &[
        "-t",
        "mangle",
        "-I",
        "PREROUTING",
        "1",
        "-i",
        iface,
        "-m",
        "conntrack",
        "--ctstate",
        "DNAT",
        "-j",
        "MARK",
        "--set-mark",
        &fwmark,
    ])
}

fn uninstall_rule(prio: u32) -> Result<(), Box<dyn std::error::Error>> {
    let prio_s = prio.to_string();
    run_ip(&["rule", "del", "priority", &prio_s])
}

fn uninstall_mangle_rule(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    let fwmark = BYPASS_FWMARK.to_string();
    run_cmd("iptables", &[
        "-t",
        "mangle",
        "-D",
        "PREROUTING",
        "-i",
        iface,
        "-m",
        "conntrack",
        "--ctstate",
        "DNAT",
        "-j",
        "MARK",
        "--set-mark",
        &fwmark,
    ])
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up an interface name by ifindex via `ip -o link` (shell command).
///
/// Uses shell instead of netlink unicast because the latter can hang on older
/// kernels (e.g. Asuswrt-Merlin 4.1.27). This is consistent with how
/// `snapshot()` gets interface info.
async fn ifname_for_ifindex(_handle: &Handle, ifindex: u32) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-o", "link"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefix = format!("{ifindex}:");
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            let name = rest.split(':').next()?.trim().to_string();
            return Some(name);
        }
    }
    None
}

/// Pull `IFLA_IFNAME` out of a LinkMessage's attribute list.
fn ifname_from_link(m: &LinkMessage) -> Option<String> {
    for attr in &m.attributes {
        if let LinkAttribute::IfName(n) = attr {
            return Some(n.clone());
        }
    }
    None
}

/// Parse one `ip -o addr show dev <iface>` output line.
///
/// BusyBox/iproute variants differ for PPP peer addresses: regular interfaces
/// usually report `inet 192.168.50.1/24`, while PPP may report
/// `inet 122.234.133.166 peer 122.234.133.129/32` with no prefix on the local
/// address token. In the PPP form the peer token carries the interface prefix;
/// for routing bypass purposes that is the local address prefix too.
fn parse_inet_addr_line(line: &str) -> Option<(Ipv4Addr, u8)> {
    let mut fields = line.split_whitespace();
    let _index = fields.next()?;
    let _name = fields.next()?;
    if fields.next()? != "inet" {
        return None;
    }

    let addr = fields.next()?;
    if let Some((ip, prefix)) = parse_ipv4_with_prefix(addr) {
        return Some((ip, prefix));
    }

    let ip = addr.parse::<Ipv4Addr>().ok()?;
    while let Some(field) = fields.next() {
        if field != "peer" {
            continue;
        }
        let peer = fields.next()?;
        let (_, prefix) = peer.split_once('/')?;
        return Some((ip, prefix.parse::<u8>().ok()?));
    }

    None
}

fn parse_ipv4_with_prefix(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = value.split_once('/')?;
    Some((ip.parse().ok()?, prefix.parse().ok()?))
}

/// Compute the subnet CIDR (network address + prefix) from an IPv4 address
/// and prefix length. e.g. `(192.168.50.1, 24) -> "192.168.50.0/24"`.
fn subnet_cidr(ip: Ipv4Addr, prefix: u8) -> String {
    let ip_u32 = u32::from(ip);
    let mask = if prefix >= 32 {
        !0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let net = Ipv4Addr::from(ip_u32 & mask);
    format!("{net}/{prefix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_cidr_basic() {
        assert_eq!(
            subnet_cidr(Ipv4Addr::new(192, 168, 50, 1), 24),
            "192.168.50.0/24"
        );
        assert_eq!(
            subnet_cidr(Ipv4Addr::new(36, 22, 240, 253), 32),
            "36.22.240.253/32"
        );
        assert_eq!(subnet_cidr(Ipv4Addr::new(10, 0, 0, 5), 8), "10.0.0.0/8");
    }

    #[test]
    fn parse_inet_addr_line_handles_regular_cidr() {
        assert_eq!(
            parse_inet_addr_line(
                "19: br0    inet 192.168.50.1/24 brd 192.168.50.255 scope \
                 global br0",
            ),
            Some((Ipv4Addr::new(192, 168, 50, 1), 24)),
        );
    }

    #[test]
    fn parse_inet_addr_line_handles_ppp_peer_prefix() {
        assert_eq!(
            parse_inet_addr_line(
                "20: ppp0    inet 122.234.133.166 peer 122.234.133.129/32 \
                 brd 122.234.133.166 scope global ppp0",
            ),
            Some((Ipv4Addr::new(122, 234, 133, 166), 32)),
        );
    }
}
