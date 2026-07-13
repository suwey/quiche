//! TCP NAT port mapping table for TUN transparent proxy.
//!
//! Maintains a mapping between allocated NAT ports (10000–65535) and
//! (client_addr, target_addr) pairs. Lookups are O(1) via HashMap.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

/// A NAT session entry.
#[derive(Debug, Clone)]
pub struct TCPSession {
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub last_activity: Instant,
}

/// TCP NAT table.
pub struct TCPNat {
    /// NAT port → session
    port_map: HashMap<u16, TCPSession>,
    /// (client_ip, client_port) → NAT port (for reusing existing mappings)
    addr_map: HashMap<(SocketAddr, SocketAddr), u16>,
    /// Next NAT port to try
    next_port: u16,
    /// Idle timeout
    timeout: Duration,
    /// FIFO queue tracking port allocation order. When all ports are occupied,
    /// the front of this queue is evicted in O(1) instead of scanning all 55K
    /// entries with `min_by_key`.
    allocation_order: VecDeque<u16>,
}

impl TCPNat {
    const NAT_PORT_START: u16 = 10000;

    pub fn new(timeout: Duration) -> Self {
        Self {
            port_map: HashMap::new(),
            addr_map: HashMap::new(),
            next_port: Self::NAT_PORT_START,
            timeout,
            allocation_order: VecDeque::with_capacity(55536), // 10000..=65535
        }
    }

    /// Look up or allocate a NAT port for the given (client, target) tuple.
    ///
    /// Returns the NAT port. If a mapping already exists for this (client,
    /// target) pair, returns the existing port and updates the activity
    /// timestamp.
    pub fn lookup(
        &mut self, client_addr: SocketAddr, target_addr: SocketAddr,
    ) -> u16 {
        let key = (client_addr, target_addr);

        // Reuse existing mapping.
        if let Some(&port) = self.addr_map.get(&key) {
            if let Some(session) = self.port_map.get_mut(&port) {
                session.last_activity = Instant::now();
            }
            return port;
        }

        // Allocate new port.
        let port = self.allocate_port();
        let session = TCPSession {
            client_addr,
            target_addr,
            last_activity: Instant::now(),
        };
        self.port_map.insert(port, session);
        self.addr_map.insert(key, port);
        self.allocation_order.push_back(port);
        port
    }

    /// Reverse lookup: given a NAT port, return the session.
    pub fn lookup_back(&self, nat_port: u16) -> Option<&TCPSession> {
        self.port_map.get(&nat_port)
    }

    /// Return whether a NAT port is still mapped.
    pub fn contains_port(&self, nat_port: u16) -> bool {
        self.port_map.contains_key(&nat_port)
    }

    /// Refresh a NAT port's activity timestamp.
    pub fn touch_by_port(&mut self, nat_port: u16) -> bool {
        if let Some(session) = self.port_map.get_mut(&nat_port) {
            session.last_activity = Instant::now();
            true
        } else {
            false
        }
    }

    /// Remove a session by NAT port.
    pub fn remove(&mut self, nat_port: u16) {
        if let Some(session) = self.port_map.remove(&nat_port) {
            self.addr_map
                .remove(&(session.client_addr, session.target_addr));
        }
    }

    /// Remove all expired sessions and return their NAT ports.
    pub fn cleanup_expired(&mut self) -> Vec<u16> {
        let now = Instant::now();
        let timeout = self.timeout;
        let expired: Vec<u16> = self
            .port_map
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_activity) > timeout)
            .map(|(&p, _)| p)
            .collect();

        for &port in &expired {
            self.remove(port);
        }

        expired
    }

    /// Allocate the next NAT port, wrapping around if needed.
    ///
    /// Under normal load (ports available), this is O(1) — just advance
    /// `next_port` and check if the port is free.
    ///
    /// When all 55536 ports are occupied, evicts the oldest session in O(1)
    /// by popping from the front of `allocation_order` (FIFO queue), avoiding
    /// the O(n) `min_by_key` scan over all entries.
    fn allocate_port(&mut self) -> u16 {
        let start = self.next_port;
        loop {
            let port = self.next_port;
            self.next_port = if port == 65535 {
                Self::NAT_PORT_START
            } else {
                port + 1
            };

            if !self.port_map.contains_key(&port) {
                return port;
            }

            // All ports in range are occupied — evict oldest via FIFO queue.
            if self.next_port == start {
                // Drain stale entries (ports freed by cleanup/remove that
                // weren't popped from the queue). Since remove() doesn't
                // touch allocation_order, stale entries accumulate and are
                // lazily skipped here.
                while let Some(oldest) = self.allocation_order.pop_front() {
                    if self.port_map.contains_key(&oldest) {
                        self.remove(oldest);
                        return oldest;
                    }
                }
                // allocation_order is never empty when port_map is full:
                // every lookup() push_backs, and remove() never pops, so
                // allocation_order.len() >= port_map.len() always.
                unreachable!("allocation_order empty but port_map full");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;

    fn sa(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    }

    #[test]
    fn test_lookup_allocates_new_port() {
        let mut nat = TCPNat::new(Duration::from_secs(30));
        let client = sa([192, 168, 1, 100], 40000);
        let target = sa([1, 2, 3, 4], 80);

        let port = nat.lookup(client, target);
        assert!(port >= 10000);

        let session = nat.lookup_back(port).unwrap();
        assert_eq!(session.client_addr, client);
        assert_eq!(session.target_addr, target);
    }

    #[test]
    fn test_lookup_reuses_existing() {
        let mut nat = TCPNat::new(Duration::from_secs(30));
        let client = sa([192, 168, 1, 100], 40000);
        let target = sa([1, 2, 3, 4], 80);

        let port1 = nat.lookup(client, target);
        let port2 = nat.lookup(client, target);
        assert_eq!(port1, port2);
    }

    #[test]
    fn test_cleanup_removes_expired() {
        let mut nat = TCPNat::new(Duration::from_millis(1));
        let client = sa([192, 168, 1, 100], 40000);
        let target = sa([1, 2, 3, 4], 80);

        nat.lookup(client, target);
        assert_eq!(nat.port_map.len(), 1);

        std::thread::sleep(Duration::from_millis(5));
        let _ = nat.cleanup_expired();
        assert_eq!(nat.port_map.len(), 0);
    }

    #[test]
    fn test_lookup_back_nonexistent() {
        let nat = TCPNat::new(Duration::from_secs(30));
        assert!(nat.lookup_back(9999).is_none());
    }

    #[test]
    fn test_contains_port_tracks_remove() {
        let mut nat = TCPNat::new(Duration::from_secs(30));
        let client = sa([192, 168, 1, 100], 40000);
        let target = sa([1, 2, 3, 4], 80);
        let port = nat.lookup(client, target);

        assert!(nat.contains_port(port));
        nat.remove(port);
        assert!(!nat.contains_port(port));
    }

    #[test]
    fn test_touch_by_port_keeps_session_alive() {
        let mut nat = TCPNat::new(Duration::from_millis(100));
        let client = sa([192, 168, 1, 100], 40000);
        let target = sa([1, 2, 3, 4], 80);
        let port = nat.lookup(client, target);

        std::thread::sleep(Duration::from_millis(30));
        assert!(nat.touch_by_port(port));
        std::thread::sleep(Duration::from_millis(50));

        assert!(nat.cleanup_expired().is_empty());
        assert!(nat.contains_port(port));
    }

    #[test]
    fn test_cleanup_expired_returns_ports() {
        let mut nat = TCPNat::new(Duration::from_millis(1));
        let client = sa([192, 168, 1, 100], 40000);
        let target = sa([1, 2, 3, 4], 80);
        let port = nat.lookup(client, target);

        std::thread::sleep(Duration::from_millis(5));

        assert_eq!(nat.cleanup_expired(), vec![port]);
        assert!(!nat.contains_port(port));
    }
}
