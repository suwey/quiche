//! Pure-iphlpapi routing primitives for the Windows TUN.
//!
//! Replaces every former `route.exe` subprocess call: route installation and
//! removal go through the IP Helper v2 API (`MIB_IPFORWARD_ROW2` +
//! `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` / `GetIpForwardTable2`),
//! adapter resolution through `GetAdaptersAddresses`. No child processes, no
//! text parsing, no code-page surprises.
#![cfg(target_os = "windows")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetAdaptersAddresses, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
    SOCKADDR_INET,
};

/// Resolve an adapter's IfIndex by FriendlyName or Description
/// (case-insensitive: netsh accepts either name form). Returns None when no
/// adapter matches.
pub fn adapter_index_by_name(name: &str) -> Option<u32> {
    let want = name.to_lowercase();
    with_adapters(|a| {
        let friendly = pwstr_to_string(a.FriendlyName);
        let desc = pwstr_to_string(a.Description);
        if friendly.to_lowercase() == want || desc.to_lowercase() == want {
            // IfIndex lives in the struct arm of the Anonymous1 union
            // (Length/IfIndex), filled in on every adapter the API returns.
            Some(unsafe { a.Anonymous1.Anonymous.IfIndex })
        } else {
            None
        }
    })
}

/// Resolve an adapter's IfIndex by one of its unicast addresses.
///
/// This is the primary way to find the Wintun adapter: `tun_addr` is the
/// address we ourselves assigned to it, so the match cannot be thrown off by
/// naming. The `tun` crate does not configure a Wintun adapter name, so the
/// adapter's FriendlyName ends up being the crate default ("wintun"), not the
/// internal "tun0" label anywhere logs.
pub fn adapter_index_by_addr(addr: IpAddr) -> Option<u32> {
    with_adapters(|a| {
        let mut sa = a.FirstUnicastAddress;
        while !sa.is_null() {
            if let Some(ip) = socket_address_to_ip(unsafe { &*sa }) {
                if ip == addr {
                    return Some(unsafe { a.Anonymous1.Anonymous.IfIndex });
                }
            }
            sa = unsafe { (*sa).Next };
        }
        None
    })
}

/// Poll `f` until it returns `Some` or `timeout` elapses (200 ms steps).
///
/// WintunCreateAdapter returns before the adapter is fully visible to the IP
/// Helper API, so a freshly created adapter may miss the first enumeration.
fn poll_adapter<T, F>(timeout: std::time::Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Option<T>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Resolve the TUN adapter's IfIndex: by its own unicast address first, then
/// by name, polling for up to 3 s in total to absorb adapter-registration
/// latency right after WintunCreateAdapter.
pub fn find_tun_adapter(
    tun_addr: IpAddr, name: &str,
) -> Option<(u32, &'static str)> {
    poll_adapter(std::time::Duration::from_secs(3), || {
        adapter_index_by_addr(tun_addr).map(|i| (i, "address"))
    })
    .or_else(|| {
        poll_adapter(std::time::Duration::from_millis(200), || {
            adapter_index_by_name(name).map(|i| (i, "name"))
        })
    })
}

/// Install a route via iphlpapi v2 (`CreateIpForwardEntry2`). `next_hop` is
/// the TUN address. On failure returns the raw Win32 error code.
pub fn route_add(
    prefix: IpAddr, prefix_len: u8, iface_index: u32, next_hop: IpAddr,
) -> Result<(), u32> {
    // SAFETY: row is a fully initialized MIB_IPFORWARD_ROW2 (see forward_row).
    let err = unsafe {
        CreateIpForwardEntry2(&forward_row(
            prefix,
            prefix_len,
            iface_index,
            next_hop,
        ))
    };
    if err == NO_ERROR { Ok(()) } else { Err(err) }
}

/// Remove a route via iphlpapi v2 (`DeleteIpForwardEntry2`). A missing route
/// (`ERROR_NOT_FOUND`) is success: cleanup must stay idempotent.
pub fn route_delete(
    prefix: IpAddr, prefix_len: u8, iface_index: u32, next_hop: IpAddr,
) -> Result<(), u32> {
    // SAFETY: same row layout as route_add; the API matches by destination
    // prefix + interface, other fields are not dereferenced.
    let err = unsafe {
        DeleteIpForwardEntry2(&forward_row(
            prefix,
            prefix_len,
            iface_index,
            next_hop,
        ))
    };
    if err == NO_ERROR || err == ERROR_NOT_FOUND {
        Ok(())
    } else {
        Err(err)
    }
}

/// Delete every route of `family` whose destination prefix is in `prefixes`,
/// returning the number of rows actually removed. Mirrors the global
/// "route DELETE <prefix>" semantics of the old route.exe stale cleanup: all
/// matching rows go, not just the ones this process installed.
pub fn routes_delete_by_prefix(family: u16, prefixes: &[(IpAddr, u8)]) -> usize {
    if prefixes.is_empty() {
        return 0;
    }
    let mut deleted = 0;
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // GetIpForwardTable2 supports AF_INET/AF_INET6 only - what we pass.
        if GetIpForwardTable2(family, &mut table) != NO_ERROR || table.is_null() {
            return 0;
        }
        let rows = std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            (*table).NumEntries as usize,
        );
        for row in rows {
            let Some(dest) = sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix)
            else {
                continue;
            };
            let len = row.DestinationPrefix.PrefixLength;
            if !prefixes.iter().any(|(p, l)| *p == dest && *l == len) {
                continue;
            }
            // The row pointer points into the API-owned table, which is what
            // DeleteIpForwardEntry2 expects (const read, then delete by key).
            if DeleteIpForwardEntry2(row) == NO_ERROR {
                deleted += 1;
                log::debug!("Windows: removed stale TUN route {dest}/{len}");
            } else {
                log::debug!(
                    "Windows: stale TUN route {dest}/{len} not removable (already gone?)"
                );
            }
        }
        // The table buffer is heap-allocated by iphlpapi: always release it.
        FreeMibTable(table.cast());
    }
    deleted
}

/// Fill a `MIB_IPFORWARD_ROW2` for Create/DeleteIpForwardEntry2.
///
/// Must start from `Default::default()`: leftover garbage in the padding /
/// union fields makes the v2 API fail with ERROR_INVALID_PARAMETER. Known
/// trap: `SitePrefixLength` must be 0xFF - any "legal-looking" value also
/// yields ERROR_INVALID_PARAMETER.
fn forward_row(
    prefix: IpAddr, prefix_len: u8, iface_index: u32, next_hop: IpAddr,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // Key the row by interface index; InterfaceLuid stays 0.
    row.InterfaceIndex = iface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet(prefix),
        PrefixLength: prefix_len,
    };
    row.NextHop = sockaddr_inet(next_hop);
    row.SitePrefixLength = 0xFF;
    row.ValidLifetime = 0xFFFFFFFF; // infinite
    row.PreferredLifetime = 0xFFFFFFFF; // infinite
    row.Metric = 1;
    row.Protocol = MIB_IPPROTO_NETMGMT; // same protocol route.exe used
    row
}

/// Convert an `IpAddr` into a `SOCKADDR_INET` for the v2 route APIs.
fn sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(v4) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                // in_addr's S_addr holds the four octets in memory order
                // (network byte order): on little-endian Windows that is the
                // byte-swapped u32.
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_le_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(v6) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                // in6_addr's Byte arm is the octets in wire order, no swap.
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

/// Convert a `SOCKADDR_INET` from a forwarding-table row back to `IpAddr`.
/// Returns None for other address families.
fn sockaddr_inet_to_ip(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    Some(unsafe {
        match sa.si_family {
            AF_INET => {
                // Inverse of sockaddr_inet: the u32's little-endian bytes are
                // the four octets in wire order.
                IpAddr::V4(Ipv4Addr::from(
                    sa.Ipv4.sin_addr.S_un.S_addr.to_le_bytes(),
                ))
            },
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte)),
            _ => return None,
        }
    })
}

/// Convert a unicast-address entry's `SOCKET_ADDRESS` back to `IpAddr`.
/// Returns None for other address families or malformed sockaddr.
fn socket_address_to_ip(entry: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Option<IpAddr> {
    let sa = &entry.Address;
    if sa.lpSockaddr.is_null() || sa.iSockaddrLength < 4 {
        return None;
    }
    // SOCKADDR_INET shares the sockaddr layout: family at offset 0, then the
    // address; reading it as SOCKADDR_INET is the standard iphlpapi pattern.
    sockaddr_inet_to_ip(unsafe { &*(sa.lpSockaddr as *const SOCKADDR_INET) })
}

/// Walk the adapter list from `GetAdaptersAddresses` (AF_UNSPEC), growing the
/// buffer on `ERROR_BUFFER_OVERFLOW` (the API then reports the required size),
/// and invoke `f` on each adapter until it returns `Some`.
fn with_adapters<T>(
    mut f: impl FnMut(&IP_ADAPTER_ADDRESSES_LH) -> Option<T>,
) -> Option<T> {
    unsafe {
        // MSDN suggests a 15 KiB working buffer for the first call.
        let mut size: u32 = 15 * 1024;
        let mut attempts = 0;
        // Alignment matters: IP_ADAPTER_ADDRESSES_LH contains u64 fields, so
        // the backing buffer must be 8-byte aligned (a Vec<u8> is align-1).
        let mut buf: Vec<u64>;
        loop {
            buf = vec![0u64; (size as usize + 7) / 8];
            let ret = GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                0, // no GAA flags: FriendlyName + Description are populated
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            );
            if ret == NO_ERROR {
                break;
            }
            if ret != ERROR_BUFFER_OVERFLOW || attempts >= 3 {
                return None;
            }
            attempts += 1; // `size` now holds the required byte count
        }
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            if let Some(v) = f(&*adapter) {
                return Some(v);
            }
            // `Next` points inside the same buffer, valid until it is dropped.
            adapter = (*adapter).Next;
        }
        None
    }
}

/// Copy a NUL-terminated wide string (PWSTR field) into a Rust String.
fn pwstr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        // Length is counted in WCHARs (u16 units), not bytes.
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}
