#!/bin/bash
# Manually verify the macOS IPv6 behavior (see tun/platform/macos.rs).
#
# Simulates an ISP handing out global IPv6 on the physical interface, then
# walks through the same reject routes anywhere installs, prepares a
# dual-stack alias inside the fake-ip v6 pool for the fake-ip v6 end-to-end
# checklist, and finally starts anywhere so its own detection path can be
# observed in the log.
#
# Run with sudo (route/ifconfig need root):
#   sudo scripts/test_v6_leak_guard.sh [iface]     # default: en0

set -euo pipefail
IFACE="${1:-en0}"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run with sudo" >&2
    exit 1
fi

cleanup() {
    route -n delete -inet6 ::/1 2>/dev/null || true
    route -n delete -inet6 8000::/1 2>/dev/null || true
    ifconfig "$IFACE" inet6 2001:db8::1/64 -alias 2>/dev/null || true
    ifconfig lo0 inet6 fdfe:dcba:9876::1/64 -alias 2>/dev/null || true
    route -n delete -inet6 -net fdfe:dcba:9876::/64 2>/dev/null || true
    echo "=== cleanup done (alias + reject routes removed) ==="
}
trap cleanup EXIT

echo "=== 1. Simulate ISP global IPv6 on $IFACE (2001:db8:: is doc space) ==="
ifconfig "$IFACE" inet6 2001:db8::1/64 alias
ifconfig "$IFACE" | grep inet6

echo ""
echo "=== 2. Install the same reject routes anywhere installs ==="
route -n add -inet6 ::/1 -reject
route -n add -inet6 8000::/1 -reject

echo ""
echo "=== 3. Route table (expect two reject routes, more specific than /1 wins) ==="
netstat -rn -f inet6 | grep -E '::/1|8000::/1' || true

echo ""
echo "=== 4. Fail-fast check: v6 connect must error immediately (no leak, no hang) ==="
START=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(time.time()*1e9)')
if curl -6 -s --max-time 10 -o /dev/null 'http://[2400:3200::1]/' 2>/dev/null; then
    echo "UNEXPECTED: v6 connect succeeded — reject routes not effective!"
else
    END=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(time.time()*1e9)')
    echo "v6 connect failed as expected (fast-fail, took $(( (END-START)/1000000 ))ms — should be well under 1s)"
fi

echo ""
echo "=== 5. Link-local must still work (NDP table = local v6 services intact) ==="
ndp -a -n | head -5

echo ""
echo "=== 6. Fake-ip v6 end-to-end prep (dual-stack TUN simulation) ==="
# anywhere's fake-ip v6 pool (dns.fakeip_inet6_range, default
# fdfe:dcba:9876::/64) hands AAAA answers from this ULA /64; with
# tun.addr6 = "fdfe:dcba:9876::1/64" the tunnel interface itself owns ::1.
# Give lo0 that address so the host demonstrably accepts a dual-stack
# address inside the fake pool — the same shape a real TUN run produces.
ifconfig lo0 inet6 fdfe:dcba:9876::1/64 alias 2>/dev/null || \
    echo "NOTE: lo0 alias add failed (already present?)"
ifconfig lo0 | grep -F 'fdfe:dcba:9876' || true
netstat -rn -f inet6 | grep -F 'fdfe:dcba:9876' || true

# The alias installs a connected /64 route on lo0 — MORE specific than the
# ::/1 + 8000::/1 split routes anywhere installs, so it must NOT survive
# into a real anywhere run: fake-ip v6 packets would stay on lo0 instead of
# entering utun. Remove it right away; the script only proves the host
# accepts the pool address. The actual end-to-end run is anywhere's job
# (checklist below).
ifconfig lo0 inet6 fdfe:dcba:9876::1/64 -alias 2>/dev/null || true
route -n delete -inet6 -net fdfe:dcba:9876::/64 2>/dev/null || true
echo "lo0 alias removed again (its /64 route would shadow the TUN)."

echo ""
echo "Fake-ip v6 end-to-end checklist (requires anywhere run with tun.addr6):"
echo "  1. config: tun inbound addr6 = \"fdfe:dcba:9876::1/64\", dns fakeip on"
echo "     (defaults suffice; fakeip_inet6_range defaults to the same /64)"
echo "  2. start anywhere — the log shows the v6 address + ::/1 + 8000::/1 split"
echo "     routes on utun (the leak guard stays silent for dual-stack tunnels)"
echo "  3. dig AAAA <name> -> answer fdfe:dcba:9876::2+ (fake pool starts at ::2;"
echo "     ::1 is the TUN's own address)"
echo "  4. curl -6 --resolve <name>:443:[fdfe:dcba:9876::2] https://<name>/ ->"
echo "     the packet enters utun, the domain is restored from the fake-ip and"
echo "     proxied (v6 data plane)"
echo "  5. netstat -rn -f inet6 | grep utun -> ::/1 + 8000::/1 point at utun and"
echo "     NO fdfe:dcba:9876::/64 route sits on lo0 (this script removed it)"
echo "  6. after shutdown: no utun v6 routes remain"

echo ""
echo "=== 7. Full round-trip ==="
echo "Now launch anywhere normally. The log should show:"
echo "  macOS v6 leak guard: reject routes installed (::/1 + 8000::/1) ..."
echo "and on shutdown (or when the alias is removed + a route event fires):"
echo "  macOS v6 leak guard: reject routes removed"
echo "(with tun.addr6 configured for a dual-stack tunnel, the guard instead"
echo " backs off and the v6 split routes are installed on utun)"
echo ""
echo "Try: cargo run -p anywhere   (leave this script's cleanup running after)"
echo "Press Enter to continue, or Ctrl-C to abort."
read -r
