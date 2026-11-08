#!/bin/bash
# Manually verify the macOS IPv6 leak guard (see tun/platform/macos.rs).
#
# Simulates an ISP handing out global IPv6 on the physical interface, then
# walks through the same reject routes anywhere installs, and finally starts
# anywhere so its own detection path can be observed in the log.
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
echo "=== 6. Full round-trip ==="
echo "Now launch anywhere normally. The log should show:"
echo "  macOS v6 leak guard: reject routes installed (::/1 + 8000::/1) ..."
echo "and on shutdown (or when the alias is removed + a route event fires):"
echo "  macOS v6 leak guard: reject routes removed"
echo ""
echo "Try: cargo run -p anywhere   (leave this script's cleanup running after)"
echo "Press Enter to continue, or Ctrl-C to abort."
read -r
