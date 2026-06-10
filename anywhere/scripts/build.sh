#!/bin/bash
# fingerprint-client build & capture helper
# Chrome fingerprint matching for QUIC TLS ClientHello
#
# Usage: run from anywhere, script auto-cds to workspace root

set -e

# cd to workspace root (one level up from this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# --- Build ---
cargo build -p anywhere
cargo zigbuild -p anywhere --target aarch64-unknown-linux-musl --release

echo ""
echo "== Build complete =="
echo ""

# --- Usage commands ---
echo "=== Full Chrome comparison workflow ==="
echo "# 1. Start capture"
echo "sudo tcpdump -i any -w chrome.pcap udp port 443"
echo "sudo tcpdump -i any -w client.pcap udp port 4433"
echo ""
echo "# 2. Open Chrome, navigate to https://cloudflare-quic.com"
echo ""
echo "# 3. Compare extension lists"
echo "tshark -r chrome.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extension.type | tr ',' '\n' | sort -n"
echo "tshark -r client.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extension.type | tr ',' '\n' | sort -n"
echo ""

echo "=== JA4 hash extraction ==="
echo "tshark -r capture.pcap -Y 'quic' -T fields -e ja4.q.quic"
echo ""

echo "- JA4 extension hash differs from Chrome due to:"
echo "  1. ECH (65037) - proxy server doesn't support ECH (structural difference)"
echo "  2. ALPS type number - BoringSSL uses 17513, Chrome uses 17613 (draft revision)"
echo "  3. Extension order affects JA3 but not JA4"
echo ""

echo "=== DNS force interface to tun ==="
echo "sudo resolvectl dns enp2s0 ''; sudo resolvectl dns tun0 1.1.1.1"
