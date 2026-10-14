#!/bin/bash
# Launcher for the Linux release package (Linux twin of deploy/windows/start.bat).
#
# Unpack anywhere-v<version>-linux-<arch>-musl.tgz anywhere, cd into the
# resulting directory and run ./start.sh. Put a config.toml next to the
# binary, or point elsewhere with:  ./start.sh -c /path/to/config.toml
#
# Any extra arguments are forwarded to anywhere as-is.
set -uo pipefail

cd "$(dirname "$0")"

BIN="./anywhere"
LOG="anywhere.log"

export RUST_LOG="${RUST_LOG:-DEBUG}"

echo "Working directory: $(pwd)"
echo "RUST_LOG = $RUST_LOG"

# --- Check if the anywhere binary exists ---
if [[ ! -f "$BIN" ]]; then
    echo ""
    echo "ERROR: $BIN not found in $(pwd)"
    echo "  Extract the anywhere binary next to this script."
    exit 1
fi

# --- Check privileges ---
# tun inbound and the transparent-proxy iptables/nftables rules need root
# (CAP_NET_ADMIN + CAP_NET_RAW); without it those inbounds fail at startup.
if [[ "$(id -u)" -eq 0 ]]; then
    echo "Running as root."

    # Minimal images and containers can ship without the TUN node; same
    # fix-up as deploy/koolshare/anywhere.sh.
    if [[ ! -c /dev/net/tun ]]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200 || echo "  could not create /dev/net/tun"
    fi
else
    echo ""
    echo "Not running as root."
    echo "Use tun inbound / transparent proxy mode? (requires root)"
    echo "  [Y] Yes, restart with sudo"
    echo "  [N] No, continue without root"
    choice=N
    read -r -p "Select (y/N): " choice

    if [[ "$choice" =~ ^[Yy]$ ]]; then
        echo "Restarting with sudo..."
        exec sudo -E "$0" "$@"
    fi
    echo "Continuing without root privileges."
fi

echo ""
echo "Starting $BIN... (output -> $LOG)"
echo ""

# Unlike start.bat (double-click, console is disposable), this runs in a
# terminal, so tee keeps the log file *and* live output on screen.
"$BIN" "$@" 2>&1 | tee "$LOG"
status=${PIPESTATUS[0]}

echo ""
echo "$BIN exited with code $status."
exit "$status"
