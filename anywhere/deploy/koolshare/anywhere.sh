#!/bin/bash
# =============================================
# anywhere.sh {start|stop|restart|status}
# UI: https://github.com/MetaCubeX/metacubexd/releases
# =============================================

ANYWHERE_DIR=$(cd $(dirname $0) && pwd)
cd $ANYWHERE_DIR
ANYWHERE_BIN="$ANYWHERE_DIR/anywhere"
LOG="$ANYWHERE_DIR/anywhere.log"

do_stop() {
    ps | grep 'anywhere -s' | grep -v grep | awk {'print $1F'} | xargs kill -INT
    echo "[anywhere] stopped at $(date "+%Y-%m-%d %H:%M:%S")."
}

do_start() {
    modprobe tun
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 666 /dev/net/tun

    # Increase fd limit — the default 1024 is too low for TUN + many UDP sessions.
    ulimit -n 65535

    echo "[anywhere] started at $(date "+%Y-%m-%d %H:%M:%S")."
    RUST_LOG=ERROR $ANYWHERE_BIN -s $0 > $LOG 2>&1
}

case "$1" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    restart)
        do_stop
        sleep 5
        do_start
        ;;
    status)
        ps | grep 'anywhere -s' | grep -v grep | awk {'print $1F'} | xargs -I {} cat /proc/{}/status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
