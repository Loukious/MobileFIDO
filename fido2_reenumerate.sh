#!/system/bin/sh
#
# fido2_reenumerate.sh -- phone-side attempt at a USB re-enumeration test.
#
# ===========================================================================
# THIS DOES NOT WORK ON THIS DEVICE, AND ITS "PASS" IS MEANINGLESS.
# ===========================================================================
#
# Kept only as the record of an attempt. The vendor USB HAL watches the gadget
# and re-binds the UDC within well under a second, so `echo none > UDC` never
# takes effect: eight consecutive attempts all read back bound, and /dev/hidg2
# never disappears. The gadget is therefore never torn down, the server never
# sees a disconnect, and the pid-unchanged check below passes vacuously --
# it proves the server survived a re-enumeration that did not happen.
#
# Re-enumeration is tested from the host side instead (restarting the
# composite device on Windows), which is what actually happens in the field.
# See README-milestone2.md, "Re-enumeration: what was and was not testable".
#
# ===========================================================================
#
# The intended design, had the unbind worked: the server must notice the gadget
# vanish, invalidate every channel (the host's view of the connection is gone,
# so its channel numbers are meaningless), rediscover the device -- possibly at
# a different /dev/hidgN -- and carry on, all without being restarted. The pid
# is checked before and after for that reason.
#
# This would be the single deliberate exception to "do not rebind the gadget".
# It changes nothing: no descriptor, no link, no identity is touched.

set -u

CFG=/config/usb_gadget/g1
CHROOT=/data/local/nhsystem/kali-arm64
LOG=$CHROOT/root/ctaphid.log
OUT=$CHROOT/root/reenumerate.log
OUT_DIR=$(dirname "$OUT")

log() { echo "$(date '+%H:%M:%S') $*" >> "$OUT"; }

snapshot() {
    _udc=$(cat $CFG/UDC 2>/dev/null)
    _vid=$(cat $CFG/idVendor 2>/dev/null)
    _pid=$(cat $CFG/idProduct 2>/dev/null)
    _links=$(ls $CFG/configs/b.1/ 2>/dev/null | grep '^function' | sort | tr '\n' ' ')
    _lens=""
    for h in hid.0 hid.1 hid.2; do
        _lens="$_lens$h=$(cat $CFG/functions/$h/report_length 2>/dev/null) "
    done
    _node=$(ls -l /dev/hidg* 2>/dev/null | tr -s ' ' | tr '\n' ';')
    _srv=$(for f in $(grep -l ctaphid.server /proc/[0-9]*/cmdline 2>/dev/null); do
               p=${f#/proc/}; p=${p%/cmdline}
               a=$( { tr '\0' ' ' < "$f"; } 2>/dev/null )
               case "${a%% *}" in */python3|*/python3.*) echo "$p" ;; esac
           done | head -n 1)
}

[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }

mkdir -p "$OUT_DIR"
: > "$OUT"

# Keep the watchdog machinery unaware of us: this test does not change config,
# so nothing needs reverting. Only the UDC is cycled.
log "=== CTAPHID re-enumeration test ==="

log "--- before ---"
snapshot
log "UDC=$_udc VID=$_vid PID=$_pid"
log "links: $_links"
log "report_length: $_lens"
log "nodes: $_node"
log "server pid: ${_srv:-<none>}"
SERVER_PID=$_srv

if [ -z "$SERVER_PID" ]; then
    log "FAIL: no server running, nothing to test"
    exit 1
fi

# Note where we are in the daemon log so the analysis only reads what this
# test produced.
LOGLINES=$(wc -l < "$LOG" 2>/dev/null)
log "daemon log starts at line $((LOGLINES + 1))"

log "--- unbinding UDC (USB ADB will drop for a few seconds) ---"
echo none > $CFG/UDC 2>>"$OUT"
sleep 1
log "after unbind: UDC=$(cat $CFG/UDC 2>/dev/null) nodes=$(ls /dev/hidg* 2>/dev/null | tr '\n' ' ')"
sleep 4

log "--- rebinding UDC ---"
echo "$_udc" > $CFG/UDC 2>>"$OUT"
sleep 8

log "--- after ---"
snapshot
log "UDC=$_udc VID=$_vid PID=$_pid"
log "links: $_links"
log "report_length: $_lens"
log "nodes: $_node"
log "server pid: ${_srv:-<none>}"

# --- verdict ---------------------------------------------------------------

if [ "${_srv:-}" = "$SERVER_PID" ]; then
    log "PASS server survived the re-enumeration (pid $SERVER_PID unchanged)"
else
    log "FAIL server pid changed or vanished: was $SERVER_PID, now ${_srv:-<none>}"
fi

log "--- daemon log during the test ---"
sed -n "$((LOGLINES + 1)),\$p" "$LOG" 2>/dev/null | sed 's/^/    /' >> "$OUT"

log "=== done ==="
