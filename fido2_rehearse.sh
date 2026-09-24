#!/system/bin/sh
#
# fido2_rehearse.sh -- validate the safety net WITHOUT changing any config.
#
# This does everything fido2_provision.sh does around the dangerous part
# (arm the watchdog, unbind the UDC, rebind the UDC) but changes no identity,
# adds no link and creates no function. It answers the two questions that
# matter before we rely on this machinery for real:
#
#   1. Does the watchdog actually survive a UDC rebind -- including one where
#      adbd is NOT restarted?
#   2. Does adb (USB and wireless) survive a rebind when adbd is not stopped?
#
# If either answer is no, provisioning must not proceed.

. "$(dirname "$0")/fido2_env.sh"

escape_adbd_cgroup || die "cannot escape adbd's cgroup"

mkdir -p "$LOG_DIR" "$STATE_DIR"
rm -f "$KEEP_FLAG" "$REVERTED_FLAG"

log "rehearsal: =============================================="
log "rehearsal: arming watchdog, window 90s"
setsid sh "$(dirname "$0")/fido2_watchdog.sh" 90 > "$WATCHDOG_LOG" 2>&1 &
_wpid=$!
echo "$_wpid" > "$WATCHDOG_PID"

sleep 2
if ! kill -0 "$_wpid" 2>/dev/null; then
    die "rehearsal: watchdog died immediately after start"
fi
_wcg=$(sed -n 's/^0:://p' "/proc/$_wpid/cgroup" 2>/dev/null)
log "rehearsal: watchdog pid=$_wpid cgroup=$_wcg"
case "$_wcg" in
    /system/uid_0/*) log "rehearsal: [FAIL] watchdog is still in adbd's cgroup" ;;
    *)               log "rehearsal: [ok]   watchdog is outside adbd's cgroup" ;;
esac

_udc=$(cat "$CFG_ROOT/UDC" 2>/dev/null)
log "rehearsal: UDC before = $_udc"
log "rehearsal: adbd before = $(pidof adbd)"
log "rehearsal: links before = $(list_links | tr '\n' ' ')"

log "rehearsal: unbinding UDC (adbd deliberately NOT stopped)"
echo none > "$CFG_ROOT/UDC"
sleep 2
log "rehearsal: during unbind, adbd = $(pidof adbd)"

log "rehearsal: rebinding UDC"
echo "$_udc" > "$CFG_ROOT/UDC"
sleep 4

log "rehearsal: ------------- after rebind -------------"
log "rehearsal: UDC      = $(cat "$CFG_ROOT/UDC" 2>/dev/null)"
log "rehearsal: adbd     = $(pidof adbd)"
log "rehearsal: links    = $(list_links | tr '\n' ' ')"
log "rehearsal: identity = VID=$(cat "$CFG_ROOT/idVendor") PID=$(cat "$CFG_ROOT/idProduct")"

if kill -0 "$_wpid" 2>/dev/null; then
    log "rehearsal: [ok]   watchdog SURVIVED the rebind"
else
    log "rehearsal: [FAIL] watchdog did not survive the rebind"
fi

log "rehearsal: writing KEEP to stand the watchdog down"
sh "$(dirname "$0")/fido2_keep.sh"
sleep 6

if kill -0 "$_wpid" 2>/dev/null; then
    log "rehearsal: [WARN] watchdog still alive after KEEP"
else
    log "rehearsal: [ok]   watchdog stood down cleanly on KEEP"
fi
rm -f "$WATCHDOG_PID"
log "rehearsal: done"
