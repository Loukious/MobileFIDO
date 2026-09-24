#!/system/bin/sh
#
# fido2_watchdog.sh -- dead-man switch for the CTAP HID provisioning.
#
# Started (setsid-detached) by fido2_provision.sh *before* the UDC is touched,
# so it is already running when the USB device is disturbed. It then waits for
# a keep-flag to appear.
#
#   * flag appears   -> the change was confirmed good, watchdog exits quietly
#   * window expires -> the change was NOT confirmed, watchdog runs
#                      fido2_rollback.sh, locally, with no host involvement
#
# This is the mechanism that covers "Windows fails to enumerate the device"
# and "ADB fails to reconnect": in both cases the host can no longer tell the
# phone anything, so the phone has to put itself right. setsid is what makes
# that work -- it detaches the watchdog from adb shell's session, so the
# watchdog does not receive SIGHUP when adb disconnects.
#
# Usage: setsid sh fido2_watchdog.sh <window-seconds>

. "$(dirname "$0")/fido2_env.sh"

WINDOW="$1"
case "$WINDOW" in
    ''|*[!0-9]*) WINDOW=180 ;;
esac

# The whole point of this process is to still be alive when adbd is not. If it
# is sitting in adbd's cgroup, `stop adbd` kills it and the dead-man switch is
# fiction. Leave that cgroup first -- see escape_adbd_cgroup in fido2_env.sh.
escape_adbd_cgroup || log "WARN: could not leave adbd's cgroup; this watchdog may be killed by stop adbd"

log "watchdog up: pid=$$ window=${WINDOW}s cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)"
log "watchdog: waiting for $KEEP_FLAG"

_elapsed=0
while [ "$_elapsed" -lt "$WINDOW" ]; do
    sleep 5
    _elapsed=$((_elapsed + 5))

    if [ -f "$KEEP_FLAG" ]; then
        log "watchdog: keep-flag found after ${_elapsed}s -- change confirmed, standing down"
        exit 0
    fi
    if [ -f "$REVERTED_FLAG" ]; then
        log "watchdog: rollback already performed by another path, standing down"
        exit 0
    fi
done

log "watchdog: NOT confirmed within ${WINDOW}s -- running rollback"
log "watchdog: (this is the expected path when Windows fails to enumerate"
log "watchdog:  or when adb did not reconnect)"

sh "$(dirname "$0")/fido2_rollback.sh" --no-prompt
_rc=$?

if [ "$_rc" = "0" ]; then
    log "watchdog: rollback succeeded -- USB gadget restored, adb should be back"
else
    log "watchdog: ROLLBACK FAILED (rc=$_rc). Reboot the phone to recover;"
    log "watchdog: configfs is RAM-backed so a reboot restores the stock gadget."
fi
exit $_rc
