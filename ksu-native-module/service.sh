#!/system/bin/sh
# KernelSU late_start service. Native arm64 responder; no Kali/chroot/NetHunter.
MODDIR=${0%/*}
export MODDIR
. "$MODDIR/lib/common.sh"
. "$MODDIR/lib/usb.sh"
. "$MODDIR/lib/daemon.sh"

m_init || exit 1
_svc_cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
case "$_svc_cgroup" in
    /system/uid_0/*) m_fail "service inherited adbd's cgroup; abort"; exit 1 ;;
esac

# KSU service can run before Android's USB HAL and package manager stabilize.
_svc_try=0
while [ "$_svc_try" -lt 60 ] && [ ! -f "$MODDIR/disable" ]; do
    [ "$(getprop sys.boot_completed 2>/dev/null)" = 1 ] &&
        [ -n "$(cat "$G/UDC" 2>/dev/null)" ] && break
    sleep 2
    _svc_try=$((_svc_try + 1))
done
[ ! -f "$MODDIR/disable" ] || exit 0
[ "$(getprop sys.boot_completed 2>/dev/null)" = 1 ] ||
    { m_fail "boot or USB never stabilized"; exit 1; }

if [ -e "$STATE/lock" ]; then
    [ -d "$STATE/lock" ] && [ ! -L "$STATE/lock" ] || exit 1
    _svc_lockboot=$(cat "$STATE/lock/boot" 2>/dev/null)
    if [ -n "$_svc_lockboot" ] && [ "$_svc_lockboot" != "$(m_boot_id)" ]; then
        # Lock directories survive KSU module updates/reboots; no process or
        # ConfigFS transaction from the old boot can still be in progress.
        rm -f "$STATE/lock/boot"
        rmdir "$STATE/lock" 2>/dev/null || exit 1
    else
        m_log "same-boot lock exists or unreadable; refusing concurrent USB mutation"
        exit 1
    fi
fi
mkdir "$STATE/lock" || exit 1
printf '%s\n' "$(m_boot_id)" > "$STATE/lock/boot" || exit 1
_svc_unlock() { rm -f "$STATE/lock/boot"; rmdir "$STATE/lock" 2>/dev/null; }
trap '_svc_unlock' EXIT

# Do not disturb existing manually configured FIDO USB: adopt only when
# descriptor, ADB, /dev/hidgN, and UDC all verify. No configfs remount.
if ! usb_setup; then
    m_log "USB setup failed; independent watchdog owns any pending module-only rollback"
    exit 1
fi

[ -x "$NATIVE_BIN" ] || { m_fail "native executable unavailable"; exit 1; }
rm -f "$STATE/stopping"
_svc_unlock
trap - EXIT
exec /system/bin/sh "$MODDIR/lib/daemon.sh" supervise
