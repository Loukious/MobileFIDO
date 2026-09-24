#!/system/bin/sh
# Called by KernelSU uninstall, without touching legacy manual FIDO state or
# any other module's files. Reboot re-creates stock configfs if cleanup cannot
# be done without jeopardizing adb.
MODDIR=${0%/*}
export MODDIR
. "$MODDIR/lib/common.sh"
. "$MODDIR/lib/usb.sh"
. "$MODDIR/lib/daemon.sh"

if ! m_init; then exit 0; fi
touch "$STATE/stopping"
daemon_stop

_un_cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
case "$_un_cgroup" in
    /system/uid_0/*)
        m_log "uninstall in adbd cgroup: no gadget rebind; reboot clears only this boot's FIDO link"
        ;;
    *)
        if [ -f "$TX/committed" ] &&
           [ "$(cat "$TX/owns-link" 2>/dev/null)" = 1 ] &&
           [ "$(cat "$TX/boot" 2>/dev/null)" = "$(m_boot_id)" ]; then
            usb_rollback ||
                m_log "uninstall USB rollback blocked to preserve active ADB/Arsenal; reboot recommended"
        else
            m_log "uninstall: legacy/unowned FIDO gadget left completely unchanged"
        fi
        ;;
esac

# No Python runtime, chroot or bind mount was created. The Android helper app,
# app data and StrongBox credential aliases are NEVER uninstalled or cleared.
exit 0
