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

# The module-owned chroot directory is distinct from the existing
# /root/ctaphid. Remove only if its exact marker confirms our ownership.
if [ -f "$PYPKG_PARENT/.ksu-managed" ] &&
   [ "$(cat "$PYPKG_PARENT/.ksu-managed" 2>/dev/null)" = pocof7_ctap3b ] &&
   [ ! -L "$PYPKG_PARENT" ]; then
    # The ownership marker permits cleanup of the module's own Python
    # package, NOT a recursive deletion of arbitrary later user files under
    # the parent. Leave any unknown siblings/staging folders for inspection.
    if [ -d "$PYPKG" ] && [ ! -L "$PYPKG" ] &&
       [ -f "$PYPKG/server.py" ]; then
        rm -rf "$PYPKG"
    fi
    rm -f "$PYPKG_PARENT/.ksu-managed"
    rmdir "$PYPKG_PARENT" 2>/dev/null ||
        m_log "uninstall: preserving nonempty module chroot parent (unknown files present)"
fi
if [ "$(cat "$STATE/owned-config-mount" 2>/dev/null)" = "$(m_boot_id)" ] &&
   grep -F " $CHROOT/config " /proc/mounts >/dev/null 2>&1; then
    umount "$CHROOT/config" 2>/dev/null ||
        m_log "uninstall: chroot /config still busy; leave other mounts alone"
fi
exit 0
