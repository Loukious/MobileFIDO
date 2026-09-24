#!/system/bin/sh
# Standalone native CTAPHID: KernelSU Manager Action opens Android helper.
# Optional explicit CLI: sh action.sh status|open|start|stop|rollback.
MODDIR=${0%/*}
export MODDIR
. "$MODDIR/lib/common.sh"
. "$MODDIR/lib/usb.sh"
. "$MODDIR/lib/daemon.sh"

_act_mode=${1:-open}
case "$_act_mode" in
    open)
        _act_uid=$(m_app_uid)
        case "$_act_uid" in
            ''|*[!0-9]*)
                echo "CTAP 3B helper app is not installed." >&2
                exit 1 ;;
        esac
        # This is only called by a deliberate Manager Action/CLI invocation,
        # never by KernelSU boot service. No silent biometric or consent.
        am start -n org.pocof7.ctap3b/.MainActivity ||
            { echo "Could not open the Android helper Activity." >&2; exit 1; }
        echo "Opened CTAP3B helper; approve requests in the foreground."
        /system/bin/sh "$MODDIR/action.sh" status
        ;;
    status)
        echo "Standalone FIDO2 Android native CTAPHID (no Kali/NetHunter)"
        echo "State: $STATE"
        echo "Boot: $(m_boot_id)"
        echo "UDC: $(cat "$G/UDC" 2>/dev/null)"
        echo "USB functions (read-only):"
        usb_links 2>/dev/null || echo "  unavailable"
        _act_node=$(m_fido_node) || _act_node=unavailable
        echo "CTAP HID: $_act_node; descriptor: $(m_fido_valid && echo valid || echo invalid)"
        echo "Android helper UID: $(m_app_uid)"
        echo "Native responder PID (module-owned): $(daemon_owned_pid || echo none)"
        if [ -r "$STATE/usb-txn/owns-link" ]; then
            echo "USB link module-owned: $(cat "$STATE/usb-txn/owns-link")"
        else
            echo "USB link module-owned: no (existing gadget adopted or not set up)"
        fi
        echo "Foreground biometric: open the MobileFIDO DEV app manually."
        echo "Recent logs:"
        tail -n 15 "$LOG" 2>/dev/null || true
        ;;
    start)
        # Start/retry daemon ONLY. Never provision/rebind gadget from adb/KSU
        # UI action; boot-time USB changes require independent watchdog.
        m_init || exit 1
        rm -f "$STATE/stopping"
        daemon_launch ||
            { echo "Native CTAP daemon unavailable: check gadget and module logs"; exit 1; }
        echo "Native CTAPHID started. Android biometric UI must be foreground."
        ;;
    stop)
        m_init || exit 1
        touch "$STATE/stopping"
        daemon_stop || exit 1
        echo "Module-owned CTAP daemon stopped; USB ADB/gadget unchanged."
        ;;
    rollback)
        # Deliberately do not rollback via an adb-hosted shell: a UDC rebind
        # can kill this session before it restores ADB. Use KSU manager/local
        # root context or reboot to restore CONFIGFS's original stock state.
        _act_cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
        case "$_act_cgroup" in
            /system/uid_0/*)
                echo "Refusing USB rollback from adbd cgroup. Use KSU Manager or reboot." >&2
                exit 1 ;;
        esac
        m_init || exit 1
        [ -f "$STATE/usb-txn/committed" ] ||
            { echo "No module-owned, committed USB HID link to rollback."; exit 0; }
        touch "$STATE/stopping"
        daemon_stop || exit 1
        usb_rollback || exit 1
        echo "Module-owned USB HID link restored; ADB preserved."
        ;;
    *) echo "usage: action.sh open|status|start|stop|rollback" >&2; exit 2 ;;
esac
