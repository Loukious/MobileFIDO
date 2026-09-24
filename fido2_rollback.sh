#!/system/bin/sh
#
# fido2_rollback.sh -- restore the USB gadget to its exact pre-change state.
#
# Requirements this satisfies:
#   * runs entirely locally on Android -- no adb, no host, no network needed
#   * idempotent: safe to run twice, safe to run when nothing was changed
#   * reproduces NetHunter usbarsenal's own proven revert sequence
#     (unbind -> stop adbd -> ffs.ready 0 -> fix links -> start adbd ->
#      ffs.ready 1 -> bind)
#
# Invoke from a local root shell (Termux, NetHunter terminal, or the
# watchdog):
#   su -c 'sh /data/local/tmp/fido2/fido2_rollback.sh'
#
# It removes ONLY its own symlink. hid.0/hid.1/usbarsenal are never touched.

. "$(dirname "$0")/fido2_env.sh"

NO_PROMPT=0
DETACH=0
for _a in "$@"; do
    case "$_a" in
        --no-prompt) NO_PROMPT=1 ;;
        --detach)    DETACH=1 ;;
        --help|-h)
            echo "usage: $0 [--no-prompt] [--detach]"
            echo "  --no-prompt  do not wait 3s before reverting"
            echo "  --detach     re-exec under setsid, backgrounded, output to a log."
            echo "               USE THIS when invoking over USB adb: the rollback"
            echo "               unbinds the UDC, which drops USB adb and kills any"
            echo "               process still attached to that shell."
            exit 0 ;;
        *) echo "unknown option: $_a" >&2; exit 1 ;;
    esac
done

# --------------------------------------------------------------------------
# Self-detach.
#
# Measured on this device: running the rollback in the foreground of a USB adb
# shell kills it partway through. The rollback unbinds the UDC, USB adb drops,
# adbd tears down the shell, and the rollback dies with it -- leaving the change
# half-reverted. (The watchdog never hits this because it is already setsid'd.)
#
# Note this is a *session* problem, not a cgroup problem: escape_adbd_cgroup
# below keeps the script alive when adbd itself is stopped, but it does not
# detach it from the adb shell's session. Both are needed.
#
# Escaping the cgroup alone is not enough here, which is exactly why the
# automatic path (watchdog -> rollback) is the one to rely on.
# --------------------------------------------------------------------------
if [ "$DETACH" = "1" ] && [ "$FIDO2_ROLLBACK_DETACHED" != "1" ]; then
    FIDO2_ROLLBACK_DETACHED=1
    export FIDO2_ROLLBACK_DETACHED
    mkdir -p "$LOG_DIR" 2>/dev/null
    _self_log="$LOG_DIR/rollback-$(date '+%Y%m%d-%H%M%S').log"
    setsid sh "$0" "$@" > "$_self_log" 2>&1 < /dev/null &
    echo "rollback detached as pid $! -- output follows in $_self_log"
    exit 0
fi

log "=============================================================="
log "fido2_rollback.sh"
log "=============================================================="

# Rollback stops/restarts adbd, so it must not be running inside adbd's
# cgroup -- otherwise `stop adbd` would kill this script before it could
# start adbd again, leaving the phone with no adb at all.
escape_adbd_cgroup || log "WARN: continuing, but stop adbd may kill this script"

# --------------------------------------------------------------------------
# Stop the watchdog first, so it cannot fire a second rollback underneath us.
# --------------------------------------------------------------------------
if [ -f "$WATCHDOG_PID" ]; then
    _wpid=$(cat "$WATCHDOG_PID" 2>/dev/null)
    case "$_wpid" in
        ''|*[!0-9]*) : ;;
        *)
            if kill -0 "$_wpid" 2>/dev/null; then
                log "stopping watchdog pid=$_wpid"
                kill "$_wpid" 2>/dev/null
                sleep 1
                kill -9 "$_wpid" 2>/dev/null
            fi
            ;;
    esac
    rm -f "$WATCHDOG_PID"
fi
# Belt and braces: the pidfile can be lost or stale if the watchdog was
# re-parented, so also scan /proc for any surviving watchdog by command line.
for _d in /proc/[0-9]*; do
    _pid=${_d#/proc/}
    [ -r "$_d/cmdline" ] || continue
    _cl=$(tr '\0' ' ' < "$_d/cmdline" 2>/dev/null)
    case "$_cl" in
        *fido2_watchdog.sh*)
            log "killing surviving watchdog pid=$_pid"
            kill -9 "$_pid" 2>/dev/null
            ;;
    esac
done
rm -f "$KEEP_FLAG"

if [ ! -f "$ORIGINAL_ENV" ]; then
    log "WARN: no snapshot at $ORIGINAL_ENV -- best-effort revert only"
    log "      (VID/PID cannot be restored without a snapshot)"
    ORI_UDC=$(cat "$CFG_ROOT/UDC" 2>/dev/null)
    ORI_LINKS=
    RESTORE_IDENTITY=0
else
    . "$ORIGINAL_ENV"
    RESTORE_IDENTITY=1
    log "snapshot loaded: VID=$ORI_VID PID=$ORI_PID bcdDevice=$ORI_BCDDEVICE"
    log "                 links=$ORI_LINKS"
fi

[ -n "$ORI_UDC" ] || ORI_UDC=$(getprop sys.usb.controller)

if [ "$NO_PROMPT" != "1" ]; then
    log "reverting in 3s -- ^C to abort"
    sleep 3
fi

# --------------------------------------------------------------------------
# Down
#
# adbd is deliberately NOT stopped here. We never removed the ffs.adb link, so
# adbd keeps its function instance across the rebind, and leaving adbd alone
# keeps wireless adb alive for the whole rollback. If adbd does end up broken,
# the verification step at the bottom escalates to a full adbd restart.
# --------------------------------------------------------------------------
log "unbinding UDC"
unbind_udc || log "WARN: could not confirm the UDC unbind; continuing"

# --------------------------------------------------------------------------
# Remove our link, and only our link.
# --------------------------------------------------------------------------
FIDO_LINK=$(link_for_func "$FIDO_FUNC_NAME")
if [ -n "$FIDO_LINK" ]; then
    log "removing symlink $CFG_DIR/$FIDO_LINK"
    rm -f "$CFG_DIR/$FIDO_LINK"
else
    log "no link to $FIDO_FUNC_NAME present (already clean)"
fi

# Restore the original link set. Re-linking an existing link would fail, so
# each is checked first. This also repairs the case where a NetHunter mode
# switch left the config in an unexpected shape.
if [ -n "$ORI_LINKS" ]; then
    echo "$ORI_LINKS" | tr ';' '\n' | while read -r _pair; do
        [ -n "$_pair" ] || continue
        _name=${_pair%% *}
        _tgt=${_pair#* }
        [ -n "$_name" ] && [ -n "$_tgt" ] || continue
        if [ -e "$CFG_DIR/$_name" ] || [ -L "$CFG_DIR/$_name" ]; then
            log "  link $_name already present"
        else
            if ln -s "$FUNCS_DIR/$_tgt" "$CFG_DIR/$_name" 2>/dev/null; then
                log "  restored link $_name -> $_tgt"
            else
                log "  WARN: could not restore link $_name -> $_tgt"
            fi
        fi
    done
fi

# Safety net: whatever the snapshot said, adb must end up linked or we have
# locked ourselves out.
if ! list_links | grep -q 'ffs.adb'; then
    _adbname=$(choose_link_name 2>/dev/null) || _adbname=function0
    log "adb was not linked -- adding $CFG_DIR/$_adbname -> ffs.adb"
    ln -s "$FUNCS_DIR/ffs.adb" "$CFG_DIR/$_adbname" 2>/dev/null
fi

# --------------------------------------------------------------------------
# Restore identity
# --------------------------------------------------------------------------
if [ "$RESTORE_IDENTITY" = "1" ]; then
    log "restoring identity"
    [ -n "$ORI_VID" ]       && cfg_write "$CFG_ROOT/idVendor"  "$ORI_VID"
    [ -n "$ORI_PID" ]       && cfg_write "$CFG_ROOT/idProduct" "$ORI_PID"
    [ -n "$ORI_BCDDEVICE" ] && cfg_write "$CFG_ROOT/bcdDevice" "$ORI_BCDDEVICE"
    [ -f "$STR_DIR/manufacturer" ] && [ -n "$ORI_MANUFACTURER" ] && cfg_write "$STR_DIR/manufacturer" "$ORI_MANUFACTURER"
    [ -f "$STR_DIR/product" ]      && [ -n "$ORI_PRODUCT" ]      && cfg_write "$STR_DIR/product"      "$ORI_PRODUCT"
    [ -f "$STR_DIR/serialnumber" ] && [ -n "$ORI_SERIALNUMBER" ] && cfg_write "$STR_DIR/serialnumber" "$ORI_SERIALNUMBER"
    log "  VID=$(cat "$CFG_ROOT/idVendor") PID=$(cat "$CFG_ROOT/idProduct") bcdDevice=$(cat "$CFG_ROOT/bcdDevice")"
fi

# --------------------------------------------------------------------------
# Remove the function instance we added, restoring the exact original set.
# Done last, after the link is gone and the UDC is unbound (configfs refuses
# to rmdir a linked or bound instance).
# --------------------------------------------------------------------------
if [ -d "$FIDO_FUNC_DIR" ]; then
    if rmdir "$FIDO_FUNC_DIR" 2>/dev/null; then
        log "removed $FIDO_FUNC_DIR (minor slot freed)"
    else
        log "WARN: could not remove $FIDO_FUNC_DIR -- harmless while unlinked"
    fi
fi

# --------------------------------------------------------------------------
# Up -- bind only. adbd was never stopped, so it should still be running and
# should re-acquire its ffs endpoint on its own.
# --------------------------------------------------------------------------
log "binding UDC"
bind_udc "$ORI_UDC" || log "WARN: UDC bind did not confirm immediately"

# --------------------------------------------------------------------------
# Escalate IFF adbd did not survive the rebind.
#
# This is the NetHunter sequence, used only as a repair path: it is the
# reliable way to get adbd and its ffs endpoint back into a consistent state.
# --------------------------------------------------------------------------
if ! pidof adbd >/dev/null 2>&1; then
    log "adbd is not running after the rebind -- escalating to a full adbd restart"
    unbind_udc
    stop adbd
    setprop sys.usb.ffs.ready 0
    sleep 1
    start adbd
    setprop sys.usb.ffs.ready 1
    sleep 2
    bind_udc "$ORI_UDC" || log "WARN: UDC bind did not confirm after the adbd restart"
else
    log "adbd still running (pid $(pidof adbd)) -- no restart needed"
fi

# --------------------------------------------------------------------------
# Confirm
# --------------------------------------------------------------------------
_rc=0
if [ "$(cat "$CFG_ROOT/UDC" 2>/dev/null)" = "$ORI_UDC" ]; then
    log "  [ok]   UDC bound to $ORI_UDC"
else
    log "  [FAIL] UDC is not bound"
    _rc=1
fi
if list_links | grep -q 'ffs.adb'; then
    log "  [ok]   ffs.adb linked"
else
    log "  [FAIL] ffs.adb not linked"
    _rc=1
fi
if pidof adbd >/dev/null 2>&1; then
    log "  [ok]   adbd running (pid $(pidof adbd))"
else
    log "  [FAIL] adbd not running"
    _rc=1
fi
if [ -n "$(link_for_func "$FIDO_FUNC_NAME")" ]; then
    log "  [FAIL] FIDO link still present"
    _rc=1
else
    log "  [ok]   FIDO link removed"
fi

# hid.0 / hid.1 must be byte-identical to the snapshot.
if [ "$RESTORE_IDENTITY" = "1" ]; then
    _h0=$($BUSYBOX head -c 4096 "$FUNCS_DIR/hid.0/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    _h1=$($BUSYBOX head -c 4096 "$FUNCS_DIR/hid.1/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    if [ "$_h0" = "$ORI_HID0_DESC_SHA" ] && [ "$_h1" = "$ORI_HID1_DESC_SHA" ]; then
        log "  [ok]   hid.0/hid.1 descriptors unchanged"
    else
        log "  [FAIL] hid.0/hid.1 descriptors changed!"
        _rc=1
    fi
fi

touch "$REVERTED_FLAG"

if [ "$_rc" = "0" ]; then
    log "ROLLBACK COMPLETE -- gadget is back to its original state"
else
    log "ROLLBACK INCOMPLETE -- see failures above."
    log "Last resort: reboot the phone. configfs is RAM-backed, so a reboot"
    log "recreates the stock adb-only gadget regardless of current state."
fi
exit $_rc
