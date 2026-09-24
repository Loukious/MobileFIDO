#!/system/bin/sh
#
# fido2_provision.sh -- idempotently expose the CTAP HID function on the
# Poco F7's composite USB gadget.
#
# Designed to be safe to re-run: every step checks current state first, and
# re-running after a NetHunter "USB Arsenal" mode switch (which removes ALL
# links from configs/b.1, taking our link with them) restores the FIDO link.
#
# It never modifies hid.0/hid.1 and never modifies usbarsenal.
#
# Usage:
#   sh fido2_provision.sh                 # full: identity + CTAP HID interface
#   sh fido2_provision.sh --hid-only      # add the HID interface, keep VID/PID
#   sh fido2_provision.sh --identity-only # change VID/PID only, no new interface
#   sh fido2_provision.sh --window 300    # watchdog grace period, seconds
#
# Exit codes: 0 ok, 1 fatal, 2 provisioned-but-verification-failed-and-reverted
#
# THIS SCRIPT UNBINDS THE UDC. adb over USB will drop for a few seconds and
# come back. A watchdog is armed before anything is touched; see
# fido2_watchdog.sh and fido2_rollback.sh.

. "$(dirname "$0")/fido2_env.sh"

WINDOW=180
MODE=full
RESTART_ADBD=0
CHMOD_666=0

while [ $# -gt 0 ]; do
    case "$1" in
        --hid-only)      MODE=hid; shift ;;
        --identity-only) MODE=identity; shift ;;
        --window)        WINDOW="$2"; shift 2 ;;
        --restart-adbd)  RESTART_ADBD=1; shift ;;
        --chmod-666)     CHMOD_666=1; shift ;;
        -h|--help)
            echo "usage: $0 [--hid-only|--identity-only] [--window SECONDS] [--restart-adbd] [--chmod-666]"
            exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

case "$WINDOW" in
    ''|*[!0-9]*) die "--window needs a whole number of seconds" ;;
esac

# ===========================================================================
# Snapshot
# ===========================================================================
#
# Written exactly once. This is deliberate and important: if we re-snapshotted
# on every run we would eventually record the *modified* state as "original"
# and lose the ability to revert. Write-once means the first snapshot is the
# only one, so rollback always returns to genuine pre-change state.
# Source the snapshot and refuse to continue on a bad one. Without a usable
# snapshot the rollback cannot restore the identity, so proceeding would mean
# making a change we cannot undo.
#
# This runs on BOTH paths -- freshly written and already-present. The
# already-present path needs it just as much: a snapshot left behind by an
# earlier run, or truncated by a crash mid-write, would otherwise be trusted
# blindly and only discovered at `echo "$ORI_UDC" > UDC`.
validate_snapshot() {
    . "$ORIGINAL_ENV" || return 1
    [ -n "$ORI_VID" ] || { log "snapshot check: ORI_VID is empty"; return 1; }
    [ -n "$ORI_PID" ] || { log "snapshot check: ORI_PID is empty"; return 1; }
    [ -n "$ORI_UDC" ] || { log "snapshot check: ORI_UDC is empty"; return 1; }
    case "$ORI_LINKS" in
        *ffs.adb*) : ;;
        *) log "snapshot check: no ffs.adb link recorded in ORI_LINKS"; return 1 ;;
    esac
    return 0
}

take_snapshot() {
    if [ -f "$ORIGINAL_ENV" ]; then
        log "snapshot already present (write-once, not overwriting): $ORIGINAL_ENV"
        validate_snapshot || die "existing snapshot is unusable; delete $ORIGINAL_ENV to re-snapshot, or fix it by hand"
        log "  original identity : VID=$ORI_VID PID=$ORI_PID bcdDevice=$ORI_BCDDEVICE"
        log "  original links    : $ORI_LINKS"
        log "  original UDC      : $ORI_UDC"
        return 0
    fi
    mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR"

    _udc=$(cat "$CFG_ROOT/UDC" 2>/dev/null)
    _hid0sha=$($BUSYBOX head -c 4096 "$FUNCS_DIR/hid.0/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    _hid1sha=$($BUSYBOX head -c 4096 "$FUNCS_DIR/hid.1/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    _links=$(list_links | tr '\n' ';')

    {
        echo "# Pre-change snapshot, taken $(date '+%Y-%m-%d %H:%M:%S %z')"
        echo "# Restored verbatim by fido2_rollback.sh. Do not edit."
        echo "ORI_UDC='$_udc'"
        echo "ORI_VID='$(cat "$CFG_ROOT/idVendor" 2>/dev/null)'"
        echo "ORI_PID='$(cat "$CFG_ROOT/idProduct" 2>/dev/null)'"
        echo "ORI_BCDDEVICE='$(cat "$CFG_ROOT/bcdDevice" 2>/dev/null)'"
        echo "ORI_MANUFACTURER='$(cat "$STR_DIR/manufacturer" 2>/dev/null)'"
        echo "ORI_PRODUCT='$(cat "$STR_DIR/product" 2>/dev/null)'"
        echo "ORI_SERIALNUMBER='$(cat "$STR_DIR/serialnumber" 2>/dev/null)'"
        echo "ORI_OSDESC_USE='$(cat "$CFG_ROOT/os_desc/use" 2>/dev/null)'"
        echo "ORI_OSDESC_VENDOR_CODE='$(cat "$CFG_ROOT/os_desc/b_vendor_code" 2>/dev/null)'"
        echo "ORI_OSDESC_QW_SIGN='$(cat "$CFG_ROOT/os_desc/qw_sign" 2>/dev/null)'"
        echo "ORI_LINKS='$_links'"
        echo "ORI_HID0_DESC_SHA='$_hid0sha'"
        echo "ORI_HID1_DESC_SHA='$_hid1sha'"
        echo "ORI_HID0_PROTOCOL='$(cat "$FUNCS_DIR/hid.0/protocol" 2>/dev/null)'"
        echo "ORI_HID0_SUBCLASS='$(cat "$FUNCS_DIR/hid.0/subclass" 2>/dev/null)'"
        echo "ORI_HID0_REPORT_LENGTH='$(cat "$FUNCS_DIR/hid.0/report_length" 2>/dev/null)'"
        echo "ORI_HID1_PROTOCOL='$(cat "$FUNCS_DIR/hid.1/protocol" 2>/dev/null)'"
        echo "ORI_HID1_SUBCLASS='$(cat "$FUNCS_DIR/hid.1/subclass" 2>/dev/null)'"
        echo "ORI_HID1_REPORT_LENGTH='$(cat "$FUNCS_DIR/hid.1/report_length" 2>/dev/null)'"
    } > "$ORIGINAL_ENV.tmp" || die "cannot write snapshot"

    mv "$ORIGINAL_ENV.tmp" "$ORIGINAL_ENV" || die "cannot finalise snapshot"

    # Read it back and refuse to continue on a bad snapshot.
    validate_snapshot || die "freshly written snapshot failed validation -- refusing to change anything"

    log "snapshot written and verified: $ORIGINAL_ENV"
    log "  original identity : VID=$ORI_VID PID=$ORI_PID bcdDevice=$ORI_BCDDEVICE"
    log "  original links    : $ORI_LINKS"
    log "  original UDC      : $ORI_UDC"
    return 0
}

# ===========================================================================
# Preflight
# ===========================================================================
preflight() {
    [ -d "$CFG_ROOT" ]     || die "$CFG_ROOT missing -- kernel is not using ConfigFS Composite Gadget"
    [ -d "$CFG_DIR" ]      || die "$CFG_DIR missing"
    [ -d "$FUNCS_DIR" ]    || die "$FUNCS_DIR missing"
    # ffs.adb is a *directory* (the function instance), not a file.
    [ -d "$FUNCS_DIR/ffs.adb" ] || die "functions/ffs.adb is missing -- refusing to run without the adb function"

    _udc_now=$(cat "$CFG_ROOT/UDC" 2>/dev/null)
    [ -n "$_udc_now" ] || die "UDC is unbound before we started -- refusing to run"

    if ! list_links | grep -q .; then
        die "no symlinked function in $CFG_DIR -- cannot determine the vendor's link naming scheme"
    fi

    log "preflight ok: UDC=$_udc_now links=[$(list_links | tr '\n' ' ')]"
}

# ===========================================================================
# Step 1 -- create and configure functions/hid.2  (INERT)
# ===========================================================================
#
# Creating and configuring a function *instance* has no effect on the USB
# device: nothing is exposed until the instance is linked into configs/b.1 and
# the UDC is bound. We do this before touching anything else so that a
# configfs failure aborts with zero USB disruption.
ensure_fido_function() {
    if [ ! -d "$FIDO_FUNC_DIR" ]; then
        log "creating function instance $FIDO_FUNC_NAME"
        mkdir "$FIDO_FUNC_DIR" || die "cannot mkdir $FIDO_FUNC_DIR (HID function unsupported?)"
    else
        log "function instance $FIDO_FUNC_NAME already exists"
    fi

    # Idempotent: only write what differs.
    [ "$(cat "$FIDO_FUNC_DIR/protocol" 2>/dev/null)" = "$FIDO_PROTOCOL" ] || \
        cfg_write "$FIDO_FUNC_DIR/protocol" "$FIDO_PROTOCOL" || die "protocol write failed"
    [ "$(cat "$FIDO_FUNC_DIR/subclass" 2>/dev/null)" = "$FIDO_SUBCLASS" ] || \
        cfg_write "$FIDO_FUNC_DIR/subclass" "$FIDO_SUBCLASS" || die "subclass write failed"
    [ "$(cat "$FIDO_FUNC_DIR/report_length" 2>/dev/null)" = "$FIDO_REPORT_LENGTH" ] || \
        cfg_write "$FIDO_FUNC_DIR/report_length" "$FIDO_REPORT_LENGTH" || die "report_length write failed"
    [ "$(cat "$FIDO_FUNC_DIR/no_out_endpoint" 2>/dev/null)" = "$FIDO_NO_OUT_ENDPOINT" ] || \
        cfg_write "$FIDO_FUNC_DIR/no_out_endpoint" "$FIDO_NO_OUT_ENDPOINT" || die "no_out_endpoint write failed"

    if hid_desc_matches "$FIDO_FUNC_DIR"; then
        log "CTAP report descriptor already correct ($FIDO_DESC_LEN bytes)"
    else
        log "writing CTAP report descriptor ($FIDO_DESC_LEN bytes)"
        # busybox printf expands the \xNN escapes; redirecting straight to the
        # configfs attribute avoids any shell NUL-truncation (the descriptor
        # legitimately contains 0x00 bytes).
        $BUSYBOX printf "$FIDO_DESC_ESC" > "$FIDO_FUNC_DIR/report_desc" 2>/dev/null
        hid_desc_matches "$FIDO_FUNC_DIR" || die "report_desc did not verify after write"
        log "descriptor verified"
    fi

    log "  protocol=$(cat "$FIDO_FUNC_DIR/protocol") subclass=$(cat "$FIDO_FUNC_DIR/subclass") report_length=$(cat "$FIDO_FUNC_DIR/report_length") no_out_endpoint=$(cat "$FIDO_FUNC_DIR/no_out_endpoint")"
    log "  kernel-assigned dev=$(hid_func_dev "$FIDO_FUNC_DIR")"
}

# ===========================================================================
# Watchdog
# ===========================================================================
#
# Armed before the UDC is touched. It is detached with setsid so it survives
# adb disconnecting -- that is the whole point: if adb does not come back, the
# watchdog is the thing that puts the phone right, with no host involvement.
arm_watchdog() {
    mkdir -p "$LOG_DIR" "$STATE_DIR"
    rm -f "$KEEP_FLAG" "$REVERTED_FLAG"

    setsid sh "$(dirname "$0")/fido2_watchdog.sh" "$WINDOW" \
        > "$WATCHDOG_LOG" 2>&1 &
    _pid=$!
    echo "$_pid" > "$WATCHDOG_PID"

    # Confirm it is running AND that it is outside adbd's cgroup. A watchdog
    # inside adbd's cgroup is worse than no watchdog: it looks armed and dies
    # silently the moment anything stops adbd.
    sleep 2
    if ! kill -0 "$_pid" 2>/dev/null; then
        die "watchdog failed to start -- refusing to modify USB without a safety net"
    fi
    _wcg=$(sed -n 's/^0:://p' "/proc/$_pid/cgroup" 2>/dev/null)
    case "$_wcg" in
        /system/uid_0/*)
            kill -9 "$_pid" 2>/dev/null
            die "watchdog is inside adbd's cgroup ($_wcg) and would be killed by stop adbd -- aborting"
            ;;
    esac
    log "watchdog armed: pid=$_pid cgroup=$_wcg window=${WINDOW}s"
    log "  auto-revert unless $KEEP_FLAG appears"
}

# ===========================================================================
# Allow adb to reconnect
# ===========================================================================
#
# Two strategies, and the difference matters a lot.
#
# DEFAULT -- do not touch adbd. The ffs.adb link is preserved (we never remove
# it), so adbd keeps its function instance across the rebind. Wireless adb is a
# TCP socket to adbd and never traverses the USB gadget at all, so it is
# completely unaffected by a UDC unbind/rebind. Not stopping adbd keeps that
# channel open for the whole operation.
#
# --restart-adbd -- NetHunter usbarsenal's sequence: stop adbd, force
# sys.usb.ffs.ready 0, rebind, then start adbd and force ffs.ready 1. Proven on
# this ROM, but it tears down wireless adb as well, because wireless and USB
# debugging are the same adbd process. netHunter only needs this because its
# clear_funcs() deletes the adb link; we do not, so it is a fallback, not the
# default.
adb_down() {
    if [ "$RESTART_ADBD" = "1" ]; then
        log "restart-adbd: stopping adbd (this also drops wireless adb)"
        stop adbd
        setprop sys.usb.ffs.ready 0
    else
        log "leaving adbd running (wireless adb stays up)"
    fi
}

adb_up() {
    if [ "$RESTART_ADBD" = "1" ]; then
        start adbd
        setprop sys.usb.ffs.ready 1
    fi
    sleep 1
}

# ===========================================================================
# Verification
# ===========================================================================
verify() {
    _ok=0

    # 1. adb function still linked
    if list_links | grep -q 'ffs.adb'; then
        log "  [ok]   ffs.adb still linked"
    else
        log "  [FAIL] ffs.adb link is gone -- adb will not reconnect"
        _ok=1
    fi

    # 2. UDC bound
    if [ -n "$(cat "$CFG_ROOT/UDC" 2>/dev/null)" ]; then
        log "  [ok]   UDC bound to $(cat "$CFG_ROOT/UDC")"
    else
        log "  [FAIL] UDC is unbound"
        _ok=1
    fi

    # 3. adbd running
    if pidof adbd >/dev/null 2>&1; then
        log "  [ok]   adbd running (pid $(pidof adbd))"
    else
        log "  [WARN] adbd not running -- watchdog will still revert if needed"
    fi

    # 4. HID node for our function (only when we linked it)
    if [ "$MODE" != "identity" ]; then
        _node=$(hid_func_node "$FIDO_FUNC_DIR")
        if [ -n "$_node" ]; then
            log "  [ok]   $FIDO_FUNC_NAME -> $_node (char dev, dev=$(hid_func_dev "$FIDO_FUNC_DIR"))"
        else
            log "  [FAIL] $FIDO_FUNC_NAME has dev=$(hid_func_dev "$FIDO_FUNC_DIR") but no matching /dev node"
            log "         /dev/hidg* present: $(ls /dev/hidg* 2>/dev/null | tr '\n' ' ')"
            _ok=1
        fi
    fi

    return $_ok
}

# ===========================================================================
# Main
# ===========================================================================
mkdir -p "$WORKDIR" "$LOG_DIR" "$STATE_DIR" || die "cannot create $WORKDIR"

# Must happen before anything else forks: this script and its watchdog have to
# outlive adbd if --restart-adbd is used.
escape_adbd_cgroup || die "cannot safely leave adbd's cgroup"

log "=============================================================="
log "fido2_provision.sh  mode=$MODE window=${WINDOW}s restart_adbd=$RESTART_ADBD chmod666=$CHMOD_666"
log "=============================================================="

preflight
take_snapshot
. "$ORIGINAL_ENV"

if [ "$MODE" != "identity" ]; then
    ensure_fido_function
fi

# Re-check idempotency: is the link already there?
FIDO_LINK=$(link_for_func "$FIDO_FUNC_NAME")
if [ "$MODE" != "identity" ]; then
    if [ -n "$FIDO_LINK" ]; then
        log "already linked as '$FIDO_LINK' -- will not re-link"
    else
        FIDO_LINK=$(choose_link_name) || die "could not determine a free symlink name"
        log "will link as '$FIDO_LINK'"
    fi
fi

arm_watchdog

# ---- From here on the USB device is disturbed. ----
log "unbinding UDC"
unbind_udc || log "WARN: could not confirm the UDC unbind; continuing"
adb_down

if [ "$MODE" != "identity" ]; then
    if [ -z "$(link_for_func "$FIDO_FUNC_NAME")" ]; then
        ln -s "$FIDO_FUNC_DIR" "$CFG_DIR/$FIDO_LINK" || die "cannot create symlink $FIDO_LINK"
        log "linked $FIDO_LINK -> $FIDO_FUNC_DIR"
    else
        log "link already present, skipping"
    fi
fi

if [ "$MODE" != "hid" ]; then
    log "setting identity: VID=$FIDO_VID PID=$FIDO_PID bcdDevice=$FIDO_BCDDEVICE"
    cfg_write "$CFG_ROOT/idVendor"  "$FIDO_VID"  || log "WARN: idVendor write failed"
    cfg_write "$CFG_ROOT/idProduct" "$FIDO_PID"  || log "WARN: idProduct write failed"
    cfg_write "$CFG_ROOT/bcdDevice" "$FIDO_BCDDEVICE" || log "WARN: bcdDevice write failed"
    [ -f "$STR_DIR/manufacturer" ] && cfg_write "$STR_DIR/manufacturer" "$FIDO_MANUFACTURER"
    [ -f "$STR_DIR/product" ]      && cfg_write "$STR_DIR/product"      "$FIDO_PRODUCT"
    # serialnumber untouched on purpose
fi

adb_up

log "binding UDC"
bind_udc "$ORI_UDC" || die "UDC bind failed"
sleep 2

# Match NetHunter's convention so the eventual CTAP daemon (running as root in
# the Kali chroot) can open the node, and so we match hidg0/hidg1's mode.
#
# OPT-IN, default off. The kernel/ueventd default is 0600 root:root, and there
# is no ueventd, init or SELinux rule for hidg anywhere on this device (checked).
# A root CTAP daemon opens 0600 fine, so widening to 666 buys nothing and only
# lets any process that can reach /dev drive the authenticator endpoint. It is
# also not durable: ueventd re-creates the node on every re-bind, so the mode
# reverts to 600 the next time the gadget is rebound (measured -- an adbd
# restart reset it). Use --chmod-666 only for a deliberately non-root daemon,
# and note that doing so properly needs a ueventd rule plus an SELinux type,
# which is a Milestone 2 item.
if [ "$MODE" != "identity" ] && [ "$CHMOD_666" = "1" ]; then
    _node=$(hid_func_node "$FIDO_FUNC_DIR")
    if [ -n "$_node" ]; then
        _mode_before=$(ls -l "$_node" | $BUSYBOX awk '{print $1}')
        chmod 666 "$_node" 2>/dev/null
        log "chmod 666 $_node (was $_mode_before; NOT durable across a re-bind)"
    fi
fi

log "verifying"
if verify; then
    log "VERIFIED"
    log ""
    log "Now confirm on the Windows side, then run:"
    log "  sh $WORKDIR/fido2_keep.sh"
    log "within ${WINDOW}s or the watchdog will revert automatically."
    exit 0
else
    log "VERIFICATION FAILED -- reverting immediately"
    sh "$(dirname "$0")/fido2_rollback.sh" --no-prompt
    exit 2
fi
