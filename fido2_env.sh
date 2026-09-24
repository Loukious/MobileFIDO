#!/system/bin/sh
#
# fido2_env.sh -- shared constants and helpers for the CTAP HID gadget scripts.
#
# Milestone 1: expose a third HID function (hid.2) carrying the standard
# FIDO Alliance CTAP HID report descriptor, alongside the existing
# NetHunter hid.0 (keyboard) / hid.1 (mouse) function instances and the
# live ADB (ffs.adb) function.
#
# This file is sourced by every other script here. It deliberately uses only
# POSIX/mksh constructs (Android's /system/bin/sh is mksh): no arrays, no
# [[ ]], no bash-isms, no `local`.
#
# Nothing in this file touches the USB gadget. Sourcing it is inert.

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CFG_ROOT=/config/usb_gadget/g1
FUNCS_DIR=$CFG_ROOT/functions
CFG_DIR=$CFG_ROOT/configs/b.1
STR_DIR=$CFG_ROOT/strings/0x409

FIDO_FUNC_NAME=hid.2
FIDO_FUNC_DIR=$FUNCS_DIR/$FIDO_FUNC_NAME
FIDO_STR_DIR=$CFG_DIR/strings/0x409

WORKDIR=/data/local/tmp/fido2
STATE_DIR=$WORKDIR/state
LOG_DIR=$WORKDIR/logs
ORIGINAL_ENV=$STATE_DIR/original.env
KEEP_FLAG=$WORKDIR/KEEP
REVERTED_FLAG=$WORKDIR/REVERTED
WATCHDOG_PID=$WORKDIR/watchdog.pid
WATCHDOG_LOG=$LOG_DIR/watchdog.log

# ---------------------------------------------------------------------------
# Target identity.
#
# Development identity only. 0x1209 is the pid.codes community "development
# VID" reserved for open-source/hobby hardware; 0x0001 is a self-assigned
# product ID. This is NOT a FIDO Alliance certified identity, it does not
# impersonate any commercial security key vendor, and it makes no
# certification claim. See README.md.
# ---------------------------------------------------------------------------
FIDO_VID=0x1209
FIDO_PID=0x0001
FIDO_BCDDEVICE=0x0001
FIDO_MANUFACTURER='POCO F7 FIDO Dev'
FIDO_PRODUCT='CTAP2 HID Dev Key'
# serialnumber is deliberately NOT changed -- adb host authorisation and the
# Windows device instance ID both key off it.

# ---------------------------------------------------------------------------
# Target HID interface parameters (requirement 3 of the task).
#   protocol=0 (none), subclass=0 (no subclass), report_length=64,
#   no_out_endpoint=0  -> keep the OUT endpoint, CTAP needs it.
# ---------------------------------------------------------------------------
FIDO_PROTOCOL=0
FIDO_SUBCLASS=0
FIDO_REPORT_LENGTH=64
FIDO_NO_OUT_ENDPOINT=0

# Standard FIDO Alliance CTAP HID report descriptor, 34 bytes.
#
#   06 D0 F1   Usage Page (FIDO Alliance, 0xF1D0 on the wire)
#   09 01      Usage (CTAP HID, 0x01)
#   A1 01      Collection (Application)
#   09 20       Usage (Input Report Data, 0x20)
#   15 00        Logical Minimum (0)
#   26 FF 00     Logical Maximum (255)
#   75 08        Report Size (8)
#   95 40        Report Count (64)
#   81 02        Input (Data,Var,Abs)
#   09 21       Usage (Output Report Data, 0x21)
#   15 00        Logical Minimum (0)
#   26 FF 00     Logical Maximum (255)
#   75 08        Report Size (8)
#   95 40        Report Count (64)
#   91 02        Output (Data,Var,Abs)
#   C0         End Collection
#
# Note on byte order: the descriptor encodes the usage page little-endian as
# 0xD0 0xF1, so Windows reports UsagePage = 0xF1D0. The FIDO specification
# writes the same value as 0xD0F1. Both refer to the identical 16-bit value.
FIDO_DESC_ESC='\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0'
FIDO_DESC_LEN=34

# ---------------------------------------------------------------------------
# Runtime helpers
# ---------------------------------------------------------------------------

# Locate a usable busybox. NetHunter's own is the canonical one on this device.
find_busybox() {
    if [ -x /system/xbin/busybox_nh ]; then
        echo /system/xbin/busybox_nh
    elif [ -x /system/xbin/busybox ]; then
        echo /system/xbin/busybox
    else
        command -v busybox 2>/dev/null
    fi
}
BUSYBOX=$(find_busybox)

log() {
    # Timestamped line to stdout and, if the log dir exists, to the shared log.
    _ln="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$_ln"
    [ -d "$LOG_DIR" ] && echo "$_ln" >> "$LOG_DIR/fido2.log" 2>/dev/null
    return 0
}

# Leave adbd's service cgroup before doing anything that stops adbd.
#
# THIS IS LOAD-BEARING. Android's init runs adbd as a service in its own cgroup
# (/system/uid_0/pid_<adbd>), and every process spawned from an adb shell
# inherits that cgroup. When adbd is stopped, init kills the cgroup -- so the
# script that issued `stop adbd` is killed by its own command, and so is any
# watchdog it started. setsid does NOT help: setsid changes the session and
# process group, not the cgroup.
#
# Measured on this device: a plain `setsid` process died 2s into `stop adbd`,
# while the same process moved to the root cgroup first ran to completion.
#
# Must be called before forking anything that has to outlive adbd.
escape_adbd_cgroup() {
    _cur=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
    case "$_cur" in
        /system/uid_0/*)
            if echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null; then
                _new=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
                log "cgroup: left adbd's service cgroup ($_cur -> $_new)"
            else
                log "ERROR: could not leave adbd's cgroup ($_cur)."
                log "ERROR: 'stop adbd' will kill this script. Aborting."
                return 1
            fi
            ;;
        *)
            log "cgroup: already outside adbd's service cgroup ($_cur)"
            ;;
    esac
    return 0
}

die() {
    log "FATAL: $*"
    exit 1
}

# Write a value to a configfs attribute, with a readable error on failure.
# Usage: cfg_write <file> <value>
cfg_write() {
    if ! echo "$2" > "$1" 2>/dev/null; then
        log "ERROR: failed to write '$2' to $1"
        return 1
    fi
    return 0
}

# Bind the UDC -- and verify it actually took.
#
# The write's exit status is NOT trustworthy. Measured on this device: the
# `echo "$ORI_UDC" > UDC` returned non-zero and `|| die` fired, yet the gadget
# was fully bound a moment later -- VID/PID, links and the /dev node all
# correct. The cause is a race with the vendor USB HAL: it watches the gadget,
# notices our unbind, and re-binds the UDC itself using whatever configfs state
# exists at that instant. Our own write then hits EBUSY on an already-bound
# controller and reports failure for a bind that actually succeeded.
#
# The authoritative statement of "is the gadget bound" is the UDC attribute's
# contents, not the write's exit code. So read it back, and retry to cover a
# HAL that is mid-rebind.
#
# Usage: bind_udc <udc-name>
bind_udc() {
    _want="$1"
    [ -n "$_want" ] || return 1
    _try=0
    while [ "$_try" -lt 6 ]; do
        _try=$((_try + 1))

        if [ "$(cat "$CFG_ROOT/UDC" 2>/dev/null)" = "$_want" ]; then
            [ "$_try" -gt 1 ] && log "UDC bound to $_want (confirmed on attempt $_try)"
            return 0
        fi

        if echo "$_want" > "$CFG_ROOT/UDC" 2>/dev/null; then
            log "UDC bind write accepted (attempt $_try)"
        else
            log "UDC bind write returned an error on attempt $_try; re-reading state"
        fi

        sleep 1
        if [ "$(cat "$CFG_ROOT/UDC" 2>/dev/null)" = "$_want" ]; then
            return 0
        fi
        log "  UDC reads '$(cat "$CFG_ROOT/UDC" 2>/dev/null)' after attempt $_try -- retrying"
        sleep 1
    done
    log "ERROR: UDC never reached '$_want' after $_try attempts"
    return 1
}

# Unbind the UDC, verified the same way.
unbind_udc() {
    _try=0
    while [ "$_try" -lt 4 ]; do
        _try=$((_try + 1))
        [ -z "$(cat "$CFG_ROOT/UDC" 2>/dev/null)" ] && return 0
        echo none > "$CFG_ROOT/UDC" 2>/dev/null
        sleep 1
        [ -z "$(cat "$CFG_ROOT/UDC" 2>/dev/null)" ] && return 0
    done
    log "WARN: UDC still reads '$(cat "$CFG_ROOT/UDC" 2>/dev/null)' after $_try unbind attempts"
    return 1
}

# Print the kernel-assigned major:minor for a HID function instance.
# The f_hid configfs instance exposes a `dev` attribute as soon as the
# instance directory exists (the minor is allocated in hidg_alloc_inst, i.e.
# at mkdir time -- NOT at bind time). Empty output means not yet allocated.
hid_func_dev() {
    cat "$1/dev" 2>/dev/null
}

# Resolve a HID function instance's actual /dev node.
#
# Requirement 9: do NOT assume hid.2 maps to /dev/hidg2. The kernel names the
# node "hidg%d" from the *first free slot* returned by ida_simple_get() at
# mkdir time, so today hid.2 does get minor 2 -- but that is a positional
# coincidence of hid.0/hid.1 already holding slots 0 and 1, not a property of
# the directory name. We therefore read the authoritative major:minor out of
# the `dev` attribute and derive the node from it, then confirm the node
# really exists. If it does not, we list every /dev/hidg* node so a mismatch
# is visible rather than silently wrong.
#
# Usage: hid_func_node <function dir>   -> prints node path, or nothing.
hid_func_node() {
    _hm=$(hid_func_dev "$1")
    [ -n "$_hm" ] || return 1
    _minor=${_hm#*:}
    case "$_minor" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ -c "/dev/hidg$_minor" ]; then
        echo "/dev/hidg$_minor"
        return 0
    fi
    # Fall back to scanning, so a ueventd naming difference is detected
    # instead of producing a false negative.
    for _n in /dev/hidg*; do
        [ -c "$_n" ] || continue
        _nhm=$(stat -c '%t:%T' "$_n" 2>/dev/null)
        [ -n "$_nhm" ] || continue
        # compare minor in hex, zero-padded both sides
        _want=$(printf '%x' "$_minor" 2>/dev/null)
        _have=${_nhm#*:}
        if [ "$(printf '%d' "0x$_have" 2>/dev/null)" = "$_minor" ]; then
            echo "$_n"
            return 0
        fi
    done
    return 1
}

# Print every symlink in configs/b.1 as "<basename> <target-basename>".
list_links() {
    for _l in "$CFG_DIR"/*; do
        [ -L "$_l" ] || continue
        _t=$(readlink "$_l" 2>/dev/null)
        echo "$(basename "$_l") $(basename "$_t")"
    done
}

# Print the basename of the link pointing at functions/<name>, or nothing.
link_for_func() {
    for _l in "$CFG_DIR"/*; do
        [ -L "$_l" ] || continue
        _t=$(readlink "$_l" 2>/dev/null)
        if [ "$(basename "$_t")" = "$1" ]; then
            basename "$_l"
            return 0
        fi
    done
    return 1
}

# Decide the next free symlink name, following whatever naming scheme the
# vendor/ROM already uses.
#
# Requirement 8: Qualcomm's USB HAL names these "function0", "function1", ...
# rather than the upstream "f1"/"f2". NetHunter works this out with sed on the
# first link; we do the same thing generically by splitting each link's
# basename into a non-numeric head and a trailing integer, then taking
# max(index)+1. This handles function0 -> function1 and f1 -> f2 alike.
#
# Returns non-zero if there is no existing link to learn the scheme from --
# in that case we refuse to guess rather than invent a name.
choose_link_name() {
    _max=-1
    _prefix=
    _other_prefix=
    for _l in "$CFG_DIR"/*; do
        [ -L "$_l" ] || continue
        _b=$(basename "$_l")
        # split the basename into a non-numeric head and a trailing integer
        _head=$(printf '%s' "$_b" | sed 's/[0-9]\{1,\}$//')
        _digits=$(printf '%s' "$_b" | sed 's/^.*[^0-9]//')
        case "$_digits" in
            ''|*[!0-9]*) continue ;;
        esac
        # only accept names that really are head+digits (no stray digits inside)
        [ "$_head$_digits" = "$_b" ] || continue
        if [ -z "$_prefix" ]; then
            _prefix=$_head
        elif [ "$_head" != "$_prefix" ]; then
            _other_prefix=$_head
        fi
        if [ "$_digits" -gt "$_max" ]; then
            _max=$_digits
        fi
    done
    if [ -z "$_prefix" ] || [ "$_max" -lt 0 ]; then
        return 1
    fi
    if [ -n "$_other_prefix" ]; then
        log "WARN: mixed symlink naming schemes seen ('$_prefix', '$_other_prefix'); using '$_prefix'"
    fi
    echo "${_prefix}$((_max + 1))"
    return 0
}

# Verify that a HID function instance holds exactly the CTAP descriptor.
hid_desc_matches() {
    [ -f "$1/report_desc" ] || return 1
    _a=$($BUSYBOX head -c "$FIDO_DESC_LEN" "$1/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    _b=$($BUSYBOX printf "$FIDO_DESC_ESC" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    [ -n "$_a" ] && [ "$_a" = "$_b" ]
}
