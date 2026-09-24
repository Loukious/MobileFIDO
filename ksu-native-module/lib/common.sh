#!/system/bin/sh
# Sourced only by this module's scripts. POSIX/mksh-compatible.
PATH=/system/bin:/system/xbin:/vendor/bin:/product/bin:/sbin
export PATH
MODDIR=${MODDIR:-/data/adb/modules/pocof7_ctap_native}
STATE=$MODDIR/state
LOG=$STATE/module.log
G=/config/usb_gadget/g1
CFG=$G/configs/b.1
FUNCS=$G/functions
FIDO=$FUNCS/hid.2
NATIVE_BIN=$MODDIR/bin/pocof7-native-ctaphid
BOOT_ID_FILE=/proc/sys/kernel/random/boot_id
WATCHDOG_WINDOW=30

m_log() {
    [ -d "$STATE" ] || mkdir -p "$STATE" 2>/dev/null
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null
    return 0
}
m_fail() { m_log "FAIL: $*"; return 1; }
m_boot_id() { [ -r "$BOOT_ID_FILE" ] && cat "$BOOT_ID_FILE" 2>/dev/null; }
m_init() {
    [ "$(id -u)" = 0 ] || return 1
    mkdir -p "$STATE" || return 1
    chmod 700 "$STATE" 2>/dev/null || return 1
    [ -n "$(m_boot_id)" ] || return 1
}
m_safe_name() {
    case "$1" in ''|*[!a-zA-Z0-9._-]*) return 1 ;; esac
}
m_func_target() {
    [ -L "$1" ] || return 1
    _m_target=$(readlink "$1" 2>/dev/null) || return 1
    case "$_m_target" in
        */functions/*) printf '%s\n' "${_m_target##*/}" ;;
        *) return 1 ;;
    esac
}
m_sha() { sha256sum "$1" 2>/dev/null | cut -d ' ' -f 1; }
m_report() {
    # 34-byte FIDO HID descriptor; octal escapes work with Android mksh printf.
    printf '\006\320\361\011\001\241\001\011\040\025\000\046\377\000\165\010\225\100\201\002\011\041\025\000\046\377\000\165\010\225\100\221\002\300'
}
m_expected_sha() { m_report | sha256sum | cut -d ' ' -f 1; }
m_fido_descriptor_sha() {
    # ConfigFS HID report_desc can read back as a 4096-byte padded attribute
    # even when exactly 34 descriptor bytes were written. The authoritative
    # CTAP descriptor is its first 34 bytes; never hash the padded tail.
    head -c 34 "$FIDO/report_desc" 2>/dev/null | sha256sum | cut -d ' ' -f 1
}
m_fido_valid() {
    [ -d "$FIDO" ] || return 1
    [ "$(cat "$FIDO/protocol" 2>/dev/null)" = 0 ] || return 1
    [ "$(cat "$FIDO/subclass" 2>/dev/null)" = 0 ] || return 1
    [ "$(cat "$FIDO/report_length" 2>/dev/null)" = 64 ] || return 1
    [ "$(cat "$FIDO/no_out_endpoint" 2>/dev/null)" = 0 ] || return 1
    [ "$(m_fido_descriptor_sha)" = "$(m_expected_sha)" ]
}
m_fido_node() {
    [ -r "$FIDO/dev" ] || return 1
    _m_dev=$(cat "$FIDO/dev" 2>/dev/null)
    case "$_m_dev" in *:*) _m_minor=${_m_dev#*:} ;; *) return 1 ;; esac
    case "$_m_minor" in ''|*[!0-9]*) return 1 ;; esac
    [ -c "/dev/hidg$_m_minor" ] || return 1
    printf '%s\n' "/dev/hidg$_m_minor"
}
m_app_uid() {
    pm list packages -U org.pocof7.ctap3b 2>/dev/null |
        sed -n 's/^package:org\.pocof7\.ctap3b uid:\([0-9][0-9]*\)$/\1/p' |
        head -n 1
}
m_server_pid() {
    # Refuse signalling a recycled PID, legacy Kali Python process or another
    # module's native binary. readlink /proc/PID/exe is kernel supplied.
    _m_pid=$1
    case "$_m_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -e "/proc/$_m_pid/exe" ] || return 1
    [ "$(readlink "/proc/$_m_pid/exe" 2>/dev/null)" = "$NATIVE_BIN" ] || return 1
    [ -r "/proc/$_m_pid/cmdline" ] || return 1
    _m_cmd=$(tr '\000' ' ' < "/proc/$_m_pid/cmdline" 2>/dev/null)
    case "$_m_cmd" in
        *' --android-helper-uid '*) return 0 ;;
        *) return 1 ;;
    esac
}
