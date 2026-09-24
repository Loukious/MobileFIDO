#!/system/bin/sh
# Conservative gadget ownership: never edit hid.0/hid.1, VID/PID, USB strings,
# os_desc, serial, ffs.adb, sys.usb.* or adbd. Do not call legacy rollback:
# it restores old links and can overwrite a newer USB Arsenal configuration.
[ -n "${MODDIR:-}" ] || MODDIR=${0%/lib/*}
. "$MODDIR/lib/common.sh"
TX=$STATE/usb-txn

usb_links() {
    for _usb_l in "$CFG"/*; do
        [ -L "$_usb_l" ] || continue
        _usb_name=${_usb_l##*/}
        _usb_target=$(m_func_target "$_usb_l") || return 1
        printf '%s %s\n' "$_usb_name" "$_usb_target"
    done
}

usb_adb_link() {
    _usb_adb=
    for _usb_l in "$CFG"/*; do
        [ -L "$_usb_l" ] || continue
        _usb_target=$(m_func_target "$_usb_l") || return 1
        if [ "$_usb_target" = ffs.adb ]; then
            [ -z "$_usb_adb" ] || return 1
            _usb_adb=${_usb_l##*/}
        fi
    done
    [ -n "$_usb_adb" ] || return 1
    printf '%s\n' "$_usb_adb"
}

usb_fido_link() {
    _usb_found=
    for _usb_l in "$CFG"/*; do
        [ -L "$_usb_l" ] || continue
        _usb_target=$(m_func_target "$_usb_l") || return 1
        if [ "$_usb_target" = hid.2 ]; then
            [ -z "$_usb_found" ] || return 1
            _usb_found=${_usb_l##*/}
        fi
    done
    [ -n "$_usb_found" ] || return 1
    printf '%s\n' "$_usb_found"
}

usb_preflight() {
    [ -d "$G" ] && [ -d "$CFG" ] && [ -d "$FUNCS/ffs.adb" ] ||
        { m_fail "g1 ConfigFS/ADB function missing"; return 1; }
    _usb_udc=$(cat "$G/UDC" 2>/dev/null)
    [ -n "$_usb_udc" ] || { m_fail "UDC unbound; refusing to alter USB"; return 1; }
    case "$_usb_udc" in *[!a-zA-Z0-9._-]*) return 1 ;; esac
    _usb_controller=$(getprop sys.usb.controller 2>/dev/null)
    [ -z "$_usb_controller" ] || [ "$_usb_controller" = "$_usb_udc" ] ||
        { m_fail "UDC changed from vendor controller"; return 1; }
    pidof adbd >/dev/null 2>&1 || { m_fail "adbd is not running"; return 1; }
    _usb_adb=$(usb_adb_link) || { m_fail "exactly one ffs.adb link is required"; return 1; }
    _usb_links=$(usb_links) || { m_fail "unrecognized gadget function symlink"; return 1; }
    [ -n "$_usb_links" ] || return 1
    return 0
}

usb_healthy() {
    usb_preflight || return 1
    m_fido_valid || return 1
    _usb_fido=$(usb_fido_link) || return 1
    [ -n "$_usb_fido" ] || return 1
    m_fido_node >/dev/null || return 1
}

usb_snapshot() {
    [ ! -e "$TX" ] || { m_fail "USB transaction journal already exists"; return 1; }
    mkdir "$TX" || return 1
    chmod 700 "$TX" || return 1
    printf '%s\n' "$(m_boot_id)" > "$TX/boot" || return 1
    printf '%s\n' "$_usb_udc" > "$TX/udc" || return 1
    printf '%s\n' "$_usb_adb" > "$TX/adb-link" || return 1
    printf '%s\n' "$_usb_links" > "$TX/links" || return 1
    for _usb_attr in idVendor idProduct bcdDevice; do
        cat "$G/$_usb_attr" > "$TX/$_usb_attr" || return 1
    done
    # Original fingerprints make it possible to catch changes to Arsenal's
    # inert keyboard/mouse functions without ever modifying those functions.
    for _usb_hid in hid.0 hid.1; do
        [ -e "$FUNCS/$_usb_hid/report_desc" ] || continue
        m_sha "$FUNCS/$_usb_hid/report_desc" > "$TX/$_usb_hid.sha" || return 1
    done
    printf '0\n' > "$TX/owns-function" || return 1
    printf '0\n' > "$TX/owns-link" || return 1
    printf '%s\n' "$_usb_adb" > "$TX/adb-link" || return 1
    printf '%s\n' "$_usb_udc" > "$TX/udc" || return 1
    touch "$TX/pending" || return 1
    m_log "USB journal captured: UDC=$_usb_udc; ADB link=$_usb_adb (identity unchanged)"
}

usb_verify_identity() {
    [ -d "$TX" ] || return 1
    for _usb_attr in idVendor idProduct bcdDevice; do
        [ "$(cat "$G/$_usb_attr" 2>/dev/null)" = "$(cat "$TX/$_usb_attr" 2>/dev/null)" ] ||
            return 1
    done
    for _usb_hid in hid.0 hid.1; do
        [ -r "$TX/$_usb_hid.sha" ] || continue
        [ "$(m_sha "$FUNCS/$_usb_hid/report_desc")" = "$(cat "$TX/$_usb_hid.sha")" ] ||
            return 1
    done
}

usb_watchdog() {
    # Independent deadline if service.sh dies while USB ADB is disconnected.
    _usb_elapsed=0
    while [ "$_usb_elapsed" -lt "$WATCHDOG_WINDOW" ]; do
        [ ! -f "$TX/pending" ] && exit 0
        sleep 1
        _usb_elapsed=$((_usb_elapsed + 1))
    done
    [ -f "$TX/pending" ] || exit 0
    m_log "WATCHDOG: provision did not commit: locally restoring owned link"
    usb_rollback
}

usb_arm_watchdog() {
    command -v setsid >/dev/null 2>&1 || { m_fail "setsid unavailable; no safe watchdog"; return 1; }
    # service.sh is run by KSU late_start, not by adbd. An adb-shell action
    # must never provision, so this process cannot inherit adbd's service cgroup.
    _usb_cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
    case "$_usb_cgroup" in /system/uid_0/*) m_fail "adbd cgroup; refusing gadget writes"; return 1 ;; esac
    setsid /system/bin/sh "$MODDIR/lib/usb.sh" watchdog </dev/null >> "$LOG" 2>&1 &
    _usb_wpid=$!
    printf '%s\n' "$_usb_wpid" > "$TX/watchdog-pid"
    sleep 1
    kill -0 "$_usb_wpid" 2>/dev/null || { m_fail "watchdog failed to arm"; return 1; }
    m_log "USB rollback watchdog armed pid=$_usb_wpid"
}

usb_unbind() {
    # Strict: unlike the older prototype, NEVER continue after an
    # unconfirmed unbind. HAL may race us and rebind automatically.
    printf '\n' > "$G/UDC" 2>/dev/null || return 1
    _usb_retry=0
    while [ "$_usb_retry" -lt 3 ]; do
        [ -z "$(cat "$G/UDC" 2>/dev/null)" ] && return 0
        sleep 1
        _usb_retry=$((_usb_retry + 1))
    done
    return 1
}

usb_bind() {
    _usb_want=$1
    m_safe_name "$_usb_want" || return 1
    _usb_retry=0
    while [ "$_usb_retry" -lt 6 ]; do
        [ "$(cat "$G/UDC" 2>/dev/null)" = "$_usb_want" ] && return 0
        printf '%s\n' "$_usb_want" > "$G/UDC" 2>/dev/null
        sleep 1
        [ "$(cat "$G/UDC" 2>/dev/null)" = "$_usb_want" ] && return 0
        _usb_retry=$((_usb_retry + 1))
    done
    return 1
}

usb_rollback() {
    [ -d "$TX" ] || return 0
    [ "$(cat "$TX/boot" 2>/dev/null)" = "$(m_boot_id)" ] || {
        m_fail "rollback snapshot from older boot; refusing stale restore"
        return 1
    }
    _usb_name=$(cat "$TX/link-name" 2>/dev/null)
    _usb_original=$(cat "$TX/udc" 2>/dev/null)
    _usb_adblink=$(cat "$TX/adb-link" 2>/dev/null)
    m_safe_name "$_usb_original" || return 1
    m_safe_name "$_usb_adblink" || return 1
    [ "$(m_func_target "$CFG/$_usb_adblink")" = ffs.adb ] || {
        m_fail "ADB link changed; refusing to alter current Arsenal gadget"
        return 1
    }
    # If USB Arsenal changed configuration, leave it alone: we ONLY remove
    # the link that this transaction created, never relink stock functions.
    _usb_expected=$(cat "$TX/links" 2>/dev/null)
    _usb_current=$(usb_links) || return 1
    _usb_own=$(cat "$TX/owns-link" 2>/dev/null)
    if [ "$_usb_own" = 1 ] && [ "$_usb_current" != "$_usb_expected" ]; then
        m_safe_name "$_usb_name" || return 1
        [ "$(m_func_target "$CFG/$_usb_name")" = hid.2 ] || {
            m_fail "module-owned link replaced; refusing to unlink"
            return 1
        }
        [ "$_usb_current" = "$(printf '%s\n%s hid.2' "$_usb_expected" "$_usb_name")" ] ||
            { m_fail "foreign function links changed; leave Arsenal untouched"; return 1; }
        usb_unbind || { m_fail "cannot safely unbind for rollback"; return 1; }
        rm "$CFG/$_usb_name" || { usb_bind "$_usb_original"; return 1; }
        m_log "rollback removed only our $_usb_name -> hid.2 link"
    else
        # A provisioned-but-uncommitted function may be inert and unlinked.
        [ "$_usb_current" = "$_usb_expected" ] ||
            { m_fail "foreign link set changed; refusing rollback"; return 1; }
    fi
    if [ "$(cat "$TX/owns-function" 2>/dev/null)" = 1 ]; then
        [ -d "$FIDO" ] && rmdir "$FIDO" 2>/dev/null ||
            m_log "rollback: owned HID instance still referenced; leaving it"
    fi
    usb_bind "$_usb_original" || { m_fail "failed to restore original UDC"; return 1; }
    [ "$(usb_links)" = "$_usb_expected" ] || return 1
    usb_verify_identity || { m_fail "original VID/PID or Arsenal descriptor changed"; return 1; }
    rm -f "$TX/pending"
    touch "$TX/rolled-back"
    m_log "rollback complete: original ADB link, identity and UDC preserved"
}

usb_setup() {
    usb_preflight || return 1
    _usb_fido=$(usb_fido_link 2>/dev/null)
    if [ -n "$_usb_fido" ]; then
        # Adopt pre-existing legacy FIDO prototype read-only, no ownership:
        # uninstall must not break the user's existing CTAP gadget.
        usb_healthy || { m_fail "pre-existing FIDO link is incompatible"; return 1; }
        m_log "adopted existing FIDO hid.2 link $_usb_fido; zero ConfigFS writes"
        return 0
    fi
    # Only *exactly* adb is permitted; all MTP/RNDIS/Arsenal/etc modes are
    # outside our authority. Their functions may never be unlinked or rebound.
    [ "$_usb_links" = "$_usb_adb ffs.adb" ] ||
        { m_fail "non-ADB functions linked: incompatible USB Arsenal mode"; return 1; }
    case "$_usb_adb" in
        function0) _usb_newlink=function1 ;;
        f1) _usb_newlink=f2 ;;
        *) m_fail "unrecognized vendor link naming; refusing to guess"; return 1 ;;
    esac
    [ ! -e "$CFG/$_usb_newlink" ] && [ ! -L "$CFG/$_usb_newlink" ] ||
        { m_fail "proposed HID link name already used"; return 1; }
    [ ! -d "$FIDO" ] ||
        { m_fail "unlinked hid.2 belongs to another tool; refusing to adopt"; return 1; }
    if [ -d "$TX" ]; then
        [ ! -L "$TX" ] || return 1
        _usb_txboot=$(cat "$TX/boot" 2>/dev/null)
        [ -n "$_usb_txboot" ] || { m_fail "unreadable USB journal; manual inspection required"; return 1; }
        if [ "$_usb_txboot" != "$(m_boot_id)" ]; then
            # ConfigFS is volatile across reboot. An old module-only journal
            # must not become the current boot's baseline, and must never
            # trigger a stale rollback against the newly built vendor gadget.
            m_safe_name "$_usb_txboot" || return 1
            rm -rf "$TX" || return 1
            m_log "cleared stale module-only journal from previous boot"
        fi
    fi
    [ ! -e "$TX/pending" ] ||
        { m_fail "previous USB transaction incomplete; manual inspection required"; return 1; }
    [ ! -d "$TX" ] ||
        { m_fail "existing same-boot module journal; refusing to re-provision"; return 1; }
    # Root mounted configfs ro is common after the manual prototype's RO bind.
    # NEVER remount /config or interfere with USB Arsenal's mount namespace.
    [ -w "$FUNCS" ] || { m_fail "ConfigFS readonly; no remount attempt"; return 1; }
    usb_snapshot || return 1
    usb_arm_watchdog || { rm -f "$TX/pending"; return 1; }
    printf '%s\n' "$_usb_newlink" > "$TX/link-name" || return 1
    mkdir "$FIDO" || { m_fail "cannot create hid.2"; return 1; }
    printf '1\n' > "$TX/owns-function"
    printf '0\n' > "$FIDO/protocol" || return 1
    printf '0\n' > "$FIDO/subclass" || return 1
    printf '64\n' > "$FIDO/report_length" || return 1
    printf '0\n' > "$FIDO/no_out_endpoint" || return 1
    m_report > "$FIDO/report_desc" || return 1
    m_fido_valid || { m_fail "CTAP HID descriptor rejected"; return 1; }
    usb_unbind || { m_fail "HAL races UDC unbind; no link added"; return 1; }
    [ -z "$(cat "$G/UDC" 2>/dev/null)" ] || return 1
    # Journal ownership BEFORE adding the USB-visible link, covering a crash.
    printf '1\n' > "$TX/owns-link" || return 1
    ln -s "$FIDO" "$CFG/$_usb_newlink" ||
        { printf '0\n' > "$TX/owns-link"; return 1; }
    usb_bind "$_usb_udc" || { m_fail "UDC bind could not be confirmed"; return 1; }
    usb_healthy || { m_fail "post-bind CTAP/ADB verification failed"; return 1; }
    usb_verify_identity || { m_fail "vendor identity or Arsenal descriptor changed"; return 1; }
    _usb_expected=$(cat "$TX/links" 2>/dev/null)
    [ "$(usb_links)" = "$(printf '%s\n%s hid.2' "$_usb_expected" "$_usb_newlink")" ] ||
        { m_fail "link set changed unexpectedly"; return 1; }
    rm -f "$TX/pending"
    touch "$TX/committed"
    m_log "USB setup committed; preserving ADB + USB VID/PID + legacy state"
    return 0
}

# When sourced by daemon.sh, inherited $1 is e.g. "supervise": never
# interpret the caller's arguments as commands for this library.
case "${0##*/}" in
    usb.sh)
        case "${1:-}" in
            watchdog) usb_watchdog ;;
            rollback) m_init && usb_rollback ;;
            inspect) m_init && usb_preflight && usb_links ;;
            setup) m_init && usb_setup ;;
            *) echo "usage: usb.sh setup|rollback|inspect|watchdog" >&2; exit 2 ;;
        esac
        ;;
esac
