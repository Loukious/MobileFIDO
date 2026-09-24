#!/system/bin/sh
# CTAPHID Android helper supervisor. No USB gadget writes here.
[ -n "${MODDIR:-}" ] || MODDIR=${0%/lib/*}
. "$MODDIR/lib/common.sh"
. "$MODDIR/lib/usb.sh"
DPID=$STATE/daemon.pid
SPID=$STATE/supervisor.pid

daemon_find_any() {
    for _daemon_f in /proc/[0-9]*/cmdline; do
        [ -r "$_daemon_f" ] || continue
        _daemon_cmd=$(tr '\000' ' ' < "$_daemon_f" 2>/dev/null)
        _daemon_argv0=${_daemon_cmd%% *}
        case "$_daemon_argv0" in
            */python3|*/python3.*) : ;;
            *) continue ;;
        esac
        case "$_daemon_cmd" in
            *' -m ctaphid.server '*) printf '%s\n' "${_daemon_f#/proc/}" | cut -d / -f 1 ;;
        esac
    done
}

daemon_owned_pid() {
    [ -r "$DPID" ] || return 1
    _daemon_pid=$(cat "$DPID" 2>/dev/null)
    m_server_pid "$_daemon_pid" || return 1
    printf '%s\n' "$_daemon_pid"
}

daemon_stop() {
    _daemon_pid=$(daemon_owned_pid) || { rm -f "$DPID"; return 0; }
    kill -TERM "$_daemon_pid" 2>/dev/null
    _daemon_tries=0
    while m_server_pid "$_daemon_pid" && [ "$_daemon_tries" -lt 15 ]; do
        sleep 1
        _daemon_tries=$((_daemon_tries + 1))
    done
    if m_server_pid "$_daemon_pid"; then
        m_log "daemon did not stop; leaving process rather than forced kill"
        return 1
    fi
    rm -f "$DPID"
    m_log "owned CTAPHID server stopped; USB gadget untouched"
}

daemon_mount_config() {
    [ -d "$CHROOT/config" ] || mkdir "$CHROOT/config" || return 1
    if grep -F " $CHROOT/config " /proc/mounts >/dev/null 2>&1; then
        return 0
    fi
    # Deliberately DO NOT remount the bind read-only: on this ROM the legacy
    # remount changed the GLOBAL /config configfs to read-only, breaking
    # USB Arsenal and our own future gadget modifications.
    mount --bind /config "$CHROOT/config" || return 1
    printf '%s\n' "$(m_boot_id)" > "$STATE/owned-config-mount"
    m_log "bound /config to Kali chroot; did not remount /config globally"
}

daemon_stage_payload() {
    [ -f "$MODDIR/payload/ctaphid/server.py" ] ||
        { m_fail "no bundled Python server in payload/ctaphid"; return 1; }
    [ ! -L "$PYPKG_PARENT" ] && [ ! -L "$PYPKG" ] ||
        { m_fail "unsafe symlink in module-owned chroot path"; return 1; }
    mkdir -p "$PYPKG_PARENT" || return 1
    if [ -e "$PYPKG" ] && [ ! -f "$PYPKG_PARENT/.ksu-managed" ]; then
        m_fail "module-owned path occupied by external files; refusing update"
        return 1
    fi
    # Distinct path: NEVER replace the legacy /root/ctaphid manually installed
    # during M2/M3A. Atomic directory swap avoids mixed Python versions.
    _daemon_new=$PYPKG_PARENT/ctaphid-next-$$
    mkdir "$_daemon_new" || return 1
    cp -R "$MODDIR/payload/ctaphid/." "$_daemon_new/" ||
        { m_fail "cannot copy bundled Python package"; return 1; }
    [ -f "$_daemon_new/server.py" ] || return 1
    if [ -e "$PYPKG" ]; then
        _daemon_old=$PYPKG_PARENT/ctaphid-old-$$
        mv "$PYPKG" "$_daemon_old" || return 1
    else
        _daemon_old=
    fi
    if ! mv "$_daemon_new" "$PYPKG"; then
        [ -n "$_daemon_old" ] && mv "$_daemon_old" "$PYPKG"
        return 1
    fi
    printf 'pocof7_ctap3b\n' > "$PYPKG_PARENT/.ksu-managed" || return 1
    if [ -n "$_daemon_old" ]; then
        rm -rf "$_daemon_old"
    fi
    m_log "installed module-owned Python into Kali /root/.pocof7_ctap3b (legacy /root/ctaphid untouched)"
}

daemon_launch() {
    usb_healthy || { m_fail "USB HID/ADB not healthy; not starting daemon"; return 1; }
    [ -f "$PYPKG/server.py" ] || return 1
    _daemon_uid=$(m_app_uid)
    case "$_daemon_uid" in ''|*[!0-9]*) m_fail "Android helper app not installed"; return 1 ;; esac
    [ "$_daemon_uid" -ge 10000 ] ||
        { m_fail "Android helper UID not an unprivileged app"; return 1; }
    _daemon_others=$(daemon_find_any)
    if [ -n "$_daemon_others" ]; then
        _daemon_mine=$(daemon_owned_pid) || _daemon_mine=
        [ "$_daemon_others" = "$_daemon_mine" ] ||
            { m_fail "another ctaphid.server is running; will not replace it"; return 1; }
        return 0
    fi
    [ -d "$CHROOT/root" ] && [ -x "$CHROOT/usr/bin/python3" ] ||
        { m_fail "Kali Python/chroot missing"; return 1; }
    daemon_mount_config || return 1
    # Keep strong software-only --dev mode OFF: Android helper alone can sign.
    # A hidden Android Activity cannot approve BiometricPrompt; do not launch
    # or fake foreground UI. Retry this daemon when the user opens the app.
    _daemon_cmd="cd /root/.pocof7_ctap3b && exec /usr/bin/python3 -u -m ctaphid.server --android-helper --android-helper-uid $_daemon_uid --log-level INFO"
    setsid chroot "$CHROOT" /bin/sh -c "$_daemon_cmd" \
        >> "$STATE/ctaphid.log" 2>&1 </dev/null &
    _daemon_child=$!
    sleep 2
    _daemon_others=$(daemon_find_any)
    [ -n "$_daemon_others" ] &&
        [ "$(printf '%s\n' "$_daemon_others" | wc -l | tr -d ' ')" = 1 ] ||
        { m_log "CTAPHID failed / multiple daemon PIDs; refusing pidfile"; return 1; }
    m_server_pid "$_daemon_others" ||
        { m_fail "new CTAPHID daemon is not Android-helper mode"; return 1; }
    printf '%s\n' "$_daemon_others" > "$DPID"
    m_log "CTAPHID started pid=$_daemon_others helperUID=$_daemon_uid (foreground consent still required)"
}

daemon_supervise() {
    m_init || exit 1
    printf '%s\n' "$$" > "$SPID"
    trap 'rm -f "$SPID"; exit 0' HUP INT TERM
    while [ ! -f "$MODDIR/disable" ] && [ ! -f "$STATE/stopping" ]; do
        # Never compete with NetHunter USB Arsenal or another live USB mode.
        if ! usb_healthy; then
            m_log "gadget changed / CTAP interface unavailable; stopping owned daemon only"
            daemon_stop
            break
        fi
        if [ ! -f "$PYPKG/server.py" ]; then
            m_log "Kali payload missing; supervisor stopping"
            break
        fi
        _daemon_pid=$(daemon_owned_pid)
        if [ -z "$_daemon_pid" ]; then
            rm -f "$DPID"
            daemon_launch || m_log "helper daemon waiting for app/socket or user action"
        fi
        sleep 15
    done
    rm -f "$SPID"
}

case "${0##*/}" in
    daemon.sh)
        case "${1:-}" in
            launch) m_init && daemon_stage_payload && daemon_launch ;;
            supervise) daemon_supervise ;;
            stop) m_init && daemon_stop ;;
            *) echo "usage: daemon.sh launch|supervise|stop" >&2; exit 2 ;;
        esac
        ;;
esac
