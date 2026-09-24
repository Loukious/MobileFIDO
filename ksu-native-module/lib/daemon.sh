#!/system/bin/sh
# Android native CTAPHID only. No NetHunter, Kali, Python, chroot or bind mounts.
[ -n "${MODDIR:-}" ] || MODDIR=${0%/lib/*}
. "$MODDIR/lib/common.sh"
. "$MODDIR/lib/usb.sh"
DPID=$STATE/daemon.pid
SPID=$STATE/supervisor.pid

daemon_owned_pid() {
    [ -r "$DPID" ] || return 1
    _native_pid=$(cat "$DPID" 2>/dev/null)
    m_server_pid "$_native_pid" || return 1
    printf '%s\n' "$_native_pid"
}

daemon_find_owned() {
    # setsid(1) may fork when the launcher is a session/group leader; do not
    # assume shell $! is the final ELF PID. A readlink on EVERY /proc/PID/exe
    # can take >20s on this phone after boot; first enumerate names in ONE ps
    # invocation, then verify only exact native candidates via kernel exe and
    # root-owned argv in m_server_pid. Unverified or spoofed names are ignored.
    ps -A -o PID,NAME 2>/dev/null | while read -r _native_candidate _native_name; do
        [ "$_native_name" = pocof7-native-ctaphid ] || continue
        m_server_pid "$_native_candidate" && printf '%s\n' "$_native_candidate"
    done
}

daemon_helper_socket() {
    # The Android app starts its own service after the user is unlocked.
    # Waiting for the existing root-only abstract listener is read-only:
    # NEVER use root am start/-foreground-service or launch the Activity.
    # Presence is only a readiness hint; native SO_PEERCRED authenticates the
    # actual peer UID before it sends any getInfo/signing request.
    [ -r /proc/net/unix ] &&
        grep -q ' @ctaphid-m3b-v1$' /proc/net/unix 2>/dev/null
}

daemon_conflict() {
    # Never bind /dev/hidgN alongside a legacy Python CTAPHID server or an
    # unowned native/tracing responder. A separate tr process for every
    # /proc/PID/cmdline took tens of seconds on Android 17 at cold boot;
    # scan one ps snapshot instead, then verify exact module-owned PIDs via
    # /proc/PID/exe. Never signal or adopt a competing responder.
    ps -A -o PID,ARGS 2>/dev/null | (
        while read -r _native_p _native_cmd; do
            case "$_native_p" in ''|*[!0-9]*) continue ;; esac
            case "$_native_cmd" in
                *' -m ctaphid.server '*|*' -m ctaphid.server'|\
                *'pocof7-native-ctaphid '*|*'ctap-trace '*)
                    m_server_pid "$_native_p" && continue
                    m_log "another CTAPHID responder may own the USB HID interface (pid=$_native_p)"
                    exit 0 ;;
            esac
        done
        exit 1
    )
}

daemon_stop() {
    _native_pid=$(daemon_owned_pid) || { rm -f "$DPID"; return 0; }
    kill -TERM "$_native_pid" 2>/dev/null || return 1
    _native_tries=0
    while m_server_pid "$_native_pid" && [ "$_native_tries" -lt 15 ]; do
        sleep 1
        _native_tries=$((_native_tries + 1))
    done
    m_server_pid "$_native_pid" && { m_fail "native responder did not stop"; return 1; }
    rm -f "$DPID"
    m_log "native responder stopped; ADB and gadget unchanged"
}

daemon_launch() {
    usb_healthy || { m_fail "USB FIDO HID/ADB not ready"; return 1; }
    [ -x "$NATIVE_BIN" ] || { m_fail "native arm64 responder missing"; return 1; }
    [ ! -e /data/adb/modules/pocof7_ctap3b ] ||
        [ -e /data/adb/modules/pocof7_ctap3b/disable ] ||
        { m_fail "previous Kali-based module is active; disable it first"; return 1; }
    _native_uid=$(m_app_uid)
    case "$_native_uid" in ''|*[!0-9]*) m_fail "Android helper UID unavailable"; return 1 ;; esac
    [ "$_native_uid" -ge 10000 ] || return 1
    _native_mine=$(daemon_owned_pid) || _native_mine=
    if [ -n "$_native_mine" ]; then
        m_log "native responder already running pid=$_native_mine"
        return 0
    fi
    # If supervisor died between spawning native and writing daemon.pid,
    # adopt the *same module-owned executable* instead of launching a second
    # reader of the same USB HID endpoint. Never signal or adopt unrelated
    # responders or ambiguous multiple candidates.
    _native_existing=$(daemon_find_owned)
    case "$_native_existing" in
        '') ;;
        *'
'*) m_fail "multiple module-owned native responders; refusing duplicate launch"; return 1 ;;
        *)
            printf '%s\n' "$_native_existing" > "$DPID" || return 1
            m_log "recovered existing native responder pid=$_native_existing"
            return 0 ;;
    esac
    daemon_conflict && { m_fail "legacy/other responder active; no takeover"; return 1; }
    daemon_helper_socket ||
        { m_fail "trusted helper listener not yet available; app boot receiver must start foreground service after unlock"; return 1; }
    _native_node=$(m_fido_node) || return 1
    m_log "starting standalone responder appUID=$_native_uid FIDO=$_native_node"
    setsid "$NATIVE_BIN" --android-helper-uid "$_native_uid" \
        --hid "$_native_node" --configfs "$FIDO" --socket ctaphid-m3b-v1 \
        >> "$STATE/native.log" 2>&1 </dev/null &
    sleep 2
    _native_child=$(daemon_find_owned)
    case "$_native_child" in ''|*'
'*)
        m_fail "native responder failed startup; inspect $STATE/native.log"
        return 1 ;;
    esac
    printf '%s\n' "$_native_child" > "$DPID" || return 1
    m_log "native responder running pid=$_native_child (helper notification tap and biometric approve)"
}

daemon_supervise() {
    m_init || exit 1
    printf '%s\n' "$$" > "$SPID"
    trap 'rm -f "$SPID"; exit 0' HUP INT TERM
    _native_waiting_socket=0
    _native_usb_unavailable=0
    while [ ! -f "$MODDIR/disable" ] && [ ! -f "$STATE/stopping" ]; do
        # Onyx's USB HAL temporarily unbinds UDC when the cable is unplugged.
        # The FIDO ConfigFS link and /dev/hidgN can later return unchanged,
        # WITHOUT KernelSU running service.sh again. Dropping out of this
        # supervisor permanently therefore strands Chrome's next CTAPHID_INIT.
        # Cancel the old operation by stopping only our responder; retain the
        # supervisor so reconnect can start a FRESH CTAP session. Never replay
        # an old request or sign again without a new BiometricPrompt.
        if [ -z "$(cat "$G/UDC" 2>/dev/null)" ] || ! usb_healthy; then
            if [ "$_native_usb_unavailable" != 1 ]; then
                m_log "USB FIDO gadget unavailable; cancelling current CTAP and waiting for reconnect"
                _native_usb_unavailable=1
            fi
            daemon_stop || m_log "waiting for module-owned responder to stop"
            sleep 2
            continue
        fi
        if [ "$_native_usb_unavailable" = 1 ]; then
            m_log "USB FIDO gadget restored; accepting new host CTAP requests"
            _native_usb_unavailable=0
        fi
        _native_running=$(daemon_owned_pid) || _native_running=
        if [ -z "$_native_running" ]; then
            if ! daemon_helper_socket; then
                if [ "$_native_waiting_socket" != 1 ]; then
                    m_log "waiting for Android helper boot/unlock listener (no automatic Activity launch)"
                    _native_waiting_socket=1
                fi
                # Promptly notice ACTION_USER_UNLOCKED / BOOT_COMPLETED FGS
                # readiness without spawning repeated doomed daemon attempts.
                sleep 3
                continue
            fi
            if [ "$_native_waiting_socket" = 1 ]; then
                m_log "Android helper listener appeared; native startup may proceed"
            fi
            _native_waiting_socket=0
            rm -f "$DPID"
            daemon_launch || m_log "waiting for compatible USB gadget and Android helper"
        fi
        sleep 15
    done
    rm -f "$SPID"
}

case "${0##*/}" in
    daemon.sh)
        case "${1:-}" in
            launch) m_init && daemon_launch ;;
            supervise) daemon_supervise ;;
            stop) m_init && daemon_stop ;;
            *) echo "usage: daemon.sh launch|supervise|stop" >&2; exit 2 ;;
        esac ;;
esac
