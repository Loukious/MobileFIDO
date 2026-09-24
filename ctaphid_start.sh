#!/system/bin/sh
#
# ctaphid_start.sh -- start the CTAPHID responder on the phone.
#
# Run as root on Android. This does NOT touch the USB gadget: it adds no
# function, changes no descriptor, and writes nothing under /config. Milestone
# 1 provisioned the gadget; this only talks to it from userspace.
#
# What it does:
#   1. makes ConfigFS visible inside the Kali chroot, read-only
#   2. starts the server detached, in its own cgroup and session, logging to a file
#
# Why the bind mount: the chroot gets its own /dev and /sys but never /config,
# and the server discovers its device node from ConfigFS by design rather than
# assuming /dev/hidg2. The mount is read-only on purpose -- it means the server
# provably cannot alter the gadget it is serving, which keeps the Milestone 1
# guarantee that hid.0/hid.1 and the composite descriptor are untouched.
#
# Usage:
#   ctaphid_start.sh                 # start, detached
#   ctaphid_start.sh --foreground    # stay attached (Ctrl-C to stop)
#   ctaphid_start.sh --log-level DEBUG
#   ctaphid_start.sh --dev           # LOCALHOST-ONLY software credentials;
#                                    # physical Poco F7 Volume Up required
#   ctaphid_start.sh --android       # localhost-only Android Keystore helper;
#                                    # helper app MUST already be running
#
# Stop with ctaphid_stop.sh.

set -u

CHROOT=${CHROOT:-/data/local/nhsystem/kali-arm64}
PKG_DIR=${PKG_DIR:-/root/ctaphid}
# The directory *containing* the ctaphid package. The server is started with
# `-m ctaphid.server`, which resolves the package relative to the working
# directory, so this is where the daemon has to run from -- not PKG_DIR itself.
PKG_PARENT=$(dirname "$PKG_DIR")
LOG=${LOG:-$CHROOT/root/ctaphid.log}
PIDFILE=${PIDFILE:-$CHROOT/root/ctaphid.pid}
DEVICE=${DEVICE:-/dev/hidg2}
HID_FUNC=${HID_FUNC:-/config/usb_gadget/g1/functions/hid.2}

FOREGROUND=0
LOG_LEVEL=INFO
DEV=0
ANDROID=0
while [ $# -gt 0 ]; do
    case "$1" in
        --foreground) FOREGROUND=1 ;;
        --dev) DEV=1 ;;
        --android) ANDROID=1 ;;
        --log-level) shift; LOG_LEVEL=${1:-INFO} ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "ctaphid_start: $*" >&2; exit 1; }

# Find the running server by inspecting /proc.
#
# Two reasons not to use $! or pgrep:
#   * setsid forks, so $! is the pid of setsid -- which has already exited by
#     the time we look -- not of the server it launched.
#   * pgrep -f matches any process whose command line merely *mentions* the
#     pattern, including the adb shell running this very script.
#
# So the command line is matched properly: argv[0] must be a python
# interpreter, and an argument must be ctaphid.server. The candidate list
# comes from a single grep, because opening a subprocess per pid makes the
# scan take minutes on a phone.
find_server_pid() {
    for f in $(grep -l ctaphid.server /proc/[0-9]*/cmdline 2>/dev/null); do
        pid=${f#/proc/}
        pid=${pid%/cmdline}
        # The braces matter: a plain `2>/dev/null` would only silence tr, not
        # the shell's own "can't open" message when a pid vanishes between the
        # grep and this read.
        args=$( { tr '\0' ' ' < "$f"; } 2>/dev/null )
        argv0=${args%% *}
        case "$argv0" in
            */python3|*/python3.*) echo "$pid" ;;
        esac
    done
}

[ "$(id -u)" = "0" ] || die "must run as root"
[ "$DEV" = "1" ] && [ "$ANDROID" = "1" ] && die "--dev and --android are mutually exclusive"

# --- 1. ConfigFS visible in the chroot, read-only -------------------------

if ! grep -q " $CHROOT/config " /proc/mounts 2>/dev/null; then
    mkdir -p "$CHROOT/config" || die "cannot create $CHROOT/config"
    mount --bind /config "$CHROOT/config" || die "bind mount of /config failed"
    # remount read-only; a plain bind would let the server write to the gadget
    mount -o remount,bind,ro "$CHROOT/config" 2>/dev/null
    echo "mounted /config into the chroot (read-only)"
fi

if grep -q " $CHROOT/config configfs ro," /proc/mounts 2>/dev/null; then
    echo "  confirmed read-only: the server cannot modify the gadget"
else
    echo "  WARNING: $CHROOT/config is mounted read-write" >&2
fi

# --- 2. sanity-check the gadget before starting ---------------------------

[ -f "$HID_FUNC/report_length" ] || die "$HID_FUNC not found -- run the Milestone 1 provisioning script first"
REPORT_LENGTH=$(cat "$HID_FUNC/report_length" 2>/dev/null)
[ "$REPORT_LENGTH" = "64" ] || die "$HID_FUNC has report_length=$REPORT_LENGTH, expected 64"

UDC=$(cat /config/usb_gadget/g1/UDC 2>/dev/null)
[ -n "$UDC" ] || die "gadget is not bound to a UDC"

[ -c "$DEVICE" ] || echo "  note: $DEVICE does not exist yet; the server will wait for it"

[ -d "$CHROOT$PKG_DIR" ] || die "$CHROOT$PKG_DIR not found -- push the ctaphid package first"

# --- 3. refuse to start twice ---------------------------------------------

RUNNING=$(find_server_pid | head -n 1)
if [ -n "$RUNNING" ]; then
    die "already running as pid $RUNNING (use ctaphid_stop.sh)"
fi
rm -f "$PIDFILE"

# --- 4. start -------------------------------------------------------------

echo "gadget UDC=$UDC  $HID_FUNC report_length=$REPORT_LENGTH  node=$DEVICE"

DEV_ARGS=""
if [ "$DEV" = "1" ]; then
    DEV_ARGS="--development-store /root/ctap-dev-credentials.json --presence volume-up"
    echo "WARNING: development-only, unencrypted software credential store (localhost RP only)"
    echo "         approve an operation only by physically pressing phone Volume Up"
fi
if [ "$ANDROID" = "1" ]; then
    # Check the package manager's UID; the Python endpoint then verifies the
    # connected AF_UNIX server's SO_PEERCRED. The abstract socket name alone
    # is NOT an authentication mechanism: another app could otherwise bind it.
    APP_UID=$(pm list packages -U org.pocof7.ctap3b 2>/dev/null |
        sed -n 's/^package:org\.pocof7\.ctap3b uid:\([0-9][0-9]*\)$/\1/p' | head -n 1)
    [ -n "$APP_UID" ] || die "org.pocof7.ctap3b not installed; cannot trust Android helper socket"
    [ "$APP_UID" -ge 10000 ] || die "Android helper UID is not an unprivileged app UID"
    DEV_ARGS="--android-helper --android-helper-uid $APP_UID"
    echo "Android helper mode: hardware-key policy must be verified before server starts"
    echo "  On the Poco F7, open the CTAP helper Activity and leave it visible"
    echo "  Helper package UID: $APP_UID (peer credentials validated by Python)"
fi
DAEMON="cd $PKG_PARENT && exec /usr/bin/python3 -u -m ctaphid.server --log-level $LOG_LEVEL $DEV_ARGS"

if [ "$FOREGROUND" = "1" ]; then
    echo "running in the foreground; Ctrl-C to stop"
    chroot "$CHROOT" /bin/sh -c "$DAEMON"
    exit $?
fi

# Escape adbd's cgroup before detaching.
#
# Every process started from an adb shell inherits adbd's cgroup. When init
# restarts adbd -- or the USB stack re-enumerates -- that cgroup is torn down
# and everything in it is killed, which would take the server with it. Moving
# to the root cgroup makes the server independent of adbd's lifetime.
if [ -w /sys/fs/cgroup/cgroup.procs ]; then
    echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null
fi

# setsid for a second, independent reason: the server must not be in the adb
# shell's session, or it dies when that shell exits.
setsid chroot "$CHROOT" /bin/sh -c "$DAEMON" >> "$LOG" 2>&1 < /dev/null &

PID=""
for _ in $(seq 1 20); do
    PID=$(find_server_pid | head -n 1)
    [ -n "$PID" ] && break
    sleep 0.5
done

if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
    echo "$PID" > "$PIDFILE"
    sleep 1
    echo "started, pid $PID"
    echo "log: $LOG"
    echo
    echo "--- first log lines ---"
    tail -n 15 "$LOG" 2>/dev/null
else
    echo "FAILED to start; last log lines:" >&2
    tail -n 30 "$LOG" 2>/dev/null >&2
    rm -f "$PIDFILE"
    exit 1
fi
