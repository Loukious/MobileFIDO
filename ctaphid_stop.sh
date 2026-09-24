#!/system/bin/sh
#
# ctaphid_stop.sh -- stop the CTAPHID responder.
#
# Sends SIGTERM so the server exits between packets rather than mid-response,
# then waits for it to actually go. Does not touch the USB gadget, so the FIDO
# HID interface stays enumerated and hid.0/hid.1/ADB are unaffected.
#
# Usage:
#   ctaphid_stop.sh              # stop the server
#   ctaphid_stop.sh --unmount    # also remove the chroot's /config bind mount
#   ctaphid_stop.sh --full       # --unmount and revert the gadget entirely
#                                #  (equivalent to the Milestone 1 rollback)

set -u

CHROOT=${CHROOT:-/data/local/nhsystem/kali-arm64}
PIDFILE=${PIDFILE:-$CHROOT/root/ctaphid.pid}

UNMOUNT=0
FULL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --unmount) UNMOUNT=1 ;;
        --full) UNMOUNT=1; FULL=1 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "ctaphid_stop: $*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || die "must run as root"

STOPPED=0

# --- stop the server -------------------------------------------------------

if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        # Confirm it really is our server before signalling: a recycled pid
        # must not be shot at.
        cmdline=$(tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null)
        case "$cmdline" in
            *ctaphid.server*)
                echo "stopping pid $PID"
                kill -TERM "$PID" 2>/dev/null
                for _ in $(seq 1 20); do
                    [ -d "/proc/$PID" ] || break
                    sleep 0.25
                done
                if [ -d "/proc/$PID" ]; then
                    echo "  did not exit on SIGTERM; sending SIGKILL" >&2
                    kill -KILL "$PID" 2>/dev/null
                    sleep 1
                fi
                STOPPED=1
                ;;
            *) echo "pid $PID is not the ctaphid server; leaving it alone" >&2 ;;
        esac
    fi
    rm -f "$PIDFILE"
fi

if [ "$STOPPED" = "0" ]; then
    echo "no server running (no pidfile, or the process was already gone)"
fi

# The server leaves the HID endpoint open; closing it is what the kernel does
# when the process exits. Nothing else needs undoing: the gadget configuration
# was never modified.
if [ -c /dev/hidg2 ]; then
    echo "gadget interface left as-is: /dev/hidg2 still present"
fi

# --- optionally drop the chroot mount --------------------------------------

if [ "$UNMOUNT" = "1" ]; then
    if grep -q " $CHROOT/config " /proc/mounts 2>/dev/null; then
        umount "$CHROOT/config" && echo "unmounted $CHROOT/config"
    fi
fi

# --- optionally revert the gadget ------------------------------------------

if [ "$FULL" = "1" ]; then
    SCRIPT_DIR=$(dirname "$0")
    if [ -x "$SCRIPT_DIR/fido2_rollback.sh" ]; then
        echo "running the Milestone 1 rollback"
        "$SCRIPT_DIR/fido2_rollback.sh" --no-prompt
    else
        echo "fido2_rollback.sh not found next to this script; gadget left as-is" >&2
        exit 1
    fi
fi
