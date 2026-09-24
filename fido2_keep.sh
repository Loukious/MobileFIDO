#!/system/bin/sh
#
# fido2_keep.sh -- confirm the change and stand the watchdog down.
#
# Run this ONLY after you have verified from the Windows side that the device
# enumerated as expected (new VID/PID present, CTAP HID collection with usage
# page 0xF1D0, 64-byte input and output reports) AND that adb reconnected.
#
# If you never run it, the watchdog reverts automatically. That is the
# intended behaviour, not a failure.

. "$(dirname "$0")/fido2_env.sh"

date '+confirmed %Y-%m-%d %H:%M:%S %z' > "$KEEP_FLAG"
log "keep-flag written: $KEEP_FLAG"
log "watchdog will stand down within 5s."
