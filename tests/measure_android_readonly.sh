#!/usr/bin/env bash
# Optional, read-only capture for comparing idle and active MobileFIDO runs.
# Usage: bash tests/measure_android_readonly.sh SERIAL [SAMPLES=6] [INTERVAL_SECONDS=10]
# No writes, app launches, permission changes, logcat clearing, or power toggles.
set -euo pipefail

serial="${1:-}"
samples="${2:-6}"
interval="${3:-10}"
if [[ -z "$serial" || "$serial" == -* || ! "$samples" =~ ^[1-9][0-9]*$ || ! "$interval" =~ ^[1-9][0-9]*$ ]]; then
  echo 'Usage: bash tests/measure_android_readonly.sh SERIAL [SAMPLES=6] [INTERVAL_SECONDS=10]' >&2
  exit 2
fi
if (( samples > 360 )); then echo 'Samples must be <= 360' >&2; exit 2; fi
command -v adb >/dev/null || { echo 'adb not found' >&2; exit 2; }
state="$(adb -s "$serial" get-state 2>/dev/null | tr -d '\r' || true)"
if [[ "$state" != device ]]; then echo 'Specified adb device is not ready' >&2; exit 2; fi

echo "# device=$serial samples=$samples interval_seconds=$interval"
echo '# Read-only snapshots; battery current is vendor dependent and may be absent.'
for (( i=1; i<=samples; i++ )); do
  printf '\n===== sample %d/%d host_utc=%s =====\n' "$i" "$samples" "$(date -u +%FT%TZ)"
  adb -s "$serial" shell 'date; cat /proc/loadavg; cat /proc/stat | head -n 2; dumpsys battery | grep -Ei "level:|temperature:|voltage:|status:|health:"; dumpsys thermalservice | head -n 65; for f in /sys/class/power_supply/battery/current_now /sys/class/power_supply/battery/charge_counter /sys/class/power_supply/battery/temp; do if [ -r "$f" ]; then printf "%s=" "$f"; cat "$f"; fi; done; ps -A -o PID,NAME,%CPU 2>/dev/null | grep -Ei "ctaphid|pocof7|mobilefido|PID" | head -n 20 || true'
  if (( i < samples )); then sleep "$interval"; fi
done
