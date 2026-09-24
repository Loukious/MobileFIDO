#!/system/bin/sh
# KernelSU Next sources customize.sh AFTER its default ZIP extraction.
# No SKIPUNZIP: the manager handles module staging/update atomically.
# Nothing changes ConfigFS, stops a daemon or edits credential stores.

ksu_fail() {
    abort "! Poco F7 CTAP3B: $*"
}

[ "${KSU:-}" = true ] || ksu_fail "install via KernelSU Next Manager, not recovery"
[ "${ARCH:-}" = arm64 ] || ksu_fail "requires arm64 Poco F7"
[ -n "${MODPATH:-}" ] && [ -d "$MODPATH" ] || ksu_fail "module stage missing"
[ -f "$MODPATH/skip_mount" ] || ksu_fail "skip_mount required (no system overlays)"
[ ! -e "$MODPATH/system" ] || ksu_fail "must not overlay system"

sdk="${API:-$(getprop ro.build.version.sdk 2>/dev/null)}"
[ "$sdk" = 37 ] || ksu_fail "requires Android 17 (API 37), got $sdk"
device="$(getprop ro.product.device 2>/dev/null)"
vendor_device="$(getprop ro.product.vendor.device 2>/dev/null)"
[ "$device" = onyx ] || [ "$vendor_device" = onyx ] ||
    ksu_fail "Poco F7/onyx required, got $device/$vendor_device"

# Every module payload byte is pinned at build time. sha256sums.txt cannot
# cover itself; the builder separately reports the final ZIP's SHA-256.
( cd "$MODPATH" && sha256sum -c sha256sums.txt >/dev/null ) ||
    ksu_fail "module provenance mismatch; refusing installation"

CHROOT=/data/local/nhsystem/kali-arm64
[ -x "$CHROOT/usr/bin/python3" ] || ksu_fail "Kali /usr/bin/python3 missing"
[ -d "$CHROOT/root" ] || ksu_fail "Kali root folder missing"
# Kali's own cryptography is a compiled extension tied to Python/ABI. Do not
# ship a mismatched .so/wheel or use pip at boot. Verify required import now.
chroot "$CHROOT" /usr/bin/python3 -c \
    'import cryptography; from cryptography.hazmat.primitives.asymmetric import ec; import socket, json' \
    >/dev/null 2>&1 || ksu_fail "Kali python cryptography unavailable"

# Install only when absent. Never replace/reinstall the existing app: Android
# Keystore ownership and data (including the enrolled credentials) are tied
# to its UID and signing certificate. An existing APK is left untouched.
installed_apk="$(pm path org.pocof7.ctap3b 2>/dev/null |
    sed -n 's/^package://p' | head -n 1)"
if [ -n "$installed_apk" ]; then
    [ -f "$installed_apk" ] || ksu_fail "installed APK path invalid"
    bundle_sha="$(sha256sum "$MODPATH/payload/helper.apk" | cut -d ' ' -f 1)"
    existing_sha="$(sha256sum "$installed_apk" | cut -d ' ' -f 1)"
    [ "$bundle_sha" = "$existing_sha" ] ||
        ksu_fail "installed helper APK differs from approved signed build; leaving it unchanged"
    ui_print "- Existing CTAP3B app EXACTLY matches bundled APK; no reinstall/data clearing"
else
    ui_print "- Installing bundled signed helper (first install only)"
    pm install "$MODPATH/payload/helper.apk" >/dev/null 2>&1 ||
        ksu_fail "Android helper fresh installation failed"
    pm path org.pocof7.ctap3b 2>/dev/null | grep -q '^package:' ||
        ksu_fail "Android helper absent after package installation"
fi

# The manager already extracted contents. Install-time never copies scripts
# into chroot, starts services, or rewrites credential/private application data.
set_perm_recursive "$MODPATH" 0 0 0755 0644
for script in service.sh action.sh uninstall.sh; do
    set_perm "$MODPATH/$script" 0 0 0755
done
for script in "$MODPATH"/lib/*.sh; do
    [ -f "$script" ] && set_perm "$script" 0 0 0755
done
ui_print "- Authenticated module payload; existing gadget left unchanged"
ui_print "- Bundled signed APK verified against approved installed build"
ui_print "- Credentials must remain in Android app/Kali external stores"
