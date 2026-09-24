#!/system/bin/sh
# Installed by KernelSU Next Manager only. No USB gadget or daemon changes
# during installation. Reboot activates this module's late_start service.

native_abort() { abort "! Standalone CTAPHID: $*"; }

[ "${KSU:-}" = true ] || native_abort "install through KernelSU Next Manager"
[ "${ARCH:-}" = arm64 ] || native_abort "requires 64-bit ARM Android"
[ -n "${MODPATH:-}" ] && [ -d "$MODPATH" ] || native_abort "staging directory missing"
[ -f "$MODPATH/skip_mount" ] && [ ! -e "$MODPATH/system" ] ||
    native_abort "must not overlay Android system"

native_sdk=${API:-$(getprop ro.build.version.sdk 2>/dev/null)}
case "$native_sdk" in ''|*[!0-9]*) native_abort "invalid Android API level" ;; esac
[ "$native_sdk" -ge 31 ] || native_abort "requires Android 12 or newer"

( cd "$MODPATH" && sha256sum -c sha256sums.txt >/dev/null ) ||
    native_abort "ZIP payload integrity check failed"

NATIVE="$MODPATH/bin/pocof7-native-ctaphid"
[ -f "$NATIVE" ] || native_abort "missing native arm64 CTAPHID responder"
MOBILEFIDO_RELEASE_CERT_SHA=c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da
MOBILEFIDO_LEGACY_DEV_CERT_SHA=3f133472fa0066963cc16ae19a6250e275e7f0f8265589dc5a0b05f746d20da2
. "$MODPATH/lib/apk_signer.sh" || native_abort "cannot load APK signer verifier"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$NATIVE" 0 0 0755
for native_file in service.sh action.sh uninstall.sh; do
    set_perm "$MODPATH/$native_file" 0 0 0755
done
for native_file in "$MODPATH"/lib/*.sh; do
    [ -f "$native_file" ] && set_perm "$native_file" 0 0 0755
done

"$NATIVE" --self-test >/dev/null 2>&1 ||
    native_abort "native responder cannot execute or failed self-test"

native_bundle_signer="$(native_apk_signer_sha256 "$MODPATH/payload/helper.apk")"
[ "$native_bundle_signer" = "$MOBILEFIDO_RELEASE_CERT_SHA" ] ||
    native_abort "bundled Android helper signer is not the pinned MobileFIDO release certificate"

# Installed app/private StrongBox keys are tied to the installed package and
# signing identity. Never force reinstall, uninstall, clear or migrate data.
native_installed="$(pm path org.pocof7.ctap3b 2>/dev/null |
    sed -n 's/^package://p' | head -n 1)"
if [ -n "$native_installed" ]; then
    [ -f "$native_installed" ] || native_abort "installed helper APK path is invalid"
    native_bundle="$(sha256sum "$MODPATH/payload/helper.apk" | cut -d ' ' -f 1)"
    native_existing="$(sha256sum "$native_installed" | cut -d ' ' -f 1)"
    native_existing_signer="$(native_apk_signer_sha256 "$native_installed")"
    [ -n "$native_bundle" ] && [ -n "$native_existing" ] ||
        native_abort "unable to verify existing signed helper"
    case "$native_existing_signer" in
        "$MOBILEFIDO_RELEASE_CERT_SHA") ;;
        "$MOBILEFIDO_LEGACY_DEV_CERT_SHA")
            native_abort "legacy development signer detected; automatic signer migration is refused to protect app data"
            ;;
        *) native_abort "installed helper signer is not the pinned MobileFIDO release certificate" ;;
    esac
    if [ "$native_bundle" = "$native_existing" ]; then
        ui_print "- Existing release-signed helper already current; app data untouched"
    else
        native_uid="$(pm list packages -U org.pocof7.ctap3b 2>/dev/null |
            sed -n 's/^package:org\.pocof7\.ctap3b uid:\([0-9][0-9]*\)$/\1/p' | head -n 1)"
        case "$native_uid" in ''|*[!0-9]*) native_abort "cannot verify existing helper UID" ;; esac
        pm install -r "$MODPATH/payload/helper.apk" >/dev/null 2>&1 ||
            native_abort "release-signed helper update failed; original app data untouched"
        native_after="$(pm path org.pocof7.ctap3b 2>/dev/null |
            sed -n 's/^package://p' | head -n 1)"
        [ -f "$native_after" ] &&
            [ "$(sha256sum "$native_after" | cut -d ' ' -f 1)" = "$native_bundle" ] ||
            native_abort "updated helper APK did not match verified bundle"
        [ "$(native_apk_signer_sha256 "$native_after")" = "$MOBILEFIDO_RELEASE_CERT_SHA" ] ||
            native_abort "updated helper signer changed unexpectedly"
        native_new_uid="$(pm list packages -U org.pocof7.ctap3b 2>/dev/null |
            sed -n 's/^package:org\.pocof7\.ctap3b uid:\([0-9][0-9]*\)$/\1/p' | head -n 1)"
        [ "$native_uid" = "$native_new_uid" ] ||
            native_abort "installed helper UID changed unexpectedly"
        ui_print "- Updated release-signed helper with same package/UID; preserved StrongBox credentials"
    fi
else
    pm install "$MODPATH/payload/helper.apk" >/dev/null 2>&1 ||
        native_abort "first-time Android helper installation failed"
    native_after="$(pm path org.pocof7.ctap3b 2>/dev/null | sed -n 's/^package://p' | head -n 1)"
    [ -f "$native_after" ] || native_abort "Android helper absent after installation"
    [ "$(native_apk_signer_sha256 "$native_after")" = "$MOBILEFIDO_RELEASE_CERT_SHA" ] ||
        native_abort "installed helper signer is not the pinned MobileFIDO release certificate"
    ui_print "- Installed approved signed Android helper for first use"
fi

ui_print "- Native CTAPHID: no Kali/NetHunter/Python dependency"
ui_print "- Existing USB gadget and other modules untouched during installation"
ui_print "- For migration disable old pocof7_ctap3b module BEFORE reboot"
ui_print "- Allow notifications once; after subsequent reboot FGS auto-starts on first user unlock"
ui_print "- Subsequent requests: tap approval notification, then fingerprint"
