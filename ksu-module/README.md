# Poco F7 A17 CTAP3B KernelSU module — safety contract

**Development only.** Module ID is `pocof7_ctap3b`. The module does not
enable USB debugging or activate BiometricPrompt. KernelSU Manager installs
the bundled signed helper APK only if the package is absent; an existing APK
must byte-match the approved build and is **never reinstalled or cleared**.
The user MUST open `org.pocof7.ctap3b` in the foreground before authentication.

## Packaging prerequisite

Package the Python sources as `payload/ctaphid/*.py` in the ZIP. At boot
the module stages this source into **its own** Kali
`/root/.pocof7_ctap3b/ctaphid` package, without overwriting the legacy
`/root/ctaphid`. Runtime packages include the Android backend and server.
The approved signed Android APK is included at `payload/helper.apk` for
first installation; the module never launches it automatically on boot,
background-grants the app, or bypasses biometric consent.

## USB behavior

1. Wait for Android boot completion, inspect exact `g1` link set, UDC,
   live adbd, module-owned journal and HID descriptor.
2. If the already-linked `hid.2` has the verified standard FIDO descriptor
   and ADB is linked, **adopt without changing configfs at all**. This is
   the currently observed Poco F7 state (function0 -> ffs.adb,
   function1 -> hid.2, VID 1209/PID 0001, UDC a600000.dwc3).
   Existing legacy `/data/local/tmp/fido2/state/original.env` and KEEP
   are NEVER modified.
3. If CTAP HID is absent, ONLY a single ADB-only function configuration
   may be modified. Fail closed if MTP/RNDIS/NetHunter Arsenal keyboard,
   mouse or another function is linked, or an unlinked `hid.2` already
   belongs to another tool. No gadget identity/serial/strings/os_desc
   changes and no adbd stop/start.
4. For an eligible writable gadget: snapshot pre-change identity, exact
   function links and hid.0/hid.1 hashes in the module's OWN
   `state/usb-txn`, then arm a detached 30-second watchdog before
   adding the FIDO instance; strictly confirm the UDC was unbound before
   linking. If a HAL race prevents unbinding, never proceed to linking.
   Automatic rollback only unlinks a module-owned FIDO link and instance;
   it refuses to touch a later USB Arsenal mode or missing/changed ADB.
5. **Never globally remount /config.** Current on-device configfs was
   observed as globally read-only, due to a historical bind remount.
   A fresh boot may restore it writable, but if it stays read-only
   provisioning must fail closed. No root remount workaround.

The module starts/supervises the Android-helper CTAPHID daemon, confirms
helper app UID, and will not replace another running CTAPHID server. It
never enables legacy software-backed `--dev` signing. If the helper is
not foregrounded, the daemon may not establish its IPC session; the
supervisor retries without creating or bypassing a biometric prompt.

**Do not assume new VID/PID 1209/0001 after an actual reboot:** the module
intentionally preserves the USB identity provided by the ROM (previously
18d1/4e11 before manual FIDO testing). Windows FIDO HID enumeration
with stock VID/PID has not been verified.

## Operations

KernelSU Manager Action **opens** the Android helper and displays status,
only after the user taps the Action button. CLI from a local root shell:
`sh action.sh open|status|start|stop|rollback`. Explicit `status` is
read-only; `open` launches the visible Activity and does not bypass its
consent/biometric prompt. The `start` action only starts
the daemon; it never provisions the USB gadget from an adb shell.
`stop` stops only the module-owned daemon. Explicit rollback and uninstall
refuse USB rebinding from adbd's service cgroup, to avoid dropping the
only recovery channel. Reboot rebuilds volatile stock configfs.

Shell syntax, library sourcing and offline packaging tests passed. A
**read-only** probe of `usb.sh inspect` and `usb_healthy` on the running Poco F7
confirmed an existing compatible FIDO interface and preserved ADB. There has
been no module installation, phone reboot or boot-time USB re-enumeration test.
