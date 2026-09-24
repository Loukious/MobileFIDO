# Native CTAPHID for Poco F7 / Android 17

Standalone Rust USB CTAPHID transport and CTAP2 client for the existing
`org.pocof7.ctap3b` AndroidKeyStore helper. **No Kali, chroot, NetHunter, Python,
private-key store, or software-signing fallback.** This is a development FIDO
device and its AAGUID is not a certified authenticator model.

## Source boundaries

- `src/protocol.rs`: bounded 64-byte CTAPHID packet framing/reassembly,
  channels, INIT, PING, CBOR, CANCEL, KEEPALIVE and ERROR. Up to eight
  channels/workers; 5s stalled message timeout, 30s idle channel timeout,
  70s CBOR execution deadline; atomic cancellation and globally unique
  worker-job numbers so old responses cannot escape a USB reset.
- `src/transport.rs`: sole file allowed to open `/dev/hidgN`.
  Read-only ConfigFS discovery requires exact FIDO 34-byte descriptor,
  protocol/subclass 0, report length 64, OUT endpoint present, linked
  function and matching kernel device major:minor. ConfigFS may return
  4096 bytes padded after the 34-byte descriptor; only first 34 are
  compared. It never opens an unidentified keyboard/mouse HID endpoint.
- `src/backend.rs`: Android helper IPC owned by the Android-backend worker.
  Verifies helper app UID with kernel `SO_PEERCRED`, validates rooted
  canonical ASCII DNS RP-bound CTAP2 arguments, CBOR and ES256 responses;
  legacy `localhost` remains supported; no signing key
  is created or used in Rust.
  The 4.5.0-dev GetInfo accurately omits `clientPin` (not supported), reports
  `rk=true` only with the new RP-bound Android account-chooser handshake,
  and enforces hardware per-use `uv=true`. As a `FIDO_2_0` authenticator it rejects
  makeCredential's CTAP2.1-only explicit `options.up`.
- `src/main.rs`: one USB-owning event loop, bounded cancellable Android
  IPC worker threads, fixed HID report writes, watchdog/timeouts and
  reconnection with all old channels invalidated.

## CLI ABI for separate KernelSU module

```sh
bin/pocof7-native-ctaphid \
  --android-helper-uid <PM_INSTALLED_APP_UID> \
  --configfs /config/usb_gadget/g1/functions/hid.2 \
  --hid /dev/hidg2 \
  --socket ctaphid-m3b-v1
```

`--app-uid` is an alias for `--android-helper-uid`.
`--configfs` accepts the gadget root or a `functions/hid.N`
directory; the latter is normalized to the root. `--hid` is optional,
but when specified must match **verified** ConfigFS discovery; it never
bypasses descriptor/rdev checks. `--check` performs read-only ConfigFS
and node discovery without opening USB or connecting to Android.
`--self-test` checks static constants and does not access the phone.
`--help` is offline.

### Diagnosing Windows "plug your security key" without changing USB VID/PID

Add **`--trace-hid`** to the native responder CLI and inspect its own
stderr/module log after Windows attempts WebAuthn. Tracing is opt-in; it
records only report direction, 64-byte report counts, session channel ID,
CTAPHID command, declared length or continuation sequence, poll/read/write
error class and aggregate RX/TX counts every five seconds. **It never logs
INIT nonce, PING body, CBOR bytes, credential ID, client data, signature or
private key material.**

- `TRACE-HID heartbeat rx_reports=0 tx_reports=0`: Windows enumerated the
  FIDO usage page but did not send CTAPHID_INIT to this endpoint. Check
  Windows device selection/interface ownership before changing USB identity.
- `RX ... cmd=INIT` without `TX ... cmd=INIT`: inspect protocol errors
  and gadget write errors. A successful TX confirms only that the kernel
  accepted a report, not that Windows actually received it.
- `RX INIT` + `TX INIT` then `RX CBOR`: Windows has reached the native
  CTAP handshake and the next step is the Android backend/UI.

The native transport does **not** rewrite USB VID/PID, and this trace does
not prove stock VID 18d1/PID 4e11 caused the WebAuthn prompt.

## Host validation and cross-build

Rust 1.98.1 and Android NDK r30 were used. Host `cargo test` passes
15 unit tests (protocol, transport and Android mock IPC), including
Windows `up=false` preflight behavior; host CLI `--self-test` passes.
To build for the Poco F7 (Android API 37):

```sh
cargo build --release --target aarch64-linux-android
```

Point Cargo's aarch64 linker at the NDK's
`aarch64-linux-android37-clang`; a working host C linker is also needed
for Rust build scripts. Output:
`target/aarch64-linux-android/release/pocof7-native-ctaphid`, an ARM64
PIE ELF with interpreter `/system/bin/linker64`.

**No Android device execution, USB gadget mutations, install or reboot
were performed by the native transport worker.** Compilation, mock
tests and ELF inspection do not establish end-to-end USB enumeration or
biometric operation, which need a separately authorized runtime test.
