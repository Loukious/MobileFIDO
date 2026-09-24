# Milestone 2 — a minimal CTAPHID authenticator responder

The Poco F7 now answers CTAP HID requests from Windows. A userspace daemon reads
64-byte HID reports from the FIDO endpoint Milestone 1 provisioned, reassembles
and parses CTAPHID messages, and frames replies back — enough for Microsoft's
and Yubico's own client library to discover the device, allocate a channel, run
PING, and retrieve `authenticatorGetInfo` over `CTAPHID_CBOR`.

**Milestone completion criterion — met.** Yubico's python-fido2, running on
Windows against the real USB device, discovers VID `0x1209` / PID `0x0001`,
completes INIT, and decodes a valid `authenticatorGetInfo` response:
**40 assertions passed, 0 failed**, across four consecutive runs.

Nothing here generates credentials or performs authentication. `makeCredential`,
`getAssertion`, ClientPIN and credential management are all refused by design —
see [What is deliberately not implemented](#what-is-deliberately-not-implemented).

---

## Architecture

The implementation is split so the protocol work is testable without hardware
and reusable outside Kali. The rule is that exactly **one** module touches the
device, and the protocol modules never import it.

| Module | Responsibility | Touches hardware |
|---|---|---|
| `ctaphid/constants.py` | Protocol constants and enums. No logic. | no |
| `ctaphid/framing.py` | Packet framing: parse a 64-byte report, reassemble a message, build response packets. Pure bytes. | no |
| `ctaphid/cbor.py` | Minimal canonical CBOR encoder/decoder (no `cbor2` in Kali). | no |
| `ctaphid/channels.py` | Channel table, allocation, expiry, eviction. | no |
| `ctaphid/backend.py` | The authenticator itself — what a command *means*. | no |
| `ctaphid/server.py` | The main loop: read, dispatch, respond, recover. | via an injected transport |
| `ctaphid/transport.py` | **The only module that opens a device.** ConfigFS discovery and `/dev/hidgN` I/O. | yes |

`server.py` talks to a `HidGadgetTransport` it obtains from one overridable
method, `_open_transport()`. Substituting a different transport is what lets
`tests/test_offline.py` drive the real server through a loopback and exercise
every protocol path with no phone attached.

**Why this matters for the next milestone.** `backend.py` is the seam where an
Android Kotlin/Java authenticator plugs in. It is a plain interface over bytes:
`GetInfoBackend` today, a credential backend later. The protocol half
(`framing.py`, `constants.py`, and the reassembly in `server.py`) is directly
portable, and nothing about it assumes Python, Kali, or Linux — only that
something hands it 64-byte reports. See
[Porting to Android](#porting-to-android).

---

## Running it

```sh
# on the phone, as root
sh ctaphid_start.sh                 # start detached; log to /root/ctaphid.log
sh ctaphid_start.sh --foreground    # stay attached, Ctrl-C to stop
sh ctaphid_start.sh --log-level DEBUG

sh ctaphid_stop.sh                  # stop the daemon (leaves the gadget alone)
sh ctaphid_stop.sh --unmount        # also drop the chroot's /config bind mount
```

The start script renders ConfigFS visible inside the Kali chroot with a
**read-only** bind mount. That is deliberate: the server needs `/config` to
discover which `hid.N` function is really the FIDO one, and a read-only mount
means the server *provably cannot* alter the gadget it is serving. The Milestone
1 guarantee that `hid.0`, `hid.1` and the composite descriptor are untouched is
enforced by the mount, not by good intentions.

`--device` overrides the discovery result if you ever need to point it
elsewhere; by default it discovers the node from ConfigFS. On this device
`hid.0` and `hid.1` exist as function directories but are not linked into the
active configuration, so they have no device node — discovery skips them and
finds `hid.2` → `/dev/hidg2` on its own. Hard-coding `/dev/hidg2` would have
worked by luck here and broken the moment the function order changed.

---

## Protocol behaviour

### CTAPHID_INIT

Sent on the broadcast channel `0xFFFFFFFF` with an 8-byte nonce. The reply goes
out **on the channel the request arrived on** — broadcast, for a broadcast INIT
— and the newly allocated channel ID travels *inside* the payload. This is not
a stylistic choice: python-fido2 checks the reply's channel against the one it
sent to, and a host learns its new ID by reading it out of the body.

Measured on the wire (`--traffic`, elevated run):

```
SEND: ffffffff 86 0008 ee8557d34de3402c
RECV: ffffffff 86 0011 ee8557d34de3402c 5ab7fc8f 02 00 01 00 04
      └ cid ──┘ │  │len │  nonce (echoed)  │new id │  │  │  │  └ capabilities 0x04
                │  └ 17 bytes             └ 4 bytes│  │  └ build 0
                └ 0x86 = TYPE_INIT | CTAPHID_INIT  │  └ minor 1
                                                   └ major 0
                                              protocol version 2
```

Verified field by field: the nonce is echoed byte for byte, the channel ID is
new and non-zero, the protocol version is 2, and capabilities is `0x04` —
CBOR, and nothing else. WINK and LOCK are **not** advertised and are refused if
sent anyway.

**Resynchronisation.** INIT on a channel that already exists does *not* allocate
a second one; the reply repeats that same channel ID. This is what a host sends
after losing track of a transaction, and allocating a fresh ID there would
strand it — it is still listening on the old one.

**INIT on a channel that was never allocated** is an error, not an implicit
allocation. A host may only obtain a channel through broadcast.

### CTAPHID_PING

The payload is returned verbatim, which tests the transport with no CBOR or
authentication in the way. All sizes pass, including the maximum:

| Case | Payload | Packets |
|---|---|---|
| empty | 0 B | 1 |
| small | 1 B | 1 |
| exactly fills one packet | 57 B | 1 |
| one continuation | 58 B | 2 |
| several continuations | 1000 B | 17 |
| **maximum message** | **7609 B** | **129** |

The maximum is `57 + 128 × 59 = 7609` bytes: 57 in the initialization packet,
then up to 128 continuation packets of 59 bytes each. 50 sequential PINGs on
one channel also pass, so the channel is reusable and nothing leaks per request.

### CTAPHID_CBOR → authenticatorGetInfo

Command byte `0x04`. The response carries a **leading status byte** — `0x00` for
CTAP2_OK — followed by canonical CBOR. Omitting that byte makes a client read
the CBOR map header as an error code, which is exactly the bug the offline
harness caught before any hardware was involved (`0xa5` was being interpreted
as CTAP error `0xA5`).

```
RECV: 5ab7fc8f 90 0042 00 a5 ...
      └ cid ──┘ │  │len │  └ status byte, then CBOR map(5)
                └ 0x90 = TYPE_INIT | CTAPHID_CBOR
                       └ 66 bytes total, spanning 2 packets
```

The 66-byte response, decoded:

| Field | Key | Value |
|---|---|---|
| `versions` | 1 | `["FIDO_2_0"]` |
| `aaguid` | 3 | `506f636f46372d43544150322d444556` (16 bytes) |
| `options` | 4 | `{"rk": false, "up": false, "uv": false, "clientPin": false}` |
| `maxMsgSize` | 5 | 7609 |
| `transports` | 9 | `["usb"]` |

python-fido2 runs with `strict_cbor=True` by default, which decodes the payload,
re-encodes it, and compares the bytes. Passing that check means the hand-rolled
encoder emits genuinely canonical CBOR — shortest-form integers and lengths,
map keys sorted by their encoded bytes — and not merely something that happens
to decode.

### Error handling

Every case is answered rather than ignored, and the channel survives all of them.

| Condition | Response |
|---|---|
| Unsupported CTAPHID command (WINK, LOCK, MSG, vendor `0x40`) | `ERR_INVALID_CMD` |
| Non-INIT command on the broadcast channel | `ERR_INVALID_CHANNEL` |
| Packet for a channel that was never allocated | `ERR_INVALID_CHANNEL` |
| Continuation with no transaction in progress | `ERR_INVALID_SEQ` |
| Continuation with the wrong sequence number | `ERR_INVALID_SEQ` |
| Declared length above the maximum message size | `ERR_INVALID_LEN` |
| INIT with a nonce that is not 8 bytes | `ERR_INVALID_LEN` |
| Transaction that stops making progress | `ERR_MSG_TIMEOUT` |
| Unsupported CTAP2 command byte | status `0x01`, CTAP2_ERR_INVALID_COMMAND |

`CTAPHID_CANCEL` discards the in-flight message on that channel and produces no
response, as the specification requires.

**No deadlocks.** Reads use a bounded `select` timeout, so the loop keeps
turning when the host goes quiet. A stalled transaction is expired and answered
with `ERR_MSG_TIMEOUT` rather than left hanging — python-fido2's read has no
timeout of its own, so silence would block it forever. Writes have their own
deadline, and a write that cannot complete is treated as a disconnect rather
than retried indefinitely.

---

## Results on real hardware

Windows 10, elevated, against the live daemon. Four consecutive runs, each
**40 passed / 0 failed**.

```
[1] Device discovery        report_size_in/out = 64, product name present
[2] CTAPHID_INIT            protocol version 2, capabilities 0x04, nonce echoed
[3] CTAPHID_PING            0, 1, 57, 58, 1000 and 7609 bytes — all exact
[4] Repeatability           50 sequential PINGs on one channel
[5] authenticatorGetInfo    decodable, FIDO_2_0, 16-byte AAGUID, usb transport
[6] Error handling          all CTAPHID and CTAP2 refusals, channel still usable
[7] Reconnect               close/reopen, fresh INIT, PING and GetInfo work
```

Note `report_size_in/out = 64`: python-fido2 subtracts the report ID byte from
the HID capabilities Windows reports, so 64 here means Windows reported 65-byte
reports — a full 64-byte CTAPHID packet plus the report ID. A 63 would have
meant a framing mismatch on every packet, so it is asserted explicitly.

### The Windows elevation requirement

**The Windows client must run as Administrator**, and this is not a quirk of our
device. Since Windows 10 1903 the OS denies raw CTAPHID access to FIDO HID
devices from non-Administrator processes — confirmed here as Win32 **error 5,
ERROR_ACCESS_DENIED**, on the exact interface path, for both access mode 0 and
`GENERIC_READ|WRITE`. It applies to every authenticator, commercial security
keys included. Without elevation python-fido2 reports *no devices at all*,
because the handle it uses to read the report descriptor cannot be opened; the
client detects this and says so rather than printing a misleading "no device
found".

### A defect this testing found

Running the client repeatedly filled the channel table and produced ~75
`CTAP channel busy` retries over eight seconds before a run could proceed.

The cause was a real design flaw. CTAPHID has **no command that releases a
channel** — a host simply stops using one, and Windows opens a fresh channel on
every enumeration. With the idle timeout set to 300 s, a handful of test runs
left the 8-slot table full of channels nobody would ever use again, and the next
legitimate INIT was refused with `ERR_CHANNEL_BUSY` until one aged out.

Two changes fixed it:

1. **The idle timeout is now 30 s**, not 300 s. There was no basis for five
   minutes; 30 s is far longer than any transaction here (the transaction
   timeout is 5 s) while being short enough that a host which has gone away is
   forgotten promptly.
2. **A full table now reclaims the least-recently-used channel** instead of
   refusing. `ERR_CHANNEL_BUSY` is spec-legal and a conforming host does retry,
   but it makes that host wait out a timeout for nothing. By definition the LRU
   channel is the one no host is transacting on, so evicting it cannot
   interrupt live work, and its owner is not left guessing — it receives
   `ERR_INVALID_CHANNEL` on its next packet and re-INITs, which is the recovery
   path the specification already describes. `ERR_CHANNEL_BUSY` is retained as
   the fallback if eviction is ever impossible.

After the fix, the same four consecutive runs give **zero** busy retries, and
the daemon logs four evictions in their place:

```
INFO ctaphid.server: channel table full; evicted least-recently-used channel 6e8fb71e to serve a new INIT
```

Regression coverage lives in `tests/test_offline.py` section [3], which asserts
that the LRU channel is the one evicted, that the channel in recent use survives
and still works, and that the evicted host is told `ERR_INVALID_CHANNEL`.

### Re-enumeration: what was and was not testable

Recovery from USB re-enumeration was tested **from the host side**, by
restarting the composite device on Windows. That is what actually happens in the
field, and it touches nothing on the phone. The client re-read the report
descriptor afterwards, re-INITed, and retrieved GetInfo normally; the gadget was
verified unchanged, and `/dev/hidg2`'s mtime never moved.

The phone-side alternative — unbinding the UDC to force a re-enumeration — is
**not possible on this device while the vendor USB HAL is running**. The HAL
watches the gadget and re-binds it almost immediately: eight consecutive
`echo none > UDC` writes all read back bound, and `/dev/hidg2` never
disappeared. An earlier attempt to test this way therefore produced a
misleading "pass" — the server was reported as surviving a re-enumeration that
never happened. That result is discarded; the host-side test above replaces it.

**Consequence worth recording:** because a host-initiated re-enumeration does
not tear the gadget down, the server never sees a disconnect and so never runs
its `channels.clear()` path. Combined with the old 300 s timeout this is what
made the bug above so persistent. With a 30 s timeout and LRU eviction the
server recovers in seconds regardless, which is why both changes matter.

Because the disconnect path cannot be provoked on the real device, it is
covered by the offline suite instead — `test_disconnect_recovery`, section [10].
The loopback transport is given a switch that severs the link, and the test
asserts the whole sequence: the server notices, reopens its device by itself,
has invalidated every channel, serves a fresh INIT on the new connection, and
rejects the pre-disconnect channel with `ERR_INVALID_CHANNEL` rather than
silently accepting it.

---

## GetInfo fields: what is temporary

Per the brief, the development values are called out explicitly.

| Field | Status |
|---|---|
| `versions: ["FIDO_2_0"]` | Accurate — this is the version implemented. |
| `aaguid` | **Temporary.** `"PocoF7-CTAP2-DEV"` as ASCII — a readable development marker, not a registered AAGUID. A real one must be issued by the FIDO Alliance. |
| `options` | **Accurate, and deliberately pessimistic.** `rk`, `up`, `uv` and `clientPin` are all `false` because none are implemented. They must not be flipped to `true` until the corresponding capability genuinely exists — advertising `rk` or `uv` we cannot honour would make a relying party's policy decision on false information. |
| `maxMsgSize: 7609` | Accurate for this transport. |
| `transports: ["usb"]` | Accurate. |
| `extensions` | Empty, and correct — no extension is implemented. |
| Device version `0.1.0` | Temporary development version. |

**Not claimed:** FIDO certification, or compliance with anything beyond the
transport and GetInfo behaviour described here. The test client requests only
`authenticatorGetInfo`; no assertion is made about attestation, credential
storage, or user verification, because none of it exists yet.

## What is deliberately not implemented

`makeCredential` (`0x01`), `getAssertion` (`0x02`), `getNextAssertion` (`0x08`),
`clientPin` (`0x06`), `reset` (`0x07`) and credential management (`0x0A`) all
return CTAP2_ERR_INVALID_COMMAND. No credentials are generated, no authentication
happens, and there is no Android Keystore integration. WINK and LOCK are not
advertised and not implemented. There is no boot service — the daemon is started
by hand.

## Constraints honoured

Milestone 1's USB configuration was not modified. Verified after all testing:

- `hid.0`, `hid.1`, `hid.2` report lengths unchanged at 8, 4 and 64
- VID `0x1209` / PID `0x0001` unchanged; UDC still bound to `a600000.dwc3`
- `function0 → ffs.adb`, `function1 → hid.2` — links unchanged
- USB ADB operational throughout
- the CTAPHID server touches only its own endpoint, `/dev/hidg2`
- no boot service installed

The one exception, announced before it was taken: a deliberate attempt to
unbind the UDC to test re-enumeration. It did not modify anything — the vendor
HAL overrode the unbind every time — and the gadget was verified identical
afterwards. See [Re-enumeration](#re-enumeration-what-was-and-was-not-testable).

## Logging

Protocol activity is logged by shape, not content: at INFO the server records
that a message of a given command and length arrived on a given channel, never
the payload. Full hex is available with `--log-level DEBUG` and is off by
default. No key material exists yet; when it does, the rule is that it never
reaches this path.

## Files

```
ctaphid/                 the server (see Architecture)
tests/test_offline.py    end-to-end harness: 103 assertions, real python-fido2
                         over an in-process loopback, no hardware needed
ctaphid_start.sh         start the daemon (root, Android)
ctaphid_stop.sh          stop it; --unmount, --full
windows/ctaphid_windows_test.py   the Windows client (must run elevated)
fido2_reenumerate.sh     phone-side re-enumeration attempt and its log
README.md                Milestone 1 — the USB gadget itself
```

Run the offline suite with:

```sh
python3 tests/test_offline.py
```

It stubs only `fido2.hid.linux` and drives the genuine `CtapHidDevice` and
`Ctap2` classes over a loopback, so the client library is under test alongside
the server. It is what caught the missing CTAP2 status byte before any hardware
was touched.

## Porting to Android

The transport half is the only part that is Linux-specific, and it is small:
open `/dev/hidgN`, `read()` a report, `write()` a report. On Android that
becomes a `FileInputStream`/`FileOutputStream` on the same node, or a JNI shim.

The protocol half — framing, reassembly, channel bookkeeping, CBOR, the INIT
and error rules — has no dependency on Python, Kali or Linux. `framing.py` and
`constants.py` are the reference for the Kotlin port, and `backend.py` is the
interface a Keystore-backed authenticator would implement.
