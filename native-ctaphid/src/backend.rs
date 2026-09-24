//! Standalone Android-17 CTAP2 -> Keystore helper bridge; **no Kali or Python**.
//!
//! Exactly the existing Milestone 3B Android helper wire contract:
//! an AF_UNIX ABSTRACT stream named `ctaphid-m3b-v1`; one request per
//! connection; four-byte big-endian length + UTF-8 JSON, max 65536 bytes.
//! Request: {"v":1,"id":<128-bit random lowercase hex>,"op":...,"params":{}}.
//! Reply: {"v":1,"id":...,"ok":true,"result":{...}} or fixed error name.
//! Interim events user_presence_required/user_presence_done toggle KEEPALIVE
//! UP_NEEDED via the caller's callback. Binary fields are strict base64.
//!
//! Android checks the socket client is UID 0, while this backend checks the
//! *kernel* SO_PEERCRED matches the installed helper's known app UID before
//! sending any request. A public abstract socket name is NOT authentication.
//! USB transport calls handle_cbor on a cancellable worker thread. It must set
//! cancel on HID CANCEL, disconnect and timeout; no retry of ambiguous writes.
//!
//! Hardware-backed *storage* does not imply hardware-enforced user verification.
//! Advertise uv=true only if helper requires per-use CryptoObject biometric
//! authentication and has no silent-sign route. Windows up=false credential
//! preflight still signs *after biometric* when uv=true, but with UP bit clear.
//! Do not silently manufacture UV/UP flags or sign keys in native code.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::Signature;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map as JsonMap, Value as Json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(all(test, target_os = "android"))]
use std::os::android::net::SocketAddrExt;
#[cfg(all(test, target_os = "linux"))]
use std::os::linux::net::SocketAddrExt;
#[cfg(test)]
use std::os::unix::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_cbor::Value as Cbor;

pub const DEFAULT_SOCKET_NAME: &str = "ctaphid-m3b-v1";
pub const AAGUID: &[u8; 16] = b"PocoF7-BIO-DEV01";
const MAX_FRAME: usize = 65_536;
const MAX_CTAP: usize = 7_609; // 64-byte CTAPHID reports.
const MAX_CREDENTIAL_ID: usize = 1_023; // WebAuthn Level 3 credential ID maximum.
const POLL: Duration = Duration::from_millis(100);

const OK: u8 = 0x00;
const INVALID_COMMAND: u8 = 0x01;
const INVALID_PARAMETER: u8 = 0x02;
const INVALID_LENGTH: u8 = 0x03;
const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const INVALID_CBOR: u8 = 0x12;
const MISSING_PARAMETER: u8 = 0x14;
const LIMIT_EXCEEDED: u8 = 0x15;
const UNSUPPORTED_EXTENSION: u8 = 0x16;
const CREDENTIAL_EXCLUDED: u8 = 0x19;
const UNSUPPORTED_ALGORITHM: u8 = 0x26;
const OPERATION_DENIED: u8 = 0x27;
const KEY_STORE_FULL: u8 = 0x28;
const UNSUPPORTED_OPTION: u8 = 0x2b;
const INVALID_OPTION: u8 = 0x2c;
const KEEPALIVE_CANCEL: u8 = 0x2d;
const NO_CREDENTIALS: u8 = 0x2e;
const USER_ACTION_TIMEOUT: u8 = 0x2f;
const OTHER: u8 = 0x7f;
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

#[derive(Debug)]
pub enum BackendError {
    Cancelled,
    Timeout,
    Unavailable,
    WrongPeerUid,
    Protocol(&'static str),
    Remote(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "Android IPC cancelled"),
            Self::Timeout => write!(f, "Android IPC timed out"),
            Self::Unavailable => write!(f, "Android helper unavailable"),
            Self::WrongPeerUid => write!(f, "Android helper SO_PEERCRED UID mismatch"),
            Self::Protocol(why) => write!(f, "invalid Android helper protocol: {why}"),
            Self::Remote(code) => write!(f, "Android helper refused operation: {code}"),
        }
    }
}
impl std::error::Error for BackendError {}

/// Strict recursive JSON deserialization: serde_json::Value alone silently
/// accepts duplicate object keys (including id, ok, v or userVerified).
/// Reject duplication throughout every nested object before interpreting it.
struct StrictJson(Json);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "JSON without duplicate keys or floating-point values")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::from(v)))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Err(E::custom("floating point not permitted in protocol"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Json::Null))
            }
            fn visit_some<D: Deserializer<'de>>(
                self, value: D,
            ) -> Result<Self::Value, D::Error> {
                StrictJson::deserialize(value)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self, mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(item) = seq.next_element::<StrictJson>()? {
                    values.push(item.0);
                }
                Ok(StrictJson(Json::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self, mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = JsonMap::new();
                while let Some((key, value)) = map.next_entry::<String, StrictJson>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(StrictJson(Json::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

/// CBOR maps are security-sensitive too: decoding directly into Value silently
/// discards repeated keys, potentially changing options. Reject duplicates.
struct StrictCbor(Cbor);

impl<'de> Deserialize<'de> for StrictCbor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictCbor;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "CTAP CBOR with unique map keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Integer(v as i128)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Integer(v as i128)))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Err(E::custom("CBOR float unsupported"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Text(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Text(v)))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Bytes(v.to_vec())))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Bytes(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictCbor(Cbor::Null))
            }
            fn visit_some<D: Deserializer<'de>>(
                self, inner: D,
            ) -> Result<Self::Value, D::Error> {
                StrictCbor::deserialize(inner)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self, mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(item) = seq.next_element::<StrictCbor>()? {
                    values.push(item.0);
                }
                Ok(StrictCbor(Cbor::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self, mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<StrictCbor, StrictCbor>()? {
                    if values.insert(key.0, value.0).is_some() {
                        return Err(de::Error::custom("duplicate CBOR map key"));
                    }
                }
                Ok(StrictCbor(Cbor::Map(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn strict_json(bytes: &[u8]) -> Result<Json, BackendError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(BackendError::Protocol("JSON frame outside size limit"));
    }
    let parsed: StrictJson = serde_json::from_slice(bytes)
        .map_err(|_| BackendError::Protocol("invalid or duplicate-key JSON"))?;
    Ok(parsed.0)
}

fn check(cancel: &AtomicBool, deadline: Instant) -> Result<Duration, BackendError> {
    if cancel.load(Ordering::Acquire) {
        return Err(BackendError::Cancelled);
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(BackendError::Timeout)?;
    Ok(remaining.min(POLL))
}

fn io_error(error: std::io::Error) -> BackendError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => BackendError::Timeout,
        _ => BackendError::Unavailable,
    }
}

fn read_exact_cancel(
    stream: &mut UnixStream,
    count: usize,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Vec<u8>, BackendError> {
    let mut bytes = vec![0_u8; count];
    let mut received = 0;
    while received < count {
        stream
            .set_read_timeout(Some(check(cancel, deadline)?))
            .map_err(io_error)?;
        match stream.read(&mut bytes[received..]) {
            Ok(0) => return Err(BackendError::Unavailable),
            Ok(n) => received += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(bytes)
}

fn write_cancel(
    stream: &mut UnixStream,
    bytes: &[u8],
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<(), BackendError> {
    let mut sent = 0;
    while sent < bytes.len() {
        stream
            .set_write_timeout(Some(check(cancel, deadline)?))
            .map_err(io_error)?;
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err(BackendError::Unavailable),
            Ok(n) => sent += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(())
}

fn read_frame(
    stream: &mut UnixStream,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Json, BackendError> {
    let header = read_exact_cancel(stream, 4, cancel, deadline)?;
    let length = u32::from_be_bytes(header.try_into().expect("four bytes")) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(BackendError::Protocol("invalid helper frame length"));
    }
    strict_json(&read_exact_cancel(stream, length, cancel, deadline)?)
}

fn write_frame(
    stream: &mut UnixStream,
    value: &Json,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<(), BackendError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| BackendError::Protocol("cannot serialize IPC JSON"))?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(BackendError::Protocol("outgoing IPC JSON too large"));
    }
    write_cancel(stream, &(bytes.len() as u32).to_be_bytes(), cancel, deadline)?;
    write_cancel(stream, &bytes, cancel, deadline)
}

#[repr(C)]
struct PeerCred {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn check_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), BackendError> {
    let mut cred = PeerCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<PeerCred>() as libc::socklen_t;
    // SAFETY: cred is a valid writable C buffer with exact socklen_t bytes.
    let ok = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut PeerCred).cast(),
            &mut length,
        )
    };
    if ok != 0 || length as usize != std::mem::size_of::<PeerCred>() {
        return Err(BackendError::Protocol("SO_PEERCRED unavailable or malformed"));
    }
    if cred.uid != expected_uid {
        return Err(BackendError::WrongPeerUid);
    }
    Ok(())
}

/// Connect without risking an unbounded blocked connect() when a client or
/// compromised helper fills the AF_UNIX listen backlog. The kernel connect,
/// POLLOUT and SO_ERROR path is cancellable and uses the same RPC deadline as
/// all subsequent writes/reads. Never fall back to unauthenticated TCP.
fn connect_abstract(
    name: &str,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<UnixStream, BackendError> {
    if name.is_empty() || name.len() > 100 || name.as_bytes().contains(&0) {
        return Err(BackendError::Protocol("invalid abstract socket name"));
    }
    check(cancel, deadline)?;
    // SAFETY: flags and AF_UNIX are Linux/Android constants. Own the returned
    // fd immediately to close it on any error/cancellation.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(BackendError::Unavailable);
    }
    // SAFETY: raw is the unique successful fd returned by socket().
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: Linux sockaddr_un is a plain C struct; all members start zero.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in name.as_bytes().iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }
    // Include only leading NUL + actual name, not padded trailing NUL bytes
    // (which Linux considers part of an abstract socket name).
    let address_length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len())
            as libc::socklen_t;
    // SAFETY: initialized sockaddr_un buffer and exact length.
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            address_length,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error().raw_os_error();
        if !matches!(
            error,
            Some(libc::EINPROGRESS | libc::EALREADY | libc::EAGAIN)
        ) {
            return Err(BackendError::Unavailable);
        }
        loop {
            let remaining = check(cancel, deadline)?;
            let mut waiter = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // A 100 ms maximum poll interval keeps CANCEL responsive.
            let millis = remaining.as_millis().clamp(1, 100) as libc::c_int;
            // SAFETY: waiter is one writable pollfd, referenced only here.
            let polled = unsafe { libc::poll(&mut waiter, 1, millis) };
            if polled == 0 {
                continue;
            }
            if polled < 0 {
                if std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(BackendError::Unavailable);
            }
            let mut socket_error: libc::c_int = 0;
            let mut error_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: initialized integer buffer of reported length.
            let ok = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut error_len,
                )
            };
            if ok != 0
                || error_len as usize != std::mem::size_of::<libc::c_int>()
                || socket_error != 0
                || (waiter.revents & libc::POLLOUT) == 0
            {
                return Err(BackendError::Unavailable);
            }
            break;
        }
    }
    check(cancel, deadline)?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(io_error)?;
    Ok(stream)
}

fn hex_id() -> Result<String, BackendError> {
    // Android /dev/urandom is available without a userspace crypto provider.
    // A counter or timestamp is NOT an acceptable request ID.
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| BackendError::Unavailable)?;
    let mut hex = String::with_capacity(32);
    for byte in random {
        use fmt::Write as _;
        write!(&mut hex, "{byte:02x}")
            .map_err(|_| BackendError::Protocol("cannot render request ID"))?;
    }
    Ok(hex)
}

fn one_reply(
    value: Json,
    expected_id: &str,
    up_needed: &mut bool,
    on_presence: &mut impl FnMut(bool),
) -> Result<Option<JsonMap<String, Json>>, BackendError> {
    let fields = value
        .as_object()
        .ok_or(BackendError::Protocol("non-object reply"))?;
    if fields.get("v").and_then(Json::as_u64) != Some(1)
        || fields.get("id").and_then(Json::as_str) != Some(expected_id)
    {
        return Err(BackendError::Protocol("wrong helper protocol/request id"));
    }
    if let Some(event) = fields.get("event") {
        if fields.len() != 3 {
            return Err(BackendError::Protocol("extra event fields"));
        }
        let desired = match event.as_str() {
            Some("user_presence_required") => true,
            Some("user_presence_done") => false,
            _ => return Err(BackendError::Protocol("unknown helper progress event")),
        };
        if *up_needed != desired {
            *up_needed = desired;
            on_presence(desired);
        }
        return Ok(None);
    }
    match fields.get("ok").and_then(Json::as_bool) {
        Some(true) if fields.len() == 4 => {
            let payload = fields
                .get("result")
                .and_then(Json::as_object)
                .ok_or(BackendError::Protocol("non-object helper result"))?;
            Ok(Some(payload.clone()))
        }
        Some(false) if fields.len() == 4 => {
            let error = fields
                .get("error")
                .and_then(Json::as_str)
                .ok_or(BackendError::Protocol("invalid Android error code"))?;
            Err(BackendError::Remote(error.to_owned()))
        }
        _ => Err(BackendError::Protocol("invalid helper reply envelope")),
    }
}

#[derive(Debug)]
struct Ipc {
    socket_name: String,
    expected_app_uid: u32,
    timeout: Duration,
}

impl Ipc {
    fn new(name: &str, expected_app_uid: u32, timeout: Duration) -> Result<Self, BackendError> {
        if name.is_empty()
            || name.len() > 100
            || name.bytes().any(|c| c == 0)
            || expected_app_uid < 10_000
            || timeout.is_zero()
        {
            return Err(BackendError::Protocol("invalid socket, UID or deadline"));
        }
        Ok(Self {
            socket_name: name.to_owned(),
            expected_app_uid,
            timeout,
        })
    }

    fn call(
        &self,
        op: &str,
        params: Json,
        cancel: &AtomicBool,
        mut on_presence: impl FnMut(bool),
    ) -> Result<JsonMap<String, Json>, BackendError> {
        if !matches!(op, "getInfo" | "makeCredential" | "getAssertion") || !params.is_object() {
            return Err(BackendError::Protocol("unsupported IPC operation/params"));
        }
        let deadline = Instant::now() + self.timeout;
        let mut stream = connect_abstract(&self.socket_name, cancel, deadline)?;
        check_peer(&stream, self.expected_app_uid)?; // BEFORE sending JSON.
        let id = hex_id()?;
        let mut up_needed = false;
        let result = (|| {
            write_frame(
                &mut stream,
                &json!({"v":1,"id":id,"op":op,"params":params}),
                cancel,
                deadline,
            )?;
            loop {
                let reply = read_frame(&mut stream, cancel, deadline)?;
                if let Some(result) = one_reply(reply, &id, &mut up_needed, &mut on_presence)? {
                    if cancel.load(Ordering::Acquire) {
                        return Err(BackendError::Cancelled);
                    }
                    return Ok(result);
                }
            }
        })();
        if up_needed {
            on_presence(false);
        }
        // Drop stream here even on CANCEL/timeout. Android monitors EOF and
        // cancels its own biometric operation; do not retry ambiguous writes.
        result
    }
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn from_b64(value: Option<&Json>, expected: Option<usize>, limit: usize) -> Result<Vec<u8>, BackendError> {
    let raw = value
        .and_then(Json::as_str)
        .ok_or(BackendError::Protocol("missing base64 field"))?;
    if raw.len() > ((limit + 2) / 3) * 4 + 4 {
        return Err(BackendError::Protocol("oversized base64 field"));
    }
    let decoded = B64
        .decode(raw)
        .map_err(|_| BackendError::Protocol("invalid base64 field"))?;
    if decoded.len() > limit || expected.is_some_and(|size| decoded.len() != size) {
        return Err(BackendError::Protocol("incorrect binary length"));
    }
    Ok(decoded)
}

fn verified(result: &JsonMap<String, Json>, uv_enforced: bool, up: bool) -> Result<(), BackendError> {
    if result.get("userVerified").and_then(Json::as_bool) != Some(uv_enforced)
        || result.get("userPresent").and_then(Json::as_bool) != Some(up)
    {
        return Err(BackendError::Protocol("helper misreported UP/UV"));
    }
    Ok(())
}

fn cmap(entries: impl IntoIterator<Item = (Cbor, Cbor)>) -> Cbor {
    Cbor::Map(entries.into_iter().collect::<BTreeMap<_, _>>())
}
fn key(key: i128) -> Cbor {
    Cbor::Integer(key)
}
fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}
fn bytes(value: impl Into<Vec<u8>>) -> Cbor {
    Cbor::Bytes(value.into())
}
fn value_map(value: &Cbor) -> Option<&BTreeMap<Cbor, Cbor>> {
    if let Cbor::Map(map) = value {
        Some(map)
    } else {
        None
    }
}
fn param<'a>(map: &'a BTreeMap<Cbor, Cbor>, number: i128) -> Option<&'a Cbor> {
    map.get(&key(number))
}
fn field<'a>(map: &'a BTreeMap<Cbor, Cbor>, name: &str) -> Option<&'a Cbor> {
    map.get(&text(name))
}
fn ctap_bytes(value: Option<&Cbor>, length: Option<usize>) -> Result<&[u8], u8> {
    match value {
        Some(Cbor::Bytes(bytes)) if length.is_none_or(|n| bytes.len() == n) => Ok(bytes),
        _ => Err(CBOR_UNEXPECTED_TYPE),
    }
}
/// Conservative DNS RP ID subset, mirrored in Android RelyingPartyPolicy.
/// The Windows/browser WebAuthn client separately validates RP vs origin.
fn valid_rp_id(rp: &str) -> bool {
    if rp == "localhost" { return true; }
    if rp.is_empty() || rp.len() > 253 || !rp.contains('.')
        || rp.starts_with('.') || rp.ends_with('.') { return false; }
    let mut numeric = true;
    for label in rp.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for ch in label.bytes() {
            if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != b'-' {
                return false;
            }
            if !ch.is_ascii_digit() { numeric = false; }
        }
    }
    !numeric
}

fn require_rp(value: Option<&Cbor>) -> Result<&str, u8> {
    match value {
        Some(Cbor::Text(rp)) if valid_rp_id(rp) => Ok(rp),
        Some(Cbor::Text(_)) => Err(OPERATION_DENIED),
        _ => Err(INVALID_PARAMETER),
    }
}

/// Optional, RP-supplied account labels are display-only metadata. Limit
/// their UTF-8 length and reject terminal/control and bidirectional format
/// characters before forwarding to Android. They never affect user.id, RP
/// binding, credential selection or permission to sign.
fn account_label(value: Option<&Cbor>) -> Result<Option<&str>, u8> {
    let Some(value) = value else { return Ok(None) };
    let Cbor::Text(value) = value else { return Err(CBOR_UNEXPECTED_TYPE) };
    if value.as_bytes().len() > 128 || value.chars().any(|ch| {
        ch.is_control() || matches!(ch as u32,
            0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
    }) {
        return Err(INVALID_PARAMETER);
    }
    Ok((!value.trim().is_empty()).then_some(value.as_str()))
}
fn validate_options(params: &BTreeMap<Cbor, Cbor>, number: i128, make: bool, uv: bool) -> Result<bool, u8> {
    let Some(raw) = param(params, number) else {
        return Ok(true);
    };
    let options = value_map(raw).ok_or(CBOR_UNEXPECTED_TYPE)?;
    let mut up = true;
    for (name, enabled) in options {
        let Cbor::Text(name) = name else {
            return Err(CBOR_UNEXPECTED_TYPE);
        };
        let Cbor::Bool(enabled) = enabled else {
            return Err(CBOR_UNEXPECTED_TYPE);
        };
        match name.as_str() {
            // FIDO_2_0 does not support authenticatorMakeCredential options.up.
            // Even up=true must return INVALID_OPTION for version honesty;
            // CTAP2.1 allows explicit true but this authenticator is NOT 2.1.
            "up" if make => return Err(INVALID_OPTION),
            "up" => up = *enabled,
            "uv" if *enabled && !uv => return Err(INVALID_OPTION),
            "uv" => {}
            "rk" if !make => return Err(UNSUPPORTED_OPTION),
            "rk" => {} // Discoverability is fixed at registration time.
            _ => return Err(UNSUPPORTED_OPTION),
        }
    }
    if make && !up {
        return Err(INVALID_OPTION);
    }
    Ok(up)
}
fn descriptors(value: Option<&Cbor>) -> Result<Vec<Vec<u8>>, u8> {
    let Some(value) = value else { return Ok(vec![]) };
    let Cbor::Array(items) = value else { return Err(CBOR_UNEXPECTED_TYPE) };
    if items.len() > 64 {
        return Err(LIMIT_EXCEEDED);
    }
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        let desc = value_map(item).ok_or(CBOR_UNEXPECTED_TYPE)?;
        if field(desc, "type") != Some(&text("public-key")) {
            return Err(INVALID_PARAMETER);
        }
        let id = ctap_bytes(field(desc, "id"), None)?;
        if id.len() < 16 || id.len() > MAX_CREDENTIAL_ID {
            return Err(INVALID_PARAMETER);
        }
        result.push(id.to_vec());
    }
    Ok(result)
}
fn make_resident(params: &BTreeMap<Cbor, Cbor>) -> bool {
    param(params, 7)
        .and_then(value_map)
        .and_then(|options| field(options, "rk"))
        == Some(&Cbor::Bool(true))
}
fn extensions(params: &BTreeMap<Cbor, Cbor>, number: i128) -> Result<(), u8> {
    if let Some(value) = param(params, number) {
        let map = value_map(value).ok_or(CBOR_UNEXPECTED_TYPE)?;
        if !map.is_empty() {
            return Err(UNSUPPORTED_EXTENSION);
        }
    }
    Ok(())
}
fn reject_pin(params: &BTreeMap<Cbor, Cbor>, keys: &[i128]) -> Result<(), u8> {
    if keys.iter().any(|n| param(params, *n).is_some()) {
        Err(UNSUPPORTED_OPTION)
    } else {
        Ok(())
    }
}
fn ipc_status(error: BackendError) -> u8 {
    match error {
        BackendError::Cancelled => KEEPALIVE_CANCEL,
        BackendError::Timeout => USER_ACTION_TIMEOUT,
        BackendError::Remote(code) => match code.as_str() {
            "CANCELLED" => KEEPALIVE_CANCEL,
            "TIMEOUT" => USER_ACTION_TIMEOUT,
            "NO_CREDENTIALS" => NO_CREDENTIALS,
            "CREDENTIAL_EXCLUDED" => CREDENTIAL_EXCLUDED,
            "NOT_ALLOWED" => OPERATION_DENIED,
            "STORE_FULL" => KEY_STORE_FULL,
            _ => OTHER,
        },
        _ => OTHER,
    }
}

/// Native CTAP2 backend; no private keys, credential store or USB device.
/// The helper's app UID must be resolved from Android PackageManager, not
/// hard-coded. The initial getInfo IPC handshake fails closed if no helper.
pub struct AndroidBackend {
    ipc: Ipc,
    uv_enforced: bool,
    /// Informational only; never used as a substitute for per-use UV.
    pub security_level: String,
}

fn validate_helper_info(info: &JsonMap<String, Json>) -> Result<(bool, String), BackendError> {
    if from_b64(info.get("aaguid"), Some(16), 16)?.as_slice() != AAGUID {
        return Err(BackendError::Protocol("wrong M3B AAGUID"));
    }
    if info.get("rpIdPolicy") != Some(&json!("ascii-dns-rp-v1"))
        || info.get("discoverablePolicy") != Some(&json!("rp-bound-account-picker-v1"))
        || info.get("up") != Some(&json!(true))
    {
        return Err(BackendError::Protocol("helper RP/UP policy mismatch"));
    }
    let enforced = info
        .get("uvEnforced")
        .and_then(Json::as_bool)
        .ok_or(BackendError::Protocol("UV policy missing"))?;
    let crypto = info
        .get("perUseCryptoObject")
        .and_then(Json::as_bool)
        .ok_or(BackendError::Protocol("per-use policy missing"))?;
    let silent = info
        .get("silentSigning")
        .and_then(Json::as_bool)
        .ok_or(BackendError::Protocol("silent signing policy missing"))?;
    if !enforced || !crypto || silent {
        // No mode switch to an unverified or silently signing authenticator.
        // StrongBox/TEE + each BiometricPrompt.CryptoObject are mandatory.
        return Err(BackendError::Protocol("helper must enforce hardware per-use UV"));
    }
    let level = info.get("securityLevel").and_then(Json::as_str).unwrap_or("UNKNOWN");
    if !matches!(level, "UNKNOWN" | "SOFTWARE" | "TEE" | "TRUSTED_ENVIRONMENT" | "STRONGBOX") {
        return Err(BackendError::Protocol("unrecognized helper security level"));
    }
    Ok((enforced, level.to_owned()))
}

impl AndroidBackend {
    pub fn connect(
        socket_name: &str,
        expected_app_uid: u32,
        timeout: Duration,
    ) -> Result<Self, BackendError> {
        let ipc = Ipc::new(socket_name, expected_app_uid, timeout)?;
        let cancel = AtomicBool::new(false);
        let info = ipc.call("getInfo", json!({}), &cancel, |_| {})?;
        let (enforced, level) = validate_helper_info(&info)?;
        Ok(Self {
            ipc,
            uv_enforced: enforced,
            security_level: level,
        })
    }

    pub fn get_info(&self) -> Cbor {
        cmap([
            (key(1), Cbor::Array(vec![text("FIDO_2_0")])),
            (key(3), bytes(AAGUID.to_vec())),
            (
                key(4),
                cmap([
                    (text("rk"), Cbor::Bool(true)),
                    (text("up"), Cbor::Bool(true)),
                    (text("uv"), Cbor::Bool(self.uv_enforced)),
                    // Do NOT advertise clientPin:false: per CTAP2, false
                    // means PIN capable but not yet configured; omitted means
                    // PIN entirely unsupported, which is our actual policy.
                ]),
            ),
            (key(5), key(MAX_CTAP as i128)),
            (key(8), key(MAX_CREDENTIAL_ID as i128)),
            (key(9), Cbor::Array(vec![text("usb")])),
            (
                key(10),
                Cbor::Array(vec![cmap([
                    (text("type"), text("public-key")),
                    (text("alg"), key(-7)),
                ])]),
            ),
        ])
    }

    fn make(
        &self,
        params: &BTreeMap<Cbor, Cbor>,
        cancel: &AtomicBool,
        on_presence: impl FnMut(bool),
    ) -> Result<Cbor, u8> {
        if [1, 2, 3, 4].iter().any(|n| param(params, *n).is_none()) {
            return Err(MISSING_PARAMETER);
        }
        let client_hash = ctap_bytes(param(params, 1), Some(32))?;
        let rp = value_map(param(params, 2).ok_or(MISSING_PARAMETER)?)
            .ok_or(CBOR_UNEXPECTED_TYPE)?;
        let rp_id = require_rp(field(rp, "id"))?;
        let user = value_map(param(params, 3).ok_or(MISSING_PARAMETER)?)
            .ok_or(CBOR_UNEXPECTED_TYPE)?;
        let user_id = ctap_bytes(field(user, "id"), None)?;
        if user_id.is_empty() || user_id.len() > 64 {
            return Err(INVALID_PARAMETER);
        }
        let account_name = account_label(field(user, "name"))?;
        let display_name = account_label(field(user, "displayName"))?;
        let Some(Cbor::Array(algs)) = param(params, 4) else {
            return Err(CBOR_UNEXPECTED_TYPE);
        };
        let es256 = algs.iter().any(|item| {
            value_map(item).is_some_and(|m| {
                field(m, "type") == Some(&text("public-key"))
                    && field(m, "alg") == Some(&key(-7))
            })
        });
        if !es256 {
            return Err(UNSUPPORTED_ALGORITHM);
        }
        let excluded = descriptors(param(params, 5))?;
        extensions(params, 6)?;
        validate_options(params, 7, true, self.uv_enforced)?;
        let resident = make_resident(params);
        reject_pin(params, &[8, 9, 10])?;
        let result = self
            .ipc
            .call(
                "makeCredential",
                json!({
                    "rpId":rp_id,"clientDataHash":b64(client_hash),
                    "userId":b64(user_id),
                    "userName": account_name,
                    "displayName": display_name,
                    "excludeIds": excluded.iter().map(|x| b64(x)).collect::<Vec<_>>(),
                    "residentKey":resident,
                    "up":true
                }),
                cancel,
                on_presence,
            )
            .map_err(ipc_status)?;
        verified(&result, self.uv_enforced, true).map_err(ipc_status)?;
        let credential_id = from_b64(result.get("credentialId"), None, MAX_CREDENTIAL_ID)
            .map_err(ipc_status)?;
        if credential_id.len() < 16 {
            return Err(OTHER);
        }
        let backup_eligible = result
            .get("backupEligible")
            .map(|v| v.as_bool().ok_or(OTHER))
            .transpose()?
            .unwrap_or(false);
        let backed_up = result
            .get("backedUp")
            .map(|v| v.as_bool().ok_or(OTHER))
            .transpose()?
            .unwrap_or(false);
        if backed_up && !backup_eligible {
            return Err(OTHER);
        }
        let public = result
            .get("publicKey")
            .and_then(Json::as_object)
            .ok_or(OTHER)?;
        let x = from_b64(public.get("x"), Some(32), 32).map_err(ipc_status)?;
        let y = from_b64(public.get("y"), Some(32), 32).map_err(ipc_status)?;
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        if p256::PublicKey::from_sec1_bytes(&point).is_err() {
            return Err(OTHER);
        }
        let cose = cmap([
            (key(1), key(2)),
            (key(3), key(-7)),
            (key(-1), key(1)),
            (key(-2), bytes(x)),
            (key(-3), bytes(y)),
        ]);
        let encoded_cose = serde_cbor::to_vec(&cose).map_err(|_| OTHER)?;
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(
            UP | AT
                | if self.uv_enforced { UV } else { 0 }
                | if backup_eligible { BE } else { 0 }
                | if backed_up { BS } else { 0 },
        );
        auth.extend_from_slice(&[0; 4]);
        auth.extend_from_slice(AAGUID);
        auth.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&credential_id);
        auth.extend_from_slice(&encoded_cose);
        Ok(cmap([
            (key(1), text("none")),
            (key(2), bytes(auth)),
            (key(3), cmap([])),
        ]))
    }

    fn assertion(
        &self,
        params: &BTreeMap<Cbor, Cbor>,
        cancel: &AtomicBool,
        on_presence: impl FnMut(bool),
    ) -> Result<Cbor, u8> {
        if param(params, 1).is_none() || param(params, 2).is_none() {
            return Err(MISSING_PARAMETER);
        }
        let rp_id = require_rp(param(params, 1))?;
        let client_hash = ctap_bytes(param(params, 2), Some(32))?;
        let allow = descriptors(param(params, 3))?;
        // CTAP2 clients omit the allowList for a discoverable assertion.
        // Treat an explicitly empty array equivalently for robustness, but
        // never silently fall back to a non-discoverable credential.
        let discoverable = allow.is_empty();
        extensions(params, 4)?;
        let up = validate_options(params, 5, false, self.uv_enforced)?;
        reject_pin(params, &[6, 7])?;
        let result = self
            .ipc
            .call(
                "getAssertion",
                json!({
                    "rpId":rp_id,"clientDataHash":b64(client_hash),
                    "allowIds": allow.iter().map(|x| b64(x)).collect::<Vec<_>>(),
                    "up":up
                }),
                cancel,
                on_presence,
            )
            .map_err(ipc_status)?;
        verified(&result, self.uv_enforced, up).map_err(ipc_status)?;
        let credential_id = from_b64(result.get("credentialId"), None, MAX_CREDENTIAL_ID)
            .map_err(ipc_status)?;
        if credential_id.len() < 16 {
            return Err(OTHER);
        }
        if !discoverable && !allow.iter().any(|id| id == &credential_id) {
            return Err(OTHER);
        }
        let auth = from_b64(result.get("authData"), Some(37), 37)
            .map_err(ipc_status)?;
        let backup_eligible = result
            .get("backupEligible")
            .map(|v| v.as_bool().ok_or(OTHER))
            .transpose()?
            .unwrap_or(false);
        let backed_up = result
            .get("backedUp")
            .map(|v| v.as_bool().ok_or(OTHER))
            .transpose()?
            .unwrap_or(false);
        if backed_up && !backup_eligible {
            return Err(OTHER);
        }
        let expected_flags = (if up { UP } else { 0 })
            | if self.uv_enforced { UV } else { 0 }
            | if backup_eligible { BE } else { 0 }
            | if backed_up { BS } else { 0 };
        if auth[..32] != Sha256::digest(rp_id.as_bytes())[..]
            || auth[32] != expected_flags
            || (backup_eligible && auth[33..37] != [0, 0, 0, 0])
        {
            return Err(OTHER);
        }
        let signature = from_b64(result.get("signature"), None, 128)
            .map_err(ipc_status)?;
        if Signature::from_der(&signature).is_err() {
            return Err(OTHER);
        }
        let mut response = vec![
            (
                key(1),
                cmap([
                    (text("type"), text("public-key")),
                    (text("id"), bytes(credential_id)),
                ]),
            ),
            (key(2), bytes(auth)),
            (key(3), bytes(signature)),
        ];
        if discoverable {
            if result.get("discoverable") != Some(&json!(true)) {
                return Err(OTHER);
            }
            let user = from_b64(result.get("userId"), None, 64)
                .map_err(ipc_status)?;
            if user.is_empty() {
                return Err(OTHER);
            }
            // Chromium rejects passwordless assertions without user.id;
            // never infer an account from a host-provided credential hint.
            response.push((key(4), cmap([(text("id"), bytes(user))])));
        }
        Ok(cmap(response))
    }

    /// Receive one fully reassembled CTAPHID CBOR body, return status+CBOR.
    ///
    /// Call from a worker, not the USB I/O loop. Callback toggles the USB
    /// transaction's UP_NEEDED state. Caller drops stale responses after
    /// CTAPHID CANCEL/reconnect; helper observes EOF and aborts pending UI.
    pub fn handle_cbor(
        &self,
        request: &[u8],
        cancel: &AtomicBool,
        on_presence: impl FnMut(bool),
    ) -> Vec<u8> {
        if request.is_empty() {
            return vec![INVALID_LENGTH];
        }
        if request.len() > MAX_CTAP {
            return vec![LIMIT_EXCEEDED];
        }
        let command = request[0];
        if !matches!(command, 0x01 | 0x02 | 0x04) {
            return vec![INVALID_COMMAND];
        }
        let params = if request.len() == 1 {
            cmap([])
        } else {
            match serde_cbor::from_slice::<StrictCbor>(&request[1..]) {
                Ok(value) => value.0,
                Err(_) => return vec![INVALID_CBOR],
            }
        };
        let Some(fields) = value_map(&params) else {
            return vec![CBOR_UNEXPECTED_TYPE];
        };
        if !fields.keys().all(|k| matches!(k, Cbor::Integer(_))) {
            return vec![CBOR_UNEXPECTED_TYPE];
        }
        let reply = if command == 0x04 {
            if !fields.is_empty() {
                Err(INVALID_PARAMETER)
            } else {
                Ok(self.get_info())
            }
        } else if request.len() == 1 {
            Err(MISSING_PARAMETER)
        } else if cancel.load(Ordering::Acquire) {
            Err(KEEPALIVE_CANCEL)
        } else if command == 0x01 {
            self.make(fields, cancel, on_presence)
        } else {
            self.assertion(fields, cancel, on_presence)
        };
        match reply {
            Err(code) => vec![code],
            Ok(cbor) => {
                let Ok(body) = serde_cbor::to_vec(&cbor) else {
                    return vec![OTHER];
                };
                if body.len() + 1 > MAX_CTAP {
                    return vec![OTHER];
                }
                let mut answer = Vec::with_capacity(body.len() + 1);
                answer.push(OK);
                answer.extend(body);
                answer
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::thread;

    static NEXT: AtomicUsize = AtomicUsize::new(1);

    fn test_uid() -> u32 {
        // SAFETY: Linux getuid is side-effect free.
        unsafe { libc::getuid() }
    }

    fn mock_socket<F>(count: usize, mut handler: F) -> (String, thread::JoinHandle<()>)
    where
        F: FnMut(Json) -> Vec<Json> + Send + 'static,
    {
        let name = format!(
            "ctap4b-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        let worker = thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut size = [0_u8; 4];
                stream.read_exact(&mut size).unwrap();
                let mut json = vec![0_u8; u32::from_be_bytes(size) as usize];
                stream.read_exact(&mut json).unwrap();
                let request: Json = serde_json::from_slice(&json).unwrap();
                for mut reply in handler(request.clone()) {
                    reply["id"] = request["id"].clone();
                    let wire = serde_json::to_vec(&reply).unwrap();
                    stream.write_all(&(wire.len() as u32).to_be_bytes()).unwrap();
                    stream.write_all(&wire).unwrap();
                }
            }
        });
        (name, worker)
    }

    fn rpc(name: String) -> Ipc {
        Ipc {
            socket_name: name,
            expected_app_uid: test_uid(),
            timeout: Duration::from_secs(2),
        }
    }

    fn fake_backend(name: String, uv: bool) -> AndroidBackend {
        AndroidBackend {
            ipc: rpc(name),
            uv_enforced: uv,
            security_level: "STRONGBOX".to_owned(),
        }
    }

    fn success(result: Json) -> Json {
        json!({"v":1,"id":"set-by-test","ok":true,"result":result})
    }
    fn event(event: &str) -> Json {
        json!({"v":1,"id":"set-by-test","event":event})
    }

    fn make_params() -> Cbor {
        cmap([
            (key(1), bytes(vec![0x22; 32])),
            (
                key(2),
                cmap([(text("id"), text("localhost")), (text("name"), text("Test"))]),
            ),
            (key(3), cmap([(text("id"), bytes(b"user-1".to_vec()))])),
            (
                key(4),
                Cbor::Array(vec![cmap([
                    (text("type"), text("public-key")),
                    (text("alg"), key(-7)),
                ])]),
            ),
            (key(7), cmap([(text("uv"), Cbor::Bool(true))])),
        ])
    }
    fn assertion_params(up: bool) -> Cbor {
        cmap([
            (key(1), text("localhost")),
            (key(2), bytes(vec![0x22; 32])),
            (
                key(3),
                Cbor::Array(vec![cmap([
                    (text("type"), text("public-key")),
                    (text("id"), bytes(vec![0x11; 32])),
                ])]),
            ),
            (
                key(5),
                cmap([
                    (text("up"), Cbor::Bool(up)),
                    (text("uv"), Cbor::Bool(true)),
                ]),
            ),
        ])
    }
    fn ctap(command: u8, params: &Cbor) -> Vec<u8> {
        let mut bytes = vec![command];
        bytes.extend(serde_cbor::to_vec(params).unwrap());
        bytes
    }
    fn parsed_success(bytes: &[u8]) -> Cbor {
        assert_eq!(bytes[0], OK, "{bytes:?}");
        serde_cbor::from_slice(&bytes[1..]).unwrap()
    }

    fn known_basepoint() -> (Vec<u8>, Vec<u8>) {
        fn from_hex(text: &str) -> Vec<u8> {
            text.as_bytes()
                .chunks_exact(2)
                .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
                .collect()
        }
        (
            from_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            from_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        )
    }

    #[test]
    fn strict_json_and_cbor_reject_duplicates_nested_and_overlong_frames() {
        assert!(strict_json(br#"{"v":1,"id":"first","id":"second"}"#).is_err());
        assert!(strict_json(br#"{"ok":true,"result":{"userVerified":false,"userVerified":true}}"#).is_err());
        assert!(strict_json(br#"{"v":1.0}"#).is_err());
        assert!(strict_json(&vec![0x7b; MAX_FRAME + 1]).is_err());
        assert!(serde_cbor::from_slice::<StrictCbor>(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err());
        let backend = fake_backend("not-needed".into(), true);
        assert_eq!(
            backend.handle_cbor(&[0x01, 0xa2, 0x01, 0x01, 0x01, 0x02], &AtomicBool::new(false), |_| {}),
            vec![INVALID_CBOR],
        );
        assert_eq!(backend.handle_cbor(&[], &AtomicBool::new(false), |_| {}), vec![INVALID_LENGTH]);
        assert_eq!(backend.handle_cbor(&[0x06], &AtomicBool::new(false), |_| {}), vec![INVALID_COMMAND]);
    }

    #[test]
    fn get_info_is_local_and_advertises_only_enforced_uv() {
        for uv in [false, true] {
            let backend = fake_backend("no-socket-needed".to_string(), uv);
            let body = parsed_success(&backend.handle_cbor(&[0x04], &AtomicBool::new(false), |_| {}));
            let info = value_map(&body).unwrap();
            assert_eq!(param(info, 3), Some(&bytes(AAGUID.to_vec())));
            let options = value_map(param(info, 4).unwrap()).unwrap();
            assert_eq!(field(options, "uv"), Some(&Cbor::Bool(uv)));
            assert_eq!(field(options, "rk"), Some(&Cbor::Bool(true)));
            assert_eq!(field(options, "up"), Some(&Cbor::Bool(true)));
            assert_eq!(field(options, "clientPin"), None);
            assert_eq!(param(info, 5), Some(&key(MAX_CTAP as i128)));
            assert_eq!(param(info, 8), Some(&key(MAX_CREDENTIAL_ID as i128)));
        }
    }

    #[test]
    fn registration_passes_bounded_account_labels_as_display_metadata_only() {
        let (x, y) = known_basepoint();
        let (socket, server) = mock_socket(1, move |request| {
            assert_eq!(request["params"]["userName"], "alice@example.com");
            assert_eq!(request["params"]["displayName"], "Alice");
            assert_eq!(request["params"]["userId"], b64(b"user-1"));
            assert_eq!(request["params"]["rpId"], "localhost");
            vec![success(json!({
                "credentialId": b64(&[0x11; 32]),
                "publicKey": {"x": b64(&x), "y": b64(&y)},
                "userPresent": true,"userVerified": true,
            }))]
        });
        let backend = fake_backend(socket, true);
        let mut make = make_params();
        let Cbor::Map(ref mut params) = make else { unreachable!() };
        params.insert(key(3), cmap([
            (text("id"), bytes(b"user-1".to_vec())),
            (text("name"), text("alice@example.com")),
            (text("displayName"), text("Alice")),
        ]));
        parsed_success(&backend.handle_cbor(&ctap(1, &make),
                                            &AtomicBool::new(false), |_| {}));
        server.join().unwrap();
        for rejected in ["a\n", "a\u{202e}z", &"a".repeat(129)] {
            assert_eq!(account_label(Some(&text(rejected))), Err(INVALID_PARAMETER));
        }
        assert_eq!(account_label(Some(&Cbor::Integer(1))), Err(CBOR_UNEXPECTED_TYPE));
        assert_eq!(account_label(None), Ok(None));
    }

    #[test]
    fn recoverable_passkey_sets_be_bs_and_requires_zero_counter() {
        let (x, y) = known_basepoint();
        let make_x = x.clone();
        let make_y = y.clone();
        let mut assertion_calls = 0_u8;
        let (name, worker) = mock_socket(3, move |request| {
            match request["op"].as_str().unwrap() {
                "makeCredential" => vec![success(json!({
                    "credentialId":b64(&[0x33;32]),
                    "publicKey":{"x":b64(&make_x),"y":b64(&make_y)},
                    "userPresent":true,"userVerified":true,
                    "backupEligible":true,"backedUp":false,
                }))],
                "getAssertion" => {
                    assertion_calls += 1;
                    let mut auth = Sha256::digest(b"localhost").to_vec();
                    auth.push(UP | UV | BE | BS);
                    auth.extend_from_slice(if assertion_calls == 1 {
                        &[0, 0, 0, 0]
                    } else {
                        &[0, 0, 0, 1]
                    });
                    vec![success(json!({
                        "credentialId":b64(&[0x11;32]),"authData":b64(&auth),
                        "signature":b64(&[0x30,6,2,1,1,2,1,1]),
                        "userPresent":true,"userVerified":true,
                        "backupEligible":true,"backedUp":true,
                    }))]
                }
                _ => unreachable!(),
            }
        });
        let backend = fake_backend(name, true);
        let registration = parsed_success(&backend.handle_cbor(
            &ctap(1, &make_params()), &AtomicBool::new(false), |_| {}));
        let Cbor::Bytes(auth) = param(value_map(&registration).unwrap(), 2).unwrap() else {
            panic!("missing makeCredential authData")
        };
        assert_eq!(auth[32], UP | UV | AT | BE);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);

        let assertion = parsed_success(&backend.handle_cbor(
            &ctap(2, &assertion_params(true)), &AtomicBool::new(false), |_| {}));
        let Cbor::Bytes(auth) = param(value_map(&assertion).unwrap(), 2).unwrap() else {
            panic!("missing getAssertion authData")
        };
        assert_eq!(auth[32], UP | UV | BE | BS);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);

        // Same helper flags with a non-zero signCount violate the portable
        // passkey profile and must never be forwarded to the relying party.
        assert_eq!(backend.handle_cbor(
            &ctap(2, &assertion_params(true)), &AtomicBool::new(false), |_| {}),
            vec![OTHER]);
        worker.join().unwrap();
    }

    #[test]
    fn backup_state_never_exists_without_backup_eligibility() {
        let (x, y) = known_basepoint();
        let (name, worker) = mock_socket(1, move |_request| vec![success(json!({
            "credentialId":b64(&[0x11;32]),
            "publicKey":{"x":b64(&x),"y":b64(&y)},
            "userPresent":true,"userVerified":true,
            "backupEligible":false,"backedUp":true,
        }))]);
        let backend = fake_backend(name, true);
        assert_eq!(backend.handle_cbor(&ctap(1, &make_params()),
            &AtomicBool::new(false), |_| {}), vec![OTHER]);
        worker.join().unwrap();
    }

    #[test]
    fn rp_policy_accepts_canonical_dns_and_rejects_cross_rp_ambiguity() {
        for rp in ["localhost", "example.com", "login.example.com", "xn--bcher-kva.example",
                   "a.localhost", "a-b.example"] {
            assert!(valid_rp_id(rp), "valid RP rejected: {rp}");
        }
        for rp in ["", "foo", "example.com.", ".example.com", "EXAMPLE.com",
                   "https://example.com", "example.com:443", "example.com/path",
                   "127.0.0.1", "[::1]", "a..example", "foo_.example",
                   "bücher.example", "-foo.example", "foo-.example", "foo.example\n"] {
            assert!(!valid_rp_id(rp), "malformed RP accepted: {rp}");
            let backend = fake_backend("unused".to_owned(), true);
            let mut assertion = match assertion_params(true) {
                Cbor::Map(values) => values,
                _ => unreachable!(),
            };
            assertion.insert(key(1), text(rp));
            assert_eq!(backend.handle_cbor(&ctap(0x02, &Cbor::Map(assertion)),
                        &AtomicBool::new(false), |_| {}), vec![OPERATION_DENIED]);
        }
        assert!(!valid_rp_id(&format!("{}.example", "a".repeat(64))));
        assert!(!valid_rp_id(&format!("{}.test", "a".repeat(250))));
    }

    #[test]
    fn real_rp_is_forwarded_and_auth_data_hash_matches_exact_rp() {
        let rp = "accounts.example.com";
        let (name, server) = mock_socket(1, move |request| {
            assert_eq!(request["op"], "getAssertion");
            assert_eq!(request["params"]["rpId"], rp);
            let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
            auth.push(0x05);
            auth.extend_from_slice(&7_u32.to_be_bytes());
            vec![event("user_presence_required"), success(json!({
                "credentialId": b64(&[0x11;32]), "authData": b64(&auth),
                "signature": b64(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
                "userPresent": true, "userVerified": true
            }))]
        });
        let backend = fake_backend(name, true);
        let mut fields = match assertion_params(true) {
            Cbor::Map(fields) => fields,
            _ => unreachable!(),
        };
        fields.insert(key(1), text(rp));
        let response = backend.handle_cbor(&ctap(0x02, &Cbor::Map(fields)),
                                           &AtomicBool::new(false), |_| {});
        let assertion = parsed_success(&response);
        let auth = match param(value_map(&assertion).unwrap(), 2).unwrap() {
            Cbor::Bytes(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(&auth[..32], &Sha256::digest(rp.as_bytes())[..]);
        server.join().unwrap();
    }

    #[test]
    fn register_then_windows_up_false_preflight_then_actual_assertion() {
        let (x, y) = known_basepoint();
        let public_x = x.clone();
        let public_y = y.clone();
        let (name, server) = mock_socket(3, move |request| {
            match request["op"].as_str().unwrap() {
                "makeCredential" => {
                    assert_eq!(request["params"]["rpId"], "localhost");
                    assert_eq!(request["params"]["up"], true);
                    vec![
                        event("user_presence_required"),
                        success(json!({
                            "credentialId": b64(&[0x11;32]),
                            "publicKey": {"x":b64(&public_x), "y":b64(&public_y)},
                            "userPresent":true,"userVerified":true
                        })),
                    ]
                }
                "getAssertion" => {
                    let up = request["params"]["up"].as_bool().unwrap();
                    let mut auth = Sha256::digest(b"localhost").to_vec();
                    auth.push(if up { 0x05 } else { 0x04 });
                    auth.extend_from_slice(&1_u32.to_be_bytes());
                    let signature = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
                    vec![
                        event("user_presence_required"),
                        event("user_presence_done"),
                        success(json!({
                            "credentialId": b64(&[0x11;32]),
                            "authData":b64(&auth),
                            "signature":b64(&signature),
                            "userPresent":up,"userVerified":true
                        })),
                    ]
                }
                _ => panic!("unexpected helper operation"),
            }
        });
        let backend = fake_backend(name, true);
        let events = Arc::new(Mutex::new(Vec::new()));
        let note = Arc::clone(&events);
        let result = backend.handle_cbor(
            &ctap(0x01, &make_params()),
            &AtomicBool::new(false),
            move |v| note.lock().unwrap().push(v),
        );
        let registration = parsed_success(&result);
        let auth = match param(value_map(&registration).unwrap(), 2).unwrap() {
            Cbor::Bytes(auth) => auth,
            _ => panic!("missing authData"),
        };
        assert_eq!(auth[32], 0x45);
        assert_eq!(&auth[37..53], AAGUID);
        assert_eq!(events.lock().unwrap().as_slice(), &[true, false]);
        for (up, flags) in [(false, 0x04), (true, 0x05)] {
            let body = parsed_success(&backend.handle_cbor(
                &ctap(0x02, &assertion_params(up)),
                &AtomicBool::new(false),
                |_| {},
            ));
            let result = value_map(&body).unwrap();
            let Cbor::Bytes(auth) = param(result, 2).unwrap() else {
                panic!("missing assertion auth data");
            };
            assert_eq!(auth[32], flags);
        }
        server.join().unwrap();
    }

    #[test]
    fn preflight_never_claims_up_or_uv_without_explicit_verified_signing() {
        let (name, worker) = mock_socket(1, |request| {
            assert_eq!(request["params"]["up"], false);
            let mut auth = Sha256::digest(b"localhost").to_vec();
            auth.push(0x05); // helper lies; preflight MUST NOT have UP set.
            auth.extend_from_slice(&2_u32.to_be_bytes());
            vec![success(json!({
                "credentialId":b64(&[0x11;32]),"authData":b64(&auth),
                "signature":b64(&[0x30,6,2,1,1,2,1,1]),
                "userPresent":false,"userVerified":true,
            }))]
        });
        let backend = fake_backend(name, true);
        assert_eq!(
            backend.handle_cbor(
                &ctap(0x02, &assertion_params(false)),
                &AtomicBool::new(false),
                |_| {},
            ),
            vec![OTHER],
        );
        worker.join().unwrap();
        let weak = fake_backend("no-socket-needed".into(), false);
        assert_eq!(
            weak.handle_cbor(
                &ctap(0x02, &assertion_params(false)),
                &AtomicBool::new(false),
                |_| {},
            ),
            vec![INVALID_OPTION], // requested UV not supported.
        );
    }

    #[test]
    fn invalid_rp_allowlist_and_option_requests_fail_without_ipc() {
        let backend = fake_backend("no-socket-needed".to_owned(), true);
        let descriptor = |id: Vec<u8>| {
            Cbor::Array(vec![cmap([
                (text("type"), text("public-key")),
                (text("id"), bytes(id)),
            ])])
        };
        assert!(descriptors(Some(&descriptor(vec![0x41; 16]))).is_ok());
        assert!(descriptors(Some(&descriptor(vec![0x42; MAX_CREDENTIAL_ID]))).is_ok());
        assert_eq!(descriptors(Some(&descriptor(vec![0x43; 15]))), Err(INVALID_PARAMETER));
        assert_eq!(descriptors(Some(&descriptor(vec![0x44; MAX_CREDENTIAL_ID + 1]))),
                   Err(INVALID_PARAMETER));
        let other_rp = {
            let mut params = make_params();
            let Cbor::Map(ref mut map) = params else { unreachable!() };
            map.insert(key(2), cmap([(text("id"), text("other.example."))]));
            params
        };
        assert_eq!(
            backend.handle_cbor(&ctap(1, &other_rp), &AtomicBool::new(false), |_| {}),
            vec![OPERATION_DENIED],
        );
        let bad_option = {
            let mut params = make_params();
            let Cbor::Map(ref mut map) = params else { unreachable!() };
            map.insert(key(7), cmap([(text("unsupportedOption"), Cbor::Bool(true))]));
            params
        };
        assert_eq!(
            backend.handle_cbor(&ctap(1, &bad_option), &AtomicBool::new(false), |_| {}),
            vec![UNSUPPORTED_OPTION],
        );
        for explicit_up in [true, false] {
            let mut params = make_params();
            let Cbor::Map(ref mut map) = params else { unreachable!() };
            map.insert(key(7), cmap([(text("up"), Cbor::Bool(explicit_up))]));
            assert_eq!(backend.handle_cbor(&ctap(1, &params),
                                          &AtomicBool::new(false), |_| {}),
                       vec![INVALID_OPTION]);
        }
        let mut bad_assertion = assertion_params(false);
        let Cbor::Map(ref mut map) = bad_assertion else { unreachable!() };
        map.insert(key(5), cmap([(text("rk"), Cbor::Bool(true))]));
        assert_eq!(
            backend.handle_cbor(&ctap(2, &bad_assertion), &AtomicBool::new(false), |_| {}),
            vec![UNSUPPORTED_OPTION],
        );
    }

    #[test]
    fn resident_registration_is_explicit_and_discoverable_assertion_has_user_id() {
        let (x, y) = known_basepoint();
        let (name, worker) = mock_socket(3, move |request| {
            match request["op"].as_str().unwrap() {
                "makeCredential" => {
                    assert_eq!(request["params"]["residentKey"], true);
                    vec![success(json!({
                        "credentialId":b64(&[0x11;32]),
                        "publicKey":{"x":b64(&x),"y":b64(&y)},
                        "userPresent":true,"userVerified":true,
                    }))]
                }
                "getAssertion" => {
                    assert_eq!(request["params"]["allowIds"],json!([]));
                    let mut auth = Sha256::digest(b"localhost").to_vec();
                    auth.push(0x05);
                    auth.extend_from_slice(&1_u32.to_be_bytes());
                    vec![success(json!({
                        "credentialId":b64(&[0x11;32]),"authData":b64(&auth),
                        "signature":b64(&[0x30,6,2,1,1,2,1,1]),
                        "userPresent":true,"userVerified":true,
                        "userId":b64(b"user-1"),"discoverable":true,
                    }))]
                }
                _ => panic!("unexpected request"),
            }
        });
        let backend = fake_backend(name, true);
        let mut make = make_params();
        let Cbor::Map(ref mut fields) = make else { unreachable!() };
        fields.insert(key(7), cmap([(text("uv"),Cbor::Bool(true)),
                                      (text("rk"),Cbor::Bool(true))]));
        parsed_success(&backend.handle_cbor(&ctap(1,&make),&AtomicBool::new(false), |_| {}));
        for explicit_empty in [false,true] {
            let mut assertion = assertion_params(true);
            let Cbor::Map(ref mut fields) = assertion else { unreachable!() };
            if explicit_empty { fields.insert(key(3), Cbor::Array(vec![])); }
            else { fields.remove(&key(3)); }
            let body = parsed_success(&backend.handle_cbor(
                &ctap(2,&assertion),&AtomicBool::new(false), |_| {}));
            let map = value_map(&body).unwrap();
            let user = value_map(param(map, 4).expect("discoverable user entity missing")).unwrap();
            assert_eq!(field(user,"id"), Some(&bytes(b"user-1".to_vec())));
        }
        worker.join().unwrap();
    }

    #[test]
    fn omitted_allowlist_never_returns_an_assertion_without_user_identity() {
        let (name, worker) = mock_socket(1, |request| {
            assert_eq!(request["params"]["allowIds"], json!([]));
            let mut auth = Sha256::digest(b"localhost").to_vec();
            auth.push(0x05);
            auth.extend_from_slice(&1_u32.to_be_bytes());
            vec![success(json!({
                "credentialId":b64(&[0x11;32]), "authData":b64(&auth),
                "signature":b64(&[0x30,6,2,1,1,2,1,1]),
                "userPresent":true, "userVerified":true,
                "discoverable":true,
            }))]
        });
        let backend = fake_backend(name, true);
        let mut request = assertion_params(true);
        let Cbor::Map(ref mut fields) = request else { unreachable!() };
        fields.remove(&key(3));
        assert_eq!(backend.handle_cbor(&ctap(2,&request),
                     &AtomicBool::new(false), |_| {}), vec![OTHER]);
        worker.join().unwrap();
    }

    #[test]
    fn pin_peer_uid_before_sending_any_request() {
        let (_name, worker) = mock_socket(0, |_| unreachable!());
        // The fake listener intentionally accepts no connections; use an
        // alternate one-client listener to observe zero bytes on a refused UID.
        worker.join().unwrap();
        let name = format!("ctap-wrong-uid-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buffer = [0; 1];
            assert_eq!(stream.read(&mut buffer).unwrap(), 0);
        });
        let mut ipc = rpc(name);
        ipc.expected_app_uid = test_uid() + 1;
        assert!(matches!(
            ipc.call("getInfo", json!({}), &AtomicBool::new(false), |_| {}),
            Err(BackendError::WrongPeerUid)
        ));
        worker.join().unwrap();
        let _ = name;
    }

    #[test]
    fn progress_event_cancellation_clears_up_needed_and_does_not_retry() {
        let (name, worker) = mock_socket(1, |_| vec![event("user_presence_required")]);
        let ipc = rpc(name);
        let cancel = AtomicBool::new(false);
        let notifications = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&notifications);
        assert!(matches!(
            ipc.call("makeCredential", json!({}), &cancel, |needed| {
                log.lock().unwrap().push(needed);
                if needed {
                    cancel.store(true, Ordering::Release);
                }
            }),
            Err(BackendError::Cancelled)
        ));
        assert_eq!(*notifications.lock().unwrap(), vec![true, false]);
        worker.join().unwrap();
    }

    #[test]
    fn notification_wait_keeps_up_needed_without_autoapproval_until_helper_reply() {
        // A notification tap is outside Rust's control: after
        // user_presence_required the IPC stream may be silent while the
        // user unlocks the phone, taps, and uses BiometricPrompt. The bridge
        // must keep the WAITING/UP_NEEDED signal without claiming success.
        let name = format!(
            "ctap-notification-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        );
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        let (release, received) = std::sync::mpsc::channel::<()>();
        let worker = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            let mut header = [0_u8; 4];
            peer.read_exact(&mut header).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(header) as usize];
            peer.read_exact(&mut request).unwrap();
            let request: Json = serde_json::from_slice(&request).unwrap();
            let send = |peer: &mut UnixStream, mut answer: Json| {
                answer["id"] = request["id"].clone();
                let wire = serde_json::to_vec(&answer).unwrap();
                peer.write_all(&(wire.len() as u32).to_be_bytes()).unwrap();
                peer.write_all(&wire).unwrap();
            };
            send(&mut peer, event("user_presence_required"));
            // This wait represents time spent checking/tapping a notification,
            // not a hidden/silent approval. No final result exists yet.
            received.recv_timeout(Duration::from_secs(2)).unwrap();
            send(&mut peer, event("user_presence_done"));
            send(&mut peer, success(json!({"approved":true})));
        });
        let events = Arc::new(Mutex::new(Vec::<bool>::new()));
        let observed = Arc::clone(&events);
        let ipc = rpc(name);
        let cancel = AtomicBool::new(false);
        let result = ipc
            .call("makeCredential", json!({}), &cancel, |needed| {
                observed.lock().unwrap().push(needed);
                if needed {
                    let events = Arc::clone(&observed);
                    let release = release.clone();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(150));
                        // The user has not yet approved; the test-only
                        // simulated UI will now return a signed result.
                        assert_eq!(*events.lock().unwrap(), vec![true]);
                        release.send(()).unwrap();
                    });
                }
            })
            .unwrap();
        assert_eq!(result.get("approved"), Some(&json!(true)));
        assert_eq!(*events.lock().unwrap(), vec![true, false]);
        worker.join().unwrap();
    }

    #[test]
    fn handshake_rejects_missing_app_and_contradictory_policy() {
        let valid = json!({
            "aaguid":b64(AAGUID),
            "rpIdPolicy":"ascii-dns-rp-v1",
            "discoverablePolicy":"rp-bound-account-picker-v1",
            "up":true,
            "uvEnforced":true,
            "perUseCryptoObject":true,
            "silentSigning":false,
            "securityLevel":"STRONGBOX",
        });
        let valid = valid.as_object().unwrap();
        assert_eq!(
            validate_helper_info(valid).unwrap(),
            (true, "STRONGBOX".to_owned())
        );
        for change in [
            ("silentSigning", json!(true)),
            ("perUseCryptoObject", json!(false)),
            ("rpIdPolicy", json!("unrestricted-unsafe")),
            ("discoverablePolicy", json!("ambiguous-or-no-picker")),
            ("up", json!(false)),
            ("aaguid", json!(b64(b"incorrect-m3b-id"))),
            ("securityLevel", json!("not-enforced")),
        ] {
            let mut changed = valid.clone();
            changed.insert(change.0.to_owned(), change.1);
            assert!(
                validate_helper_info(&changed).is_err(),
                "expected fail-closed for {}",
                change.0,
            );
        }
        let mut weak = valid.clone();
        weak.insert("uvEnforced".into(), json!(false));
        weak.insert("perUseCryptoObject".into(), json!(false));
        weak.insert("silentSigning".into(), json!(true));
        assert!(validate_helper_info(&weak).is_err());
        let mut old_helper = valid.clone();
        old_helper.remove("discoverablePolicy");
        assert!(validate_helper_info(&old_helper).is_err());
        assert!(matches!(
            Ipc::new("", 10_271, Duration::from_secs(1)),
            Err(BackendError::Protocol(_))
        ));
        assert!(matches!(
            Ipc::new("normal", 0, Duration::from_secs(1)),
            Err(BackendError::Protocol(_))
        ));
        assert!(matches!(
            Ipc::new("normal", 10_271, Duration::ZERO),
            Err(BackendError::Protocol(_))
        ));
        assert!(matches!(
            AndroidBackend::connect(
                "absent-m3b-helper",
                10_271,
                Duration::from_millis(100)
            ),
            Err(BackendError::Unavailable)
        ));
    }
}
