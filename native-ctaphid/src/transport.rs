//! The sole module that opens /dev/hidgN. Never changes ConfigFS, USB, or ADB.
use crate::{FIDO_DESCRIPTOR, REPORT_SIZE};
use libc::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_CONFIGFS: &str = "/config/usb_gadget/g1";
#[derive(Debug, Clone)]
pub struct Gadget {
    pub function: PathBuf,
    pub node: PathBuf,
    pub rdev: u64,
    pub controller: String,
}
fn text(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}
fn descriptor_match(path: &Path) -> io::Result<bool> {
    // ConfigFS returns up to 4096 bytes, padded, for a 34-byte descriptor.
    let mut raw = [0; FIDO_DESCRIPTOR.len()];
    let mut f = File::open(path)?;
    match f.read_exact(&mut raw) {
        Ok(()) => Ok(raw == FIDO_DESCRIPTOR),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}
fn dev_major(dev: u64) -> u64 {
    ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)
}
fn dev_minor(dev: u64) -> u64 {
    (dev & 0xff) | ((dev >> 12) & !0xff)
}
fn node_matches(node: &Path, major: u64, minor: u64) -> io::Result<bool> {
    let meta = match fs::symlink_metadata(node) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(meta.file_type().is_char_device()
        && dev_major(meta.rdev()) == major
        && dev_minor(meta.rdev()) == minor)
}
fn resolve_node(dev_dir: &Path, major: u64, minor: u64) -> io::Result<Option<(PathBuf, u64)>> {
    let conventional = dev_dir.join(format!("hidg{minor}"));
    if node_matches(&conventional, major, minor)? {
        let rdev = fs::symlink_metadata(&conventional)?.rdev();
        return Ok(Some((conventional, rdev)));
    }
    for entry in fs::read_dir(dev_dir)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("hidg") {
            continue;
        }
        let path = entry.path();
        if node_matches(&path, major, minor)? {
            return Ok(Some((path.clone(), fs::symlink_metadata(path)?.rdev())));
        }
    }
    Ok(None)
}
fn linked(root: &Path, function: &Path) -> io::Result<bool> {
    for config in fs::read_dir(root.join("configs"))? {
        let config = config?;
        if !config.file_type()?.is_dir() { continue; }
        for link in fs::read_dir(config.path())? {
            let link = link?;
            if !link.file_type()?.is_symlink() { continue; }
            if fs::canonicalize(link.path())? == function { return Ok(true); }
        }
    }
    Ok(false)
}
/// Read-only discovery, exact descriptor, linked function, matching rdev.
/// Never guess a keyboard/mouse HID function if CTAP descriptor is absent.
pub fn discover(root: &Path, dev_dir: &Path) -> io::Result<Gadget> {
    let controller = text(root.join("UDC"))?;
    if controller.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "UDC unbound"));
    }
    let mut found = None;
    for item in fs::read_dir(root.join("functions"))? {
        let entry = item?;
        if !entry.file_name().to_string_lossy().starts_with("hid.")
            || !entry.file_type()?.is_dir() { continue; }
        let path = entry.path();
        if !descriptor_match(&path.join("report_desc"))? { continue; }
        if text(path.join("report_length"))? != "64"
            || text(path.join("protocol"))? != "0"
            || text(path.join("subclass"))? != "0"
            || text(path.join("no_out_endpoint"))? != "0" { continue; }
        let canonical = fs::canonicalize(&path)?;
        if !linked(root, &canonical)? { continue; }
        let dev = text(path.join("dev"))?;
        let (major, minor) = dev.split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad ConfigFS dev"))?;
        let (major, minor): (u64, u64) = (
            major.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad major"))?,
            minor.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad minor"))?,
        );
        let Some((node, rdev)) = resolve_node(dev_dir, major, minor)? else { continue; };
        if found.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ambiguous FIDO HID functions"));
        }
        found = Some(Gadget { function: canonical, node, rdev, controller: controller.clone() });
    }
    found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound,
        "no linked FIDO HID function with matching /dev/hidgN"))
}

fn poll_fd(fd: libc::c_int, events: i16, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd, events, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let status = unsafe { libc::poll(&mut pfd, 1, ms) };
    if status < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted { Ok(false) } else { Err(e) };
    }
    if status == 0 { return Ok(false); }
    if pfd.revents & (POLLERR | POLLHUP | POLLNVAL) != 0 {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "HID device disconnected"));
    }
    Ok((pfd.revents & events) != 0)
}

pub struct Transport {
    gadget: Gadget,
    file: File,
    trace_hid: bool,
    rx_count: u64,
    tx_count: u64,
}

/// Sanitized report *header* only: never print nonce, CBOR body, PIN,
/// credential ID, clientDataHash, signature, or PING body.
fn trace_header(report: &[u8; REPORT_SIZE]) -> String {
    let cid = u32::from_be_bytes(report[..4].try_into().expect("fixed report"));
    let marker = report[4];
    if marker & 0x80 != 0 {
        let command = match marker & 0x7f {
            0x01 => "PING",
            0x06 => "INIT",
            0x10 => "CBOR",
            0x11 => "CANCEL",
            0x3b => "KEEPALIVE",
            0x3f => "ERROR",
            _ => "OTHER",
        };
        let declared = u16::from_be_bytes([report[5], report[6]]);
        format!("init cid={cid:08x} cmd={command} declared_len={declared}")
    } else {
        format!("cont cid={cid:08x} seq={marker}")
    }
}

impl Transport {
    pub fn open(gadget: Gadget) -> io::Result<Self> {
        Self::open_with_trace(gadget, false)
    }

    /// Identical I/O policy with opt-in metadata-only diagnostic tracing.
    pub fn open_with_trace(gadget: Gadget, trace_hid: bool) -> io::Result<Self> {
        if !node_matches(&gadget.node, dev_major(gadget.rdev), dev_minor(gadget.rdev))? {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "rdev changed before open"));
        }
        // Never create/truncate the gadget or follow a synthetic node symlink.
        let file = OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&gadget.node)?;
        if file.metadata()?.rdev() != gadget.rdev {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "rdev changed during open"));
        }
        Ok(Self { gadget, file, trace_hid, rx_count: 0, tx_count: 0 })
    }

    pub fn path(&self) -> &Path { &self.gadget.node }
    pub fn counters(&self) -> (u64, u64) { (self.rx_count, self.tx_count) }

    /// Detect UDC/link/function replacement. Call once per second while open.
    pub fn healthy(&self, root: &Path, dev_dir: &Path) -> bool {
        let Ok(now) = discover(root, dev_dir) else { return false; };
        now.node == self.gadget.node
            && now.rdev == self.gadget.rdev
            && now.function == self.gadget.function
            && now.controller == self.gadget.controller
    }

    pub fn read_packet(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT_SIZE]>> {
        let ready = poll_fd(self.file.as_raw_fd(), POLLIN, timeout).map_err(|e| {
            if self.trace_hid {
                eprintln!("TRACE-HID poll RX failed kind={:?} errno={:?}",
                    e.kind(), e.raw_os_error());
            }
            e
        })?;
        if !ready { return Ok(None); }
        let mut bytes = [0; REPORT_SIZE];
        match self.file.read(&mut bytes) {
            Ok(REPORT_SIZE) => {
                self.rx_count += 1;
                if self.trace_hid {
                    eprintln!("TRACE-HID RX #{} bytes={} {}", self.rx_count, REPORT_SIZE,
                        trace_header(&bytes));
                }
                Ok(Some(bytes))
            }
            Ok(0) => {
                if self.trace_hid { eprintln!("TRACE-HID RX EOF"); }
                Err(io::Error::new(io::ErrorKind::NotConnected, "HID gadget EOF"))
            }
            Ok(n) => {
                if self.trace_hid { eprintln!("TRACE-HID RX SHORT bytes={n} expected=64"); }
                Err(io::Error::new(io::ErrorKind::InvalidData, "short HID report"))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => {
                if self.trace_hid {
                    eprintln!("TRACE-HID read failed kind={:?} errno={:?}",
                        e.kind(), e.raw_os_error());
                }
                Err(e)
            }
        }
    }

    pub fn write_report(&mut self, bytes: &[u8; REPORT_SIZE]) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match self.file.write(bytes) {
                Ok(REPORT_SIZE) => {
                    self.tx_count += 1;
                    if self.trace_hid {
                        eprintln!("TRACE-HID TX #{} bytes={} {}", self.tx_count, REPORT_SIZE,
                            trace_header(bytes));
                    }
                    return Ok(());
                }
                Ok(n) => {
                    if self.trace_hid { eprintln!("TRACE-HID TX SHORT bytes={n} expected=64"); }
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "partial HID write"));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let ready = poll_fd(self.file.as_raw_fd(), POLLOUT, remaining).map_err(|e| {
                        if self.trace_hid {
                            eprintln!("TRACE-HID poll TX failed kind={:?} errno={:?}",
                                e.kind(), e.raw_os_error());
                        }
                        e
                    })?;
                    if remaining.is_zero() || !ready {
                        if self.trace_hid { eprintln!("TRACE-HID TX deadline"); }
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "HID write deadline"));
                    }
                }
                Err(e) => {
                    if self.trace_hid {
                        eprintln!("TRACE-HID write failed kind={:?} errno={:?}",
                            e.kind(), e.raw_os_error());
                    }
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configfs_4096_padded_and_corrupt_descriptors() {
        let path = std::env::temp_dir().join(format!(
            "ctap-desc-{}-{:?}", std::process::id(), std::thread::current().id()
        ));
        let mut raw = FIDO_DESCRIPTOR.to_vec();
        raw.resize(4096, 0);
        fs::write(&path, &raw).unwrap();
        assert!(descriptor_match(&path).unwrap());
        raw[7] ^= 1;
        fs::write(&path, &raw).unwrap();
        assert!(!descriptor_match(&path).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn linux_major_minor_matches_null_device() {
        let dev = fs::metadata("/dev/null").unwrap().rdev();
        assert_eq!((dev_major(dev), dev_minor(dev)), (1, 3));
    }

    #[test]
    fn trace_header_cannot_expose_payload_or_init_nonce() {
        let mut report = [0x53u8; REPORT_SIZE];
        report[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        report[4] = 0x80 | 0x06;
        report[5..7].copy_from_slice(&8u16.to_be_bytes());
        report[7..15].copy_from_slice(b"SECRETH!");
        let line = trace_header(&report);
        assert_eq!(line, "init cid=ffffffff cmd=INIT declared_len=8");
        assert!(!line.contains("SECRETH"));
        report[4] = 0;
        let line = trace_header(&report);
        assert_eq!(line, "cont cid=ffffffff seq=0");
        assert!(!line.contains("SECRETH"));
    }
}
