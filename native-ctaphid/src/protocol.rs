//! Stateless CTAPHID framing plus bounded, single-USB-owner protocol engine.
//! IPC/signing runs on separate workers. Protocol never silently signs.
use crate::{MAX_MESSAGE, REPORT_SIZE};
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const BROADCAST: u32 = 0xffff_ffff;
pub const PING: u8 = 0x01;
pub const INIT: u8 = 0x06;
pub const CBOR: u8 = 0x10;
pub const CANCEL: u8 = 0x11;
pub const KEEPALIVE: u8 = 0x3b;
pub const ERROR: u8 = 0x3f;
const INVALID_CMD: u8 = 0x01;
const INVALID_LEN: u8 = 0x03;
const INVALID_SEQ: u8 = 0x04;
const MSG_TIMEOUT: u8 = 0x05;
const BUSY: u8 = 0x06;
const INVALID_CHANNEL: u8 = 0x0b;
const MAX_CHANNELS: usize = 8;
const INCOMPLETE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Helper allows 60 seconds for the user to tap the notification and finish
// per-use biometric authorization. Native IPC ends by 65 seconds; allow a
// further 5 seconds for the worker reply to reach the USB thread.
const CBOR_TIMEOUT: Duration = Duration::from_secs(70);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(250);
// A USB reset discards every CID, but cancelled worker replies may still be
// sitting in the MPSC queue. Never reuse (CID, job) across Engine instances:
// fresh device enumeration could coincidentally allocate the same random CID.
static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

pub type Report = [u8; REPORT_SIZE];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub cid: u32,
    pub command: u8,
    pub bytes: Vec<u8>,
}

/// All outbound reports are produced by the owning USB thread.
#[derive(Debug)]
pub enum Action {
    Send(Vec<Report>),
    Start {
        cid: u32,
        job: u64,
        request: Vec<u8>,
        cancel: Arc<AtomicBool>,
        up_needed: Arc<AtomicBool>,
    },
}

fn packet_cid(packet: &Report) -> u32 {
    u32::from_be_bytes(packet[..4].try_into().expect("fixed-size CID"))
}

pub fn frame(cid: u32, command: u8, message: &[u8]) -> Result<Vec<Report>, &'static str> {
    if command >= 0x80 || message.len() > MAX_MESSAGE {
        return Err("invalid CTAPHID command or oversized message");
    }
    let mut out = Vec::with_capacity(1 + message.len().saturating_sub(57).div_ceil(59));
    let mut first = [0u8; REPORT_SIZE];
    first[..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = command | 0x80;
    first[5..7].copy_from_slice(&(message.len() as u16).to_be_bytes());
    let initial = message.len().min(57);
    first[7..7 + initial].copy_from_slice(&message[..initial]);
    out.push(first);
    for (seq, chunk) in message[initial..].chunks(59).enumerate() {
        if seq > 127 {
            return Err("too many continuation frames");
        }
        let mut cont = [0u8; REPORT_SIZE];
        cont[..4].copy_from_slice(&cid.to_be_bytes());
        cont[4] = seq as u8;
        cont[5..5 + chunk.len()].copy_from_slice(chunk);
        out.push(cont);
    }
    Ok(out)
}

fn send(cid: u32, cmd: u8, payload: &[u8]) -> Action {
    Action::Send(frame(cid, cmd, payload).expect("internally bounded response"))
}

fn error(cid: u32, code: u8) -> Action {
    send(cid, ERROR, &[code])
}

#[derive(Debug)]
struct Pending {
    command: u8,
    required: usize,
    bytes: Vec<u8>,
    next_seq: u8,
    started: Instant,
}

#[derive(Debug)]
struct Running {
    job: u64,
    started: Instant,
    keepalive: Instant,
    cancel: Arc<AtomicBool>,
    up_needed: Arc<AtomicBool>,
}

#[derive(Debug)]
struct Channel {
    last_used: Instant,
}

/// No unbounded frames/channels/transactions. Cancelled workers are ignored
/// even if the Android IPC call finishes after CANCEL or re-enumeration.
#[derive(Debug)]
pub struct Engine {
    channels: HashMap<u32, Channel>,
    pending: HashMap<u32, Pending>,
    active: HashMap<u32, Running>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            pending: HashMap::new(),
            active: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        for running in self.active.values() {
            running.cancel.store(true, Ordering::Release);
        }
        self.channels.clear();
        self.pending.clear();
        self.active.clear();
    }

    pub fn cancel_all(&mut self) {
        self.clear();
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    fn abort(&mut self, cid: u32) {
        self.pending.remove(&cid);
        if let Some(job) = self.active.remove(&cid) {
            job.cancel.store(true, Ordering::Release);
        }
    }

    fn channel(&mut self, now: Instant) -> Option<u32> {
        if self.channels.len() >= MAX_CHANNELS {
            let victim = self.channels
                .iter()
                .filter(|(cid, _)| !self.pending.contains_key(cid) && !self.active.contains_key(cid))
                .min_by_key(|(_, channel)| channel.last_used)
                .map(|(&cid, _)| cid);
            if let Some(victim) = victim {
                self.channels.remove(&victim);
            } else {
                return None;
            }
        }
        let mut random = std::fs::File::open("/dev/urandom").ok()?;
        for _ in 0..64 {
            let mut raw = [0u8; 4];
            random.read_exact(&mut raw).ok()?;
            let cid = u32::from_be_bytes(raw);
            if cid != 0 && cid != BROADCAST && !self.channels.contains_key(&cid) {
                self.channels.insert(cid, Channel { last_used: now });
                return Some(cid);
            }
        }
        None
    }

    /// Exactly one host report, never a variable-size input stream.
    pub fn ingest(&mut self, packet: &Report, now: Instant) -> Vec<Action> {
        let cid = packet_cid(packet);
        let marker = packet[4];
        if marker & 0x80 == 0 {
            return self.continuation(packet, cid, marker, now);
        }
        let command = marker & 0x7f;
        if cid == BROADCAST {
            if command != INIT {
                return vec![error(cid, INVALID_CHANNEL)];
            }
        } else if !self.channels.contains_key(&cid) {
            return vec![error(cid, INVALID_CHANNEL)];
        } else {
            self.channels.get_mut(&cid).expect("exists").last_used = now;
            if self.active.contains_key(&cid) {
                if command == INIT {
                    self.abort(cid);
                } else if command != CANCEL {
                    return vec![error(cid, BUSY)];
                }
            }
        }
        self.pending.remove(&cid); // Restart an incomplete request on this CID.
        let length = u16::from_be_bytes([packet[5], packet[6]]) as usize;
        if length > MAX_MESSAGE {
            return vec![error(cid, INVALID_LEN)];
        }
        let got = length.min(57);
        let data = packet[7..7 + got].to_vec();
        if got == length {
            return self.dispatch(cid, command, data, now);
        }
        // Broadcast never permits multi-packet non-INIT. INIT always 8 bytes.
        self.pending.insert(cid, Pending {
            command,
            required: length,
            bytes: data,
            next_seq: 0,
            started: now,
        });
        vec![]
    }

    fn continuation(&mut self, packet: &Report, cid: u32, seq: u8, now: Instant) -> Vec<Action> {
        if !self.pending.contains_key(&cid) {
            let code = if cid == BROADCAST || self.channels.contains_key(&cid) {
                if self.active.contains_key(&cid) { BUSY } else { INVALID_SEQ }
            } else {
                INVALID_CHANNEL
            };
            return vec![error(cid, code)];
        }
        let pending = self.pending.get_mut(&cid).expect("exists");
        if pending.next_seq != seq {
            self.pending.remove(&cid);
            return vec![error(cid, INVALID_SEQ)];
        }
        pending.next_seq = pending.next_seq.saturating_add(1);
        let copy = (pending.required - pending.bytes.len()).min(59);
        pending.bytes.extend_from_slice(&packet[5..5 + copy]);
        if let Some(channel) = self.channels.get_mut(&cid) {
            channel.last_used = now;
        }
        if pending.bytes.len() == pending.required {
            let message = self.pending.remove(&cid).expect("exists");
            self.dispatch(cid, message.command, message.bytes, now)
        } else {
            vec![]
        }
    }

    fn dispatch(&mut self, cid: u32, cmd: u8, data: Vec<u8>, now: Instant) -> Vec<Action> {
        match cmd {
            INIT => {
                if data.len() != 8 {
                    return vec![error(cid, INVALID_LEN)];
                }
                let new_cid = if cid == BROADCAST {
                    match self.channel(now) {
                        Some(cid) => cid,
                        None => return vec![error(cid, BUSY)],
                    }
                } else {
                    cid
                };
                let mut info = data;
                info.extend_from_slice(&new_cid.to_be_bytes());
                // CTAPHID protocol v2; self-assigned dev firmware 0.1.0,
                // CBOR only: do not advertise unsupported U2F/MSG/LOCK.
                info.extend_from_slice(&[2, 0, 1, 0, 0x04]);
                vec![send(cid, INIT, &info)]
            }
            PING => vec![send(cid, PING, &data)],
            CANCEL => {
                self.abort(cid);
                vec![]
            }
            CBOR => {
                if self.active.len() >= MAX_CHANNELS {
                    return vec![error(cid, BUSY)];
                }
                let cancel = Arc::new(AtomicBool::new(false));
                let up_needed = Arc::new(AtomicBool::new(false));
                let job = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
                self.active.insert(cid, Running {
                    job,
                    started: now,
                    keepalive: now + KEEPALIVE_INTERVAL,
                    cancel: cancel.clone(),
                    up_needed: up_needed.clone(),
                });
                vec![Action::Start {
                    cid, job, request: data, cancel, up_needed,
                }]
            }
            _ => vec![error(cid, INVALID_CMD)],
        }
    }

    pub fn finished(&mut self, cid: u32, job: u64, response: Vec<u8>) -> Vec<Action> {
        let current = self.active.get(&cid);
        if current.is_none_or(|running| running.job != job || running.cancel.load(Ordering::Acquire)) {
            return vec![];
        }
        self.active.remove(&cid);
        if response.len() > MAX_MESSAGE {
            return vec![error(cid, INVALID_LEN)];
        }
        vec![send(cid, CBOR, &response)]
    }

    /// If bounded worker slots are all occupied (including cancelled but not
    /// yet exited IPC threads), do not leave a phantom active request.
    pub fn worker_busy(&mut self, cid: u32, job: u64) -> Vec<Action> {
        if self.active.get(&cid).is_some_and(|r| r.job == job) {
            self.abort(cid);
            return vec![error(cid, BUSY)];
        }
        vec![]
    }

    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut result = Vec::new();
        let timed_out: Vec<u32> = self.pending.iter()
            .filter(|(_, partial)| now.duration_since(partial.started) > INCOMPLETE_TIMEOUT)
            .map(|(&cid, _)| cid).collect();
        for cid in timed_out {
            self.pending.remove(&cid);
            result.push(error(cid, MSG_TIMEOUT));
        }
        let active_ids: Vec<u32> = self.active.keys().copied().collect();
        for cid in active_ids {
            let running = self.active.get_mut(&cid).expect("snapshot");
            if now.duration_since(running.started) > CBOR_TIMEOUT {
                running.cancel.store(true, Ordering::Release);
                self.active.remove(&cid);
                result.push(error(cid, MSG_TIMEOUT));
            } else if now >= running.keepalive {
                let state = if running.up_needed.load(Ordering::Acquire) { 2 } else { 1 };
                result.push(send(cid, KEEPALIVE, &[state]));
                running.keepalive = now + KEEPALIVE_INTERVAL;
            }
        }
        let evict: Vec<u32> = self.channels.iter()
            .filter(|(cid, entry)| !self.pending.contains_key(cid) && !self.active.contains_key(cid)
                && now.duration_since(entry.last_used) > IDLE_TIMEOUT)
            .map(|(&cid, _)| cid).collect();
        for cid in evict {
            self.channels.remove(&cid);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(cid: u32, cmd: u8, data: &[u8]) -> Vec<Report> {
        frame(cid, cmd, data).unwrap()
    }
    fn first(engine: &mut Engine, now: Instant) -> u32 {
        let response = engine.ingest(&req(BROADCAST, INIT, &[3; 8])[0], now);
        if let Action::Send(packets) = &response[0] {
            assert_eq!(&packets[0][7..15], &[3u8; 8]);
            let cid = u32::from_be_bytes(packets[0][15..19].try_into().unwrap());
            assert_ne!(cid, BROADCAST);
            assert_eq!(packets[0][4], INIT | 0x80);
            assert_eq!(packets[0][23], 0x04);
            cid
        } else {
            panic!("not INIT response")
        }
    }
    #[test]
    fn boundary_frames_round_trip() {
        for size in [0, 1, 57, 58, 64, 200, MAX_MESSAGE] {
            let now = Instant::now();
            let mut engine = Engine::new();
            let cid = first(&mut engine, now);
            let msg = vec![0x39; size];
            let frames = req(cid, PING, &msg);
            let mut last = Vec::new();
            for frame in frames {
                assert_eq!(frame.len(), REPORT_SIZE);
                last = engine.ingest(&frame, now);
            }
            if let Action::Send(got) = &last[0] {
                let mut assembled = Vec::new();
                for (index, pkt) in got.iter().enumerate() {
                    assembled.extend_from_slice(&pkt[if index == 0 { 7.. } else { 5.. }]);
                }
                assert_eq!(&assembled[..size], &msg);
            } else {
                panic!("no PING response")
            }
        }
        assert!(frame(1, PING, &vec![0; MAX_MESSAGE + 1]).is_err());
    }
    #[test]
    fn channel_resync_and_foreign_cid() {
        let mut e = Engine::new();
        let t = Instant::now();
        let cid = first(&mut e, t);
        let out = e.ingest(&req(cid, INIT, &[5; 8])[0], t);
        if let Action::Send(reports) = &out[0] {
            assert_eq!(&reports[0][15..19], &cid.to_be_bytes());
        } else { panic!() }
        assert!(matches!(e.ingest(&req(7, PING, b"a")[0], t)[0], Action::Send(_)));
    }
    #[test]
    fn continuation_order_and_transaction_timeout() {
        let mut e = Engine::new();
        let t = Instant::now();
        let cid = first(&mut e, t);
        let f = req(cid, PING, &[1; 160]);
        assert!(e.ingest(&f[0], t).is_empty());
        let bad = e.ingest(&f[2], t);
        if let Action::Send(ref x) = bad[0] { assert_eq!(x[0][7], INVALID_SEQ); }
        assert!(e.ingest(&f[0], t).is_empty());
        let expired = e.tick(t + Duration::from_secs(6));
        if let Action::Send(ref x) = expired[0] { assert_eq!(x[0][7], MSG_TIMEOUT); }
    }
    #[test]
    fn cancel_keepalive_late_result() {
        let mut e = Engine::new();
        let t = Instant::now();
        let cid = first(&mut e, t);
        let start = e.ingest(&req(cid, CBOR, &[4])[0], t);
        let (job, flag, up) = match &start[0] {
            Action::Start { job, cancel, up_needed, .. } => (*job, cancel.clone(), up_needed.clone()),
            _ => panic!(),
        };
        up.store(true, Ordering::Release);
        if let Action::Send(ref x) = e.tick(t + Duration::from_millis(251))[0] {
            assert_eq!(x[0][4], KEEPALIVE | 0x80);
            assert_eq!(x[0][7], 2);
        }
        assert!(e.ingest(&req(cid, CANCEL, &[])[0], t).is_empty());
        assert!(flag.load(Ordering::Acquire));
        assert!(e.finished(cid, job, vec![0]).is_empty());
    }
    #[test]
    fn notification_tap_window_keeps_channel_alive_then_times_out_at_70s() {
        // A tap/unlock/hardware biometric may be delayed while the phone
        // Activity is in the background. The CTAPHID engine must continue
        // UP_NEEDED keepalives past the old 33-second budget, without
        // generating any synthetic approval or accepting a late signature.
        let mut e = Engine::new();
        let t = Instant::now();
        let cid = first(&mut e, t);
        let start = e.ingest(&req(cid, CBOR, &[4])[0], t);
        let (job, cancelled, up) = match &start[0] {
            Action::Start { job, cancel, up_needed, .. } =>
                (*job, cancel.clone(), up_needed.clone()),
            _ => panic!("missing worker"),
        };
        up.store(true, Ordering::Release);
        for second in [1, 40, 65, 69] {
            let actions = e.tick(t + Duration::from_secs(second));
            if let Action::Send(ref reports) = actions[0] {
                assert_eq!(reports[0][4], KEEPALIVE | 0x80);
                assert_eq!(reports[0][7], 2);
            } else {
                panic!("up-needed keepalive missing at {second}s");
            }
            assert!(!cancelled.load(Ordering::Acquire));
        }
        let expired = e.tick(t + Duration::from_secs(71));
        if let Action::Send(ref reports) = expired[0] {
            assert_eq!(reports[0][4], ERROR | 0x80);
            assert_eq!(reports[0][7], MSG_TIMEOUT);
        } else {
            panic!("missing bounded CTAPHID timeout");
        }
        assert!(cancelled.load(Ordering::Acquire));
        assert!(e.finished(cid, job, vec![0]).is_empty());
    }
    #[test]
    fn job_supersession_does_not_leak() {
        let mut e = Engine::new();
        let t = Instant::now();
        let cid = first(&mut e, t);
        let old = e.ingest(&req(cid, CBOR, &[1])[0], t);
        let old_id = if let Action::Start { job, .. } = old[0] { job } else { panic!() };
        e.ingest(&req(cid, INIT, &[5; 8])[0], t);
        let current = e.ingest(&req(cid, CBOR, &[4])[0], t);
        let now_id = if let Action::Start { job, .. } = current[0] { job } else { panic!() };
        assert_ne!(old_id, now_id);
        assert!(e.finished(cid, old_id, vec![0]).is_empty());
        assert_eq!(e.finished(cid, now_id, vec![0]).len(), 1);
    }
}
