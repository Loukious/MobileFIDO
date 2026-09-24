//! Exercises the shipped native engine directly; no USB gadget or Android device.
use pocof7_native_ctaphid::protocol::{frame, Action, Engine, BROADCAST, CANCEL, CBOR, ERROR, INIT, KEEPALIVE, PING};
use pocof7_native_ctaphid::{MAX_MESSAGE, REPORT_SIZE};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn reports(action: &Action) -> &[[u8; REPORT_SIZE]] {
    match action { Action::Send(reports) => reports, _ => panic!("expected USB response") }
}

fn status(actions: &[Action], cid: u32, code: u8) {
    assert_eq!(actions.len(), 1);
    let response = reports(&actions[0]);
    assert_eq!(response.len(), 1);
    assert_eq!(&response[0][..4], &cid.to_be_bytes());
    assert_eq!(response[0][4], ERROR | 0x80);
    assert_eq!(response[0][7], code);
}

fn send(engine: &mut Engine, cid: u32, cmd: u8, data: &[u8], now: Instant) -> Vec<Action> {
    let mut result = Vec::new();
    for packet in frame(cid, cmd, data).unwrap() { result = engine.ingest(&packet, now); }
    result
}

fn allocate(engine: &mut Engine, now: Instant) -> u32 {
    let response = send(engine, BROADCAST, INIT, b"12345678", now);
    let packet = &reports(&response[0])[0];
    u32::from_be_bytes(packet[15..19].try_into().unwrap())
}

#[test]
fn invalid_channels_commands_and_lengths_fail_closed() {
    let t = Instant::now();
    let mut engine = Engine::new();
    let cid = allocate(&mut engine, t);
    status(&send(&mut engine, BROADCAST, PING, b"x", t), BROADCAST, 0x0b);
    status(&send(&mut engine, 0, CBOR, b"x", t), 0, 0x0b);
    status(&send(&mut engine, cid, 0x03, b"x", t), cid, 0x01);
    status(&send(&mut engine, cid, INIT, b"short", t), cid, 0x03);
    let mut oversized = frame(cid, PING, b"x").unwrap()[0];
    oversized[5..7].copy_from_slice(&((MAX_MESSAGE + 1) as u16).to_be_bytes());
    status(&engine.ingest(&oversized, t), cid, 0x03);
    assert_eq!(engine.active_count(), 0);
    assert_eq!(reports(&send(&mut engine, cid, PING, b"still alive", t)[0])[0][4], PING | 0x80);
}

#[test]
fn interleaved_partial_packets_do_not_cross_channel_boundaries() {
    let t = Instant::now();
    let mut engine = Engine::new();
    let a = allocate(&mut engine, t);
    let b = allocate(&mut engine, t);
    let a_frames = frame(a, PING, &[0xa5; 120]).unwrap();
    let b_frames = frame(b, PING, &[0x5a; 120]).unwrap();
    assert!(engine.ingest(&a_frames[0], t).is_empty());
    assert!(engine.ingest(&b_frames[0], t).is_empty());
    status(&engine.ingest(&b_frames[2], t), b, 0x04);
    assert!(engine.ingest(&a_frames[1], t).is_empty());
    let completed = engine.ingest(&a_frames[2], t);
    assert_eq!(reports(&completed[0])[0][4], PING | 0x80);
    status(&engine.ingest(&b_frames[1], t), b, 0x04);
    assert_eq!(reports(&send(&mut engine, b, PING, b"recover", t)[0])[0][4], PING | 0x80);
}

#[test]
fn all_busy_channels_cannot_be_evicted_or_admit_another_worker() {
    let t = Instant::now();
    let mut engine = Engine::new();
    let mut running = Vec::new();
    for _ in 0..8 {
        let cid = allocate(&mut engine, t);
        let started = send(&mut engine, cid, CBOR, &[4], t);
        match &started[0] {
            Action::Start { cancel, job, .. } => running.push((cid, *job, cancel.clone())),
            _ => panic!("missing worker"),
        }
    }
    status(&send(&mut engine, BROADCAST, INIT, b"abcdefgh", t), BROADCAST, 0x06);
    let (cid, job, cancelled) = &running[0];
    assert!(send(&mut engine, *cid, CANCEL, &[], t).is_empty());
    assert!(cancelled.load(Ordering::Acquire));
    assert!(engine.finished(*cid, *job, vec![0]).is_empty());
    let replacement = allocate(&mut engine, t);
    assert_ne!(replacement, 0);
    assert_eq!(engine.active_count(), 7);
}

#[test]
fn reset_cancels_worker_and_never_replays_previous_reply() {
    let t = Instant::now();
    let mut engine = Engine::new();
    let cid = allocate(&mut engine, t);
    let started = send(&mut engine, cid, CBOR, &[4], t);
    let (job, cancel, up) = match &started[0] {
        Action::Start { job, cancel, up_needed, .. } => (*job, cancel.clone(), up_needed.clone()),
        _ => panic!("missing worker"),
    };
    up.store(true, Ordering::Release);
    let alive = engine.tick(t + Duration::from_secs(69));
    assert_eq!(reports(&alive[0])[0][4], KEEPALIVE | 0x80);
    assert_eq!(reports(&alive[0])[0][7], 2);
    engine.clear(); // USB detach/re-enumeration
    assert!(cancel.load(Ordering::Acquire));
    assert!(engine.finished(cid, job, vec![0]).is_empty());
    status(&send(&mut engine, cid, PING, b"stale", t), cid, 0x0b);
    let new_cid = allocate(&mut engine, t);
    assert!(engine.finished(new_cid, job, vec![0]).is_empty());
}
