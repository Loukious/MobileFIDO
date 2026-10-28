//! CTAPHID cancellation terminates the original CBOR transaction, never CANCEL.
use pocof7_native_ctaphid::protocol::{frame, Action, Engine, BROADCAST, CANCEL, CBOR, INIT, PING};
use pocof7_native_ctaphid::REPORT_SIZE;
use std::sync::atomic::Ordering;
use std::time::Instant;

fn reports(action: &Action) -> &[[u8; REPORT_SIZE]] {
    match action {
        Action::Send(reports) => reports,
        _ => panic!("expected USB response"),
    }
}

fn send(engine: &mut Engine, cid: u32, cmd: u8, data: &[u8]) -> Vec<Action> {
    let mut result = Vec::new();
    for packet in frame(cid, cmd, data).unwrap() {
        result = engine.ingest(&packet, Instant::now());
    }
    result
}

fn allocate(engine: &mut Engine) -> u32 {
    let response = send(engine, BROADCAST, INIT, b"12345678");
    let packet = &reports(&response[0])[0];
    u32::from_be_bytes(packet[15..19].try_into().unwrap())
}

#[test]
fn init_explicitly_declares_that_legacy_msg_is_not_supported() {
    let mut engine = Engine::new();
    let response = send(&mut engine, BROADCAST, INIT, b"12345678");
    let packet = &reports(&response[0])[0];
    assert_eq!(packet[23], 0x04 | 0x08); // CBOR | NMSG, no WINK.
}

#[test]
fn cancel_completes_cbor_once_and_drops_late_worker_results() {
    let mut engine = Engine::new();
    let cid = allocate(&mut engine);
    let started = send(&mut engine, cid, CBOR, &[4]);
    let (old_job, cancel) = match &started[0] {
        Action::Start { job, cancel, .. } => (*job, cancel.clone()),
        _ => panic!("expected worker"),
    };
    let cancelled = send(&mut engine, cid, CANCEL, &[]);
    assert_eq!(cancelled.len(), 1);
    let packets = reports(&cancelled[0]);
    assert_eq!(packets.len(), 1);
    assert_eq!(&packets[0][..4], &cid.to_be_bytes());
    assert_eq!(packets[0][4], CBOR | 0x80);
    assert_eq!(&packets[0][5..8], &[0, 1, 0x2d]);
    assert!(cancel.load(Ordering::Acquire));
    assert_eq!(engine.active_count(), 0);
    assert!(send(&mut engine, cid, CANCEL, &[]).is_empty());
    assert!(engine.finished(cid, old_job, vec![0]).is_empty());

    let next = send(&mut engine, cid, CBOR, &[4]);
    let new_job = match next[0] {
        Action::Start { job, .. } => job,
        _ => panic!("expected new worker"),
    };
    assert_ne!(old_job, new_job);
    assert!(engine.finished(cid, old_job, vec![0]).is_empty());
    assert_eq!(engine.finished(cid, new_job, vec![0]).len(), 1);
}

#[test]
fn cancel_on_non_active_channels_is_silent_and_preserves_partial_requests() {
    let mut engine = Engine::new();
    let cid = allocate(&mut engine);
    for inactive in [cid, 0, BROADCAST, cid ^ 0x8000_0000] {
        assert!(send(&mut engine, inactive, CANCEL, &[]).is_empty());
    }
    let partial = frame(cid, PING, &[0x42; 58]).unwrap();
    assert!(engine.ingest(&partial[0], Instant::now()).is_empty());
    assert!(send(&mut engine, cid, CANCEL, &[]).is_empty());
    let completed = engine.ingest(&partial[1], Instant::now());
    assert_eq!(reports(&completed[0])[0][4], PING | 0x80);
}

#[test]
fn malformed_cancel_does_not_cancel_an_active_operation() {
    let mut engine = Engine::new();
    let cid = allocate(&mut engine);
    let started = send(&mut engine, cid, CBOR, &[4]);
    let cancel = match &started[0] {
        Action::Start { cancel, .. } => cancel.clone(),
        _ => panic!("expected worker"),
    };
    assert!(send(&mut engine, cid, CANCEL, &[1]).is_empty());
    assert!(!cancel.load(Ordering::Acquire));
    assert_eq!(engine.active_count(), 1);
}
