//! Standalone Android/Linux CTAPHID daemon. USB I/O is owned by this thread;
//! Android RPC runs only in bounded cancellable workers. No Kali, NetHunter,
//! private key files, fallback signer, gadget reconfiguration or UI bypass.
use pocof7_native_ctaphid::backend;
use pocof7_native_ctaphid::protocol::{Action, Engine};
use pocof7_native_ctaphid::transport::{self, Transport};
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const MAX_WORKERS: usize = 8;
const READ_WAIT: Duration = Duration::from_millis(100);
const RECONNECT: Duration = Duration::from_secs(1);
// A background phone may need an explicit notification tap, unlock and a
// hardware BiometricPrompt before the helper returns its result. Android's
// operation budget is 60 seconds; leave 5 seconds for framed IPC/cleanup.
// CTAPHID's CBOR worker budget must exceed this (70 seconds).
const IPC_TIMEOUT: Duration = Duration::from_secs(65);
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_stop(_signal: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Options {
    configfs: PathBuf,
    hid: Option<PathBuf>,
    socket: String,
    app_uid: Option<u32>,
    check: bool,
    self_test: bool,
    trace_hid: bool,
}

fn usage() -> &'static str {
    "Usage: pocof7-native-ctaphid --android-helper-uid <installed-app-uid> \
     [--configfs /config/usb_gadget/g1 | /config/usb_gadget/g1/functions/hid.2] \
     [--hid /dev/hidgN] [--socket ctaphid-m3b-v1] [--trace-hid] [--check | --self-test]\n\
     --check: read-only, no Android IPC or USB gadget writes\n\
     --self-test: protocol/descriptor static check, no device access\n\
     --trace-hid: opt-in RX/TX report HEADER/count diagnostics only; never logs payloads"
}

fn parse() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let mut opts = Options {
        configfs: PathBuf::from(transport::DEFAULT_CONFIGFS),
        hid: None,
        socket: backend::DEFAULT_SOCKET_NAME.to_owned(),
        app_uid: None,
        check: false,
        self_test: false,
        trace_hid: false,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--configfs" => opts.configfs = PathBuf::from(args.next()
                .ok_or("missing --configfs path")?),
            "--hid" => opts.hid = Some(PathBuf::from(args.next()
                .ok_or("missing --hid path")?)),
            "--android-helper-uid" | "--app-uid" => {
                let value = args.next().ok_or("missing helper app UID")?;
                let uid: u32 = value.parse().map_err(|_| "invalid helper app UID")?;
                if uid < 10_000 { return Err("helper UID must be an unprivileged app UID".into()); }
                opts.app_uid = Some(uid);
            }
            "--socket" => {
                opts.socket = args.next().ok_or("missing --socket name")?;
                if opts.socket.len() > 100 || opts.socket.is_empty()
                    || opts.socket.contains('\0') {
                    return Err("invalid abstract socket name".into());
                }
            }
            "--check" => opts.check = true,
            "--self-test" => opts.self_test = true,
            "--trace-hid" => opts.trace_hid = true,
            "--help" | "-h" => { println!("{}", usage()); std::process::exit(0); }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if opts.check && opts.self_test { return Err("choose --check OR --self-test".into()); }
    if !opts.check && !opts.self_test && opts.app_uid.is_none() {
        return Err("--android-helper-uid is mandatory (no software fallback)".into());
    }
    // New KernelSU module can supply ConfigFS's function directory for
    // convenience; still derive and inspect the complete gadget and linked
    // descriptor. Never trust --hid without matching dev major:minor.
    if opts.configfs.file_name().is_some_and(|name| name.to_string_lossy().starts_with("hid."))
        && opts.configfs.parent().is_some_and(|p| p.ends_with("functions")) {
        opts.configfs = opts.configfs.parent().and_then(Path::parent)
            .ok_or("invalid ConfigFS function path")?.to_path_buf();
    }
    Ok(opts)
}

struct WorkerResult {
    cid: u32,
    job: u64,
    response: Vec<u8>,
}

fn reserve_worker(slots: &AtomicUsize) -> bool {
    let mut now = slots.load(Ordering::Acquire);
    loop {
        if now >= MAX_WORKERS { return false; }
        match slots.compare_exchange_weak(
            now, now + 1, Ordering::AcqRel, Ordering::Acquire
        ) {
            Ok(_) => return true,
            Err(actual) => now = actual,
        }
    }
}

fn emit(
    actions: Vec<Action>,
    proto: &mut Engine,
    transport: &mut Transport,
    app: &Arc<backend::AndroidBackend>,
    tx: &mpsc::Sender<WorkerResult>,
    slots: &Arc<AtomicUsize>,
) -> io::Result<()> {
    for action in actions {
        match action {
            Action::Send(reports) => {
                for report in reports { transport.write_report(&report)?; }
            }
            Action::Start { cid, job, request, cancel, up_needed } => {
                if !reserve_worker(slots) {
                    for followup in proto.worker_busy(cid, job) {
                        if let Action::Send(reports) = followup {
                            for report in reports { transport.write_report(&report)?; }
                        }
                    }
                    continue;
                }
                let app = Arc::clone(app);
                let tx = tx.clone();
                let slots = Arc::clone(slots);
                let slots_on_spawn_error = Arc::clone(&slots);
                match std::thread::Builder::new()
                    .name(format!("ctap-ipc-{cid:08x}"))
                    .spawn(move || {
                        // The helper owns all private key material and must
                        // explicitly authorize every makeCredential/sign.
                        let response = app.handle_cbor(
                            &request,
                            &cancel,
                            |needed| up_needed.store(needed, Ordering::Release),
                        );
                        slots.fetch_sub(1, Ordering::AcqRel);
                        let _ = tx.send(WorkerResult { cid, job, response });
                    })
                {
                    Ok(_thread) => {}
                    Err(e) => {
                        // The worker never existed; return its slot rather
                        // than letting repeated ENOMEM exhaust the daemon.
                        slots_on_spawn_error.fetch_sub(1, Ordering::AcqRel);
                        eprintln!("CTAP IPC worker start failed: {e}");
                        for followup in proto.worker_busy(cid, job) {
                            if let Action::Send(reports) = followup {
                                for report in reports { transport.write_report(&report)?; }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn serve(
    opts: &Options,
    backend: Arc<backend::AndroidBackend>,
) -> io::Result<()> {
    let dev_dir = Path::new("/dev");
    let slots = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<WorkerResult>();
    while !STOP.load(Ordering::Relaxed) {
        let gadget = match transport::discover(&opts.configfs, dev_dir) {
            Ok(found) if opts.hid.as_ref().is_none_or(|required| *required == found.node) => found,
            Ok(_) => {
                eprintln!("HID path differs from verified ConfigFS/rdev; refusing node");
                std::thread::sleep(RECONNECT);
                continue;
            }
            Err(e) => {
                eprintln!("Waiting for verified CTAP gadget: {e}");
                std::thread::sleep(RECONNECT);
                continue;
            }
        };
        let mut hid = match Transport::open_with_trace(gadget, opts.trace_hid) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("CTAP gadget cannot be opened: {e}");
                std::thread::sleep(RECONNECT);
                continue;
            }
        };
        eprintln!("CTAPHID USB active on {} (AndroidKeyStore helper only)",
            hid.path().display());
        let mut engine = Engine::new();
        let mut last_discovery = Instant::now();
        let mut last_trace_heartbeat = Instant::now();
        let run_result = (|| -> io::Result<()> {
            while !STOP.load(Ordering::Relaxed) {
                let now = Instant::now();
                if opts.trace_hid && now.duration_since(last_trace_heartbeat) >= Duration::from_secs(5) {
                    let (rx, tx) = hid.counters();
                    // Distinguishes Windows merely enumerating PnP from an
                    // actual CTAPHID_INIT arriving at the gadget endpoint.
                    eprintln!("TRACE-HID heartbeat rx_reports={rx} tx_reports={tx} active_cbor={}",
                        engine.active_count());
                    last_trace_heartbeat = now;
                }
                if now.duration_since(last_discovery) > Duration::from_secs(1) {
                    if !hid.healthy(&opts.configfs, dev_dir) {
                        return Err(io::Error::new(io::ErrorKind::NotConnected,
                            "ConfigFS node/UDC changed"));
                    }
                    last_discovery = now;
                }
                // Only this thread owns the gadget. Late/cancelled worker
                // replies have stale job IDs and Engine::finished drops them.
                while let Ok(result) = rx.try_recv() {
                    let actions = engine.finished(result.cid, result.job, result.response);
                    emit(actions, &mut engine, &mut hid, &backend, &tx, &slots)?;
                }
                let actions = engine.tick(now);
                emit(actions, &mut engine, &mut hid, &backend, &tx, &slots)?;
                if let Some(report) = hid.read_packet(READ_WAIT)? {
                    let actions = engine.ingest(&report, Instant::now());
                    emit(actions, &mut engine, &mut hid, &backend, &tx, &slots)?;
                }
            }
            Ok(())
        })();
        // Cancels Android IPC via atomic flags, worker drops socket -> Android
        // service observes EOF. Every CID is invalid after USB disconnect.
        engine.clear();
        drop(hid);
        if let Err(ref e) = run_result {
            eprintln!("CTAPHID gadget disconnected: {e}; rediscovering");
            std::thread::sleep(RECONNECT);
        }
    }
    Ok(())
}

fn main() {
    let opts = match parse() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("{e}\n{}", usage());
            std::process::exit(2);
        }
    };
    if opts.self_test {
        println!("self-test OK: 64-byte report, max 7609-byte CTAPHID, 34-byte FIDO descriptor, no software keys");
        return;
    }
    if opts.check {
        match transport::discover(&opts.configfs, Path::new("/dev")) {
            Ok(gadget) if opts.hid.as_ref().is_none_or(|node| *node == gadget.node) => {
                println!("CTAPHID check OK: {} rdev={} UDC={} function={}",
                    gadget.node.display(), gadget.rdev, gadget.controller,
                    gadget.function.display());
                return;
            }
            Ok(_) => eprintln!("CTAPHID check failed: --hid mismatch"),
            Err(e) => eprintln!("CTAPHID check failed: {e}"),
        }
        std::process::exit(1);
    }
    unsafe {
        libc::signal(libc::SIGINT, signal_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_stop as *const () as libc::sighandler_t);
    }
    let backend = match backend::AndroidBackend::connect(
        &opts.socket,
        opts.app_uid.expect("CLI requires Android helper UID"),
        IPC_TIMEOUT,
    ) {
        Ok(backend) => Arc::new(backend),
        Err(e) => {
            eprintln!("Refusing CTAPHID startup without trusted Android helper: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = serve(&opts, backend) {
        eprintln!("Native CTAPHID server failed: {e}");
        std::process::exit(1);
    }
}
