//! Live AT-SPI2 tree walk benchmark, equivalence and freshness checks.
//!
//! Ignored by default: they need a Chromium (`--force-renderer-accessibility`) registered
//! on the AT-SPI2 bus. `scripts/atspi_walk_bench.sh` builds pages, starts Chromium in the
//! `waybound` container and runs them. Configuration is read from `WB_ATSPI_*` variables.
#![allow(clippy::print_stderr)]

use std::error::Error;
use std::time::{Duration, Instant};

use waybound_core::{Driver, WayboundError};
use waybound_driver_linux::atspi_native::{
    AtspiClient, CALL_TIMEOUT, DEFAULT_PIPELINE_WINDOW, OPERATION_DEADLINE, WalkStrategy,
};
use waybound_driver_linux::{AtspiSnapshot, LinuxDriver};

type TestResult = Result<(), Box<dyn Error>>;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_list(key: &str, default: &[usize]) -> Vec<usize> {
    std::env::var(key).map_or_else(
        |_| default.to_vec(),
        |v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect(),
    )
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Nearest-rank percentile of an ascending slice, in milliseconds.
fn percentile(sorted: &[f64], pct: usize) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (pct * sorted.len()).div_ceil(100).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn timed(
    client: &mut AtspiClient,
    max_nodes: usize,
    strategy: WalkStrategy,
) -> Result<(AtspiSnapshot, f64), Box<dyn Error>> {
    let start = Instant::now();
    let snap = client.snapshot_with_strategy(None, max_nodes, strategy)?;
    Ok((snap, start.elapsed().as_secs_f64() * 1_000.0))
}

/// Describes the first difference between two snapshots.
fn first_difference(a: &AtspiSnapshot, b: &AtspiSnapshot) -> String {
    if a.nodes.len() != b.nodes.len() {
        return format!("node count {} vs {}", a.nodes.len(), b.nodes.len());
    }
    for (x, y) in a.nodes.iter().zip(&b.nodes) {
        if x != y {
            return format!("{x:?}\n  vs\n{y:?}");
        }
    }
    format!(
        "truncated {} vs {}, url {:?} vs {:?}, viewport {:?} vs {:?}",
        a.truncated,
        b.truncated,
        a.current_url,
        b.current_url,
        a.viewport_bounds,
        b.viewport_bounds
    )
}

/// Every node id is `atspi-<index>` and the cap holds. (`truncated` can be set below the
/// cap when the queue cap drops children, so it is not checked here; the equivalence
/// checks compare it against the sequential walk instead.)
fn assert_well_formed(snap: &AtspiSnapshot, max_nodes: usize) {
    assert!(
        snap.nodes.len() <= max_nodes,
        "{} > {max_nodes}",
        snap.nodes.len()
    );
    for (idx, node) in snap.nodes.iter().enumerate() {
        assert_eq!(node.id, format!("atspi-{idx}"));
    }
}

fn summary(times: &mut [f64]) -> String {
    times.sort_by(f64::total_cmp);
    format!(
        "{{\"median_ms\":{:.2},\"p95_ms\":{:.2},\"min_ms\":{:.2},\"runs\":{}}}",
        percentile(times, 50),
        percentile(times, 95),
        times.first().copied().unwrap_or(f64::NAN),
        times.len()
    )
}

/// Times sequential vs pipelined snapshots of the current page and, unless
/// `WB_ATSPI_EXPECT_EQUAL=0` (a page that mutates while it is walked), requires every
/// pipelined snapshot to equal the sequential one taken right before it, including at
/// small `max_nodes` caps (`WB_ATSPI_LIMITS`).
#[test]
#[ignore = "needs a live Chromium on the AT-SPI2 bus; run scripts/atspi_walk_bench.sh"]
fn atspi_walk_bench() -> TestResult {
    let label = env_string("WB_ATSPI_LABEL").unwrap_or_else(|| "page".to_owned());
    let runs = env_usize("WB_ATSPI_RUNS", 30).max(1);
    let max_nodes = env_usize("WB_ATSPI_MAX_NODES", waybound_core::MAX_MAX_NODES);
    let windows = env_list("WB_ATSPI_WINDOWS", &[DEFAULT_PIPELINE_WINDOW]);
    let limits = env_list("WB_ATSPI_LIMITS", &[1, 7, 50, 333, 1_000]);
    let expect_equal = env_usize("WB_ATSPI_EXPECT_EQUAL", 1) != 0;

    let mut client = AtspiClient::connect()?;
    let (warm, _) = timed(&mut client, max_nodes, WalkStrategy::Sequential)?;
    assert!(!warm.nodes.is_empty(), "no web document found");

    let mut seq_times = Vec::with_capacity(runs);
    let mut pip_times: Vec<Vec<f64>> = vec![Vec::with_capacity(runs); windows.len()];
    let mut compared = 0usize;
    for _ in 0..runs {
        let (seq, seq_ms) = timed(&mut client, max_nodes, WalkStrategy::Sequential)?;
        seq_times.push(seq_ms);
        assert_well_formed(&seq, max_nodes);
        for (slot, &window) in windows.iter().enumerate() {
            let (pip, pip_ms) = timed(&mut client, max_nodes, WalkStrategy::Pipelined { window })?;
            pip_times[slot].push(pip_ms);
            assert_well_formed(&pip, max_nodes);
            if expect_equal {
                assert!(
                    seq == pip,
                    "{label}: window {window} differs from sequential: {}",
                    first_difference(&seq, &pip)
                );
                compared += 1;
            }
        }
    }

    let mut limit_checks = 0usize;
    if expect_equal {
        for &limit in &limits {
            let (seq, _) = timed(&mut client, limit, WalkStrategy::Sequential)?;
            let (pip, _) = timed(&mut client, limit, WalkStrategy::default())?;
            assert_well_formed(&seq, limit);
            assert!(
                seq == pip,
                "{label}: max_nodes {limit} differs: {}",
                first_difference(&seq, &pip)
            );
            limit_checks += 1;
        }
    }

    let pip_json: Vec<String> = windows
        .iter()
        .zip(pip_times.iter_mut())
        .map(|(window, times)| format!("\"{window}\":{}", summary(times)))
        .collect();
    eprintln!(
        "WB_BENCH {{\"label\":\"{label}\",\"nodes\":{},\"truncated\":{},\"equal_pairs\":{compared},\"limit_checks\":{limit_checks},\"sequential\":{},\"pipelined\":{{{}}}}}",
        warm.nodes.len(),
        warm.truncated,
        summary(&mut seq_times),
        pip_json.join(",")
    );
    Ok(())
}

fn mentions(snap: &AtspiSnapshot, needle: &str) -> bool {
    snap.nodes.iter().any(|node| {
        node.name.as_deref().is_some_and(|n| n.contains(needle))
            || node.value.as_deref().is_some_and(|v| v.contains(needle))
    })
}

/// Freshness: snapshots the page in a loop while it changes (a DOM rewrite or a
/// navigation). The first snapshot must show `WB_ATSPI_FORBID` (the old state); the new
/// state `WB_ATSPI_EXPECT` must appear before the timeout; and once a snapshot shows only
/// the new state, no later snapshot may show the old one again. Optionally the URL must end
/// with `WB_ATSPI_EXPECT_URL`. Finally a sequential and a pipelined snapshot must agree.
#[test]
#[ignore = "needs a live Chromium on the AT-SPI2 bus; run scripts/atspi_walk_bench.sh"]
fn atspi_walk_tracks_live_page() -> TestResult {
    let expect = env_string("WB_ATSPI_EXPECT").ok_or("WB_ATSPI_EXPECT is required")?;
    let forbid = env_string("WB_ATSPI_FORBID").ok_or("WB_ATSPI_FORBID is required")?;
    let expect_url = env_string("WB_ATSPI_EXPECT_URL");
    let timeout = Duration::from_millis(u64::try_from(env_usize("WB_ATSPI_TIMEOUT_MS", 20_000))?);
    let after_switch = env_usize("WB_ATSPI_AFTER_SWITCH", 20);
    let max_nodes = waybound_core::MAX_MAX_NODES;

    let mut client = AtspiClient::connect()?;
    let first = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::default())?;
    assert!(
        mentions(&first, &forbid),
        "first snapshot lacks the old state {forbid:?}"
    );
    assert!(
        !mentions(&first, &expect),
        "first snapshot already shows {expect:?}"
    );

    let started = Instant::now();
    let mut snapshots = 1usize;
    let mut mixed = 0usize;
    let mut switched_at: Option<Duration> = None;
    let mut since_switch = 0usize;
    while since_switch < after_switch {
        assert!(started.elapsed() < timeout, "{expect:?} never appeared");
        let snap = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::default())?;
        snapshots += 1;
        let (new, old) = (mentions(&snap, &expect), mentions(&snap, &forbid));
        if switched_at.is_some() {
            assert!(
                new && !old,
                "stale snapshot after the switch: new={new} old={old}"
            );
            if let Some(suffix) = &expect_url {
                let url = snap.current_url.as_deref().unwrap_or_default();
                assert!(url.ends_with(suffix.as_str()), "stale URL {url:?}");
            }
            since_switch += 1;
        } else if new && !old {
            switched_at = Some(started.elapsed());
            since_switch = 1;
        } else if new && old {
            mixed += 1;
        }
    }

    // Settled: both walks must agree on the new page.
    let seq = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::Sequential)?;
    let pip = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::default())?;
    assert!(
        seq == pip,
        "settled page differs: {}",
        first_difference(&seq, &pip)
    );
    assert!(mentions(&pip, &expect) && !mentions(&pip, &forbid));

    eprintln!(
        "WB_FRESH {{\"expect\":\"{expect}\",\"snapshots\":{snapshots},\"mixed_during_change\":{mixed},\"switched_after_ms\":{},\"url\":{:?}}}",
        switched_at.map_or(0, |d| d.as_millis()),
        pip.current_url.unwrap_or_default()
    );
    Ok(())
}

/// Round-trip latency of one `GetRoleName` call on the browser's application root, issued
/// back to back (what the sequential walk pays per call) and `n` at a time on one
/// connection (what the pipelined walk pays), to explain where snapshot time goes.
#[test]
#[ignore = "needs a live Chromium on the AT-SPI2 bus; run scripts/atspi_walk_bench.sh"]
fn atspi_call_latency() -> TestResult {
    use zbus::blocking::Connection;

    let calls = env_usize("WB_ATSPI_RUNS", 30).max(1) * 10;
    let session = Connection::session()?;
    let addr: String = session
        .call_method(
            Some("org.a11y.Bus"),
            "/org/a11y/bus",
            Some("org.a11y.Bus"),
            "GetAddress",
            &(),
        )?
        .body()
        .deserialize()?;
    let conn = zbus::blocking::connection::Builder::address(addr.as_str())?.build()?;
    let apps: Vec<(String, zbus::zvariant::OwnedObjectPath)> = conn
        .call_method(
            Some("org.a11y.atspi.Registry"),
            "/org/a11y/atspi/accessible/root",
            Some("org.a11y.atspi.Accessible"),
            "GetChildren",
            &(),
        )?
        .body()
        .deserialize()?;
    let (bus, path) = apps.first().ok_or("no AT-SPI2 application")?;

    let mut serial = Vec::with_capacity(calls);
    for _ in 0..calls {
        let start = Instant::now();
        let _reply = conn.call_method(
            Some(bus.as_str()),
            path.as_str(),
            Some("org.a11y.atspi.Accessible"),
            "GetRoleName",
            &(),
        )?;
        serial.push(start.elapsed().as_secs_f64() * 1_000.0);
    }

    let inner = conn.inner();
    let batch = 64usize;
    let start = Instant::now();
    let mut done = 0usize;
    while done < calls {
        let n = batch.min(calls - done);
        let replies =
            futures_lite::future::block_on(futures_util::future::join_all((0..n).map(|_| {
                inner.call_method(
                    Some(bus.as_str()),
                    path.as_str(),
                    Some("org.a11y.atspi.Accessible"),
                    "GetRoleName",
                    &(),
                )
            })));
        for reply in replies {
            let _msg = reply?;
        }
        done += n;
    }
    #[allow(clippy::cast_precision_loss)]
    let pipelined_per_call = start.elapsed().as_secs_f64() * 1_000.0 / calls as f64;
    // Root resolution alone (registry + browser UI scan, no page walk), as `page.url()` does.
    let mut client = AtspiClient::connect()?;
    let mut resolve = Vec::with_capacity(calls / 10);
    for _ in 0..calls / 10 {
        let start = Instant::now();
        let _url = client.current_url(None)?;
        resolve.push(start.elapsed().as_secs_f64() * 1_000.0);
    }
    eprintln!(
        "WB_LATENCY {{\"sequential_per_call\":{},\"pipelined64_amortized_per_call_ms\":{pipelined_per_call:.4},\"current_url\":{}}}",
        summary(&mut serial),
        summary(&mut resolve)
    );
    Ok(())
}

fn signal(pid: &str, sig: &str) -> TestResult {
    let status = waybound_core::process::command("kill")
        .args([sig, pid])
        .status()?;
    assert!(status.success(), "kill {sig} {pid} failed");
    Ok(())
}

/// Stops the browser (`SIGSTOP`) after `delay` and resumes it after `stall` (if any).
fn stall_browser(
    pid: &str,
    delay: Duration,
    stall: Option<Duration>,
) -> std::thread::JoinHandle<Result<(), String>> {
    let pid = pid.to_owned();
    std::thread::spawn(move || -> Result<(), String> {
        std::thread::sleep(delay);
        signal(&pid, "-STOP").map_err(|err| err.to_string())?;
        if let Some(stall) = stall {
            std::thread::sleep(stall);
            signal(&pid, "-CONT").map_err(|err| err.to_string())?;
        }
        Ok(())
    })
}

fn join(handle: std::thread::JoinHandle<Result<(), String>>) -> TestResult {
    handle
        .join()
        .map_err(|_| "signal thread panicked")?
        .map_err(Into::into)
}

/// A browser that stops answering mid-walk: a stall shorter than `CALL_TIMEOUT` only
/// delays the snapshot; a frozen browser yields `WayboundError::Timeout` within
/// `CALL_TIMEOUT` plus a margin (through the driver, so its client mutex is released), for
/// both walks; after `SIGCONT` the same driver and client snapshot normally again.
/// `WB_ATSPI_CHROME_PID` is the browser process id.
#[test]
#[ignore = "needs a live Chromium on the AT-SPI2 bus; run scripts/atspi_walk_bench.sh"]
fn atspi_walk_survives_hung_browser() -> TestResult {
    let pid = env_string("WB_ATSPI_CHROME_PID").ok_or("WB_ATSPI_CHROME_PID is required")?;
    let max_nodes = waybound_core::MAX_MAX_NODES;
    let bound = CALL_TIMEOUT + Duration::from_secs(2);
    let driver = LinuxDriver::new(None);
    let mut client = AtspiClient::connect()?;
    let baseline = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::Sequential)?;
    assert!(!baseline.nodes.is_empty(), "no web document found");
    let mut report = Vec::new();

    // 1. A stall shorter than `CALL_TIMEOUT` (`WB_ATSPI_STALL_MS`, default 5 s) mid-walk
    //    recovers with the full, unchanged snapshot.
    let stall = Duration::from_millis(u64::try_from(env_usize("WB_ATSPI_STALL_MS", 5_000))?);
    let handle = stall_browser(&pid, Duration::from_millis(40), Some(stall));
    let start = Instant::now();
    let snap = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::default())?;
    join(handle)?;
    report.push(format!(
        "\"stall_{}ms_snapshot_ms\":{}",
        stall.as_millis(),
        start.elapsed().as_millis()
    ));
    assert!(
        snap == baseline,
        "after a short stall: {}",
        first_difference(&baseline, &snap)
    );

    // 2. Frozen mid-walk: bounded `timeout`, for the driver (pipelined) and both walks.
    let handle = stall_browser(&pid, Duration::from_millis(40), None);
    let start = Instant::now();
    let result = driver.snapshot_tree_limited(max_nodes);
    let elapsed = start.elapsed();
    join(handle)?;
    report.push(format!("\"frozen_driver_ms\":{}", elapsed.as_millis()));
    assert!(
        matches!(result, Err(WayboundError::Timeout { .. })),
        "frozen browser: {result:?}"
    );
    assert!(elapsed < bound, "driver took {elapsed:?}");
    for strategy in [WalkStrategy::default(), WalkStrategy::Sequential] {
        let start = Instant::now();
        let result = client.snapshot_with_strategy(None, max_nodes, strategy);
        let elapsed = start.elapsed();
        report.push(format!("\"frozen_{strategy:?}_ms\":{}", elapsed.as_millis()).replace(' ', ""));
        assert!(
            matches!(result, Err(WayboundError::Timeout { .. })),
            "{strategy:?}: {result:?}"
        );
        assert!(elapsed < bound, "{strategy:?} took {elapsed:?}");
        assert!(
            !client.is_broken(),
            "a timeout must not mark the client broken"
        );
    }
    let start = Instant::now();
    let url = driver.current_url();
    report.push(format!("\"frozen_url_ms\":{}", start.elapsed().as_millis()));
    assert!(matches!(url, Err(WayboundError::Timeout { .. })), "{url:?}");

    // 3. Resumed: the same driver (mutex free) and client work again.
    signal(&pid, "-CONT")?;
    std::thread::sleep(Duration::from_millis(500));
    let after = client.snapshot_with_strategy(None, max_nodes, WalkStrategy::default())?;
    assert!(
        after == baseline,
        "after SIGCONT: {}",
        first_difference(&baseline, &after)
    );
    let via_driver = driver.snapshot_tree_limited(max_nodes)?;
    assert_eq!(via_driver.nodes, baseline.nodes);

    eprintln!(
        "WB_HANG {{{},\"call_timeout_ms\":{},\"operation_deadline_ms\":{}}}",
        report.join(","),
        CALL_TIMEOUT.as_millis(),
        OPERATION_DEADLINE.as_millis()
    );
    Ok(())
}
