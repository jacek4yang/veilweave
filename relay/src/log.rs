// log.rs
// Compile-time logging switch for performance profiling.
//
// Everything here is gated on the `perf-log` cargo feature. Build with it ON when
// you want to watch the data path live and hunt for optimization points:
//
//     # one-off profiling build/deploy
//     worker-build --release --features perf-log
//     wrangler tail            # stream the worker's console in another shell
//
// …and leave it OFF (the default) for normal long-term use. With the feature
// disabled, every `vlog!` call expands to *nothing*: the format arguments are
// never evaluated, so there is no string formatting, no `Date::now()` call, no
// console FFI, and no branch left on the hot path — it is the same machine code
// as if the log line were never written, not merely a suppressed message. That
// is the whole point: profiling visibility on demand, zero overhead otherwise.
//
// `wrangler tail` and the dashboard's live logs surface anything written to the
// worker console, which is exactly what `worker::console_log!` emits (it lowers
// to `web_sys::console::log_1`). All lines are prefixed `[veilweave]` so they are
// easy to grep out of `wrangler tail --format pretty`.

/// Event log for performance profiling. See the module header for the on/off
/// semantics. Usage mirrors `println!`: `vlog!("data drive: {n} records")`.
///
/// When `perf-log` is enabled this writes one `[veilweave] …` line to the worker
/// console. When disabled it expands to an empty statement and the arguments are
/// not touched, so it is free to sprinkle on the hottest paths.
#[cfg(feature = "perf-log")]
macro_rules! vlog {
    ($($arg:tt)*) => {
        ::worker::console_log!("[veilweave] {}", ::core::format_args!($($arg)*))
    };
}

#[cfg(not(feature = "perf-log"))]
macro_rules! vlog {
    // Consume the tokens without evaluating them — generates no code at all.
    ($($arg:tt)*) => {};
}

pub(crate) use vlog;

/// Milliseconds since the Unix epoch, as seen by the Workers runtime — for
/// measuring durations in `perf-log` builds.
///
/// IMPORTANT: Cloudflare pins this clock to the moment of the last I/O (a timing
/// side-channel mitigation), so it does **not** advance during pure computation —
/// only across `await` points that perform I/O. Durations measured *around I/O*
/// (target connect, the span of a pump that does socket writes / `ws.send`s) are
/// therefore real wall time, while the CPU time of a tight crypto loop with no
/// intervening I/O reads as ~0. To reason about CPU-bound stretches (the ML-KEM
/// handshake, bulk AEAD), lean on the record/byte counts that `vlog!` records
/// rather than on these timestamps. Only compiled when `perf-log` is on, so it
/// adds nothing to a normal build.
#[cfg(feature = "perf-log")]
#[inline]
pub(crate) fn now_ms() -> f64 {
    js_sys::Date::now()
}
