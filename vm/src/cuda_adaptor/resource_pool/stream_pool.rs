use cudart::{
    device::{get_device, get_device_count},
    stream::CudaStream,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};

#[derive(Debug)]
pub struct SyncStreamPool(pub CudaStream);
unsafe impl Sync for SyncStreamPool {}
unsafe impl Send for SyncStreamPool {}

extern "C" {
    fn oss_check_layout();
}

/// Device count, and the one-time layout check that used to ride along with creating the streams.
static DEVICE_COUNT: OnceLock<usize> = OnceLock::new();

const MAX_TRACKED_DEVICES: usize = 16;

/// Streams created per device over the process's life. A `cudaStream_t` costs device memory that
/// no memory pool backs, so this count is the one that says how much of the census's out-of-pool
/// figure is streams.
static STREAMS_CREATED: [AtomicUsize; MAX_TRACKED_DEVICES] =
    [const { AtomicUsize::new(0) }; MAX_TRACKED_DEVICES];

/// Streams created on `device_id` so far. Reported by the VRAM census.
pub fn streams_created(device_id: usize) -> usize {
    STREAMS_CREATED
        .get(device_id)
        .map_or(0, |c| c.load(Ordering::Relaxed))
}

/// Streams whose thread has finished, waiting for the next thread that needs one on that card.
///
/// The prover creates a fresh set of threads for every block it proves, and a `cudaStream_t` costs
/// device memory that no memory pool backs — so a stream that ends its life with its thread is
/// memory no trim can reach, and a long run accumulates one set per block. Handing the
/// stream to the next thread instead bounds what the process holds by how many threads are alive
/// at once rather than by how many it has ever spawned.
///
/// Recycled rather than destroyed: `cudaStreamDestroy` would be correct too, but a thread exits
/// while other lanes are still proving on its card, and re-creating the stream on the next block
/// costs more than handing it over.
static FREE_STREAMS: [Mutex<Vec<&'static SyncStreamPool>>; MAX_TRACKED_DEVICES] =
    [const { Mutex::new(Vec::new()) }; MAX_TRACKED_DEVICES];

/// Streams handed back, and the microseconds their threads spent handing them back. Reported per
/// block beside the pool line in `init_mle_gpu_pool`: this path runs inside the proving window, so
/// what it costs has to be visible rather than argued.
static STREAMS_RELEASED: [AtomicUsize; MAX_TRACKED_DEVICES] =
    [const { AtomicUsize::new(0) }; MAX_TRACKED_DEVICES];
static RELEASE_MICROS: [AtomicU64; MAX_TRACKED_DEVICES] =
    [const { AtomicU64::new(0) }; MAX_TRACKED_DEVICES];

/// `(streams handed back on this card, microseconds spent doing it)` since the process started.
pub fn release_stats(device_id: usize) -> (usize, u64) {
    (
        STREAMS_RELEASED
            .get(device_id)
            .map_or(0, |c| c.load(Ordering::Relaxed)),
        RELEASE_MICROS
            .get(device_id)
            .map_or(0, |c| c.load(Ordering::Relaxed)),
    )
}

/// A thread's streams, and the hand-back that runs when it exits.
///
/// The `Drop` is the whole point of the newtype: a bare `HashMap` of `&'static` has none, which is
/// how every stream this process ever created stayed alive.
struct ThreadStreams(RefCell<HashMap<usize, &'static SyncStreamPool>>);

impl Drop for ThreadStreams {
    fn drop(&mut self) {
        for (device_id, pool) in self.0.borrow_mut().drain() {
            let t = Instant::now();
            // NOT synchronised, deliberately: what moves is the stream ITSELF, and a CUDA stream
            // runs its work in issue order — so anything this thread left queued is already
            // ordered before anything the next owner enqueues. Waiting here would buy no guarantee
            // and cost real time: with convert and combine preparers it is ~340 us each, ~6.5 ms
            // per block, inside the proving window.
            //
            // A hand-back that moves a BUFFER does have to wait (`cuda-mle`'s `D2hStage`), because
            // the next owner reaches it from a different stream, where issue order says nothing.
            let Some(slot) = FREE_STREAMS.get(device_id) else {
                continue;
            };
            if let Ok(mut free) = slot.lock() {
                free.push(pool);
                if let Some(c) = STREAMS_RELEASED.get(device_id) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                // Charged to this card alone, measured around this stream alone: a thread holding
                // streams on two cards must not have one card's cost land on the other's line.
                if let Some(c) = RELEASE_MICROS.get(device_id) {
                    c.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

thread_local! {
    /// This thread's stream per device. The chips' trace builders finish by synchronising this
    /// stream (`frac_fold/traces.rs` and its siblings), which on a process-wide stream waits for
    /// every other lane's work on that card too -- their own data is already ready, so the wait is
    /// pure coupling. That is what the trace-gen mutex was reducing by admitting one lane at a
    /// time; a per-thread stream removes the coupling instead.
    ///
    /// The reference stays `&'static` because the stream really is never destroyed — it moves to
    /// [`FREE_STREAMS`] when this thread ends and comes back out for the next one.
    static THREAD_STREAMS: ThreadStreams = ThreadStreams(RefCell::new(HashMap::new()));
}

/// Check the host/device struct layouts and record the device count. Streams themselves are created
/// per thread on first use, so there is nothing to pre-create here — the name is kept because the
/// call sites are startup code whose job is exactly this one-time check.
pub fn create_stream(device_id: usize) {
    let count = *DEVICE_COUNT.get_or_init(|| {
        println!("Check CPU DATA STRUCT");
        println!("Check GPU DATA STRUCT (OSS)");
        unsafe { oss_check_layout() };
        get_device_count().unwrap() as usize
    });
    if device_id >= count {
        panic!("Device ID {device_id} exceeds available devices ({count})");
    }
}

/// This thread's stream for `device_id`, created on first use.
///
/// The device must already be the calling thread's own: every GPU-touching thread binds its card at
/// spawn, and a stream created against a different device than the caller is bound to would enqueue
/// where the caller does not expect. Asserted rather than repaired — silently calling `set_device`
/// here would rebind the caller's thread as a side effect of asking for a stream.
pub fn get_global_stream_pool(device_id: usize) -> &'static SyncStreamPool {
    let count = *DEVICE_COUNT
        .get()
        .unwrap_or_else(|| panic!("Global pool not initialized"));
    if device_id >= count {
        panic!("Invalid device ID: {device_id}");
    }
    // Catches a caller that names a card other than the one it is bound to. No caller in the tree
    // does: the MLE machines derive `device_id` from `get_device()` themselves, and the FRI workers,
    // whose id is an independent prover index, bind that card before their first request.
    let bound = get_device().expect("cudaGetDevice failed") as usize;
    assert_eq!(
        bound, device_id,
        "stream for device {device_id} requested from a thread bound to device {bound}"
    );
    THREAD_STREAMS.with(|m| {
        *m.0.borrow_mut().entry(device_id).or_insert_with(|| {
            // An exited thread's stream first; only a card that has none outstanding creates one.
            if let Some(pool) = FREE_STREAMS
                .get(device_id)
                .and_then(|slot| slot.lock().ok())
                .and_then(|mut free| free.pop())
            {
                return pool;
            }
            if let Some(c) = STREAMS_CREATED.get(device_id) {
                c.fetch_add(1, Ordering::Relaxed);
            }
            Box::leak(Box::new(SyncStreamPool(CudaStream::create().unwrap())))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests share one process-wide free list, and `cargo test` runs them in parallel, so
    /// each takes this first: an entry a sibling hands back mid-assertion is the difference
    /// between a real regression and a flake.
    static SERIALISE: Mutex<()> = Mutex::new(());

    /// The underlying `cudaStream_t`, so the assertions below are about the stream the driver
    /// sees and not merely about two distinct wrappers. Widened to `usize` because a raw handle is
    /// not `Send` and one of these crosses a thread boundary.
    fn id(p: &'static SyncStreamPool) -> usize {
        let handle: cudart_sys::cudaStream_t = (&p.0).into();
        handle as usize
    }

    #[test]
    fn a_thread_reuses_one_stream_per_card() {
        let _serial = SERIALISE.lock();
        create_stream(0);
        assert_eq!(id(get_global_stream_pool(0)), id(get_global_stream_pool(0)));
    }

    /// What the device gate used to stand in for: two lanes on one card no longer share a stream,
    /// so each one's caller-side sync covers its own enqueues and nothing else's.
    #[test]
    fn two_threads_do_not_share_a_card_stream() {
        let _serial = SERIALISE.lock();
        create_stream(0);
        let mine = id(get_global_stream_pool(0));
        let theirs = std::thread::spawn(|| id(get_global_stream_pool(0)))
            .join()
            .unwrap();
        assert_ne!(mine, theirs, "two threads shared one card's stream");
    }

    /// The handles waiting in `device_id`'s free list. Test-only: the production paths never ask
    /// which streams are waiting, only for one.
    fn free_ids(device_id: usize) -> Vec<usize> {
        FREE_STREAMS[device_id]
            .lock()
            .map_or_else(|_| Vec::new(), |v| v.iter().map(|p| id(p)).collect())
    }

    /// The other half of `two_threads_do_not_share_a_card_stream`. Concurrent threads must not
    /// share a stream; a thread that has ENDED must not take its stream with it, or a process that
    /// spawns a fresh set of threads per block accumulates one set per block.
    ///
    /// Asserted on the handle rather than on the list's length: a thread that finds one waiting
    /// takes it and gives the same one back, so the length is unchanged and only the identity
    /// says whether it came home.
    #[test]
    fn an_exited_thread_hands_its_stream_back() {
        let _serial = SERIALISE.lock();
        create_stream(0);
        let released_before = release_stats(0).0;
        let used = std::thread::spawn(|| id(get_global_stream_pool(0)))
            .join()
            .unwrap();
        assert!(
            free_ids(0).contains(&used),
            "the stream a finished thread used did not come back"
        );
        // The counter too, and not as decoration: it is what `MLE streams:` reports and what the
        // census reads as `streams_recycled`, and dropping the `fetch_add` would leave both
        // reporting a flat zero while the recycling itself still worked.
        assert!(
            release_stats(0).0 > released_before,
            "the hand-back did not count itself"
        );

        // And on ITS OWN card's list where a second device is visible: a hand-back filed under the
        // wrong card would give the next thread a stream from a context it cannot use, and the
        // assertions above cannot tell `FREE_STREAMS[device_id]` from `FREE_STREAMS[0]`. A section
        // of a test that has already asserted something, rather than a test that can pass having
        // asserted nothing on a single-card box.
        if *DEVICE_COUNT.get().unwrap() >= 2 {
            let on_one = std::thread::spawn(|| {
                cudart::device::set_device(1).expect("bind card 1");
                id(get_global_stream_pool(1))
            })
            .join()
            .unwrap();
            assert!(
                free_ids(1).contains(&on_one),
                "a card-1 stream did not come back on card 1's list"
            );
            assert!(
                !free_ids(0).contains(&on_one),
                "a card-1 stream came back on card 0's list"
            );
        }
    }

    /// And the next thread takes one of those rather than creating another, which the snapshot of
    /// what was waiting says and the creation count would not (a sibling test creates streams on
    /// this card too).
    #[test]
    fn a_later_thread_takes_a_recycled_stream() {
        let _serial = SERIALISE.lock();
        create_stream(0);
        std::thread::spawn(|| {
            let _ = id(get_global_stream_pool(0));
        })
        .join()
        .unwrap();
        let waiting = free_ids(0);
        assert!(!waiting.is_empty(), "nothing was waiting to be taken");
        let created_before = streams_created(0);
        let taken = std::thread::spawn(|| id(get_global_stream_pool(0)))
            .join()
            .unwrap();
        assert!(
            waiting.contains(&taken),
            "a thread created a stream while {} were waiting",
            waiting.len()
        );
        // Asserted on the count as well as the identity: moving the creation counter above the
        // free-list pop would count every recycled stream as created, which is exactly the figure
        // the census reads to say whether a long run is still accumulating.
        assert_eq!(
            streams_created(0),
            created_before,
            "taking a waiting stream was counted as creating one"
        );
    }

    #[test]
    #[should_panic(expected = "Invalid device ID")]
    fn a_card_past_the_count_is_rejected() {
        create_stream(0);
        let past_the_end = *DEVICE_COUNT.get().unwrap();
        let _ = get_global_stream_pool(past_the_end);
    }
}
