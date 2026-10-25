use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use tokio::sync::Notify;

struct ReadyLatch {
    target: usize,
    count: AtomicUsize,
    notify: Notify,
}

impl ReadyLatch {
    fn new(target: usize) -> Self {
        Self {
            target,
            count: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }
    fn hit(&self) {
        let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.target {
            self.notify.notify_waiters();
        }
    }
    async fn wait(&self) {
        if self.count.load(Ordering::SeqCst) >= self.target {
            return;
        }
        self.notify.notified().await;
    }
}

static READY_LATCH: OnceLock<Arc<ReadyLatch>> = OnceLock::new();

pub fn init_ready_latch(participants: usize) {
    READY_LATCH
        .set(Arc::new(ReadyLatch::new(participants)))
        .expect("READY_LATCH already initialized");
}
pub fn ready_hit() {
    READY_LATCH
        .get()
        .expect("READY_LATCH not initialized")
        .hit();
}
pub async fn ready_wait_async() {
    READY_LATCH
        .get()
        .expect("READY_LATCH not initialized")
        .wait()
        .await;
}

impl fmt::Debug for ReadyLatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadyLatch").finish_non_exhaustive()
    }
}
