use once_cell::sync::OnceCell;
use std::{future::Future, sync::mpsc};
use tokio::runtime::{Builder, Runtime};

static RT: OnceCell<Runtime> = OnceCell::new();

fn rt() -> &'static Runtime {
    RT.get_or_init(|| {
        // independent runtime
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("async-bridge")
            .build()
            .expect("build async bridge runtime")
    })
}

/// Execute an async task on the bridge runtime and wait for the result synchronously (oneshot).
/// - Does not require a `tokio::Handle`
/// - The current thread only waits for a small result (doesn’t hold large objects for long)
/// - Suitable for scenarios where blocking until the result is mandatory
pub fn run_blocking<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel::<T>(0);
    rt().spawn(async move {
        let out = fut.await;
        let _ = tx.send(out);
    });
    rx.recv().expect("async task cancelled")
}
