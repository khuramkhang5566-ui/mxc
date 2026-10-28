// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

#[path = "../../src/core/mxc_common/module_lifetime.rs"]
mod module_lifetime;

#[no_mangle]
unsafe extern "C" fn timed_out_worker(state: *const AtomicU8) -> bool {
    if let Err(error) = module_lifetime::pin_current_module() {
        eprintln!("{error}");
        return false;
    }

    // SAFETY: the test host keeps state alive until its subprocess exits.
    let state = unsafe { &*state };
    let (started, ready) = mpsc::sync_channel(1);
    let (finished, done) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        started.send(()).unwrap();
        while state.load(Ordering::Acquire) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        state.store(2, Ordering::Release);
        let _ = finished.send(());
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    matches!(
        done.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    )
}
