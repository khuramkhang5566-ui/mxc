// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Request-scoped session and selected learning-mode attribution.

use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use uuid::Uuid;

use super::LearningMode;
use crate::mxc_common::logger::Logger;

thread_local! {
    static CURRENT: Cell<Option<Uuid>> = const { Cell::new(None) };
    static DISABLED: Cell<bool> = const { Cell::new(false) };
    static LEARNING_MODE: Cell<LearningMode> = const { Cell::new(LearningMode::NotApplicable) };
}

#[derive(Debug, Clone, Copy)]
struct ProcessContext {
    session_id: Option<Uuid>,
    learning_mode: LearningMode,
}

static PROCESS_CONTEXT: Mutex<Option<ProcessContext>> = Mutex::new(None);

/// Restores the calling thread's attribution on return or unwind.
///
/// This guard cannot move to another thread. Streaming handles retain only
/// the copyable ID/mode and install a new guard wherever they are subsequently used.
#[doc(hidden)]
#[derive(Debug)]
#[must_use = "retain the scope until invocation processing finishes"]
pub struct SessionScope {
    previous: Option<Uuid>,
    previously_disabled: bool,
    previous_learning_mode: LearningMode,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for SessionScope {
    fn drop(&mut self) {
        CURRENT.with(|slot| slot.set(self.previous));
        DISABLED.with(|slot| slot.set(self.previously_disabled));
        LEARNING_MODE.with(|slot| slot.set(self.previous_learning_mode));
    }
}

/// Start one authorized invocation, reusing the lifecycle vector's random root.
#[doc(hidden)]
pub fn start(active: bool, vector: &str, logger: &mut Logger) -> SessionScope {
    start_with_learning_mode(active, vector, LearningMode::NotApplicable, logger)
}

/// Start an invocation with its selected access-check mode.
#[doc(hidden)]
pub fn start_with_learning_mode(
    active: bool,
    vector: &str,
    learning_mode: LearningMode,
    logger: &mut Logger,
) -> SessionScope {
    if !active {
        return install(None, true, LearningMode::NotApplicable);
    }
    let id = if vector.is_empty() {
        random_id()
    } else {
        from_vector(vector).ok_or("session_vector_invalid")
    };
    let id = match id {
        Ok(id) => Some(id),
        Err(code) => {
            logger.warning_line(&format!(
                "telemetry: session attribution unavailable ({code}); recording mxc.session_id=unknown"
            ));
            None
        }
    };
    install(id, false, learning_mode)
}

fn random_id() -> Result<Uuid, &'static str> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "session_randomness_unavailable")?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

/// The random CV base is persisted already; formatting it as UUIDv4 needs no
/// additional identifier, caller-provided field, or independently mutable file.
pub(crate) fn from_vector(vector: &str) -> Option<Uuid> {
    if !super::correlation_vector::is_relayable(vector) {
        return None;
    }
    let base = vector.split('.').next()?;
    let mut bytes = [0u8; 16];
    let length = STANDARD_NO_PAD.decode_slice(base, &mut bytes).ok()?;
    (length == bytes.len()).then(|| uuid::Builder::from_random_bytes(bytes).into_uuid())
}

fn install(id: Option<Uuid>, disabled: bool, learning_mode: LearningMode) -> SessionScope {
    SessionScope {
        previous: CURRENT.with(|slot| slot.replace(id)),
        previously_disabled: DISABLED.with(|slot| slot.replace(disabled)),
        previous_learning_mode: LEARNING_MODE.with(|slot| slot.replace(learning_mode)),
        _thread_bound: PhantomData,
    }
}

pub(crate) fn current() -> Option<Uuid> {
    CURRENT.with(Cell::get)
}

pub(crate) fn invocation_disabled() -> bool {
    DISABLED.with(Cell::get)
}

pub(crate) fn learning_mode() -> LearningMode {
    LEARNING_MODE.with(Cell::get)
}

pub(crate) fn resume(id: Option<Uuid>, learning_mode: LearningMode) -> SessionScope {
    install(id, id.is_none(), learning_mode)
}

pub(crate) fn wire_id(buffer: &mut [u8; 36]) -> &str {
    match current() {
        Some(id) => id.hyphenated().encode_lower(buffer),
        None => "unknown",
    }
}

pub(super) fn remember_process() {
    let mut slot = PROCESS_CONTEXT
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if slot.is_none() {
        *slot = Some(ProcessContext {
            session_id: current(),
            learning_mode: learning_mode(),
        });
    }
}

pub(super) fn resume_process() -> SessionScope {
    let current_id = current();
    let stored = PROCESS_CONTEXT.try_lock().ok().and_then(|slot| *slot);
    let id = current_id.or_else(|| stored.and_then(|context| context.session_id));
    let mode = if current_id.is_some() {
        learning_mode()
    } else {
        stored
            .map(|context| context.learning_mode)
            .unwrap_or_else(learning_mode)
    };
    install(id, false, mode)
}

#[cfg(test)]
pub(super) fn reset_process() {
    *PROCESS_CONTEXT
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::logger::Mode;

    #[test]
    fn learning_mode_is_scoped_and_disabled_invocations_do_not_inherit_it() {
        let mut logger = Logger::new(Mode::Buffer);
        let _outer = start_with_learning_mode(true, "", LearningMode::Learning, &mut logger);
        let outer = current();
        {
            let _inner =
                start_with_learning_mode(true, "", LearningMode::PermissiveLearning, &mut logger);
            assert_eq!(learning_mode(), LearningMode::PermissiveLearning);
            {
                let _disabled = start_with_learning_mode(
                    false,
                    "",
                    LearningMode::PermissiveLearning,
                    &mut logger,
                );
                assert_eq!(learning_mode(), LearningMode::NotApplicable);
                assert!(invocation_disabled());
            }
            assert_eq!(learning_mode(), LearningMode::PermissiveLearning);
        }
        assert_eq!(learning_mode(), LearningMode::Learning);
        assert_eq!(current(), outer);
        let result = std::panic::catch_unwind(|| {
            let mut logger = Logger::new(Mode::Buffer);
            let _scope =
                start_with_learning_mode(true, "", LearningMode::PermissiveLearning, &mut logger);
            panic!("synthetic invocation unwind");
        });
        assert!(result.is_err());
        assert_eq!(learning_mode(), LearningMode::Learning);
        assert_eq!(current(), outer);
    }

    #[test]
    fn every_phase_of_a_random_vector_has_one_v4_session() {
        let root = super::super::correlation_vector::seed();
        let id = from_vector(&root).expect("valid root");
        assert_eq!(id.get_version_num(), 4);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        for _ in 0..8 {
            let child = super::super::correlation_vector::spin(&root);
            assert_eq!(from_vector(&child), Some(id));
        }
        assert_ne!(
            from_vector(&super::super::correlation_vector::seed()),
            Some(id)
        );
        for invalid in ["", "caller@example.invalid", "invalid!", "not-a-vector.0"] {
            assert_eq!(from_vector(invalid), None);
        }
    }

    #[test]
    fn nested_and_disabled_invocations_restore_the_outer_session() {
        let mut logger = Logger::new(Mode::Buffer);
        let _outer = start(true, "", &mut logger);
        let outer = current().expect("random session");
        {
            let _inner = start(true, "", &mut logger);
            assert_ne!(current(), Some(outer));
            {
                let _disabled = start(false, "invalid", &mut logger);
                assert_eq!(current(), None);
                assert!(invocation_disabled());
            }
            assert!(current().is_some());
        }
        assert_eq!(current(), Some(outer));
        assert!(!invocation_disabled());
    }

    #[test]
    fn a_streaming_session_can_be_resumed_on_another_thread() {
        let mut logger = Logger::new(Mode::Buffer);
        let _scope = start(true, "", &mut logger);
        let id = current().expect("random session");
        std::thread::spawn(move || {
            assert_eq!(current(), None);
            {
                let _scope = resume(Some(id), LearningMode::NotApplicable);
                assert_eq!(current(), Some(id));
                let mut buffer = [0; 36];
                assert_eq!(wire_id(&mut buffer), id.to_string());
            }
            assert_eq!(current(), None);
        })
        .join()
        .expect("worker completed");
        assert_eq!(current(), Some(id));
    }

    #[test]
    fn concurrent_invocations_have_distinct_ids_and_restore_context_after_unwind() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut logger = Logger::new(Mode::Buffer);
                    let _scope = start(true, "", &mut logger);
                    let id = current().unwrap();
                    barrier.wait();
                    assert_eq!(current(), Some(id));
                    let failed = std::panic::catch_unwind(|| {
                        let mut logger = Logger::new(Mode::Buffer);
                        let _nested = start(true, "", &mut logger);
                        assert_ne!(current(), Some(id));
                        panic!("synthetic invocation unwind");
                    });
                    assert!(failed.is_err());
                    assert_eq!(current(), Some(id));
                    id
                })
            })
            .collect();
        let ids: std::collections::HashSet<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(ids.len(), 8);
    }
}
