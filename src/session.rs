
use dashmap::DashMap;
use std::sync::{Arc, atomic::AtomicUsize};
use smol::lock::Mutex;

#[derive(Default)]
pub(crate) struct Sessions {
    // session-id: (user-id, is_admin)
    pub(crate) active_sessions: DashMap<usize, (usize, bool)>,
    // unused session-ids
    pub(crate) inactive_sessions: Arc<Mutex<Vec<usize>>>,
    pub(crate) session_count: AtomicUsize,
}

