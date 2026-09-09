use super::db::{User, MoveStatus};

use std::sync::{Arc, atomic::AtomicUsize};

use rocket::serde::Serialize;
// A concurrent hash map.
use dashmap::DashMap;

#[derive(Debug, Default)]
pub struct Sessions {
    // session-id: user-id
    pub active_sessions: DashMap<usize, usize>,
    pub session_count: AtomicUsize,
}

#[derive(Debug)]
pub struct Cache {
    pub users: DashMap<usize, User>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct MoveRecord<'names, 'm> {
    pub sender: &'names str,
    pub receiver: &'names str,
    pub message: &'m Option<String>,
    pub status: MoveStatus,
}
