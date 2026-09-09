use super::db::{self, Db, User, Move, MoveStatus};

use std::sync::{Arc, atomic::AtomicUsize};
use std::collections::HashMap;
use smol::lock::{Mutex, MutexGuard};

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
    pub users: Arc<Mutex<HashMap<usize, User>>>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct MoveRecord<'user, 'm> {
    pub sender: &'user str,
    pub receiver: &'user str,
    pub message: &'m Option<String>,
    pub status: MoveStatus,
}

pub const ERROR: &str = "<error>";

pub type Guard<'user> = MutexGuard<'user, HashMap<usize, User>>;
pub async fn cache_users_from_moves<'user>(db: &Db, cache: &'user Cache, moves: &[Move]) -> Guard<'user> {
    async fn cache_user(db: &Db, users: &mut HashMap<usize, User>, user_id: usize) {
        if !users.contains_key(&user_id) && let Some(user) = db::read_user_by_id(db, user_id).await {
            users.insert(user_id, user);
        }
    }
    let mut users = cache.users.lock().await;
    for move_instance in moves {
        cache_user(db, &mut users, move_instance.sender).await;
        cache_user(db, &mut users, move_instance.receiver).await;
    }
    users
}

pub fn render_moves<'g, 'm>(users: &'g HashMap<usize, User>, moves: &'m [Move]) -> Vec<MoveRecord<'g, 'm>> {
    let mut result = vec![];
    for move_instance in moves {
        let sender = match users.get(&move_instance.sender) {
            Some(user) => &user.name,
            None => ERROR,
        };
        let receiver = match users.get(&move_instance.receiver) {
            Some(user) => &user.name,
            None => ERROR,
        };
        result.push(MoveRecord {
            sender,
            receiver,
            message: &move_instance.message,
            status: move_instance.status,
        });
    }
    result
}

