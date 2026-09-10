use super::db::{self, Db, User, Move, MoveStatus};

use std::collections::HashMap;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;
use std::time::SystemTime;

// A concurrent hash map.
// use dashmap::DashMap;

use rocket::time::Duration;
use rocket::{Request, Data};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::serde::Serialize;

use smol::lock::{Mutex, MutexGuard};

#[derive(Debug, Default)]
pub struct Sessions {
    pub active: Arc<Mutex<HashMap<i64, Session>>>,
    pub session_count: AtomicI64,
}

impl Sessions {
    pub fn create(&self, user_id: usize) {
        // self.session_count.fetch_add(1, order)
    }
}

#[derive(Debug)]
pub struct Session {
    pub user_id: i64,
    pub expire_for_idle: SystemTime,
    pub expire_for_timeout: SystemTime,
}

impl Session {
    pub const DEFAULT_IDLE_DURATION: Duration = Duration::minutes(2);
    pub const DEFAULT_TIMEOUT_DURATION: Duration = Duration::hours(1);
    pub fn new(user_id: i64) -> Self {
        let now = SystemTime::now();
        Self {
            user_id,
            expire_for_idle: now + Self::DEFAULT_IDLE_DURATION,
            expire_for_timeout: now + Self::DEFAULT_TIMEOUT_DURATION,
        }
    }
}

#[derive(Debug)]
pub struct Cache {
    pub users: Arc<Mutex<HashMap<i64, User>>>,
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

pub type Guard<'user> = MutexGuard<'user, HashMap<i64, User>>;
pub async fn cache_users_from_moves<'user>(db: &Db, cache: &'user Cache, moves: &[Move]) -> Guard<'user> {
    async fn cache_user(db: &Db, users: &mut HashMap<i64, User>, user_id: i64) {
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

pub fn render_moves<'g, 'm>(users: &'g HashMap<i64, User>, moves: &'m [Move]) -> Vec<MoveRecord<'g, 'm>> {
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

pub struct Timeout;

#[rocket::async_trait]
impl Fairing for Timeout {
    fn info(&self) -> Info {
        Info {
            name: "timeouts",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let sessions = if let Some(value) = request.rocket().state::<Sessions>()  {
            value
        } else {
            return;
        };

        let now = SystemTime::now();
        let mut active = sessions.active.lock().await;
        active.retain(|_, value| !(value.expire_for_idle < now || value.expire_for_timeout < now));
    }
}

