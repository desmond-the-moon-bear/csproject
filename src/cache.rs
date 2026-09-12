use super::db::{self, Db, User, Move, MoveStatus};

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::SystemTime;

use base64::prelude::*;

use chrono::{DateTime, Local};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Cookie, private::cookie::Expiration};
use rocket::time::Duration;
use rocket::{Request, Data};
use rocket::serde::Serialize;

use rand::SeedableRng;
use rand::Rng;
use rand::rngs::{StdRng, SysRng};

use smol::lock::{Mutex, MutexGuard};

// 128 bits of entropy should be enough.
pub type Id = [u8; 16];
pub const ZERO_ID: Id = [0u8; 16];

// #[cfg(feature = "secure")]
// pub const SESSION_COOKIE_NAME: &str = "__Host-Http-id";
// #[cfg(not(feature = "secure"))]
pub const SESSION_COOKIE_NAME: &str = "id";

#[derive(Debug, Default)]
pub struct Sessions {
    pub active: Arc<Mutex<HashMap<Id, Session>>>,
    generator: SessionIdGenerator,
}

impl Sessions {
    pub async fn fetch(&self, id: Id) -> Option<i64> {
        if let Some(session) = self.active.lock().await.get_mut(&id) {
            session.expire_for_idle = SystemTime::now() + Session::DEFAULT_IDLE_DURATION;
            return Some(session.user_id);
        }
        None
    }

    pub async fn create(&self, user_id: i64) -> Cookie<'static> {
        let mut active = self.active.lock().await;
        let mut id = self.generator.generate().await;
        // One must be *extremely* unlucky to go into this loop more than 0 times.
        while active.contains_key(&id) {
            id = self.generator.generate().await;
        }
        active.insert(id, Session::new(user_id));
        let session = BASE64_URL_SAFE.encode(id);

        #[cfg(not(feature = "secure"))]
        {
            Cookie::new(SESSION_COOKIE_NAME, session)
        }

        #[cfg(feature = "secure")]
        {
            Cookie::build((SESSION_COOKIE_NAME, session))
                // Must be sent only through HTTPS.
                .secure(true)
                // Should not be accessible from JavaScript.
                .http_only(true)
                // The browser should send this cookie only to this server.
                .same_site(rocket::http::SameSite::Strict)
                .expires(Expiration::Session)
                .build()
        }
    }

    pub async fn drop(&self, id: Id) {
        self.active.lock().await.remove(&id);
    }
}

#[derive(Debug)]
struct SessionIdGenerator {
    #[cfg(not(feature = "secure"))]
    counter: AtomicU64,
    // The docs claim that this (i.e. StdRng) is a CSPRNG. Moreover I initialise it with a system
    // provided random seed so it should be secure.
    #[cfg(feature = "secure")]
    rng: Arc<Mutex<StdRng>>,
}

impl SessionIdGenerator {
    #[cfg(not(feature = "secure"))]
    async fn generate(&self) -> Id {
        let mut bytes = [0u8; 16];
        let number = self.counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        bytes[0..8].copy_from_slice(&number.to_le_bytes());
        bytes
    }

    #[cfg(feature = "secure")]
    async fn generate(&self) -> Id {
        let mut bytes = ZERO_ID;
        self.rng.lock().await.fill_bytes(&mut bytes);
        bytes
    }
}

impl Default for SessionIdGenerator {
    fn default() -> Self {
        Self {
            #[cfg(not(feature = "secure"))]
            counter: Default::default(),
            #[cfg(feature = "secure")]
            rng: Arc::new(Mutex::new(StdRng::try_from_rng(&mut SysRng).unwrap()))
        }
    }
}

#[derive(Debug)]
pub struct Session {
    pub user_id: i64,
    pub expire_for_idle: SystemTime,
    pub expire_for_timeout: SystemTime,
}

impl Session {
    // There are probably more reasonable times for this, but oh well.
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

#[derive(Debug, Default)]
pub struct Cache {
    pub users: Arc<Mutex<HashMap<i64, User>>>,
}

impl Cache {
    pub async fn set(&self, user: User) {
        self.users.lock().await.insert(user.id, user);
    }
    
    pub async fn set_points(&self, user_id: i64, points: i64) {
        if let Some(user) = self.users.lock().await.get_mut(&user_id) {
            user.points = points;
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct MoveRecord<'user, 'm> {
    pub id: i64,
    pub sender: &'user str,
    pub receiver: &'user str,
    pub amount: i64,
    pub message: &'m String,
    pub date: String,
    pub status: MoveStatus,
}

pub const ERROR: &str = "<error>";

pub type Guard<'user> = MutexGuard<'user, HashMap<i64, User>>;
pub async fn cache_users_from_moves<'user>(db: &Db, cache: &'user Cache, moves: &[Move]) -> Guard<'user> {
    async fn cache_user(db: &Db, users: &mut HashMap<i64, User>, user_id: i64) {
        if !users.contains_key(&user_id) && let Ok(user) = db::read_user_by_id(db, user_id).await {
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

pub fn render_moves<'g, 'm>(
    users: &'g HashMap<i64, User>,
    moves: &'m [Move],
) -> Vec<MoveRecord<'g, 'm>> {
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

        let system_time = db::time_from_seconds(move_instance.date);
        let date = format_date(system_time);

        result.push(MoveRecord {
            id: move_instance.id,
            sender,
            receiver,
            amount: move_instance.amount,
            message: &move_instance.message,
            date,
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
        active.retain(|_, value| value.expire_for_idle > now && value.expire_for_timeout > now);
    }
}

fn format_date(system_time: SystemTime) -> String {
    DateTime::<Local>::from(system_time)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

