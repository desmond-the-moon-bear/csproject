mod db;
mod cache;

use db::{Db, User, Move, MoveStatus};
use cache::{Cache, Sessions, Id, ZERO_ID};

use std::net::IpAddr;

use argon2::{
    password_hash::PasswordHasher,
    Argon2
};

use base64::prelude::*;


use rocket::fairing::AdHoc;
use rocket::{FromForm, form::Form};
use rocket::fs::{FileServer, relative};
use rocket::{get, post, launch, routes};
use rocket::http::CookieJar;
use rocket::State;

use rocket_dyn_templates::{Template, context};

#[launch]
fn rocket() -> _ {
    let mut rocket = rocket::build()
        .attach(Template::fairing())
        .attach(Db::fairing())
        .attach(AdHoc::on_ignite("Rusqlite Init", db::init_db))
        .manage(Cache::default())
        .manage(Sessions::default())
        .mount("/", FileServer::from(relative!("/static")))
        .mount(
            "/",
            routes![
                index,
                login_get, login_post,
                register_get, register_post,
                logout,
                send_get, send_post,
                moves, update, admin,
            ],
        );
    #[cfg(feature = "secure")]
    {
        rocket = rocket.attach(cache::Timeout);
    }

    // This request handler is only for demonstration purposes and would not be included in a
    // secure website. Fix: uncomment this cfg directive.
    // #[cfg(not(feature = "secure"))]
    {
        rocket = rocket.mount("/", routes![debug]);
    }
    rocket
}

const INDEX : &str = "index";
const LOR   : &str = "login_or_register";
const MOVES : &str = "move_view";
const SEND  : &str = "create_move";
const ADMIN : &str = "admin";

fn get_session_id(ip: IpAddr, cookies: &CookieJar<'_>) -> Option<Id> {
    // It's ok if the cookie does not exist. No logging needed.
    let encoded_id = cookies.get(cache::SESSION_COOKIE_NAME)?.value();
    let mut id = ZERO_ID;
    match BASE64_URL_SAFE.decode_slice(encoded_id, &mut id) {
        Ok(_) => {
            Some(id)
        }
        Err(error) => {
            #[cfg(feature = "secure")]
            log::warn!("[from: {}] Error decoding cookie: {}.", ip, error);
            cookies.remove(cache::SESSION_COOKIE_NAME);
            None
        }
    }
}

async fn fetch_and_cache_user(
    ip: IpAddr,
    db: &Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Option<User> {
    let session_id = get_session_id(ip, cookies)?;
    let user_id = match sessions.fetch(session_id).await {
        Some(value) => value,
        None => {
            #[cfg(feature = "secure")]
            log::warn!("[from: {}] Session from cookie did not exist: {:?}.", ip, session_id);
            return None;
        }
    };
    match db::read_user_by_id(db, user_id).await {
        Ok(user_from_db) => {
            cache.set(user_id, user_from_db.name.clone()).await;
            Some(user_from_db)
        },
        Err(error) => {
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Error fetching user from database: {}.", ip, error);
            None
        }
    }
}

#[get("/")]
async fn index(
    ip: IpAddr,
    db: Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>,
) -> Template {
    if let Some(user) = fetch_and_cache_user(ip, &db, cookies, sessions, cache).await {
        Template::render(INDEX, context! { user: user })
    } else {
        Template::render(INDEX, ())
    }
}

#[derive(FromForm)]
struct UserFormInfo {
    name: String,
    secret: String,
}

#[get("/login")]
async fn login_get() -> Template {
    Template::render(LOR, context! { action: "login" })
}

#[post("/login", data="<data>")]
async fn login_post(
    ip: IpAddr,
    data: Form<UserFormInfo>,
    db: Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Template {
    let UserFormInfo { name, secret } = data.into_inner();
    let result = db::verify_secret(&db, name, secret).await;
    match result {
        Ok(user) => {
            //
            // Fix for flaw 4: we must ensure that if the user somehow logs in again into a
            // different account, the previous session is dropped as well. Flaw 4 includes that
            // this code is not included.
            //
            #[cfg(feature = "secure")]
            if let Some(previous_session_id) = get_session_id(ip, cookies) {
                sessions.drop(previous_session_id).await;
            }


            #[cfg(feature = "secure")]
            log::info!("[from: {}] User {} logged in.", ip, user.id);
            let cookie = sessions.create(user.id).await;
            cookies.add(cookie);
            let template = Template::render(INDEX, context! { user: &user });

            // Setting the cookie overwrites the previous session it stored.
            cache.set(user.id, user.name).await;
            template
        }
        Err(error) => {
            //
            // Fix for flaw 5:
            //
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Failed to authenticate user: {}.", ip, error);
            use db::VerificationError::*;
            #[cfg(feature = "secure")]
            let error_text = match error {
                Db(_) => "user does not exist",
                Phc(_) | Password(_) => "incorrect password",
            };

            //
            // Flaw 5:
            //
            #[cfg(not(feature = "secure"))]
            let error_text = format!("{:?}", error);

            Template::render(LOR, context! { action: "login", error_text: error_text })
        }
    }
}

#[get("/logout")]
async fn logout(
    ip: IpAddr,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
) -> Template {
    let session_id_op = get_session_id(ip, cookies);

    //
    // Flaw 4: only the cookie is removed, however, the session is not dropped.
    //
    #[cfg(not(feature = "secure"))]
    if session_id_op.is_some() {
        cookies.remove(cache::SESSION_COOKIE_NAME);
    }

    //
    // Fix for flaw 4: the cookie is removed and the sesion is dropped as well.
    //
    #[cfg(feature = "secure")]
    if let Some(session_id) = session_id_op {
        cookies.remove(cache::SESSION_COOKIE_NAME);
        if let Some(user_id) = sessions.fetch(session_id).await {
            log::info!("[from: {}] User {} logged out.", ip, user_id);
        } else {
            log::warn!("[from: {}] Tried to log out with an inactive session.", ip);
        }
        sessions.drop(session_id).await;
    } else {
        log::warn!("[from: {}] Tried to log out with invalid (or nonexistant) session from cookie.", ip);
    }

    Template::render(INDEX, ())
}

const MAX_NAME_LEN: usize = 75;

#[get("/register")]
async fn register_get() -> Template {
    Template::render(LOR, context!{ action: "register" })
}

#[post("/register", data="<data>")]
async fn register_post(ip: IpAddr, data: Form<UserFormInfo>, db: Db) -> Template {
    if db::read_user_by_name(&db, data.name.clone()).await.is_ok() {
        #[cfg(feature = "secure")]
        log::warn!("[from: {}] Tried to create an account an already existing username: {}.", ip, data.name);
        return Template::render(
            LOR,
            context! {
                action: "register",
                error_text: "username taken"
            }
        );
    }

    let UserFormInfo { name, mut secret } = data.into_inner();
    let name_len = name.chars().count();
    if name_len > MAX_NAME_LEN {
        #[cfg(feature = "secure")]
        log::error!("[from: {}] Name was too long: {}", ip, name);
        return Template::render(
            LOR,
            context! {
                action: "register",
                error_text: format!("name was too long; max: {} characters, was {}", MAX_NAME_LEN, name_len)
            }
        );
    }

    #[cfg(feature = "secure")]
    match Argon2::default().hash_password(secret.as_bytes()) {
        Ok(hashed_secret) => {
            secret = hashed_secret.to_string()
        }
        Err(error) => {
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Error hashing password for user [{}]: {}", ip, name, error);
            return Template::render(
                LOR,
                context! {
                    action: "register",
                    error_text: "internal error",
                }
            );
        }
    }
    let user = db::User {
        id: 0,
        name,
        secret,
        points: 100,
        admin: false,
    };
    let result = db::write_user(&db, user).await;
    if let Err(error) = result {
        #[cfg(feature = "secure")]
        log::error!("[from: {}] Error storing user: {}.", ip, error);
        Template::render(
            INDEX,
            context! { error_text: "internal error" }
        )
    } else {
        Template::render(INDEX, ())
    }
}

#[derive(FromForm)]
struct MoveFormInfo {
    receiver: String,
    amount: String,
    message: String,
}

const MAX_MESSAGE_LEN: usize = 512;

#[get("/send")]
async fn send_get(
    ip: IpAddr,
    db: Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Template {
    if let Some(user) = fetch_and_cache_user(ip, &db, cookies, sessions, cache).await {
        Template::render(SEND, context!{ user: user })
    } else {
        #[cfg(feature = "secure")]
        log::warn!("[from: {}] Tried to send without logging in first.", ip);
        Template::render(INDEX, context!{ error_text: "login first" })
    }
}

#[post("/send", data="<data>")]
async fn send_post(
    ip: IpAddr,
    data: Form<MoveFormInfo>,
    db: Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Template {
    let user_op = fetch_and_cache_user(ip, &db, cookies, sessions, cache).await;
    if user_op.is_none() {
        return Template::render(INDEX, context!{ error_text: "login first" });
    }
    let mut user = user_op.unwrap();

    let MoveFormInfo { receiver, amount, mut message } = data.into_inner();
    message = message.chars().take(MAX_MESSAGE_LEN).collect();
    let amount: i64 = match amount.parse() {
        Ok(value) => value,
        Err(error) => {
            #[cfg(feature = "secure")]
            log::warn!("[from: {}] Invalid amount passed: {}. Error: {}.", ip, amount, error);
            return Template::render(SEND, context!{ user: user, error_text: "amount must be a positive integer" });
        }
    };

    #[cfg(feature = "secure")]
    if amount < 0 {
        log::warn!("[from: {}] Invalid amount passed: {}.", ip, amount);
        return Template::render(SEND, context!{ user: user, error_text: "amount must be positive" });
    }

    let receiver_op = db::read_user_by_name(&db, receiver).await;
    if let Err(error) = receiver_op {
        #[cfg(feature = "secure")]
        log::warn!("[from: {}] Could not fetch receiver from db: {}.", ip, error);
        return Template::render(SEND, context!{ user: user, error_text: "receiver does not exist" });
    }
    let receiver = receiver_op.unwrap();

    if user.id == receiver.id {
        #[cfg(feature = "secure")]
        log::warn!("[from: {}] User tried to send points to self.", ip);
        return Template::render(SEND, context!{ user: user, error_text: "cannot send points to self" });
    }

    let move_instance = Move {
        id: 0,
        sender: user.id,
        receiver: receiver.id,
        amount,
        message,
        date: db::seconds_from_unix_epoch(),
        status: db::MoveStatus::New,
    };
    
    let transaction_result = db::create_move(&db, user.id, move_instance).await;
    if let Err(error) = transaction_result {
        #[cfg(feature = "secure")]
        log::error!("[from: {}] Error creating move: {}.", ip, error);
        let error_text = match error {
            db::TransactionError::Db(_) => "internal error",
            db::TransactionError::Detailed(detailed_error) => detailed_error.reason,
        };
        return Template::render(SEND, context!{ user: user, error_text: error_text });
    }

    user.points -= amount;

    Template::render(INDEX, context!{ user: user, error_text: "successfuly sent points" })
}

const MOVES_INCOMING: &str = "incoming";
const MOVES_OUTGOING: &str = "outgoing";
const MOVES_PAST: &str = "past";
const MOVES_ADMIN_VIEW: &str = "admin";

#[get("/moves/<direction>")]
async fn moves(
    ip: IpAddr,
    db: Db,
    direction: &str,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Template {
    let user_op = fetch_and_cache_user(ip, &db, cookies, sessions, cache).await;
    if user_op.is_none() {
        return Template::render(INDEX, context!{ error_text: "login first" });
    }
    render_moves(ip, db, user_op.unwrap(), direction, MOVES, cache, None).await
}

const ACTION_ACCEPT: &str = "accept";
const ACTION_CANCEL: &str = "cancel";

#[allow(clippy::too_many_arguments)]
#[get("/update/<action>/<direction>/<move_id>")]
async fn update(
    ip: IpAddr,
    db: Db,
    action: &str,
    direction: &str,
    move_id: i64,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Template {
    let user_op = fetch_and_cache_user(ip, &db, cookies, sessions, cache).await;
    if user_op.is_none() {
        #[cfg(feature = "secure")]
        log::warn!("[from: {}] Tried to update move without logging in first.", ip);
        return Template::render(INDEX, context!{ error_text: "login first" });
    }
    let user = user_op.unwrap();

    match direction {
        MOVES_INCOMING | MOVES_OUTGOING  => (),
        MOVES_ADMIN_VIEW => {
            //
            // Fix for flaw 1: check whether the user is an admin in order to proceed to the admin
            // view.
            //
            #[cfg(feature = "secure")]
            if !user.admin {
                log::warn!("[from: {}] Tried to update move without being an admin.", ip);
                return Template::render(INDEX, context!{ error_text: "not an admin", user: user });
            }
        }
        _ => {
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Invalid move type: {}.", ip, direction);
            return Template::render(
                INDEX,
                context! {
                    error_text: format!("'{}' is not a valid move type", direction),
                    user: user,
                }
            );
        }
    };

    let new_move_status = match action {
        ACTION_ACCEPT => MoveStatus::Accepted,
        ACTION_CANCEL => MoveStatus::Cancelled,
        _ => {
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Invalid move operation: {}.", ip, action);
            return Template::render(INDEX, context!{
                error_text: "invalid move operation",
                user: user,
            });
        }
    };

    let mut move_instance = match db::read_move(&db, move_id).await {
        Ok(value) => value,
        Err(error) => {
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Move error: {}.", ip, error);
            return Template::render(INDEX, context!{
                error_text: "move does not exist",
                user: user,
            });
        }
    };

    if move_instance.status != MoveStatus::New {
        #[cfg(feature = "secure")]
        log::error!("[from: {}] Tried to update non-new move (user_id: {:?}).", ip, user.id);
        return Template::render(INDEX, context!{
            error_text: "cannot update a non-new move",
            user: user,
        });
    }

    //
    // Fix for flaw 1: include a check
    //
    #[cfg(feature = "secure")]
    if !user.admin {
        if new_move_status == MoveStatus::Accepted
            && move_instance.receiver != user.id
        {
            log::error!("[from: {}] User {} tried to accept an invalid move: {:?}.", ip, user.id, move_instance);
            return Template::render(INDEX, context!{
                error_text: "cannot accept someone else's move",
                user: user,
            });
        }
        if new_move_status == MoveStatus::Cancelled
            && move_instance.sender != user.id
            && move_instance.receiver != user.id
        {
            log::error!("[from: {}] User {} tried to cancel an invalid move: {:?}.", ip, user.id, move_instance);
            return Template::render(INDEX, context!{
                error_text: "cannot cancel a move you are not part of",
                user: user,
            });
        }
    } else {
        log::info!(
            "[from: {}] Admin {} changes move {:?} to status {:?}.",
            ip, user.id, move_instance, new_move_status
        );
    }

    move_instance.status = new_move_status;
    let result = db::perform_move(&db, move_instance).await;

    let error_text = if let Err(error) = result {
        #[cfg(feature = "secure")]
        log::error!("[from: {}] DB error when updating move: {}.", ip, error);
        if let db::TransactionError::Detailed(error) = error {
            Some(error.reason)
        } else {
            Some("internal error")
        }
    } else {
        Some("successfully updated")
    };

    let template = if direction == MOVES_ADMIN_VIEW { ADMIN } else { MOVES };
    render_moves(ip, db, user, direction, template, cache, error_text).await
}

#[allow(clippy::too_many_arguments)]
async fn render_moves(
    ip: IpAddr,
    db: Db,
    user: User,
    direction: &str,
    template: &'static str,
    cache: &State<Cache>,
    error_text: Option<&'static str>,
) -> Template {
    let moves_op = match direction {
        MOVES_INCOMING => db::list_incoming_moves(&db, user.id).await,
        MOVES_OUTGOING => db::list_outgoing_moves(&db, user.id).await,
        MOVES_PAST => db::list_past_moves(&db, user.id).await,
        MOVES_ADMIN_VIEW => db::list_moves(&db).await,
        _ => {
            #[cfg(feature = "secure")]
            log::error!("[from: {}] Invalid move type: {}.", ip, direction);
            return Template::render(
                INDEX,
                context! {
                    error_text: format!("'{}' is not a valid move type", direction),
                    user: user,
                }
            );
        }
    };
    if let Err(error) = moves_op {
        #[cfg(feature = "secure")]
        log::error!("[from {}] Could not load moves: {}.", ip, error);
        return Template::render(INDEX, context!{
            error_text: "internal error",
            user: user,
        });
    }
    let moves = moves_op.unwrap();

    let users = cache::cache_users_from_moves(&db, cache, &moves).await;
    let records = cache::render_moves(&users, &moves);

    let (can_cancel, can_accept, show_status) = match direction {
        MOVES_INCOMING => (true, true, false),
        MOVES_OUTGOING => (true, false, false),
        MOVES_PAST => (false, false, true),
        MOVES_ADMIN_VIEW => (true, true, true),
        _ => { unreachable!() }
    };

    Template::render(
        template,
        context! {
            move_type: direction,
            moves: records,
            can_cancel: can_cancel,
            can_accept: can_accept,
            show_status: show_status,
            error_text: error_text,
            user: user,
        }
    )
}

#[get("/admin")]
async fn admin(
    ip: IpAddr,
    db: Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Template {
    if let Some(user) = fetch_and_cache_user(ip, &db, cookies, sessions, cache).await {
        #[cfg(feature = "secure")]
        if !user.admin {
            log::warn!("[from: {}] User {} is not an admin.", ip, user.id);
            return Template::render(INDEX, context! { user: user });
        }
        render_moves(ip, db, user, MOVES_ADMIN_VIEW, ADMIN, cache, None).await
    } else {
        #[cfg(feature = "secure")]
        log::warn!("[from: {}] Attempted access to admin panel without being logged in.", ip);
        Template::render(INDEX, ())
    }
}

// This request handler is only for demonstration purposes and would not be included in a
// secure website. Fix: uncomment this cfg directive.
// #[cfg(not(feature = "secure"))]
#[get("/debug/<encoded_id>")]
async fn debug(encoded_id: &str, sessions: &State<Sessions>) -> String {
    let mut session_id = ZERO_ID;
    #[allow(clippy::collapsible_if)]
    if BASE64_URL_SAFE.decode_slice(encoded_id, &mut session_id).is_ok() {
        if let Some(user_id) = sessions.fetch(session_id).await {
            return format!("the session id belongs to user id: {}", user_id);
        }
    }
    String::from("no active session")
}

