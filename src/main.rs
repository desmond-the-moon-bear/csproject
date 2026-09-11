#![allow(unused)]
mod db;
mod cache;

use db::{Db, User};
use cache::{Cache, Sessions, Id, ZERO_ID};

use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
    Argon2
};

use base64::prelude::*;

use rocket::fairing::AdHoc;
use rocket::{FromForm, form::Form};
use rocket::fs::{FileServer, relative};
use rocket::{get, post, launch, routes};
use rocket::http::{Cookie, CookieJar};
use rocket::State;

use rocket_dyn_templates::{Template, context};

#[launch]
fn rocket() -> _ {
    env_logger::builder();
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
                send, incoming, outgoing,
                confirm, cancel,
                admin,
            ],
        );
    #[cfg(feature = "secure")]
    {
        rocket = rocket.attach(cache::Timeout);
    }
    rocket
}

const INDEX: &str = "index";
const LOR: &str = "login_or_register";

fn get_session_id(cookies: &CookieJar<'_>) -> Option<Id> {
    let encoded_id = cookies.get(cache::SESSION_COOKIE_NAME)?.value();
    let mut id = ZERO_ID;
    match BASE64_URL_SAFE.decode_slice(encoded_id, &mut id) {
        Ok(_) => {
            Some(id)
        }
        Err(error) => {
            #[cfg(feature = "secure")] log::info!("Error decoding cookie: {}.", error);
            cookies.remove(cache::SESSION_COOKIE_NAME);
            None
        }
    }
}

async fn fetch_and_cache_user(
    db: &Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>
) -> Option<User> {
    let session_id = get_session_id(cookies)?;
    let user_id = sessions.fetch(session_id).await?;
    {
        // Drop the mutex guard at the end of the scope.
        // let users = cache.users.lock().unwrap();
        let users = cache.users.lock().await;
        let cached_user_op = users.get(&user_id);
        if let Some(cached_user) = cached_user_op {
            return Some(cached_user.clone());
        }
    }
    match db::read_user_by_id(db, user_id).await {
        Ok(user_from_db) => Some(user_from_db),
        Err(error) => {
            #[cfg(feature = "secure")]
            log::info!("Error fetching user from database: {}.", error);
            None
        }
    }
}

#[get("/")]
async fn index(
    db: Db,
    cookies: &CookieJar<'_>,
    sessions: &State<Sessions>,
    cache: &State<Cache>,
) -> Template {
    if let Some(user) = fetch_and_cache_user(&db, cookies, sessions, cache).await {
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
            #[cfg(feature = "secure")]
            if let Some(previous_session_id) = get_session_id(cookies) {
                sessions.drop(previous_session_id);
            }
            let cookie = sessions.create(user.id).await;
            cookies.add(cookie);
            let template = Template::render(INDEX, context! { user: &user });
            cache.set(user);
            template
        }
        Err(error) => {
            #[cfg(feature = "secure")]
            log::error!("Failed to authenticate user: {}.", error);
            use db::VerificationError::*;
            let error_text = match error {
                Db(_) => "internal error",
                Phc(_) | Password(_) => "incorrect password",
            };
            Template::render(LOR, context! { action: "login", error_text: error_text })
        }
    }
}

#[get("/register")]
async fn register_get() -> Template {
    Template::render(LOR, context!{ action: "register" })
}

#[post("/register", data="<data>")]
async fn register_post(data: Form<UserFormInfo>, db: Db) -> Template {
    if db::read_user_by_name(&db, data.name.clone()).await.is_err() {
        let UserFormInfo { name, mut secret } = data.into_inner();
        #[cfg(feature = "secure")]
        {
            match Argon2::default().hash_password(secret.as_bytes()) {
                Ok(hashed_secret) => {
                    secret = hashed_secret.to_string()
                }
                Err(error) => {
                    log::error!("Error hashing password for user [{}]: {}", name, error);
                    return Template::render(LOR, context! { ction: "register", error_text: "internal error"});
                }
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
        if result.is_err() {
            #[cfg(feature = "secure")] log::error!("Error storing user.");
            Template::render(INDEX, context! { error_text: "internal error" })
        } else {
            Template::render(INDEX, ())
        }
    } else {
        Template::render(LOR, context! { action: "register", error_text: "username taken" })
    }
}

#[get("/send")]
async fn send() -> Template {
    todo!()
}

#[get("/incoming")]
async fn incoming() -> Template {
    todo!()
}

#[get("/outgoing")]
async fn outgoing() -> Template {
    todo!()
}

#[get("/confirm")]
async fn confirm() -> Template {
    todo!()
}

#[get("/cancel")]
async fn cancel() -> Template {
    todo!()
}

#[get("/admin")]
async fn admin() -> Template {
    todo!()
}
