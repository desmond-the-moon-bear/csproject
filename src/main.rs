mod db;
mod cache;

use db::Db;
use cache::Sessions;

use rocket::fairing::AdHoc;
use rocket::fs::{FileServer, relative};
use rocket::{get, post, launch, routes};
use rocket::{FromForm, form::Form};

use rocket_dyn_templates::{Template, context};

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Template::fairing())
        .attach(Db::fairing())
        .attach(AdHoc::on_ignite("Rusqlite Init", db::init_db))
        .manage(Sessions::default())
        .mount("/", FileServer::from(relative!("/static")))
        .mount(
            "/",
            routes![
                index, login,
                register_get, register_post,
                send, incoming, outgoing,
                confirm, cancel,
                admin,
            ],
        )
}

const INDEX: &str = "index";
const LOR: &str = "login_or_register";

#[get("/")]
async fn index() -> Template {
    Template::render(INDEX, ())
}

#[get("/login")]
async fn login() -> Template {
    Template::render(LOR, context! { action: "login" })
}

#[get("/register")]
async fn register_get() -> Template {
    Template::render(LOR, context!{ action: "register" })
}

#[derive(FromForm)]
struct RegisterFormInfo {
    name: String,
    secret: String,
}

#[post("/register", data="<data>")]
async fn register_post(db: Db, data: Form<RegisterFormInfo>) -> Template {
    if db::read_user_by_name(&db, data.name.clone()).await.is_none() {
        let user = db::User {
            name: data.name.clone(),
            secret: data.secret.clone(),
            points: 100,
            admin: false,
        };
        let result = db::write_user(&db, user).await;
        if result.is_err() {
            Template::render(INDEX, context! { error_text: "unknown error" })
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
