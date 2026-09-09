mod db;
mod cache;

use db::Db;
use cache::Sessions;

use rocket::fairing::AdHoc;
use rocket::fs::{FileServer, relative};
use rocket::{get, launch, routes};

use rocket_dyn_templates::Template;

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
            routes![index, send, incoming, outgoing, confirm, cancel, admin,],
        )
}

#[get("/")]
async fn index() -> Template {
    Template::render("index", ())
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
