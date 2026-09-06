use rocket::{Responder, get, launch, routes};

#[derive(Responder)]
#[response(status=200, content_type="html")]
pub struct Html {
    text: String,
}

impl From<String> for Html {
    fn from(value: String) -> Self {
        Self { text: value }
    }
}

#[get("/")]
fn index() -> Html {
    String::from("<!DOCTYPE html><html><body><p>Henlo</p></body></html>").into()
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
}
