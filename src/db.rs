use rocket::{Rocket, Build};
use rocket_sync_db_pools::rusqlite::{self, params};
use rocket_sync_db_pools::database;

#[database("sqlite")]
pub struct Db(rusqlite::Connection);

#[derive(Debug)]
pub struct User {
    pub id: usize,
    pub name: String,
    pub secret: Option<String>,
    pub points: usize,
    pub admin: bool,
}

pub async fn init_db(rocket: Rocket<Build>) -> Rocket<Build> {
    Db::get_one(&rocket).await
        .expect("database mounted")
        .run(move |conn| -> Result<(), rusqlite::Error> {
            conn.execute_batch(r#"
            create table if not exists users (
                id integer primary key autoincrement,
                name varchar not null unique,
                secret varchar not null,
                points integer not null,
                admin bool not null
            );

            create table if not exists moves (
                id integer primary key autoincrement,
                sender integer,
                receiver integer,
                message varchar,
                date integer not null,
                foreign key (sender)   references users(id),
                foreign key (receiver) references users(id)
            );
            "#)?;

            if let Ok(admin_password) = std::env::var("ADMIN_PASS") {
                let insert_admin = format!("insert or replace into users values (0, 'admin', '{}', 0, TRUE);", admin_password);
                conn.execute(&insert_admin, params![])?;
            }

            Ok(())
        }).await
        .expect("database init");
    rocket
}

