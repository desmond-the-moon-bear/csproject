use std::time::{SystemTime, UNIX_EPOCH};

use rocket::{Rocket, Build};
use rocket_sync_db_pools::rusqlite::{self, params, Error as DbError};
use rocket_sync_db_pools::database;

use rocket::serde::Serialize;

#[database("sqlite")]
pub struct Db(rusqlite::Connection);

#[derive(Clone, Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct User {
    pub name: String,
    #[serde(skip_serializing)]
    pub secret: String,
    pub points: i64,
    #[serde(skip_serializing)]
    pub admin: bool,
}

#[derive(Clone, Debug)]
pub struct Move {
    pub id: i64,
    pub sender: i64,
    pub receiver: i64,
    pub date: i64,
    pub message: Option<String>,
    pub status: MoveStatus,
}

fn seconds_from_unix_epoch() -> i64 {
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs() as i64,
        Err(_) => 0,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum MoveStatus {
    #[default]
    New,
    Accepted,
    Cancelled,
}

impl From<i64> for MoveStatus {
    fn from(value: i64) -> Self {
        match value {
            1 => Self::Accepted,
            2 => Self::Cancelled,
            _ => Self::New,
        }
    }
}

impl From<MoveStatus> for i64 {
    fn from(value: MoveStatus) -> Self {
        use MoveStatus::*;
        match value {
            New => 0,
            Accepted => 1,
            Cancelled => 2,
        }
    }
}

impl Serialize for MoveStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: rocket::serde::Serializer {
        serializer.serialize_u8(<i64>::from(*self) as u8)
    }
}

impl std::fmt::Display for MoveStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use MoveStatus::*;
        let name = match self {
            New => "new",
            Accepted => "accepted",
            Cancelled => "cancelled",
        };
        write!(f, "{}", name)
    }
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
                sender integer not null,
                receiver integer not null,
                message varchar,
                date integer not null,
                status integer not null,
                foreign key (sender)   references users(id),
                foreign key (receiver) references users(id)
            );

            insert or ignore into users values (0, 'placeholder', '', 0, FALSE);
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

pub async fn read_user_by_id(db: &Db, user_id: i64) -> Option<User> {
    db.run(move |connection| {
        connection.query_row(
            "select name, secret, points, admin from users where users.id = ?1;",
            params![user_id],
            |row| {
                let user = User {
                    name   : row.get(0)?,
                    secret : row.get(1)?,
                    points : row.get(2)?,
                    admin  : row.get(3)?,
                };
                Ok(user)
            })
    }).await.ok()
}

#[cfg(feature = "secure")]
pub async fn read_user_by_name(db: &Db, name: String) -> Option<User> {
    db.run(move |connection| {
        connection.query_row(
            "select name, secret, points, admin from users where users.name = ?1;",
            params![name],
            |row| {
                let user = User {
                    name   : row.get(0)?,
                    secret : row.get(1)?,
                    points : row.get(2)?,
                    admin  : row.get(3)?,
                };
                Ok(user)
            })
    }).await.ok()
}

#[cfg(not(feature = "secure"))]
pub async fn read_user_by_name(db: &Db, name: String) -> Option<User> {
    let query = format!("select name, secret, points, admin from users where users.name = '{}';", name);
    println!("{query}");
    db.run(move |connection| {
        connection.query_row(
            &query,
            params![],
            |row| {
                let user = User {
                    name   : row.get(0)?,
                    secret : row.get(1)?,
                    points : row.get(2)?,
                    admin  : row.get(3)?,
                };
                Ok(user)
            })
    }).await.ok()
}

macro_rules! handle {
    ($result:ident) => {
        #[cfg(feature = "check")]
        {
            $result.unwrap();
            #[allow(unreachable_code)]
            return Ok(());
        }
        if $result.is_ok() {
            Ok(())
        } else {
            Err(())
        }
    };
}

pub async fn write_user(db: &Db, user: User) -> Result<(), ()> {
    let result = db.run(move |connection| {
        connection.execute(
            "insert into users(name, secret, points, admin) values (?1, ?2, ?3, ?4);",
            params![
                user.name,
                user.secret,
                user.points,
                user.admin
            ]
        )
    }).await;
    handle!{result}
}

pub async fn update_user_points(db: &Db, user_id: i64, points: i64) -> Result<(), ()> {
    let result = db.run(move |connection| {
        connection.execute(
            "update users set points = ?1 where id = ?2;",
            params![
                points,
                user_id
            ]
        )
    }).await;
    handle!{result}
}

pub async fn create_move(db: &Db, move_instance: Move) -> Result<(), ()> {
    let result = db.run(move |connection| {
        connection.execute(
            "insert into moves(sender, receiver, message, date, status) values(?1, ?2, ?3, ?4, ?5);",
            params![
                move_instance.sender,
                move_instance.receiver,
                move_instance.message,
                move_instance.date,
                <i64>::from(move_instance.status),
            ]
        )
    }).await;
    handle!{result}
}

pub async fn update_move_status(db: &Db, move_id: i64, status: MoveStatus) -> Result<(), ()> {
    let result = db.run(move |connection| {
        connection.execute(
            "update moves set status = ?1 where id = ?2;",
            params![
                <i64>::from(status),
                move_id,
            ]
        )
    }).await;
    handle!{result}
}

pub fn parse_row_to_move(row: &rocket_sync_db_pools::rusqlite::Row<'_>) -> Result<Move, DbError> {
    let status: i64 = row.get(5)?;

    let move_instance = Move {
        id       : row.get(0)?,
        sender   : row.get(1)?,
        receiver : row.get(2)?,
        date     : row.get(3)?,
        message  : row.get(4)?,
        status: <MoveStatus>::from(status),
    };

    Ok(move_instance)
}

pub async fn read_move(db: &Db, move_id: i64) -> Option<Move> {
    db.run(move |connection| {
        connection.query_row(
            "select * from moves where move.id = ?1;",
            params![move_id],
            parse_row_to_move
        )
    }).await.ok()
}

pub async fn list_moves(db: &Db) -> Vec<Move> {
    let result = db.run(|connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves;")?
            .query_map(params![], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await;
    #[cfg(feature = "check")]
    #[allow(unreachable_code)]
    return result.unwrap();
    result.unwrap_or_default()
}

pub async fn list_ougoing_moves(db: &Db, sender: i64) -> Vec<Move> {
    let result = db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves where moves.sender = ?1 and moves.status = 0;")?
            .query_map(params![sender], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await;
    #[cfg(feature = "check")]
    #[allow(unreachable_code)]
    return result.unwrap();
    result.unwrap_or_default()
}

pub async fn list_incoming_moves(db: &Db, receiver: i64) -> Vec<Move> { let result = db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves where moves.receiver = ?1 and moves.status = 0;")?
            .query_map(params![receiver], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await;
    #[cfg(feature = "check")]
    #[allow(unreachable_code)]
    return result.unwrap();
    result.unwrap_or_default()
}

