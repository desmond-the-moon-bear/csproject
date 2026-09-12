use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{
        Error as PasswordError,
        PasswordHasher,
        PasswordVerifier,
        phc::{PasswordHash, Error as PhcError},
    },
    Argon2
};

use derive_more::{Display, Error, From};

use rocket::{Rocket, Build};
use rocket_sync_db_pools::rusqlite::{self, params, Error as DbError};
use rocket_sync_db_pools::database;

use rocket::serde::Serialize;

#[database("sqlite")]
pub struct Db(rusqlite::Connection);

pub type DbResult<T> = Result<T, DbError>;
pub type DefaultDbResult = DbResult<usize>;

#[derive(Clone, Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct User {
    #[serde(skip_serializing)]
    pub id: i64,
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
    pub amount: i64,
    pub message: String,
    pub date: i64,
    pub status: MoveStatus,
}

pub fn seconds_from_unix_epoch() -> i64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs() as i64,
        Err(_) => 0,
    }
}

pub fn time_from_seconds(seconds: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64)
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
                amount integer not null,
                message varchar not null,
                date integer not null,
                status integer not null,
                foreign key (sender)   references users(id),
                foreign key (receiver) references users(id)
            );

            insert or ignore into users values (0, 'placeholder', '', 0, FALSE);
            "#)?;

            // It is guaranteed that a placeholder user is present for the admin to replace.
            if let Ok(admin_password) = std::env::var("ADMIN_PASS") {
                let insert_admin = format!(
                    "insert or replace into users values (0, 'admin', '{}', 0, TRUE);",
                    admin_password
                );
                conn.execute(&insert_admin, params![])?;
            }

            Ok(())
        }).await
        .expect("database init");
    rocket
}

pub fn parse_row_to_user(row: &rocket_sync_db_pools::rusqlite::Row<'_>) -> DbResult<User> {
    let user = User {
        id     : row.get(0)?,
        name   : row.get(1)?,
        secret : row.get(2)?,
        points : row.get(3)?,
        admin  : row.get(4)?,
    };
    Ok(user)
}

pub async fn read_user_by_id(db: &Db, user_id: i64) -> DbResult<User> {
    db.run(move |connection| {
        connection.query_row(
            "select * from users where users.id = ?1;",
            params![user_id],
            parse_row_to_user,
        )
    }).await
}

pub async fn read_user_by_name(db: &Db, name: String) -> DbResult<User> {
    db.run(move |connection| {
        connection.query_row(
            "select * from users where users.name = ?1;",
            params![name],
            parse_row_to_user,
        )
    }).await
}

#[derive(Debug, Display, Error, From)]
pub enum VerificationError {
    Db(DbError),
    Phc(PhcError),
    Password(PasswordError),
}

#[cfg(feature = "secure")]
pub async fn verify_secret(
    db: &Db,
    name: String,
    secret: String
) -> Result<User, VerificationError> {
    let user = read_user_by_name(db, name).await?;
    let parsed_hash = PasswordHash::new(&user.secret)?;
    Argon2::default().verify_password(secret.as_bytes(), &parsed_hash)?;
    Ok(user)
}

#[cfg(not(feature = "secure"))]
pub async fn verify_secret(
    db: &Db,
    name: String,
    secret: String
) -> Result<User, VerificationError> {
    let query = format!("select * from users where users.name = '{}' and users.secret = '{}';", name, secret);
    // If there were no rows, returns false. 
    let user = db.run(move |connection| {
        connection.query_row(
            &query,
            params![],
            parse_row_to_user,
        )
    }).await?;
    Ok(user)
}

pub async fn write_user(db: &Db, user: User) -> DefaultDbResult {
    db.run(move |connection| {
        connection.execute(
            "insert into users(name, secret, points, admin) values (?1, ?2, ?3, ?4);",
            params![
                user.name,
                user.secret,
                user.points,
                user.admin
            ]
        )
    }).await
}

pub async fn create_move(db: &Db, user_id: i64, new_points: i64, move_instance: Move) -> DefaultDbResult {
    db.run(move |connection| {
        let transaction = connection.transaction()?;
        transaction.execute(
            "update users set points = ?1 where id = ?2;",
            params![
                new_points,
                user_id
            ]
        )?;
        transaction.execute(
            "insert into moves(sender, receiver, amount, message, date, status) values(?1, ?2, ?3, ?4, ?5, ?6);",
            params![
                move_instance.sender,
                move_instance.receiver,
                move_instance.amount,
                move_instance.message,
                move_instance.date,
                <i64>::from(move_instance.status),
            ]
        )?;
        transaction.commit()?;
        Ok(1)
    }).await
}

pub async fn update_move_status(db: &Db, move_id: i64, status: MoveStatus) -> DefaultDbResult {
    db.run(move |connection| {
        connection.execute(
            "update moves set status = ?1 where id = ?2;",
            params![
                <i64>::from(status),
                move_id,
            ]
        )
    }).await
}

pub fn parse_row_to_move(row: &rocket_sync_db_pools::rusqlite::Row<'_>) -> Result<Move, DbError> {
    let status: i64 = row.get(6)?;

    let move_instance = Move {
        id       : row.get(0)?,
        sender   : row.get(1)?,
        receiver : row.get(2)?,
        amount   : row.get(3)?,
        message  : row.get(4)?,
        date     : row.get(5)?,
        status: <MoveStatus>::from(status),
    };

    Ok(move_instance)
}

pub async fn read_move(db: &Db, move_id: i64) -> Result<Move, DbError> {
    db.run(move |connection| {
        connection.query_row(
            "select * from moves where move.id = ?1;",
            params![move_id],
            parse_row_to_move
        )
    }).await
}

pub async fn list_moves(db: &Db) -> Result<Vec<Move>, DbError> {
    db.run(|connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves;")?
            .query_map(params![], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

pub async fn list_ougoing_moves(db: &Db, sender: i64) -> Result<Vec<Move>, DbError> {
    db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves where moves.sender = ?1 and moves.status = 0;")?
            .query_map(params![sender], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

pub async fn list_incoming_moves(db: &Db, receiver: i64) -> Result<Vec<Move>, DbError> {
    db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves where moves.receiver = ?1 and moves.status = 0;")?
            .query_map(params![receiver], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

