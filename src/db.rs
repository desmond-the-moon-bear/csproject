use std::time::SystemTime;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
        // serializer.serialize_u8(<i64>::from(*self) as u8)
        serializer.serialize_str(
            match self {
                MoveStatus::New => "pending",
                MoveStatus::Accepted => "accepted",
                MoveStatus::Cancelled => "cancelled",
            }
        )
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
                points integer not null check(points >= 0),
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
            'label: {
                if let Ok(admin_password) = std::env::var("ADMIN_PASS") {
                    #[cfg(feature = "secure")]
                    let admin_password = match Argon2::default().hash_password(admin_password.as_bytes()) {
                        Ok(password) => {
                            password.to_string()
                        }
                        Err(error) => {
                            log::error!("Error hashing admin password: {}.", error);
                            break 'label;
                        }
                    };

                    conn.execute(
                        "insert or replace into users values (0, 'admin', ?1, 0, TRUE);",
                        params![admin_password]
                    )?;
                }
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

//
// Fix for flaw 3:
//
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

//
// Flaw 3:
//
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
            [],
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

#[derive(Debug, Error)]
pub struct DetailedError<'a> {
    pub reason: &'a str,
    db_error: Option<DbError>
}

impl<'a> std::fmt::Display for DetailedError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, ", self.reason)?;
        match self.db_error {
            Some(ref error) => write!(f, "{})", error),
            None => write!(f, "None)")
        }
    }
}

impl<'a> DetailedError<'a> {
    fn new(reason: &'a str, db_error: Option<DbError>) -> Self {
        Self {
            reason,
            db_error,
        }
    }
}

#[derive(Debug, Display, Error, From)]
pub enum TransactionError {
    Db(DbError),
    Detailed(DetailedError<'static>)
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

pub async fn create_move(db: &Db, sender: i64, move_instance: Move) -> Result<(), TransactionError> {
    db.run(move |connection| {
        let transaction = connection.transaction()?;
        let subtract_points_result = transaction.execute(
            "update users set points = points - ?1 where id = ?2;",
            params![
                move_instance.amount,
                sender
            ]
        );
        match subtract_points_result {
            Ok(rows) => {
                if rows != 1 {
                    Err(DetailedError::new("user does not exist", None))?
                }
            }
            Err(error) => {
                Err(DetailedError::new("not enough points", Some(error)))?
            }
        };
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
        Ok(())
    }).await
}

pub async fn perform_move(db: &Db, move_instance: Move) -> Result<(), TransactionError> {
    assert!(
        move_instance.status != MoveStatus::New,
        "To perform a move it must either be accepted or cancelled."
    );
    db.run(move |connection| {
        let transaction = connection.transaction()?;
        transaction.execute(
            "update moves set status = ?1 where id = ?2;",
            params![
                <i64>::from(move_instance.status),
                move_instance.id
            ]
        )?;
        if move_instance.status == MoveStatus::Accepted {
            transaction.execute(
                "update users set points = points + ?1 where id = ?2;",
                params![move_instance.amount, move_instance.receiver]
            )?;
        } else {
            // move_instance.status == MoveStatus::Cancelled
            transaction.execute(
                "update users set points = points + ?1 where id = ?2;",
                params![move_instance.amount, move_instance.sender]
            )?;
        }
        transaction.commit()?;
        Ok(())
    }).await
}

pub async fn read_move(db: &Db, move_id: i64) -> Result<Move, DbError> {
    db.run(move |connection| {
        connection.query_row(
            "select * from moves where moves.id = ?1;",
            params![move_id],
            parse_row_to_move
        )
    }).await
}

pub async fn list_moves(db: &Db) -> Result<Vec<Move>, DbError> {
    db.run(|connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves;")?
            .query_map([], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

pub async fn list_outgoing_moves(db: &Db, sender: i64) -> Result<Vec<Move>, DbError> {
    db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves where moves.sender = ?1 and moves.status = ?2;")?
            .query_map(params![sender, <i64>::from(MoveStatus::New)], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

pub async fn list_incoming_moves(db: &Db, receiver: i64) -> Result<Vec<Move>, DbError> {
    db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare("select * from moves where moves.receiver = ?1 and moves.status = ?2;")?
            .query_map(params![receiver, <i64>::from(MoveStatus::New)], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

pub async fn list_past_moves(db: &Db, user_id: i64) -> Result<Vec<Move>, DbError> {
    db.run(move |connection| -> Result<Vec<Move>, DbError> {
        let moves = connection
            .prepare(r#"
                select * from moves where
                    (moves.receiver = ?1 or moves.sender = ?1)
                    and moves.status != ?2;
            "#)?
            .query_map(params![user_id, <i64>::from(MoveStatus::New)], parse_row_to_move)?
            .flatten()
            .collect::<Vec<_>>();
        Ok(moves)
    }).await
}

