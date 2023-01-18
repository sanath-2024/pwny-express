use crate::{auth::authenticate, crypto, schema::passwords::dsl::*, ConnPool, Error};

use actix_web::{post, web, HttpResponse, Responder};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AppState {
    pub db: ConnPool,
    pub master_pw_hash: String,
}

#[derive(Deserialize)]
struct ListReq {
    master_pw: String,
}

#[derive(Serialize)]
struct ListResp {
    names: Vec<String>,
}

#[derive(Deserialize)]
struct CreateReq {
    master_pw: String,
    name: String,
    value: String,
}

#[derive(Serialize)]
struct CreateResp {}

#[derive(Deserialize)]
struct GetReq {
    master_pw: String,
    name: String,
}

#[derive(Serialize)]
struct GetResp {
    value: String,
}

#[derive(Deserialize)]
struct UpdateReq {
    master_pw: String,
    name: String,
    value: String,
}

#[derive(Serialize)]
struct UpdateResp {}

#[derive(Deserialize)]
struct DeleteReq {
    master_pw: String,
    name: String,
}

#[derive(Serialize)]
struct DeleteResp {}

#[post("/list")]
async fn list(state: web::Data<AppState>, req: web::Json<ListReq>) -> impl Responder {
    use Error::*;

    let resp = async {
        let mut conn = state
            .db
            .get()
            .map_err(|_| DBError("couldn't get DB connection from pool".to_owned()))?;

        authenticate(&req.master_pw, &state.master_pw_hash)?;

        Ok(ListResp {
            names: passwords
                .select(name)
                .load::<String>(&mut conn)
                .map_err(|e| DBError(format!("error getting passwords: {}", e)))?,
        })
    }
    .await;

    match resp {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => match e {
            AuthError(_) => HttpResponse::Forbidden().body(e.to_string()),
            AppError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            DBError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            _ => HttpResponse::InternalServerError().body(""),
        },
    }
}

#[post("/create")]
async fn create(state: web::Data<AppState>, req: web::Json<CreateReq>) -> impl Responder {
    use Error::*;

    let resp = async {
        let mut conn = state
            .db
            .get()
            .map_err(|_| DBError("couldn't get DB connection from pool".to_owned()))?;

        authenticate(&req.master_pw, &state.master_pw_hash)?;

        let hash = crypto::encrypt(&req.master_pw, &req.value)?;

        diesel::insert_into(passwords)
            .values((name.eq(&req.name), value_hash.eq(hash)))
            .execute(&mut conn)
            .map_err(|e| DBError(format!("error inserting new password: {}", e)))?;

        Ok(CreateResp {})
    }
    .await;

    match resp {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => match e {
            AuthError(_) => HttpResponse::Forbidden().body(e.to_string()),
            AppError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            DBError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            _ => HttpResponse::InternalServerError().body(""),
        },
    }
}

#[post("/get")]
async fn get(state: web::Data<AppState>, req: web::Json<GetReq>) -> impl Responder {
    use Error::*;

    let resp = async {
        let mut conn = state
            .db
            .get()
            .map_err(|_| DBError("couldn't get DB connection from pool".to_owned()))?;

        authenticate(&req.master_pw, &state.master_pw_hash)?;

        let hash = passwords
            .filter(name.eq(&req.name))
            .select(value_hash)
            .first::<Vec<u8>>(&mut conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => {
                    AppError(format!("key {:?} not found", req.name))
                }
                _ => DBError(format!("error getting passwords: {}", e)),
            })?;

        Ok(GetResp {
            value: crypto::decrypt(&req.master_pw, &hash)?,
        })
    }
    .await;

    match resp {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => match e {
            AuthError(_) => HttpResponse::Forbidden().body(e.to_string()),
            AppError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            DBError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            _ => HttpResponse::InternalServerError().body(""),
        },
    }
}

#[post("/update")]
async fn update(state: web::Data<AppState>, req: web::Json<UpdateReq>) -> impl Responder {
    use Error::*;

    let resp = async {
        let mut conn = state
            .db
            .get()
            .map_err(|_| DBError("couldn't get DB connection from pool".to_owned()))?;

        authenticate(&req.master_pw, &state.master_pw_hash)?;

        let hash = crypto::encrypt(&req.master_pw, &req.value)?;

        conn.transaction(|conn| {
            let nrows = diesel::update(passwords)
                .filter(name.eq(&req.name))
                .set(value_hash.eq(hash))
                .execute(conn)
                .map_err(|e| DBError(format!("error updating password entry: {}", e)))?;

            if nrows != 1 {
                if nrows == 0 {
                    return Err(AppError(format!("key {:?} not found", req.name)));
                } else {
                    return Err(DBError(format!(
                        "tried to update {} rows ... rolling back transaction",
                        nrows
                    )));
                }
            }

            Ok(UpdateResp {})
        })
    }
    .await;

    match resp {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => match e {
            AuthError(_) => HttpResponse::Forbidden().body(e.to_string()),
            AppError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            DBError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            _ => HttpResponse::InternalServerError().body(""),
        },
    }
}

#[post("/delete")]
async fn delete(state: web::Data<AppState>, req: web::Json<DeleteReq>) -> impl Responder {
    use Error::*;

    let resp = async {
        let mut conn = state
            .db
            .get()
            .map_err(|_| DBError("couldn't get DB connection from pool".to_owned()))?;

        authenticate(&req.master_pw, &state.master_pw_hash)?;

        conn.transaction(|conn| {
            let nrows = diesel::delete(passwords)
                .filter(name.eq(&req.name))
                .execute(conn)
                .map_err(|e| DBError(format!("error deleting password entry: {}", e)))?;

            if nrows != 1 {
                if nrows == 0 {
                    return Err(AppError(format!("key {:?} not found", req.name)));
                } else {
                    return Err(DBError(format!(
                        "tried to delete {} rows ... rolling back transaction",
                        nrows
                    )));
                }
            }

            Ok(DeleteResp {})
        })
    }
    .await;

    match resp {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => match e {
            AuthError(_) => HttpResponse::Forbidden().body(e.to_string()),
            AppError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            DBError(_) => HttpResponse::InternalServerError().body(e.to_string()),
            _ => HttpResponse::InternalServerError().body(""),
        },
    }
}
