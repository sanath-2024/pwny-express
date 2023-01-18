mod auth;
mod crypto;
mod result;
mod schema;
mod service;

use actix_web::{App, HttpServer};
use diesel::{prelude::*, r2d2};
use dotenvy::dotenv;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use result::{Error, Result};
pub type ConnPool = r2d2::Pool<r2d2::ConnectionManager<SqliteConnection>>;
pub type Conn = r2d2::PooledConnection<r2d2::ConnectionManager<SqliteConnection>>;

#[actix_web::main]
async fn main() -> Result<()> {
    use Error::*;

    println!("reading environment variables ...");

    dotenv().map_err(|e| ConfigError(format!("dotenv failed: {}", e)))?;
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| ConfigError("DATABASE_URL must be set".to_owned()))?;
    let bind_addr =
        std::env::var("BIND_ADDR").map_err(|_| ConfigError("BIND_ADDR must be set".to_owned()))?;
    let ssl_private_key_file = std::env::var("SSL_PRIVATE_KEY_FILE")
        .map_err(|_| ConfigError("SSL_PRIVATE_KEY_FILE must be set".to_owned()))?;
    let ssl_certificate_chain_file = std::env::var("SSL_CERTIFICATE_CHAIN_FILE")
        .map_err(|_| ConfigError("SSL_CERTIFICATE_CHAIN_FILE must be set".to_owned()))?;
    let master_pw_hash = std::env::var("MASTER_PW_HASH")
        .map_err(|_| ConfigError("MASTER_PW_HASH must be set".to_owned()))?;

    println!("setting up SSL ...");

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| ServerSetupError(format!("failed to set up SSL for server: {}", e)))?;
    builder
        .set_private_key_file(ssl_private_key_file, SslFiletype::PEM)
        .map_err(|e| ServerSetupError(format!("failed to set up SSL for server: {}", e)))?;
    builder
        .set_certificate_chain_file(ssl_certificate_chain_file)
        .map_err(|e| ServerSetupError(format!("failed to set up SSL for server: {}", e)))?;

    println!("connecting to database ...");

    // set up DB connection pool
    let conn_manager = r2d2::ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(conn_manager)
        .map_err(|e| DBError(format!("failed to build connection pool: {}", e)))?;

    let state = service::AppState {
        db: pool,
        master_pw_hash,
    };

    println!("spinning up server ...");

    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(state.clone()))
            .service(service::list)
            .service(service::create)
            .service(service::get)
            .service(service::update)
            .service(service::delete)
            .service(actix_files::Files::new("/", "static").index_file("index.html"))
    })
    .bind_openssl(&bind_addr, builder)
    .map_err(|_| ServerSetupError(format!("failed to bind server to address {}", bind_addr)))?
    .run()
    .await
    .map_err(|e| AppError(format!("web server failed: {}", e)))?;

    Ok(())
}
