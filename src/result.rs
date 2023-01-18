use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    ConfigError(String),
    ServerSetupError(String),
    AuthError(String),
    DBError(String),
    AppError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "{:?}", self);
    }
}

impl std::error::Error for Error {}

impl From<diesel::result::Error> for Error {
    fn from(value: diesel::result::Error) -> Self {
        Error::DBError(value.to_string())
    }
}
