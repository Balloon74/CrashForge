use std::fmt::{Display, Formatter};
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CrashForgeError {
    Io(io::Error),
    Json(serde_json::Error),
    Message(String),
    Collision(PathBuf),
}

impl Display for CrashForgeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Message(message) => formatter.write_str(message),
            Self::Collision(path) => {
                write!(formatter, "crash case already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for CrashForgeError {}

impl From<io::Error> for CrashForgeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CrashForgeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub type Result<T> = std::result::Result<T, CrashForgeError>;

pub fn message(message: impl Into<String>) -> CrashForgeError {
    CrashForgeError::Message(message.into())
}
