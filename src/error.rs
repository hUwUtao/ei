use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // #[error("Invalid protocol: {0}")]
    // InvalidProtocol(String),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    // #[error("Configuration error: {0}")]
    // Config(String),
}

pub type Result<T> = std::result::Result<T, Error>; 