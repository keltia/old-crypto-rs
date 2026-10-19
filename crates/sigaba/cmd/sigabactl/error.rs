//! Errors specific to the sigabactl command-line frontend.

use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ConfigFileError(pub String);

#[derive(Debug, Error)]
#[error("{0}")]
pub struct RotorFileError(pub String);
