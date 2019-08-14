//! AES-CCM errors.

use core::fmt;

/// The error type for AES-CCM.
#[derive(Debug)]
pub enum Error {
    /// Wrong MAC length.
    InvalidMacLen,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidMacLen => write!(
                f,
                "Bad MAC length. Allowed sizes are: 4, 6, 8, 10, 12, 14, 16"
            ),
        }
    }
}
