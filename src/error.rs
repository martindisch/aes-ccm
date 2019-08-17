//! AES-CCM errors.

use core::fmt;

/// The error type for AES-CCM.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Bad MAC length. Allowed sizes are: 4, 6, 8, 10, 12, 14, 16.
    InvalidMacLen,
    /// Input (associated data or payload) is larger than allowed.
    UnsupportedSize,
    /// Output buffer is too small.
    InvalidOutSize,
    /// Received and computed tag don't match.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidMacLen => write!(
                f,
                "Bad MAC length. Allowed sizes are: 4, 6, 8, 10, 12, 14, 16"
            ),
            Error::UnsupportedSize => write!(
                f,
                "Input (associated data or payload) is larger than allowed"
            ),
            Error::InvalidOutSize => write!(f, "Output buffer is too small"),
            Error::VerificationFailed => {
                write!(f, "Received and computed tag don't match")
            }
        }
    }
}
