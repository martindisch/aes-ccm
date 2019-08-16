//! AES-CCM errors.

use core::fmt;

/// The error type for AES-CCM.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Wrong MAC length.
    InvalidMacLen,
    /// Unsupported size (too large)
    UnsupportedSize,
    /// Output buffer too small
    InvalidOutSize,
    /// Received and computed tag don't match
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidMacLen => write!(
                f,
                "Bad MAC length. Allowed sizes are: 4, 6, 8, 10, 12, 14, 16"
            ),
            Error::UnsupportedSize => {
                write!(f, "AD or payload size unsupported")
            }
            Error::InvalidOutSize => write!(f, "Invalid output buffer size"),
            Error::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}
