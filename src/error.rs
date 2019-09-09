//! AES-CCM errors.

use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// The error type for AES-CCM.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Bad MAC length. Allowed sizes are: 4, 6, 8, 10, 12, 14, 16.
    ///
    /// Occurs only in `CcmMode::new()`.
    InvalidMacLen,
    /// Input (associated data or payload) is larger than allowed.
    ///
    /// Occurs in `CcmMode::generate_encrypt()` and
    /// `CcmMode::decrypt_verify()`.
    UnsupportedSize,
    /// Output buffer is too small.
    ///
    /// Occurs in `CcmMode::generate_encrypt()` and
    /// `CcmMode::decrypt_verify()`.
    InvalidOutSize,
    /// Received and computed tag don't match.
    ///
    /// Occurs only in `CcmMode::decrypt_verify()`.
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

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
