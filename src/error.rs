//! AES-CCM errors.

use core::fmt;

/// The error type for AES-CCM.
#[derive(Debug)]
pub enum Error {
    /// Wrong MAC length.
    InvalidMacLen,
    /// Out buffer and in buffer are of unequal length.
    DifferentLengthBuf,
    /// A buffer is empty.
    EmptyBuf,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidMacLen => write!(
                f,
                "Bad MAC length. Allowed sizes are: 4, 6, 8, 10, 12, 14, 16"
            ),
            Error::DifferentLengthBuf => {
                write!(f, "Out buffer and in buffer are different lengths")
            }
            Error::EmptyBuf => write!(f, "A buffer is empty"),
        }
    }
}
