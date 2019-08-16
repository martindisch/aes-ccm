#![no_std]

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

mod ccm;
mod error;

pub use ccm::CcmMode;
pub use error::Error;
