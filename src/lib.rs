#![no_std]

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

mod ccm;
#[cfg_attr(tarpaulin, skip)]
mod error;

pub use ccm::CcmMode;
pub use error::Error;
