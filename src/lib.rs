//! A pure-Rust, `#![no_std]`, zero-allocation AES-CCM implementation ported
//! from [TinyCrypt] using [RustCrypto's AES].
//! It implements the [`Aead`] trait, so it can be used effortlessly together
//! with other implementations.
//!
//! ## Overview
//! CCM (for "Counter with CBC-MAC") mode is a NIST approved mode of operation
//! defined in [SP 800-38C].
//!
//! This implementation accepts:
//! 1. Both non-empty payload and associated data (it encrypts and
//!    authenticates the payload and also authenticates the associated data).
//! 2. Non-empty payload and empty associated data (it encrypts and
//!    authenticates the payload).
//! 3. Non-empty associated data and empty payload (it degenerates to an
//!    authentication mode on the associated data).
//!
//! The implementation accepts payloads of any length between 0 and 2^16 bytes
//! and associated data of any length between 0 and (2^16 - 2^8) bytes.
//!
//! ## Usage
//! ```rust
//! use aes_ccm::{
//!     aead::{generic_array::typenum::U8, Aead, NewAead, Payload},
//!     CcmMode,
//! };
//!
//! let key = [
//!     0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
//!     0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
//! ];
//!
//! // `U8` represents the tag size as a `typenum` unsigned (8-bytes here)
//! let ccm = CcmMode::<U8>::new(key.into());
//!
//! let nonce = [
//!     0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3,
//!     0xA4, 0xA5,
//! ];
//! let msg = [
//!     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
//!     0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
//!     0x1E,
//! ];
//! let associated_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
//!
//! let ciphertext = ccm
//!     .encrypt(
//!         &nonce.into(),
//!         Payload {
//!             aad: &associated_data,
//!             msg: &msg,
//!         },
//!     )
//!     .unwrap();
//!
//! let plaintext = ccm
//!     .decrypt(
//!         &nonce.into(),
//!         Payload {
//!             aad: &associated_data,
//!             msg: &ciphertext,
//!         },
//!     )
//!     .unwrap();
//!
//! assert_eq!(&msg[..], plaintext.as_slice());
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`Aead::encrypt_in_place`] and [`Aead::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of `aead::Buffer` for [`heapless::Vec`]
//! (re-exported from the `aead` crate as `aead::heapless::Vec`),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```rust
//! use aes_ccm::{
//!     aead::{
//!         generic_array::typenum::{U128, U8},
//!         heapless::Vec,
//!         Aead, NewAead,
//!     },
//!     CcmMode,
//! };
//!
//! let key = [
//!     0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
//!     0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
//! ];
//!
//! // `U8` represents the tag size as a `typenum` unsigned (8-bytes here)
//! let ccm = CcmMode::<U8>::new(key.into());
//!
//! let nonce = [
//!     0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3,
//!     0xA4, 0xA5,
//! ];
//! let associated_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
//! let plaintext = [
//!     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
//!     0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
//!     0x1E,
//! ];
//!
//! let mut buffer: Vec<u8, U128> = Vec::new();
//! buffer.extend_from_slice(&plaintext).unwrap();
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with
//! // ciphertext
//! ccm.encrypt_in_place(&nonce.into(), &associated_data, &mut buffer)
//!     .unwrap();
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, &plaintext);
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext contents with the
//! // original plaintext
//! ccm.decrypt_in_place(&nonce.into(), &associated_data, &mut buffer)
//!     .unwrap();
//! assert_eq!(&buffer, &plaintext);
//! ```
//!
//! ## Security
//! I'm not a cryptographer and this hasn't been audited in any way.
//! It is however a careful port of [TinyCrypt], so if it's sound, then this
//! *should* be too.
//!
//! The MAC length parameter is an important parameter to estimate the security
//! against collision attacks (that aim at finding different messages that
//! produce the same authentication tag).
//! The implementation accepts any even integer between 4 and 16, as suggested
//! in [SP 800-38C].
//!
//! [RFC 3610], which also specifies CCM, presents a few relevant security
//! suggestions, such as:
//! * It is recommended that most applications use a MAC length greater than 8.
//! * The usage of the same nonce for two different messages which are
//!   encrypted with the same key destroys the security of CCM mode.
//!
//! [TinyCrypt]: https://github.com/intel/tinycrypt
//! [RustCrypto's AES]: https://github.com/RustCrypto/block-ciphers
//! [`Aead`]: https://docs.rs/aead/latest/aead/trait.Aead.html
//! [SP 800-38C]: https://csrc.nist.gov/publications/detail/sp/800-38c/final
//! [RFC 3610]: https://tools.ietf.org/html/rfc3610
//! [`Aead::encrypt_in_place`]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.encrypt_in_place
//! [`Aead::decrypt_in_place`]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.decrypt_in_place
//! [`aead::Buffer`]: https://docs.rs/aead/latest/aead/trait.Buffer.html
//! [`heapless::Vec`]: https://docs.rs/heapless/latest/heapless/struct.Vec.html

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

mod ccm;

pub use aead::{self, Error};
pub use ccm::{CcmMode, CcmTagSize};
