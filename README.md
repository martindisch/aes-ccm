# [WIP] aes-ccm
<!-- cargo-sync-readme start -->

A pure-Rust, `#![no_std]`, zero-allocation AES-CCM implementation ported
from [TinyCrypt] using [RustCrypto's AES].

## Overview
CCM (for "Counter with CBC-MAC") mode is a NIST approved mode of operation
defined in [SP 800-38C].

This implementation accepts:
1. Both non-empty payload and associated data (it encrypts and
   authenticates the payload and also authenticates the associated data).
2. Non-empty payload and empty associated data (it encrypts and
   authenticates the payload).
3. Non-empty associated data and empty payload (it degenerates to an
   authentication mode on the associated data).

The implementation accepts associated data of any length between 0 and
(2^16 - 2^8) bytes.

## Usage
```rust
use aes_ccm::CcmMode;

let key = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
    0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
];
let nonce = [
    0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3,
    0xA4, 0xA5,
];
let ccm = CcmMode::new(&key, nonce, 8).unwrap();

let mut ciphertext_buf = [0u8; 50];
let payload = [
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
    0x1E,
];
let associated_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
let ciphertext = ccm
    .generate_encrypt(&mut ciphertext_buf, &associated_data, &payload)
    .unwrap();

let mut plaintext_buf = [0u8; 50];
let plaintext = ccm
    .decrypt_verify(&mut plaintext_buf, &associated_data, &ciphertext)
    .unwrap();
assert_eq!(&payload, plaintext);
```

## Security
I'm not a cryptographer and this hasn't been audited in any way.
It is however a careful port of [TinyCrypt], so if it's sound, then this
*should* be too.

The MAC length parameter is an important parameter to estimate the security
against collision attacks (that aim at finding different messages that
produce the same authentication tag).
The implementation accepts any even integer between 4 and 16, as suggested
in [SP 800-38C].

[RFC 3610], which also specifies CCM, presents a few relevant security
suggestions, such as:
* It is recommended that most applications use a MAC length greater than 8.
* The usage of the same nonce for two different messages which are
  encrypted with the same key destroys the security of CCM mode.

[TinyCrypt]: https://github.com/intel/tinycrypt
[RustCrypto's AES]: https://github.com/RustCrypto/block-ciphers
[SP 800-38C]: https://csrc.nist.gov/publications/detail/sp/800-38c/final
[RFC 3610]: https://tools.ietf.org/html/rfc3610

<!-- cargo-sync-readme end -->

## License
Licensed under either of

 * [Apache License, Version 2.0](LICENSE-APACHE)
 * [MIT license](LICENSE-MIT)

at your option.

This is a port of TinyCrypt's CCM mode, its license file is in
[LICENSE-3RD-PARTY](LICENSE-3RD-PARTY).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
