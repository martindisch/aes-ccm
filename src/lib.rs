#![feature(libc)]
extern crate libc;

extern crate aes_soft as aes;

mod ccm;

#[cfg(test)]
mod tests {
    use super::*;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::Aes128;

    /// CCM test #1 (RFC 3610 test vector #1)
    #[test]
    fn test_vector_1() {
        let key: [u8; 16] = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
            0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
        ];
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: [
                0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0,
                0xa1, 0xa2, 0xa3, 0xa4, 0xa5
            ],
            mlen: 8,
        };

        const TC_CCM_MAX_CT_SIZE: usize = 50;
        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data: [u8; 23] = [
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
        ];
        let hdr: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        unsafe {
            ccm::tc_ccm_generation_encryption(ciphertext.as_mut_ptr(),
                                        TC_CCM_MAX_CT_SIZE as u32,
                                        hdr.as_ptr(),
                                        hdr.len() as u32,
                                        data.as_ptr(),
                                        data.len() as u32,
                                        ccm);
        }

        let expected: [u8; 31] = [
            0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
            0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
            0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84, 0x17,
            0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
        ];
        assert_eq!(expected, ciphertext[..expected.len()]);
    }
}