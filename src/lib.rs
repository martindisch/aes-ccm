#![feature(libc)]
extern crate libc;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;
extern crate aes_soft as aes;

mod ccm;

#[cfg(test)]
mod tests {
    use super::*;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::Aes128;

    const TC_CCM_MAX_CT_SIZE: usize = 50;

    /// CCM test #1 (RFC 3610 test vector #1)
    #[test]
    fn test_vector_1() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: hex!("00000003020100a0a1a2a3a4a5"),
            mlen: 8,
        };

        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data = hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let hdr = hex!("0001020304050607");
        unsafe {
            ccm::tc_ccm_generation_encryption(
                ciphertext.as_mut_ptr(),
                TC_CCM_MAX_CT_SIZE as u32,
                hdr.as_ptr(),
                hdr.len() as u32,
                data.as_ptr(),
                data.len() as u32,
                &ccm,
            );
        }

        let expected = hex!(
            "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"
        );
        assert_eq!(expected[..], ciphertext[..expected.len()]);
    }

    #[test]
    fn test_vector_2() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: hex!("00000004030201a0a1a2a3a4a5"),
            mlen: 8,
        };

        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data = hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let hdr = hex!("0001020304050607");
        unsafe {
            ccm::tc_ccm_generation_encryption(
                ciphertext.as_mut_ptr(),
                TC_CCM_MAX_CT_SIZE as u32,
                hdr.as_ptr(),
                hdr.len() as u32,
                data.as_ptr(),
                data.len() as u32,
                &ccm,
            );
        }

        let expected = hex!(
            "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916"
        );
        assert_eq!(expected[..], ciphertext[..expected.len()]);
    }

    #[test]
    fn test_vector_3() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: hex!("00000005040302a0a1a2a3a4a5"),
            mlen: 8,
        };

        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data = hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let hdr = hex!("0001020304050607");
        unsafe {
            ccm::tc_ccm_generation_encryption(
                ciphertext.as_mut_ptr(),
                TC_CCM_MAX_CT_SIZE as u32,
                hdr.as_ptr(),
                hdr.len() as u32,
                data.as_ptr(),
                data.len() as u32,
                &ccm,
            );
        }

        let expected = hex!(
            "51b1e5f44a197d1da46b0f8e2d282ae87
            1e838bb64da8596574adaa76fbd9fb0c5"
        );
        assert_eq!(expected[..], ciphertext[..expected.len()]);
    }

    #[test]
    fn test_vector_4() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: hex!("00000009080706a0a1a2a3a4a5"),
            mlen: 10,
        };

        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data = hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let hdr = hex!("0001020304050607");
        unsafe {
            ccm::tc_ccm_generation_encryption(
                ciphertext.as_mut_ptr(),
                TC_CCM_MAX_CT_SIZE as u32,
                hdr.as_ptr(),
                hdr.len() as u32,
                data.as_ptr(),
                data.len() as u32,
                &ccm,
            );
        }

        let expected = hex!(
            "0135d1b2c95f41d5d1d4fec185d166b80
            94e999dfed96c048c56602c97acbb7490"
        );
        assert_eq!(expected[..], ciphertext[..expected.len()]);
    }

    #[test]
    fn test_vector_5() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: hex!("0000000a090807a0a1a2a3a4a5"),
            mlen: 10,
        };

        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data = hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let hdr = hex!("0001020304050607");
        unsafe {
            ccm::tc_ccm_generation_encryption(
                ciphertext.as_mut_ptr(),
                TC_CCM_MAX_CT_SIZE as u32,
                hdr.as_ptr(),
                hdr.len() as u32,
                data.as_ptr(),
                data.len() as u32,
                &ccm,
            );
        }

        let expected = hex!(
            "7b75399ac0831dd2f0bbd75879a2fd8f6c
            ae6b6cd9b7db24c17b4433f434963f34b4"
        );
        assert_eq!(expected[..], ciphertext[..expected.len()]);
    }

    #[test]
    fn test_vector_6() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let mut cipher = Aes128::new(GenericArray::from_slice(&key));
        let ccm = ccm::CcmMode {
            cipher: &mut cipher,
            nonce: hex!("0000000b0a0908a0a1a2a3a4a5"),
            mlen: 10,
        };

        let mut ciphertext = [0u8; TC_CCM_MAX_CT_SIZE];
        let data = hex!("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let hdr = hex!("0001020304050607");
        unsafe {
            ccm::tc_ccm_generation_encryption(
                ciphertext.as_mut_ptr(),
                TC_CCM_MAX_CT_SIZE as u32,
                hdr.as_ptr(),
                hdr.len() as u32,
                data.as_ptr(),
                data.len() as u32,
                &ccm,
            );
        }

        let expected = hex!(
            "82531a60CC24945a4b8279181ab5c84df21
            ce7f9b73f42e197ea9c07e56b5eb17e5f4e"
        );
        assert_eq!(expected[..], ciphertext[..expected.len()]);
    }
}
