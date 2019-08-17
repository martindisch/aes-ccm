//! AES-CCM implementation.

use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;

use crate::error::Error;

// Number of columns (32-bit words) comprising the state
const NB: usize = 4;
// Number of 32-bit words comprising the key
const NK: usize = 4;
const AES_BLOCK_SIZE: usize = NB * NK;
// Max additional authenticated size in bytes: 2^16 - 2^8 = 65280
const CCM_AAD_MAX_BYTES: usize = 0xFF00;
// Max message size in bytes: 2^(8L) = 2^16 = 65536
const CCM_PAYLOAD_MAX_BYTES: usize = 0x10000;

/// The AES-CCM instance.
pub struct CcmMode<'a> {
    /// The AES-128 instance to use.
    pub cipher: &'a Aes128,
    /// The 13-byte nonce.
    pub nonce: [u8; 13],
    /// The MAC length in bytes.
    pub mlen: usize,
}

impl<'a> CcmMode<'a> {
    /// Creates a new `CcmMode`.
    ///
    /// Valid `mlen` values are: 4, 6, 8, 10, 12, 14, 16.
    pub fn new(
        cipher: &'a Aes128,
        nonce: [u8; 13],
        mlen: usize,
    ) -> Result<CcmMode, Error> {
        if mlen < 4 || mlen > 16 || mlen & 1 != 0 {
            return Err(Error::InvalidMacLen);
        }

        Ok(CcmMode {
            cipher,
            nonce,
            mlen,
        })
    }

    /// CCM tag generation and encryption procedure.
    ///
    /// `out` buffer must be at least (`payload.len()` + `c.mlen`) bytes long.
    /// A slice to the encrypted output within the buffer will be returned.
    ///
    /// # Arguments
    /// * `out` - Encrypted data output buffer.
    /// * `associated_data` - Associated data.
    /// * `payload` - Payload.
    /// * `c` - `CcmMode` instance.
    ///
    /// # Details
    /// The sequence b for encryption is formatted as follows:
    /// ```text
    /// b = [FLAGS | nonce | counter ], where:
    ///   FLAGS is 1 byte long
    ///   nonce is 13 bytes long
    ///   counter is 2 bytes long
    /// The byte FLAGS is composed by the following 8 bits:
    ///   0-2 bits: used to represent the value of q-1
    ///   3-7 btis: always 0's
    /// ```
    /// The sequence b for authentication is formatted as follows:
    /// ```text
    /// b = [FLAGS | nonce | length(mac length)], where:
    ///   FLAGS is 1 byte long
    ///   nonce is 13 bytes long
    ///   length(mac length) is 2 bytes long
    /// The byte FLAGS is composed by the following 8 bits:
    ///   0-2 bits: used to represent the value of q-1
    ///   3-5 bits: mac length (encoded as: (mlen-2)/2)
    ///   6: Adata (0 if alen == 0, and 1 otherwise)
    ///   7: always 0
    /// ```
    pub fn tc_ccm_generation_encryption<'b>(
        &self,
        out: &'b mut [u8],
        associated_data: &[u8],
        payload: &[u8],
    ) -> Result<&'b mut [u8], Error> {
        let olen = out.len();
        let alen = associated_data.len();
        let plen = payload.len();

        // Input sanity check
        if alen >= CCM_AAD_MAX_BYTES || plen >= CCM_PAYLOAD_MAX_BYTES {
            return Err(Error::UnsupportedSize);
        }
        if olen < plen + self.mlen {
            return Err(Error::InvalidOutSize);
        }

        let mut b = [0u8; AES_BLOCK_SIZE];
        let mut tag = [0u8; AES_BLOCK_SIZE];

        // Generating the authentication tag ----------------------------------

        // Formatting the sequence b for authentication
        b[0] = if alen > 0 { 0x40 } else { 0 }
            | ((self.mlen as u8 - 2) / 2) << 3
            | 1;
        b[1..14].copy_from_slice(&self.nonce[..13]);
        b[14] = (plen >> 8) as u8;
        b[15] = plen as u8;

        // Computing the authentication tag using cbc-mac
        tag.copy_from_slice(&b);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut tag));
        if alen > 0 {
            ccm_cbc_mac(&mut tag, associated_data, true, self.cipher);
        }
        if plen > 0 {
            ccm_cbc_mac(&mut tag, payload, false, self.cipher);
        }

        // Encryption ---------------------------------------------------------

        // Formatting the sequence b for encryption
        // q - 1 = 2 - 1 = 1
        b[0] = 1;
        b[14] = 0;
        b[15] = 0;

        // Encrypting payload using ctr mode
        ccm_ctr_mode(&mut out[..plen], payload, &mut b, self.cipher);

        // Restoring initial counter for ctr_mode (0)
        b[14] = 0;
        b[15] = 0;

        // Encrypting b and adding the tag to the output
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        for i in 0..self.mlen {
            out[plen + i] = tag[i] ^ b[i];
        }

        Ok(&mut out[..plen + self.mlen])
    }

    /// CCM decryption and tag verification procedure.
    ///
    /// `out` buffer must be at least (`payload.len()` - `c.mlen`) bytes long.
    /// A slice to the decrypted output within the buffer will be returned.
    ///
    /// # Arguments
    /// * `out` - Decrypted data output buffer.
    /// * `associated_data` - Associated data.
    /// * `payload` - Payload.
    /// * `c` - `CcmMode` instance.
    ///
    /// # Details
    /// The sequence b for encryption is formatted as follows:
    /// ```text
    /// b = [FLAGS | nonce | counter ], where:
    ///   FLAGS is 1 byte long
    ///   nonce is 13 bytes long
    ///   counter is 2 bytes long
    /// The byte FLAGS is composed by the following 8 bits:
    ///   0-2 bits: used to represent the value of q-1
    ///   3-7 btis: always 0's
    /// ```
    /// The sequence b for authentication is formatted as follows:
    /// ```text
    /// b = [FLAGS | nonce | length(mac length)], where:
    ///   FLAGS is 1 byte long
    ///   nonce is 13 bytes long
    ///   length(mac length) is 2 bytes long
    /// The byte FLAGS is composed by the following 8 bits:
    ///   0-2 bits: used to represent the value of q-1
    ///   3-5 bits: mac length (encoded as: (mlen-2)/2)
    ///   6: Adata (0 if alen == 0, and 1 otherwise)
    ///   7: always 0
    /// ```
    pub fn tc_ccm_decryption_verification<'b>(
        &self,
        out: &'b mut [u8],
        associated_data: &[u8],
        payload: &[u8],
    ) -> Result<&'b mut [u8], Error> {
        let olen = out.len();
        let alen = associated_data.len();
        let plen = payload.len();

        // Input sanity check
        if alen >= CCM_AAD_MAX_BYTES || plen >= CCM_PAYLOAD_MAX_BYTES {
            return Err(Error::UnsupportedSize);
        }
        if olen < plen - self.mlen {
            return Err(Error::InvalidOutSize);
        }

        let mut b = [0u8; AES_BLOCK_SIZE];
        let mut tag = [0u8; AES_BLOCK_SIZE];

        // Decryption ---------------------------------------------------------

        // Formatting the sequence b for decryption
        // q - 1 = 2 - 1 = 1
        b[0] = 1;
        b[1..14].copy_from_slice(&self.nonce[..13]);

        // Decrypting payload using ctr mode
        ccm_ctr_mode(
            &mut out[..plen - self.mlen],
            &payload[..plen - self.mlen],
            &mut b,
            self.cipher,
        );

        // Restoring initial counter value (0)
        b[14] = 0;
        b[15] = 0;

        // Encrypting b and restoring the tag from input
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        for i in 0..self.mlen {
            tag[i] = payload[plen - self.mlen + i] ^ b[i];
        }

        // Verifying the authentication tag -----------------------------------

        // Formatting the sequence b for authentication
        b[0] = if alen > 0 { 0x40 } else { 0 }
            | ((self.mlen as u8 - 2) / 2) << 3
            | 1;
        b[1..14].copy_from_slice(&self.nonce[..13]);
        b[14] = ((plen - self.mlen) >> 8) as u8;
        b[15] = (plen - self.mlen) as u8;

        // Computing the authentication tag using cbc-mac
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        if alen > 0 {
            ccm_cbc_mac(&mut b, associated_data, true, self.cipher);
        }
        if plen > 0 {
            ccm_cbc_mac(&mut b, &out[..plen - self.mlen], false, self.cipher);
        }

        // Comparing the received tag and the computed one
        if b[..self.mlen] != tag[..self.mlen] {
            return Err(Error::VerificationFailed);
        }

        Ok(&mut out[..plen - self.mlen])
    }
}

/// Variation of CBC-MAC mode used in CCM.
fn ccm_cbc_mac(t: &mut [u8; 16], data: &[u8], flag: bool, cipher: &Aes128) {
    let mut dlen = data.len();

    let mut i = if flag {
        t[0] ^= (dlen >> 8) as u8;
        t[1] ^= dlen as u8;
        dlen += 2;
        2
    } else {
        0
    };

    let mut data = data.iter();
    while i < dlen {
        t[i % AES_BLOCK_SIZE] ^= data.next().unwrap();
        i += 1;
        if i % AES_BLOCK_SIZE == 0 || dlen == i {
            cipher.encrypt_block(GenericArray::from_mut_slice(t));
        }
    }
}

/// Variation of CTR mode used in CCM.
///
/// The CTR mode used by CCM is slightly different than the conventional CTR
/// mode (the counter is increased before encryption, instead of after
/// encryption). Besides, it is assumed that the counter is stored in the last
/// 2 bytes of the nonce.
fn ccm_ctr_mode(out: &mut [u8], r#in: &[u8], ctr: &mut [u8], cipher: &Aes128) {
    let inlen = r#in.len();

    let mut buffer = [0u8; AES_BLOCK_SIZE];
    let mut nonce = [0u8; AES_BLOCK_SIZE];
    // Copy the counter to the nonce
    nonce.copy_from_slice(ctr);

    // Select the last 2 bytes of the nonce to be incremented
    let mut block_num = u16::from(nonce[14]) << 8 | u16::from(nonce[15]);
    for i in 0..inlen {
        if i % AES_BLOCK_SIZE == 0 {
            block_num += 1;
            nonce[14] = (block_num >> 8) as u8;
            nonce[15] = block_num as u8;
            // Encrypt the nonce into the buffer
            buffer.copy_from_slice(&nonce);
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut buffer));
        }
        // Update the output
        out[i] = buffer[i % AES_BLOCK_SIZE] ^ r#in[i];
    }

    // Update the counter
    ctr[14] = nonce[14];
    ctr[15] = nonce[15];
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CCM_MAX_CT_SIZE: usize = 50;

    // RFC 3610 test vectors --------------------------------------------------

    #[test]
    fn test_vector_1() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000003020100A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "588C979A61C663D2F066D0C2C0F9898
                06D5F6B61DAC38417E8D12CFDF926E0"
            ),
        });
    }

    #[test]
    fn test_vector_2() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000004030201A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            mac_len: 8,
            expected: &hex!(
                "72C91A36E135F8CF291CA894085C87E
                3CC15C439C9E43A3BA091D56E10400916"
            ),
        });
    }

    #[test]
    fn test_vector_3() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000005040302A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
            mac_len: 8,
            expected: &hex!(
                "51B1E5F44A197D1DA46B0F8E2D282AE87
                1E838BB64DA8596574ADAA76FBD9FB0C5"
            ),
        });
    }

    #[test]
    fn test_vector_4() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000006050403A0A1A2A3A4A5"),
            hdr: &hex!("000102030405060708090A0B"),
            data: &hex!("0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "A28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C96C861B9C9E61EF1"
            ),
        });
    }

    #[test]
    fn test_vector_5() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000007060504A0A1A2A3A4A5"),
            hdr: &hex!("000102030405060708090A0B"),
            data: &hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            mac_len: 8,
            expected: &hex!(
                "DCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E51E83F077D9C2D93"
            ),
        });
    }

    #[test]
    fn test_vector_6() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000008070605A0A1A2A3A4A5"),
            hdr: &hex!("000102030405060708090A0B"),
            data: &hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
            mac_len: 8,
            expected: &hex!(
                "6FC1B011F006568B5171A42D953D469B2570A4BD87405A0443AC91CB94"
            ),
        });
    }

    #[test]
    fn test_vector_7() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000009080706A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 10,
            expected: &hex!(
                "0135D1B2C95F41D5D1D4FEC185D166B80
                94E999DFED96C048C56602C97ACBB7490"
            ),
        });
    }

    #[test]
    fn test_vector_8() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000A090807A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            mac_len: 10,
            expected: &hex!(
                "7B75399AC0831DD2F0BBD75879A2FD8F6C
                AE6B6CD9B7DB24C17B4433F434963F34B4"
            ),
        });
    }

    #[test]
    fn test_vector_9() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000B0A0908A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
            mac_len: 10,
            expected: &hex!(
                "82531A60CC24945A4B8279181AB5C84DF21
                CE7F9B73F42E197EA9C07E56B5EB17E5F4E"
            ),
        });
    }

    #[test]
    fn test_vector_10() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000C0B0A09A0A1A2A3A4A5"),
            hdr: &hex!("000102030405060708090A0B"),
            data: &hex!("0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 10,
            expected: &hex!(
                "07342594157785152B074098330ABB141B947B566AA9406B4D999988DD"
            ),
        });
    }

    #[test]
    fn test_vector_11() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000D0C0B0AA0A1A2A3A4A5"),
            hdr: &hex!("000102030405060708090A0B"),
            data: &hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            mac_len: 10,
            expected: &hex!(
                "676BB20380B0E301E8AB79590A396DA78B834934F53AA2E9107A8B6C022C"
            ),
        });
    }

    #[test]
    fn test_vector_12() {
        test_vector(TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000E0D0C0BA0A1A2A3A4A5"),
            hdr: &hex!("000102030405060708090A0B"),
            data: &hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
            mac_len: 10,
            expected: &hex!(
                "C0FFA0D6F05BDB67F24D43A4338D2AA
                4BED7B20E43CD1AA31662E7AD65D6DB"
            ),
        });
    }

    #[test]
    fn test_vector_13() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("00412B4EA9CDBE3C9696766CFA"),
            hdr: &hex!("0BE1A88BACE018B1"),
            data: &hex!("08E8CF97D820EA258460E96AD9CF5289054D895CEAC47C"),
            mac_len: 8,
            expected: &hex!(
                "4CB97F86A2A4689A877947AB8091EF5
                386A6FFBDD080F8E78CF7CB0CDDD7B3"
            ),
        });
    }

    #[test]
    fn test_vector_14() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("0033568EF7B2633C9696766CFA"),
            hdr: &hex!("63018F76DC8A1BCB"),
            data: &hex!("9020EA6F91BDD85AFA0039BA4BAFF9BFB79C7028949CD0EC"),
            mac_len: 8,
            expected: &hex!(
                "4CCB1E7CA981BEFAA0726C55D3780612
                98C85C92814ABC33C52EE81D7D77C08A"
            ),
        });
    }

    #[test]
    fn test_vector_15() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("00103FE41336713C9696766CFA"),
            hdr: &hex!("AA6CFA36CAE86B40"),
            data: &hex!("B916E0EACC1C00D7DCEC68EC0B3BBB1A02DE8A2D1AA346132E"),
            mac_len: 8,
            expected: &hex!(
                "B1D23A2220DDC0AC900D9AA03C61FCF4A
                559A4417767089708A776796EDB723506"
            ),
        });
    }

    #[test]
    fn test_vector_16() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("00764C63B8058E3C9696766CFA"),
            hdr: &hex!("D0D0735C531E1BECF049C244"),
            data: &hex!("12DAAC5630EFA5396F770CE1A66B21F7B2101C"),
            mac_len: 8,
            expected: &hex!(
                "14D253C3967B70609B7CBB7C499160283245269A6F49975BCADEAF"
            ),
        });
    }

    #[test]
    fn test_vector_17() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("00F8B678094E3B3C9696766CFA"),
            hdr: &hex!("77B60F011C03E1525899BCAE"),
            data: &hex!("E88B6A46C78D63E52EB8C546EFB5DE6F75E9CC0D"),
            mac_len: 8,
            expected: &hex!(
                "5545FF1A085EE2EFBF52B2E04BEE1E2336C73E3F762C0C7744FE7E3C"
            ),
        });
    }

    #[test]
    fn test_vector_18() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("00D560912D3F703C9696766CFA"),
            hdr: &hex!("CD9044D2B71FDB8120EA60C0"),
            data: &hex!("6435ACBAFB11A82E2F071D7CA4A5EBD93A803BA87F"),
            mac_len: 8,
            expected: &hex!(
                "009769ECABDF48625594C59251E6035722675E04C847099E5AE0704551"
            ),
        });
    }

    #[test]
    fn test_vector_19() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("0042FFF8F1951C3C9696766CFA"),
            hdr: &hex!("D85BC7E69F944FB8"),
            data: &hex!("8A19B950BCF71A018E5E6701C91787659809D67DBEDD18"),
            mac_len: 10,
            expected: &hex!(
                "BC218DAA947427B6DB386A99AC1AEF23A
                DE0B52939CB6A637CF9BEC2408897C6BA"
            ),
        });
    }

    #[test]
    fn test_vector_20() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("00920F40E56CDC3C9696766CFA"),
            hdr: &hex!("74A0EBC9069F5B37"),
            data: &hex!("1761433C37C5A35FC1F39F406302EB907C6163BE38C98437"),
            mac_len: 10,
            expected: &hex!(
                "5810E6FD25874022E80361A478E3E9CF48
                4AB04F447EFFF6F0A477CC2FC9BF548944"
            ),
        });
    }

    #[test]
    fn test_vector_21() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("0027CA0C7120BC3C9696766CFA"),
            hdr: &hex!("44A3AA3AAE6475CA"),
            data: &hex!("A434A8E58500C6E41530538862D686EA9E81301B5AE4226BFA"),
            mac_len: 10,
            expected: &hex!(
                "F2BEED7BC5098E83FEB5B31608F8E29C388
                19A89C8E776F1544D4151A4ED3A8B87B9CE"
            ),
        });
    }

    #[test]
    fn test_vector_22() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("005B8CCBCD9AF83C9696766CFA"),
            hdr: &hex!("EC46BB63B02520C33C49FD70"),
            data: &hex!("B96B49E21D621741632875DB7F6C9243D2D7C2"),
            mac_len: 10,
            expected: &hex!(
                "31D750A09DA3ED7FDDD49A2032AABF17EC8EBF7D22C8088C666BE5C197"
            ),
        });
    }

    #[test]
    fn test_vector_23() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("003EBE94044B9A3C9696766CFA"),
            hdr: &hex!("47A65AC78B3D594227E85E71"),
            data: &hex!("E2FCFBB880442C731BF95167C8FFD7895E337076"),
            mac_len: 10,
            expected: &hex!(
                "E882F1DBD38CE3EDA7C23F04DD65071EB41342ACDF7E00DCCEC7AE52987D"
            ),
        });
    }

    #[test]
    fn test_vector_24() {
        test_vector(TestVector {
            key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
            nonce: hex!("008D493B30AE8B3C9696766CFA"),
            hdr: &hex!("6E37A6EF546D955D34AB6059"),
            data: &hex!("ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4"),
            mac_len: 10,
            expected: &hex!(
                "F32905B88A641B04B9C9FFB58CC3909
                00F3DA12AB16DCE9E82EFA16DA62059"
            ),
        });
    }

    // Assorted other tests ---------------------------------------------------

    #[test]
    fn nonce_len() {
        let key = hex!("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce = hex!("00000003020100a0a1a2a3a4a5");
        let cipher = Aes128::new(GenericArray::from_slice(&key));

        // Check that only even nonces in [4, 16] are allowed
        for i in 3..=17 {
            if i % 2 == 0 {
                assert!(CcmMode::new(&cipher, nonce, i).is_ok());
            } else {
                assert!(CcmMode::new(&cipher, nonce, i).is_err());
            }
        }
    }

    #[test]
    fn encryption_sanity() {
        // Testing for too small out buffer
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000003020100A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "588C979A61C663D2F066D0C2C0F9898
                06D5F6B61DAC38417E8D12CFDF926E0"
            ),
        };
        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();
        // Create an out buffer 1 byte smaller than it needs to be
        let mut ciphertext_buf = [0u8; 23 + 7];
        assert_eq!(
            Error::InvalidOutSize,
            ccm.tc_ccm_generation_encryption(
                &mut ciphertext_buf,
                &v.hdr,
                &v.data,
            )
            .unwrap_err()
        );

        // Testing for too large associated data
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000003020100A0A1A2A3A4A5"),
            // This is above the maximum allowed size
            hdr: &[0u8; 66000],
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "588C979A61C663D2F066D0C2C0F9898
                06D5F6B61DAC38417E8D12CFDF926E0"
            ),
        };
        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();
        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        assert_eq!(
            Error::UnsupportedSize,
            ccm.tc_ccm_generation_encryption(
                &mut ciphertext_buf,
                &v.hdr,
                &v.data,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn decryption_sanity() {
        // Testing for too small out buffer
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000003020100A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "588C979A61C663D2F066D0C2C0F9898
                06D5F6B61DAC38417E8D12CFDF926E0"
            ),
        };
        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();
        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let ciphertext = ccm
            .tc_ccm_generation_encryption(&mut ciphertext_buf, &v.hdr, &v.data)
            .unwrap();
        // This is 1 byte smaller than it needs to be
        let mut plaintext_buf = [0u8; 22];
        assert_eq!(
            Error::InvalidOutSize,
            ccm.tc_ccm_decryption_verification(
                &mut plaintext_buf,
                &v.hdr,
                &ciphertext,
            )
            .unwrap_err()
        );

        // Testing for too large associated data
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000003020100A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "588C979A61C663D2F066D0C2C0F9898
                06D5F6B61DAC38417E8D12CFDF926E0"
            ),
        };
        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();
        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let ciphertext = ccm
            .tc_ccm_generation_encryption(&mut ciphertext_buf, &v.hdr, &v.data)
            .unwrap();
        let mut plaintext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        assert_eq!(
            Error::UnsupportedSize,
            ccm.tc_ccm_decryption_verification(
                &mut plaintext_buf,
                // This is above the maximum allowed size
                &[0u8; 66000],
                &ciphertext,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn verification_fail() {
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("00000003020100A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
            mac_len: 8,
            expected: &hex!(
                "588C979A61C663D2F066D0C2C0F9898
                06D5F6B61DAC38417E8D12CFDF926E0"
            ),
        };

        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();
        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let ciphertext = ccm
            .tc_ccm_generation_encryption(&mut ciphertext_buf, &v.hdr, &v.data)
            .unwrap();

        let mut plaintext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        assert_eq!(
            Error::VerificationFailed,
            ccm.tc_ccm_decryption_verification(
                &mut plaintext_buf,
                // This associated data has been tampered with
                &hex!("0001020304050608"),
                &ciphertext,
            )
            .unwrap_err()
        );
        // Tamper with the ciphertext
        ciphertext[10] = 0xFF;
        assert_eq!(
            Error::VerificationFailed,
            ccm.tc_ccm_decryption_verification(
                &mut plaintext_buf,
                &v.hdr,
                &ciphertext,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn no_ad() {
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000B0A0908A0A1A2A3A4A5"),
            // No associated data
            hdr: &[],
            data: &hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
            mac_len: 10,
            // Not used
            expected: &[],
        };

        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();
        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let ciphertext = ccm
            .tc_ccm_generation_encryption(&mut ciphertext_buf, &v.hdr, &v.data)
            .unwrap();

        let mut plaintext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let plaintext = ccm
            .tc_ccm_decryption_verification(
                &mut plaintext_buf,
                &v.hdr,
                &ciphertext,
            )
            .unwrap();
        assert_eq!(&v.data[..], plaintext);
    }

    #[test]
    fn no_payload() {
        let v = TestVector {
            key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
            nonce: hex!("0000000B0A0908A0A1A2A3A4A5"),
            hdr: &hex!("0001020304050607"),
            data: &[],
            mac_len: 10,
            // Not used
            expected: &[],
        };

        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();

        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let ciphertext = ccm
            .tc_ccm_generation_encryption(&mut ciphertext_buf, &v.hdr, &v.data)
            .unwrap();

        let mut plaintext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let plaintext = ccm
            .tc_ccm_decryption_verification(
                &mut plaintext_buf,
                &v.hdr,
                &ciphertext,
            )
            .unwrap();
        assert_eq!(&v.data[..], plaintext);
    }

    // Test implementation ----------------------------------------------------

    struct TestVector<'a> {
        key: [u8; 16],
        nonce: [u8; 13],
        hdr: &'a [u8],
        data: &'a [u8],
        mac_len: usize,
        expected: &'a [u8],
    }

    fn test_vector(v: TestVector) {
        let cipher = Aes128::new(GenericArray::from_slice(&v.key));
        let ccm = CcmMode::new(&cipher, v.nonce, v.mac_len).unwrap();

        let mut ciphertext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let ciphertext = ccm
            .tc_ccm_generation_encryption(&mut ciphertext_buf, &v.hdr, &v.data)
            .unwrap();
        assert_eq!(&v.expected[..], ciphertext);

        let mut plaintext_buf = [0u8; TEST_CCM_MAX_CT_SIZE];
        let plaintext = ccm
            .tc_ccm_decryption_verification(
                &mut plaintext_buf,
                &v.hdr,
                &ciphertext,
            )
            .unwrap();
        assert_eq!(&v.data[..], plaintext);
    }
}
