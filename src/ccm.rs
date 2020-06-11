//! AES-CCM implementation.

use aead::consts::{U0, U10, U12, U13, U14, U16, U4, U6, U8};
use aead::generic_array::{ArrayLength, GenericArray};
use aead::{AeadInPlace, Error, Key, NewAead, Nonce, Tag};

use block_cipher::{Block, BlockCipher, NewBlockCipher};

use core::marker::PhantomData;

// Number of columns (32-bit words) comprising the state
const NB: usize = 4;
// Number of 32-bit words comprising the key
const NK: usize = 4;
const AES_BLOCK_SIZE: usize = NB * NK;
// Max additional authenticated size in bytes: 2^16 - 2^8 = 65280
const CCM_AAD_MAX_BYTES: usize = 0xFF00;
// Max message size in bytes: 2^(8L) = 2^16 = 65536
const CCM_PAYLOAD_MAX_BYTES: usize = 0x10000;

/// Marker trait for valid AES-CCM MAC tag sizes.
pub trait CcmTagSize: ArrayLength<u8> {}

impl CcmTagSize for U4 {}
impl CcmTagSize for U6 {}
impl CcmTagSize for U8 {}
impl CcmTagSize for U10 {}
impl CcmTagSize for U12 {}
impl CcmTagSize for U14 {}
impl CcmTagSize for U16 {}

/// AES-CCM with a 128-bit key.
///
/// In terms of [COSE](https://tools.ietf.org/html/rfc8152#section-10.2), it
/// implements AES-CCM-16-x-128, with x being the `TagSize` in bits. That is,
/// `Aes128Ccm<U8>` implements AES-CCM-16-64-128, and `Aes128Ccm<U16>`
/// implements AES-CCM-16-128-128.
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes128Ccm<TagSize> = AesCcm<aes::Aes128, TagSize>;

/// AES-CCM with a 256-bit key.
///
/// In terms of [COSE](https://tools.ietf.org/html/rfc8152#section-10.2), it
/// implements AES-CCM-16-x-256, with x being the `TagSize` in bits. That is,
/// `Aes256Ccm<U8>` implements AES-CCM-16-64-256, and `Aes256Ccm<U16>`
/// implements AES-CCM-16-128-256.
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes256Ccm<TagSize> = AesCcm<aes::Aes256, TagSize>;

/// The AES-CCM instance.
///
/// This is currently fixed to 13-byte nonces (and thus limited to 64KiB
/// messages), and generic over a block cipher type (i.e. for different key
/// sizes or potentially providing a hardware AES implementation) as well
/// as tag sizes.
pub struct AesCcm<Aes, TagSize>
where
    Aes: BlockCipher<BlockSize = U16>,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    TagSize: CcmTagSize,
{
    /// The AES block cipher instance to use.
    cipher: Aes,

    /// Tag size.
    tag_size: PhantomData<TagSize>,
}

impl<Aes, TagSize> NewAead for AesCcm<Aes, TagSize>
where
    Aes: BlockCipher<BlockSize = U16> + NewBlockCipher,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    TagSize: CcmTagSize,
{
    type KeySize = Aes::KeySize;

    /// Creates a new `AesCcm`.
    fn new(key: &Key<Self>) -> Self {
        AesCcm {
            cipher: Aes::new(key),
            tag_size: PhantomData,
        }
    }
}

impl<Aes, TagSize> AeadInPlace for AesCcm<Aes, TagSize>
where
    Aes: BlockCipher<BlockSize = U16>,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    TagSize: CcmTagSize,
{
    type NonceSize = U13;
    type TagSize = TagSize;
    type CiphertextOverhead = U0;

    /// In-place CCM encryption and generation of detached authentication tag.
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<U13>,
        associated_data: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        let alen = associated_data.len();
        let plen = payload.len();
        let tlen = TagSize::to_usize();

        // Input sanity check
        if alen >= CCM_AAD_MAX_BYTES || plen >= CCM_PAYLOAD_MAX_BYTES {
            return Err(Error);
        }

        // The sequence b for encryption is formatted as follows:
        // b = [FLAGS | nonce | counter ], where:
        //   FLAGS is 1 byte long
        //   nonce is 13 bytes long
        //   counter is 2 bytes long
        // The byte FLAGS is composed by the following 8 bits:
        //   0-2 bits: used to represent the value of q-1
        //   3-7 bits: always 0's
        let mut b = [0u8; AES_BLOCK_SIZE];
        let mut tag = [0u8; AES_BLOCK_SIZE];

        // Generating the authentication tag ----------------------------------

        // Formatting the sequence b for authentication
        b[0] =
            if alen > 0 { 0x40 } else { 0 } | ((tlen as u8 - 2) / 2) << 3 | 1;
        b[1..14].copy_from_slice(&nonce[..13]);
        b[14] = (plen >> 8) as u8;
        b[15] = plen as u8;

        // Computing the authentication tag using CBC-MAC
        tag.copy_from_slice(&b);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut tag));
        if alen > 0 {
            ccm_cbc_mac(&mut tag, associated_data, true, &self.cipher);
        }
        if plen > 0 {
            ccm_cbc_mac(&mut tag, payload, false, &self.cipher);
        }

        // Encryption ---------------------------------------------------------

        // Formatting the sequence b for encryption
        // q - 1 = 2 - 1 = 1
        b[0] = 1;
        b[14] = 0;
        b[15] = 0;

        // Encrypting payload using ctr mode
        ccm_ctr_mode(payload, &mut b, &self.cipher);

        // Restoring initial counter for ctr_mode (0)
        b[14] = 0;
        b[15] = 0;

        // Encrypting b and generating the tag
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        let mut t = GenericArray::default();
        for i in 0..TagSize::to_usize() {
            t[i] = tag[i] ^ b[i];
        }

        Ok(t)
    }

    /// In-place CCM decryption and verification of detached authentication
    /// tag.
    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        payload: &mut [u8],
        tag: &GenericArray<u8, TagSize>,
    ) -> Result<(), Error> {
        let alen = associated_data.len();
        let plen = payload.len();
        let tlen = TagSize::to_usize();

        // Input sanity check
        if alen >= CCM_AAD_MAX_BYTES || plen >= CCM_PAYLOAD_MAX_BYTES {
            return Err(Error);
        }

        // The sequence b for authentication is formatted as follows:
        // b = [FLAGS | nonce | length(MAC length)], where:
        //   FLAGS is 1 byte long
        //   nonce is 13 bytes long
        //   length(MAC length) is 2 bytes long
        // The byte FLAGS is composed by the following 8 bits:
        //   0-2 bits: used to represent the value of q-1
        //   3-5 bits: MAC length (encoded as: (mlen-2)/2)
        //   6: Adata (0 if alen == 0, and 1 otherwise)
        //   7: always 0
        let mut b = [0u8; AES_BLOCK_SIZE];
        let mut t = [0u8; AES_BLOCK_SIZE];

        // Decryption ---------------------------------------------------------

        // Formatting the sequence b for decryption
        // q - 1 = 2 - 1 = 1
        b[0] = 1;
        b[1..14].copy_from_slice(&nonce[..13]);

        // Decrypting payload using ctr mode
        ccm_ctr_mode(payload, &mut b, &self.cipher);

        // Restoring initial counter value (0)
        b[14] = 0;
        b[15] = 0;

        // Encrypting b and restoring the tag from input
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        for i in 0..tlen {
            t[i] = tag[i] ^ b[i];
        }

        // Verifying the authentication tag -----------------------------------

        // Formatting the sequence b for authentication
        b[0] =
            if alen > 0 { 0x40 } else { 0 } | ((tlen as u8 - 2) / 2) << 3 | 1;
        b[1..14].copy_from_slice(&nonce[..13]);
        b[14] = (plen >> 8) as u8;
        b[15] = plen as u8;

        // Computing the authentication tag using CBC-MAC
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        if alen > 0 {
            ccm_cbc_mac(&mut b, associated_data, true, &self.cipher);
        }
        if plen > 0 {
            ccm_cbc_mac(&mut b, payload, false, &self.cipher);
        }

        // Comparing the received tag and the computed one
        use subtle::ConstantTimeEq;
        if b[..tlen].ct_eq(&t[..tlen]).unwrap_u8() == 0 {
            // Erase the decrypted buffer
            payload.iter_mut().for_each(|e| *e = 0);
            return Err(Error);
        }

        Ok(())
    }
}

/// Variation of CBC-MAC mode used in CCM.
fn ccm_cbc_mac<Aes>(t: &mut [u8; 16], data: &[u8], flag: bool, cipher: &Aes)
where
    Aes: BlockCipher<BlockSize = U16>,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
{
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
fn ccm_ctr_mode<Aes>(payload: &mut [u8], ctr: &mut [u8], cipher: &Aes)
where
    Aes: BlockCipher<BlockSize = U16>,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
{
    let plen = payload.len();

    let mut buffer = [0u8; AES_BLOCK_SIZE];
    let mut nonce = [0u8; AES_BLOCK_SIZE];
    // Copy the counter to the nonce
    nonce.copy_from_slice(ctr);

    // Select the last 2 bytes of the nonce to be incremented
    let mut block_num = u16::from(nonce[14]) << 8 | u16::from(nonce[15]);
    for i in 0..plen {
        if i % AES_BLOCK_SIZE == 0 {
            block_num += 1;
            nonce[14] = (block_num >> 8) as u8;
            nonce[15] = block_num as u8;
            // Encrypt the nonce into the buffer
            buffer.copy_from_slice(&nonce);
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut buffer));
        }
        // Update the output
        payload[i] ^= buffer[i % AES_BLOCK_SIZE];
    }

    // Update the counter
    ctr[14] = nonce[14];
    ctr[15] = nonce[15];
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use aead::Aead;
    use hex_literal::hex;

    use super::*;

    // RFC 3610 test vectors --------------------------------------------------

    #[test]
    fn test_vector_1() {
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U8>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
        test_vector::<U10>(TestVector {
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
    #[cfg(all(feature = "aes", feature = "alloc"))]
    fn encryption_sanity() {
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

        let ccm: Aes128Ccm<U8> = Aes128Ccm::new(&v.key.into());
        assert!(ccm
            .encrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &v.data
                }
            )
            .is_err());
    }

    #[test]
    #[cfg(all(feature = "aes", feature = "alloc"))]
    fn decryption_sanity() {
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

        let ccm: Aes128Ccm<U8> = Aes128Ccm::new(&v.key.into());
        let ciphertext = ccm
            .encrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &v.data,
                },
            )
            .unwrap();

        assert!(ccm
            .decrypt(
                &v.nonce.into(),
                aead::Payload {
                    // This is above the maximum allowed size
                    aad: &[0u8; 66000],
                    msg: &ciphertext,
                }
            )
            .is_err());
    }

    #[test]
    #[cfg(all(feature = "aes", feature = "alloc"))]
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

        let ccm: Aes128Ccm<U8> = Aes128Ccm::new(&v.key.into());
        let mut ciphertext = ccm
            .encrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &v.data,
                },
            )
            .unwrap();

        assert!(ccm
            .decrypt(
                &v.nonce.into(),
                aead::Payload {
                    // This associated data has been tampered with
                    aad: &hex!("0001020304050608"),
                    msg: &ciphertext,
                }
            )
            .is_err());
        // Tamper with the ciphertext
        ciphertext[10] = 0xFF;
        assert!(ccm
            .decrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &ciphertext
                }
            )
            .is_err());
    }

    #[test]
    #[cfg(all(feature = "aes", feature = "alloc"))]
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

        let ccm: Aes128Ccm<U10> = Aes128Ccm::new(&v.key.into());
        let ciphertext = ccm
            .encrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &v.data,
                },
            )
            .unwrap();
        let plaintext = ccm
            .decrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &ciphertext,
                },
            )
            .unwrap();
        assert_eq!(&v.data[..], plaintext.as_slice());
    }

    #[test]
    #[cfg(all(feature = "aes", feature = "alloc"))]
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

        let ccm: Aes128Ccm<U10> = Aes128Ccm::new(&v.key.into());
        let ciphertext = ccm
            .encrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &v.data,
                },
            )
            .unwrap();
        let plaintext = ccm
            .decrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &ciphertext,
                },
            )
            .unwrap();
        assert_eq!(&v.data[..], plaintext.as_slice());
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

    #[cfg(all(feature = "aes", feature = "alloc"))]
    fn test_vector<TagSize: CcmTagSize>(v: TestVector) {
        assert_eq!(v.mac_len, TagSize::to_usize());
        let ccm = Aes128Ccm::<TagSize>::new(&v.key.into());

        let ciphertext = ccm
            .encrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &v.data,
                },
            )
            .unwrap();
        assert_eq!(&v.expected[..], ciphertext.as_slice());

        let plaintext = ccm
            .decrypt(
                &v.nonce.into(),
                aead::Payload {
                    aad: &v.hdr,
                    msg: &ciphertext,
                },
            )
            .unwrap();
        assert_eq!(&v.data[..], plaintext.as_slice());
    }

    #[cfg(all(feature = "aes", feature = "heapless"))]
    fn test_vector<TagSize: CcmTagSize>(v: TestVector) {
        use aead::{consts::U128, heapless::Vec};

        assert_eq!(v.mac_len, TagSize::to_usize());
        let ccm = Aes128Ccm::<TagSize>::new(&v.key.into());

        let mut buffer: Vec<u8, U128> = Vec::new();
        buffer.extend_from_slice(v.data).unwrap();

        ccm.encrypt_in_place(&v.nonce.into(), v.hdr, &mut buffer)
            .unwrap();
        assert_eq!(&v.expected[..], &buffer[..v.expected.len()]);

        ccm.decrypt_in_place(&v.nonce.into(), v.hdr, &mut buffer)
            .unwrap();
        assert_eq!(&v.data[..], &buffer[..v.data.len()]);
    }
}
