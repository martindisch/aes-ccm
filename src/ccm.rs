#![allow(dead_code,
         mutable_transmutes,
         non_camel_case_types,
         non_snake_case,
         non_upper_case_globals,
         unused_mut)]
#![feature(libc)]
extern crate libc;
pub type uint8_t = libc::c_uchar;
pub type uint16_t = libc::c_ushort;
/* max additional authenticated size in bytes: 2^16 - 2^8 = 65280 */
/* max message size in bytes: 2^(8L) = 2^16 = 65536 */
/* number of columns (32-bit words) comprising the state */
/* number of 32-bit words comprising the key */
/* number of rounds */
#[derive ( Copy , Clone )]
#[repr(C)]
pub struct tc_aes_key_sched_struct {
    pub words: [libc::c_uint; 44],
}
pub type TCAesKeySched_t = *mut tc_aes_key_sched_struct;
/* struct tc_ccm_mode_struct represents the state of a CCM computation */
#[derive ( Copy , Clone )]
#[repr(C)]
pub struct tc_ccm_mode_struct {
    pub sched: TCAesKeySched_t,
    pub nonce: *mut uint8_t,
    pub mlen: libc::c_uint,
}
pub type TCCcmMode_t = *mut tc_ccm_mode_struct;
#[no_mangle]
pub unsafe extern "C" fn tc_ccm_config(mut c: TCCcmMode_t,
                                       mut sched: TCAesKeySched_t,
                                       mut nonce: *mut uint8_t,
                                       mut nlen: libc::c_uint,
                                       mut mlen: libc::c_uint)
 -> libc::c_int {
    if c.is_null() || sched.is_null() || nonce.is_null() {
        return 0i32
    } else {
        if nlen != 13i32 as libc::c_uint {
            return 0i32
        } else {
            if mlen < 4i32 as libc::c_uint || mlen > 16i32 as libc::c_uint ||
                   0 != mlen & 1i32 as libc::c_uint {
                return 0i32
            }
        }
    }
    (*c).mlen = mlen;
    (*c).sched = sched;
    (*c).nonce = nonce;
    return 1i32;
}
/* *
 * Variation of CBC-MAC mode used in CCM.
 */
unsafe extern "C" fn ccm_cbc_mac(mut T: *mut uint8_t,
                                 mut data: *const uint8_t,
                                 mut dlen: libc::c_uint,
                                 mut flag: libc::c_uint,
                                 mut sched: TCAesKeySched_t) {
    let mut i: libc::c_uint = 0;
    if flag > 0i32 as libc::c_uint {
        let ref mut fresh0 = *T.offset(0isize);
        *fresh0 =
            (*fresh0 as libc::c_int ^
                 (dlen >> 8i32) as uint8_t as libc::c_int) as uint8_t;
        let ref mut fresh1 = *T.offset(1isize);
        *fresh1 =
            (*fresh1 as libc::c_int ^ dlen as uint8_t as libc::c_int) as
                uint8_t;
        dlen = dlen.wrapping_add(2i32 as libc::c_uint);
        i = 2i32 as libc::c_uint
    } else { i = 0i32 as libc::c_uint }
    while i < dlen {
        let fresh3 = i;
        i = i.wrapping_add(1);
        let ref mut fresh4 =
            *T.offset(fresh3.wrapping_rem((4i32 * 4i32) as libc::c_uint) as
                          isize);
        let fresh2 = data;
        data = data.offset(1);
        *fresh4 =
            (*fresh4 as libc::c_int ^ *fresh2 as libc::c_int) as uint8_t;
        if i.wrapping_rem((4i32 * 4i32) as libc::c_uint) ==
               0i32 as libc::c_uint || dlen == i {
            tc_aes_encrypt(T, T, sched);
        }
    };
}
/* *
 * Variation of CTR mode used in CCM.
 * The CTR mode used by CCM is slightly different than the conventional CTR
 * mode (the counter is increased before encryption, instead of after
 * encryption). Besides, it is assumed that the counter is stored in the last
 * 2 bytes of the nonce.
 */
unsafe extern "C" fn ccm_ctr_mode(mut out: *mut uint8_t,
                                  mut outlen: libc::c_uint,
                                  mut in_0: *const uint8_t,
                                  mut inlen: libc::c_uint,
                                  mut ctr: *mut uint8_t,
                                  sched: TCAesKeySched_t) -> libc::c_int {
    let mut buffer: [uint8_t; 16] = [0; 16];
    let mut nonce: [uint8_t; 16] = [0; 16];
    let mut block_num: uint16_t = 0;
    let mut i: libc::c_uint = 0;
    if out.is_null() || in_0 == 0 as *mut uint8_t || ctr.is_null() ||
           sched.is_null() || inlen == 0i32 as libc::c_uint ||
           outlen == 0i32 as libc::c_uint || outlen != inlen {
        return 0i32
    }
    _copy(nonce.as_mut_ptr(),
          ::std::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong, ctr,
          ::std::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong);
    block_num =
        ((nonce[14usize] as libc::c_int) << 8i32 |
             nonce[15usize] as libc::c_int) as uint16_t;
    i = 0i32 as libc::c_uint;
    while i < inlen {
        if i.wrapping_rem((4i32 * 4i32) as libc::c_uint) ==
               0i32 as libc::c_uint {
            block_num = block_num.wrapping_add(1);
            nonce[14usize] = (block_num as libc::c_int >> 8i32) as uint8_t;
            nonce[15usize] = block_num as uint8_t;
            if 0 ==
                   tc_aes_encrypt(buffer.as_mut_ptr(), nonce.as_mut_ptr(),
                                  sched) {
                return 0i32
            }
        }
        let fresh6 = out;
        out = out.offset(1);
        let fresh5 = in_0;
        in_0 = in_0.offset(1);
        *fresh6 =
            (buffer[i.wrapping_rem((4i32 * 4i32) as libc::c_uint) as usize] as
                 libc::c_int ^ *fresh5 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1)
    }
    *ctr.offset(14isize) = nonce[14usize];
    *ctr.offset(15isize) = nonce[15usize];
    return 1i32;
}
#[no_mangle]
pub unsafe extern "C" fn tc_ccm_generation_encryption(mut out: *mut uint8_t,
                                                      mut olen: libc::c_uint,
                                                      mut associated_data:
                                                          *const uint8_t,
                                                      mut alen: libc::c_uint,
                                                      mut payload:
                                                          *const uint8_t,
                                                      mut plen: libc::c_uint,
                                                      mut c: TCCcmMode_t)
 -> libc::c_int {
    if out.is_null() || c.is_null() ||
           plen > 0i32 as libc::c_uint && payload == 0 as *mut uint8_t ||
           alen > 0i32 as libc::c_uint && associated_data == 0 as *mut uint8_t
           || alen >= 0xff00i32 as libc::c_uint ||
           plen >= 0x10000i32 as libc::c_uint ||
           olen < plen.wrapping_add((*c).mlen) {
        return 0i32
    }
    let mut b: [uint8_t; 16] = [0; 16];
    let mut tag: [uint8_t; 16] = [0; 16];
    let mut i: libc::c_uint = 0;
    b[0usize] =
        ((if alen > 0i32 as libc::c_uint { 0x40i32 } else { 0i32 }) as
             libc::c_uint |
             (*c).mlen.wrapping_sub(2i32 as
                                        libc::c_uint).wrapping_div(2i32 as
                                                                       libc::c_uint)
                 << 3i32 | 1i32 as libc::c_uint) as uint8_t;
    i = 1i32 as libc::c_uint;
    while i <= 13i32 as libc::c_uint {
        b[i as usize] =
            *(*c).nonce.offset(i.wrapping_sub(1i32 as libc::c_uint) as isize);
        i = i.wrapping_add(1)
    }
    b[14usize] = (plen >> 8i32) as uint8_t;
    b[15usize] = plen as uint8_t;
    tc_aes_encrypt(tag.as_mut_ptr(), b.as_mut_ptr(), (*c).sched);
    if alen > 0i32 as libc::c_uint {
        ccm_cbc_mac(tag.as_mut_ptr(), associated_data, alen,
                    1i32 as libc::c_uint, (*c).sched);
    }
    if plen > 0i32 as libc::c_uint {
        ccm_cbc_mac(tag.as_mut_ptr(), payload, plen, 0i32 as libc::c_uint,
                    (*c).sched);
    }
    b[0usize] = 1i32 as uint8_t;
    b[15usize] = 0i32 as uint8_t;
    b[14usize] = b[15usize];
    ccm_ctr_mode(out, plen, payload, plen, b.as_mut_ptr(), (*c).sched);
    b[15usize] = 0i32 as uint8_t;
    b[14usize] = b[15usize];
    tc_aes_encrypt(b.as_mut_ptr(), b.as_mut_ptr(), (*c).sched);
    out = out.offset(plen as isize);
    i = 0i32 as libc::c_uint;
    while i < (*c).mlen {
        let fresh7 = out;
        out = out.offset(1);
        *fresh7 =
            (tag[i as usize] as libc::c_int ^ b[i as usize] as libc::c_int) as
                uint8_t;
        i = i.wrapping_add(1)
    }
    return 1i32;
}
#[no_mangle]
pub unsafe extern "C" fn tc_ccm_decryption_verification(mut out: *mut uint8_t,
                                                        mut olen:
                                                            libc::c_uint,
                                                        mut associated_data:
                                                            *const uint8_t,
                                                        mut alen:
                                                            libc::c_uint,
                                                        mut payload:
                                                            *const uint8_t,
                                                        mut plen:
                                                            libc::c_uint,
                                                        mut c: TCCcmMode_t)
 -> libc::c_int {
    if out.is_null() || c.is_null() ||
           plen > 0i32 as libc::c_uint && payload == 0 as *mut uint8_t ||
           alen > 0i32 as libc::c_uint && associated_data == 0 as *mut uint8_t
           || alen >= 0xff00i32 as libc::c_uint ||
           plen >= 0x10000i32 as libc::c_uint ||
           olen < plen.wrapping_sub((*c).mlen) {
        return 0i32
    }
    let mut b: [uint8_t; 16] = [0; 16];
    let mut tag: [uint8_t; 16] = [0; 16];
    let mut i: libc::c_uint = 0;
    b[0usize] = 1i32 as uint8_t;
    i = 1i32 as libc::c_uint;
    while i < 14i32 as libc::c_uint {
        b[i as usize] =
            *(*c).nonce.offset(i.wrapping_sub(1i32 as libc::c_uint) as isize);
        i = i.wrapping_add(1)
    }
    b[15usize] = 0i32 as uint8_t;
    b[14usize] = b[15usize];
    ccm_ctr_mode(out, plen.wrapping_sub((*c).mlen), payload,
                 plen.wrapping_sub((*c).mlen), b.as_mut_ptr(), (*c).sched);
    b[15usize] = 0i32 as uint8_t;
    b[14usize] = b[15usize];
    tc_aes_encrypt(b.as_mut_ptr(), b.as_mut_ptr(), (*c).sched);
    i = 0i32 as libc::c_uint;
    while i < (*c).mlen {
        tag[i as usize] =
            (*payload.offset(plen as
                                 isize).offset(-((*c).mlen as
                                                     isize)).offset(i as
                                                                        isize)
                 as libc::c_int ^ b[i as usize] as libc::c_int) as uint8_t;
        i = i.wrapping_add(1)
    }
    b[0usize] =
        ((if alen > 0i32 as libc::c_uint { 0x40i32 } else { 0i32 }) as
             libc::c_uint |
             (*c).mlen.wrapping_sub(2i32 as
                                        libc::c_uint).wrapping_div(2i32 as
                                                                       libc::c_uint)
                 << 3i32 | 1i32 as libc::c_uint) as uint8_t;
    i = 1i32 as libc::c_uint;
    while i < 14i32 as libc::c_uint {
        b[i as usize] =
            *(*c).nonce.offset(i.wrapping_sub(1i32 as libc::c_uint) as isize);
        i = i.wrapping_add(1)
    }
    b[14usize] = (plen.wrapping_sub((*c).mlen) >> 8i32) as uint8_t;
    b[15usize] = plen.wrapping_sub((*c).mlen) as uint8_t;
    tc_aes_encrypt(b.as_mut_ptr(), b.as_mut_ptr(), (*c).sched);
    if alen > 0i32 as libc::c_uint {
        ccm_cbc_mac(b.as_mut_ptr(), associated_data, alen,
                    1i32 as libc::c_uint, (*c).sched);
    }
    if plen > 0i32 as libc::c_uint {
        ccm_cbc_mac(b.as_mut_ptr(), out, plen.wrapping_sub((*c).mlen),
                    0i32 as libc::c_uint, (*c).sched);
    }
    if _compare(b.as_mut_ptr(), tag.as_mut_ptr(), (*c).mlen) == 0i32 {
        return 1i32
    } else { _set(out, 0i32, plen.wrapping_sub((*c).mlen)); return 0i32 };
}