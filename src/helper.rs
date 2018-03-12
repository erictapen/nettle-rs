use ::nettle_sys::{
    nettle_mpz_init_set_str_256_u,
    nettle_mpz_get_str_256,
    nettle_mpz_sizeinbase_256_u,
    __mpz_struct
};
use std::mem::zeroed;

pub fn convert_gmpz_to_buffer(mut mpz: __mpz_struct) -> Box<[u8]> {
    unsafe {
        let mut ret = vec![0u8; nettle_mpz_sizeinbase_256_u(&mut mpz)];

        nettle_mpz_get_str_256(ret.len(), ret.as_mut_ptr(), &mut mpz);

        if ret[0] == 0 { ret.remove(0); }
        ret.into()
    }
}

pub fn convert_buffer_to_gmpz(buf: &[u8]) -> __mpz_struct {
    unsafe {
        let mut ret = zeroed();

        nettle_mpz_init_set_str_256_u(&mut ret, buf.len(), buf.as_ptr());
        ret
    }
}
