use nettle_sys::{
    dsa_signature,
    nettle_dsa_signature_init,
    nettle_dsa_signature_clear,
};
use helper::{
    convert_buffer_to_gmpz,
    convert_gmpz_to_buffer,
};
use std::mem::zeroed;

pub struct Signature {
    pub(crate) signature: dsa_signature,
}

impl Signature {
    pub fn new(r: &[u8], s: &[u8]) -> Signature {
        unsafe {
            let mut ret = zeroed();

            nettle_dsa_signature_init(&mut ret);
            ret.r[0] = convert_buffer_to_gmpz(r);
            ret.s[0] = convert_buffer_to_gmpz(s);

            Signature{ signature: ret }
        }
    }

    pub fn r(&self) -> Box<[u8]> {
        convert_gmpz_to_buffer(self.signature.r[0])
    }

    pub fn s(&self) -> Box<[u8]> {
        convert_gmpz_to_buffer(self.signature.s[0])
    }
}

impl Default for Signature {
    fn default() -> Signature {
        unsafe {
            let mut signature: dsa_signature = zeroed();

            nettle_dsa_signature_init(&mut signature as *mut _);
            Signature{ signature: signature }
        }
    }
}

impl Drop for Signature {
    fn drop(&mut self) {
        unsafe {
            nettle_dsa_signature_clear(&mut self.signature as *mut _);
        }
    }
}
