use nettle_sys::{
    dsa_signature,
    nettle_dsa_signature_init,
    nettle_dsa_signature_clear,
};
use std::mem::zeroed;

pub struct Signature {
    pub(crate) signature: dsa_signature,
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
