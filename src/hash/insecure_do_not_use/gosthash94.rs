use nettle_sys::{
    gosthash94_ctx,
    nettle_gosthash94_init,
    nettle_gosthash94_digest,
    nettle_gosthash94_update,
    nettle_hash,
    nettle_gosthash94,
};
use std::default::Default;
use std::mem::zeroed;
use Hash;

/// GOST R 34.11-94 (GOSTHASH94) defined in RFC 5831.
/// # Note
/// GOSTHASH94 is no longer considered a secure cryptographic hash function. Only use it for legacy
/// applications.
pub struct GostHash94 {
    context: gosthash94_ctx,
}

impl Default for GostHash94 {
    fn default() -> Self {
        let mut ctx = unsafe { zeroed() };

        unsafe { nettle_gosthash94_init(&mut ctx as *mut _); }

        GostHash94{ context: ctx }
    }
}

impl Hash for GostHash94 {
    type Context = gosthash94_ctx;
    const DIGEST_SIZE: usize = ::nettle_sys::GOSTHASH94_DIGEST_SIZE as usize;

    fn update(&mut self, data: &[u8]) {
        unsafe {
            nettle_gosthash94_update(&mut self.context as *mut _, data.len(), data.as_ptr());
        }
    }

    fn digest(&mut self, digest: &mut [u8]) {
        unsafe {
            nettle_gosthash94_digest(&mut self.context as *mut _, digest.len(), digest.as_mut_ptr());
        }
    }

    unsafe fn nettle_hash() -> &'static nettle_hash { &nettle_gosthash94 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_nothing() {
        let _ = GostHash94::default();
    }
}
