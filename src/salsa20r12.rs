use nettle_sys::{
    salsa20_ctx,
    nettle_salsa20_128_set_key,
    nettle_salsa20_256_set_key,
    nettle_salsa20_set_nonce,
    nettle_salsa20r12_crypt,
};
use std::mem::zeroed;

/// D.J. Bernstein's Salsa20R12_128 block cipher.
pub struct Salsa20R12_128 {
    context: salsa20_ctx,
}

impl Salsa20R12_128 {
    /// Salsa20R12_128 block size in bytes.
    pub const BLOCK_SIZE: usize = ::nettle_sys::SALSA20_BLOCK_SIZE as usize;

    /// Salsa20R12_128 key size in bytes.
    pub const KEY_SIZE: usize = ::nettle_sys::SALSA20_128_KEY_SIZE as usize;

    /// Salsa20R12_128 nonce size in bytes.
    pub const NONCE_SIZE: usize = ::nettle_sys::SALSA20_NONCE_SIZE as usize;

    /// Create a new instance with `key`.
    pub fn with_key_and_nonce(key: &[u8],nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Salsa20R12_128::KEY_SIZE);
        assert_eq!(nonce.len(), Salsa20R12_128::NONCE_SIZE);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_salsa20_128_set_key(&mut ctx as *mut _, key.as_ptr()); }
        unsafe { nettle_salsa20_set_nonce(&mut ctx as *mut _, nonce.as_ptr()); }

        Salsa20R12_128{ context: ctx }
    }

    /// Encrypt/decrypt data from `src` to `dst`.
    pub fn crypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_salsa20r12_crypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

/// D.J. Bernstein's Salsa20R12_256 block cipher.
pub struct Salsa20R12_256 {
    context: salsa20_ctx,
}

impl Salsa20R12_256 {
    /// Salsa20R12_256 block size in bytes.
    pub const BLOCK_SIZE: usize = ::nettle_sys::SALSA20_BLOCK_SIZE as usize;

    /// Salsa20R12_256 key size in bytes.
    pub const KEY_SIZE: usize = ::nettle_sys::SALSA20_256_KEY_SIZE as usize;

    /// Salsa20R12_256 nonce size in bytes.
    pub const NONCE_SIZE: usize = ::nettle_sys::SALSA20_NONCE_SIZE as usize;

    /// Create a new instance with `key`.
    pub fn with_key_and_nonce(key: &[u8],nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Salsa20R12_256::KEY_SIZE);
        assert_eq!(nonce.len(), Salsa20R12_256::NONCE_SIZE);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_salsa20_256_set_key(&mut ctx as *mut _, key.as_ptr()); }
        unsafe { nettle_salsa20_set_nonce(&mut ctx as *mut _, nonce.as_ptr()); }

        Salsa20R12_256{ context: ctx }
    }

    /// Encrypt/decrypt data from `src` to `dst`.
    pub fn crypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_salsa20r12_crypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salsa128_set_key_and_nonce() {
        let key = vec![0; 16];
        let nonce = vec![1; 8];

        let _ = Salsa20R12_128::with_key_and_nonce(&key,&nonce);
    }

    #[test]
    fn salsa128_round_trip() {
        let key = vec![0; 16];
        let nonce = vec![1; 8];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Salsa20R12_128::with_key_and_nonce(&key,&nonce);
        let mut dec = Salsa20R12_128::with_key_and_nonce(&key,&nonce);

        enc.crypt(&mut cipher,&input);
        dec.crypt(&mut output,&cipher);

        assert_eq!(output, input);
    }

    #[test]
    fn salsa256_set_key_and_nonce() {
        let key = vec![0; 32];
        let nonce = vec![1; 8];

        let _ = Salsa20R12_256::with_key_and_nonce(&key,&nonce);
    }

    #[test]
    fn salsa256_round_trip() {
        let key = vec![0; 32];
        let nonce = vec![1; 8];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Salsa20R12_256::with_key_and_nonce(&key,&nonce);
        let mut dec = Salsa20R12_256::with_key_and_nonce(&key,&nonce);

        enc.crypt(&mut cipher,&input);
        dec.crypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
