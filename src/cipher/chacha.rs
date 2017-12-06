use nettle_sys::{
    chacha_ctx,
    nettle_chacha_set_key,
    nettle_chacha_set_nonce,
    nettle_chacha_crypt,
};
use std::mem::zeroed;

/// D.J. Bernstein's ChaCha block cipher.
pub struct ChaCha {
    context: chacha_ctx,
}

impl ChaCha {
    /// ChaCha block size in bytes.
    pub const BLOCK_SIZE: usize = ::nettle_sys::CHACHA_BLOCK_SIZE as usize;

    /// ChaCha key size in bytes.
    pub const KEY_SIZE: usize = ::nettle_sys::CHACHA_KEY_SIZE as usize;

    /// ChaCha nonce size in bytes.
    pub const NONCE_SIZE: usize = ::nettle_sys::CHACHA_NONCE_SIZE as usize;

    /// Create a new instance with `key`.
    pub fn with_key_and_nonce(key: &[u8],nonce: &[u8]) -> Self {
        assert_eq!(key.len(), ChaCha::KEY_SIZE);
        assert_eq!(nonce.len(), ChaCha::NONCE_SIZE);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_chacha_set_key(&mut ctx as *mut _, key.as_ptr()); }
        unsafe { nettle_chacha_set_nonce(&mut ctx as *mut _, nonce.as_ptr()); }

        ChaCha{ context: ctx }
    }

    /// Encrypt/decrypt data from `src` to `dst`.
    pub fn crypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_chacha_crypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key_and_nonce() {
        let key = vec![0; 32];
        let nonce = vec![1; 8];

        let _ = ChaCha::with_key_and_nonce(&key,&nonce);
    }

    #[test]
    fn round_trip() {
        let key = vec![0; 32];
        let nonce = vec![1; 8];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = ChaCha::with_key_and_nonce(&key,&nonce);
        let mut dec = ChaCha::with_key_and_nonce(&key,&nonce);

        enc.crypt(&mut cipher,&input);
        dec.crypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
