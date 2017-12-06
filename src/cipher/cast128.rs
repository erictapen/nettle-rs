use nettle_sys::{
    cast128_ctx,
    nettle_cast5_set_key,
    nettle_cast128_encrypt,
    nettle_cast128_decrypt,
};
use std::mem::zeroed;
use Cipher;

/// The CAST-128 block cipher defined in RFC 2144.
pub struct Cast128 {
    context: cast128_ctx,
}

impl Cast128 {
    /// Creates a new instance with `key` that can be used for both encryption and decryption.
    pub fn with_key(key: &[u8]) -> Self {
        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_cast5_set_key(&mut ctx as *mut _, key.len(), key.as_ptr()); }

        Cast128{ context: ctx }
    }
}

impl Cipher for Cast128 {
    const BLOCK_SIZE: usize = ::nettle_sys::CAST128_BLOCK_SIZE as usize;
    const KEY_SIZE: usize = ::nettle_sys::CAST5_MAX_KEY_SIZE as usize;

    fn with_encrypt_key(key: &[u8]) -> Cast128 {
        Cast128::with_key(key)
    }

    fn with_decrypt_key(key: &[u8]) -> Cast128 {
        Cast128::with_key(key)
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_cast128_encrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_cast128_decrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key() {
        let key = &(b"\x01\x02\x03\x04\x05\x06\x07\x08"[..]);
        let _ = Cast128::with_encrypt_key(key);
        let _ = Cast128::with_decrypt_key(key);
    }

    #[test]
    fn round_trip() {
        let key = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Cast128::with_encrypt_key(&key);
        let mut dec = Cast128::with_decrypt_key(&key);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
