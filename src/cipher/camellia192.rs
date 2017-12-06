use nettle_sys::{
    camellia256_ctx,
    nettle_camellia256_invert_key,
    nettle_camellia192_set_encrypt_key,
    nettle_camellia192_set_decrypt_key,
    nettle_camellia256_crypt,
};
use std::mem::zeroed;
use Cipher;

/// 192 bit variant of the Camellia block cipher developed by Mitsubishi & NTT, defined in RFC 3713.
pub struct Camellia192 {
    context: camellia256_ctx,
}

impl Camellia192 {
    /// Creates a new `Camellia192` instance for decryption that uses the same key as `encrypt`. The
    /// `encrypt` instance must be configured for encryption. This is faster than calling
    /// `with_decrypt_key`.
    pub fn with_inverted_key(encrypt: &Self) -> Self {
        let mut ctx = unsafe { zeroed() };
        unsafe {
            nettle_camellia256_invert_key(&mut ctx as *mut _, &encrypt.context as *const _);
        }

        Camellia192{ context: ctx }
    }

    /// Encrypt/decrypt data from `src` to `dst`.
    pub fn crypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_camellia256_crypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

impl Cipher for Camellia192 {
    const BLOCK_SIZE: usize = ::nettle_sys::CAMELLIA_BLOCK_SIZE as usize;
    const KEY_SIZE: usize = ::nettle_sys::CAMELLIA192_KEY_SIZE as usize;

    fn with_encrypt_key(key: &[u8]) -> Camellia192 {
        assert_eq!(key.len(), 192 / 8);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_camellia192_set_encrypt_key(&mut ctx as *mut _, key.as_ptr()); }

        Camellia192{ context: ctx }
    }

    fn with_decrypt_key(key: &[u8]) -> Camellia192 {
        assert_eq!(key.len(), 192 / 8);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_camellia192_set_decrypt_key(&mut ctx as *mut _, key.as_ptr()); }

        Camellia192{ context: ctx }
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        self.crypt(dst,src)
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        self.crypt(dst,src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key() {
        let key = &(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x09\x10\x11\x12\x13\x14\x15\x16"[..]);
        let _ = Camellia192::with_encrypt_key(key);
        let _ = Camellia192::with_decrypt_key(key);
    }

    #[test]
    fn round_trip() {
        let key = vec![
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
            0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16
        ];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Camellia192::with_encrypt_key(&key);
        let mut dec = Camellia192::with_decrypt_key(&key);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }

    #[test]
    fn round_trip_invert() {
        let key = vec![
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
            0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16
        ];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Camellia192::with_encrypt_key(&key);
        let mut dec = Camellia192::with_inverted_key(&enc);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
