use nettle_sys::{
    aes256_ctx,
    nettle_aes256_invert_key,
    nettle_aes256_set_encrypt_key,
    nettle_aes256_set_decrypt_key,
    nettle_aes256_encrypt,
    nettle_aes256_decrypt,
};
use std::mem::zeroed;
use std::os::raw::c_void;
use Cipher;
use cipher::RawCipherFunctionPointer;

/// 256 bit variant of the Advanced Encryption Standard (AES, formerly RIJNDAEL) defined in FIPS 197.
pub struct Aes256 {
    context: aes256_ctx,
}

impl Aes256 {
    /// Creates a new `Aes256` instance for decryption that uses the same key as `encrypt`. The
    /// `encrypt` instance must be configured for encryption. This is faster than calling
    /// `with_decrypt_key`.
    pub fn with_inverted_key(encrypt: &Self) -> Self {
        let mut ctx = unsafe { zeroed() };
        unsafe {
            nettle_aes256_invert_key(&mut ctx as *mut _, &encrypt.context as *const _);
        }

        Aes256{ context: ctx }
    }
}

impl Cipher for Aes256 {
    const BLOCK_SIZE: usize = ::nettle_sys::AES_BLOCK_SIZE as usize;
    const KEY_SIZE: usize = ::nettle_sys::AES256_KEY_SIZE as usize;
    const RAW_DECRYPT_FUNCTION_POINTER: RawCipherFunctionPointer = ::nettle_sys::nettle_aes256_decrypt;
    const RAW_ENCRYPT_FUNCTION_POINTER: RawCipherFunctionPointer = ::nettle_sys::nettle_aes256_encrypt;

    fn with_encrypt_key(key: &[u8]) -> Aes256 {
        assert_eq!(key.len(), 256 / 8);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_aes256_set_encrypt_key(&mut ctx as *mut _, key.as_ptr()); }

        Aes256{ context: ctx }
    }

    fn with_decrypt_key(key: &[u8]) -> Aes256 {
        assert_eq!(key.len(), 256 / 8);

        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_aes256_set_decrypt_key(&mut ctx as *mut _, key.as_ptr()); }

        Aes256{ context: ctx }
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_aes256_encrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_aes256_decrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }

    fn context(&mut self) -> *mut c_void {
        self.context.as_mut_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key() {
        let key = &(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16"[..]);
        let _ = Aes256::with_encrypt_key(key);
        let _ = Aes256::with_decrypt_key(key);
    }

    #[test]
    fn round_trip() {
        let key = vec![
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16
        ];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Aes256::with_encrypt_key(&key);
        let mut dec = Aes256::with_decrypt_key(&key);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }

    #[test]
    fn round_trip_invert() {
        let key = vec![
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16
        ];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Aes256::with_encrypt_key(&key);
        let mut dec = Aes256::with_inverted_key(&enc);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
