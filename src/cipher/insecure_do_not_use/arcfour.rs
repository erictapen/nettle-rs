use nettle_sys::{
    arcfour_ctx,
    nettle_arcfour_set_key,
    nettle_arcfour_crypt,
};
use std::mem::zeroed;
use std::os::raw::c_void;
use Cipher;
use cipher::RawCipherFunctionPointer;

/// Ron Rivest's RC4 stream cipher.
/// # Note
/// RC4 is no longer considered a secure cipher. Only use it for legacy applications.
pub struct ArcFour {
    context: arcfour_ctx,
}

impl ArcFour {
    /// Create a new instance with `key`.
    pub fn with_key(key: &[u8]) -> Self {
        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_arcfour_set_key(&mut ctx as *mut _, key.len(), key.as_ptr()); }

        ArcFour{ context: ctx }
    }

    /// Encrypt/decrypt data from `src` to `dst`.
    pub fn crypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_arcfour_crypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

impl Cipher for ArcFour {
    const BLOCK_SIZE: usize = 1;
    const KEY_SIZE: usize = ::nettle_sys::ARCFOUR_MAX_KEY_SIZE as usize;
    const RAW_DECRYPT_FUNCTION_POINTER: RawCipherFunctionPointer = ::nettle_sys::nettle_arcfour_crypt;
    const RAW_ENCRYPT_FUNCTION_POINTER: RawCipherFunctionPointer = ::nettle_sys::nettle_arcfour_crypt;

    fn with_encrypt_key(key: &[u8]) -> ArcFour {
        ArcFour::with_key(key)
    }

    fn with_decrypt_key(key: &[u8]) -> ArcFour {
        ArcFour::with_key(key)
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        self.crypt(dst,src)
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        self.crypt(dst,src)
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
        let _ = ArcFour::with_encrypt_key(key);
        let _ = ArcFour::with_decrypt_key(key);
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

        let mut enc = ArcFour::with_encrypt_key(&key);
        let mut dec = ArcFour::with_decrypt_key(&key);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
