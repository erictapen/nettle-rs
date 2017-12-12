use nettle_sys::{
    des_ctx,
    nettle_des_set_key,
    nettle_des_encrypt,
    nettle_des_decrypt,
    nettle_des_check_parity,
    nettle_des_fix_parity,
};
use std::mem::zeroed;
use std::os::raw::c_void;
use Cipher;
use cipher::RawCipherFunctionPointer;

/// The Data Encryption Standard (DES) defined in FIPS 46-3.
/// # Note
/// DES is no longer considered a secure cipher. Only use it for legacy applications.
pub struct Des {
    context: des_ctx,
}

impl Des {
    /// Creates a new instance with `key` that can be used for both encryption and decryption.
    pub fn with_key(key: &[u8]) -> Self {
        assert_eq!(key.len(), Des::KEY_SIZE);
        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_des_set_key(&mut ctx as *mut _, key.as_ptr()); }

        Des{ context: ctx }
    }

    /// Checks the parity bits of the given DES key. Returns `true` if parity is correct, `false`
    /// otherwise.
    pub fn check_parity(key: &[u8]) -> bool {
        unsafe {
            nettle_des_check_parity(key.len(), key.as_ptr()) == 1
        }
    }

    /// Sets the parity bits in the given DES key.
    pub fn fix_parity(key: &mut [u8]) {
        unsafe {
            nettle_des_fix_parity(key.len(), key.as_mut_ptr(), key.as_ptr());
        }
    }
}

impl Cipher for Des {
    const BLOCK_SIZE: usize = ::nettle_sys::DES_BLOCK_SIZE as usize;
    const KEY_SIZE: usize = ::nettle_sys::DES_KEY_SIZE as usize;

    fn with_encrypt_key(key: &[u8]) -> Des {
        Des::with_key(key)
    }

    fn with_decrypt_key(key: &[u8]) -> Des {
        Des::with_key(key)
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_des_encrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_des_decrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }

    fn context(&mut self) -> *mut c_void {
        ((&mut self.context) as *mut des_ctx) as *mut c_void
    }

    fn raw_encrypt_function() -> RawCipherFunctionPointer {
        RawCipherFunctionPointer::new(nettle_des_encrypt)
    }

    fn raw_decrypt_function() -> RawCipherFunctionPointer {
        RawCipherFunctionPointer::new(nettle_des_decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key() {
        let key = &(b"\x01\x02\x03\x04\x05\x06\x07\x08"[..]);
        let _ = Des::with_encrypt_key(key);
        let _ = Des::with_decrypt_key(key);
    }

    #[test]
    fn round_trip() {
        let key = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Des::with_encrypt_key(&key);
        let mut dec = Des::with_decrypt_key(&key);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }

    #[test]
    fn key_parity() {
        let mut key = b"\x01\x02\x03\x04\x05\x06\x07\x08"[..].iter().cloned().collect::<Vec<_>>();

        assert!(!Des::check_parity(&key));
        Des::fix_parity(&mut key);
        assert!(Des::check_parity(&key));
    }
}
