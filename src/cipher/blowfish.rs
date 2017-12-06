use nettle_sys::{
    blowfish_ctx,
    nettle_blowfish_set_key,
    nettle_blowfish_encrypt,
    nettle_blowfish_decrypt,
};
use std::mem::zeroed;
use Cipher;

/// The Blowfish block cipher.
///
/// Blowfish is defined in B. Schneiers 1993 paper "Description of a New
/// Variable-Length Key, 64-Bit Block Cipher (Blowfish)" published in "Fast Software Encryption,
/// Cambridge Security Workshop Proceedings" (December 1993), Springer-Verlag, 1994, pp. 191-204.
pub struct Blowfish {
    context: blowfish_ctx,
}

impl Blowfish {
    /// Creates a new instance with `key` that can be used for both encryption and decryption.
    pub fn with_key(key: &[u8]) -> Self {
        let mut ctx = unsafe { zeroed() };
        unsafe { nettle_blowfish_set_key(&mut ctx as *mut _, key.len(), key.as_ptr()); }

        Blowfish{ context: ctx }
    }
}

impl Cipher for Blowfish {
    const BLOCK_SIZE: usize = ::nettle_sys::BLOWFISH_BLOCK_SIZE as usize;
    const KEY_SIZE: usize = ::nettle_sys::BLOWFISH_MAX_KEY_SIZE as usize;

    fn with_encrypt_key(key: &[u8]) -> Blowfish {
        Blowfish::with_key(key)
    }

    fn with_decrypt_key(key: &[u8]) -> Blowfish {
        Blowfish::with_key(key)
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_blowfish_encrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_blowfish_decrypt(&mut self.context as *mut _, dst.len(), dst.as_mut_ptr(), src.as_ptr())
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key() {
        let key = &(b"\x01\x02\x03\x04\x05\x06\x07\x08"[..]);
        let _ = Blowfish::with_encrypt_key(key);
        let _ = Blowfish::with_decrypt_key(key);
    }

    #[test]
    fn round_trip() {
        let key = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        let input = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,];
        let mut cipher = vec![0; 16];
        let mut output = vec![0; 16];

        let mut enc = Blowfish::with_encrypt_key(&key);
        let mut dec = Blowfish::with_decrypt_key(&key);

        enc.encrypt(&mut cipher,&input);
        dec.decrypt(&mut output,&cipher);

        assert_eq!(output, input);
    }
}
