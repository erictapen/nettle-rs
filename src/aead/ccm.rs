use nettle_sys::{
    nettle_ccm_encrypt,
    nettle_ccm_decrypt,
    nettle_ccm_update,
    nettle_ccm_digest,
    nettle_ccm_set_nonce,
    ccm_ctx,
};
use std::mem::zeroed;
use Cipher;
use BlockSizeIs16;
use Aead;

/// Counter with CBC-MAC mode (NIST SP800-38C).
///
/// CCM is a generic AEAD mode for block cipher with 128 bit block size.
pub struct Ccm<C: Cipher + BlockSizeIs16> {
    cipher: C,
    context: ccm_ctx,
}

impl<C: Cipher + BlockSizeIs16> Ccm<C> {
    /// Recommended size of the CCM digest in bytes.
    pub const DIGEST_SIZE: usize = ::nettle_sys::CCM_DIGEST_SIZE as usize;

    /// Creates a new instance with secret `key` and public `nonce`. The instance expect additional
    /// data of `ad_len` bytes, a overall message of `msg_len` and will produce a digest of
    /// `digest_len` bytes.
    pub fn with_key_and_nonce(key: &[u8], nonce: &[u8], ad_len: usize, msg_len: usize, digest_len: usize) -> Self {
        let mut ctx = unsafe { zeroed() };
        let mut cipher = C::with_encrypt_key(key);
        let enc_func = C::raw_encrypt_function().ptr();
        let cipher_ctx = cipher.context();

        unsafe {
            nettle_ccm_set_nonce(
                &mut ctx as *mut _,
                cipher_ctx as *const _,
                enc_func,
                nonce.len(),
                nonce.as_ptr(),
                ad_len,
                msg_len,
                digest_len);
        }

        Ccm{
            cipher: cipher,
            context: ctx,
        }
    }
}

impl<C: Cipher + BlockSizeIs16> Aead for Ccm<C> {
    fn digest_size(&self) -> usize {
        ::nettle_sys::CCM_DIGEST_SIZE as usize
    }

    fn update(&mut self, ad: &[u8]) {
        unsafe {
            nettle_ccm_update(
                &mut self.context as *mut _,
                self.cipher.context() as *const _,
                C::raw_encrypt_function().ptr(),
                ad.len(),
                ad.as_ptr());
        }
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_ccm_encrypt(
                &mut self.context as *mut _,
                self.cipher.context() as *const _,
                C::raw_encrypt_function().ptr(),
                dst.len(),
                dst.as_mut_ptr(),
                src.as_ptr());
        }
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_ccm_decrypt(
                &mut self.context as *mut _,
                self.cipher.context() as *const _,
                C::raw_encrypt_function().ptr(),
                dst.len(),
                dst.as_mut_ptr(),
                src.as_ptr());
        }
    }

    fn digest(&mut self, digest: &mut [u8]) {
        unsafe {
            nettle_ccm_digest(
                &mut self.context as *mut _,
                self.cipher.context() as *const _,
                C::raw_encrypt_function().ptr(),
                digest.len(),
                digest.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ccm_twofish() {
        use cipher::Twofish;
        let mut enc = Ccm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2;14],Twofish::BLOCK_SIZE * 5,Twofish::BLOCK_SIZE * 10,Ccm::<Twofish>::DIGEST_SIZE);
        let mut dec = Ccm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2;14],Twofish::BLOCK_SIZE * 5,Twofish::BLOCK_SIZE * 10,Ccm::<Twofish>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Twofish::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Twofish>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Twofish>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_twofish() {
        use cipher::Twofish;
        let mut enc = Ccm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2;14],Twofish::BLOCK_SIZE * 5,Twofish::BLOCK_SIZE * 10,Ccm::<Twofish>::DIGEST_SIZE);
        let mut dec = Ccm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2;14],Twofish::BLOCK_SIZE * 5,Twofish::BLOCK_SIZE * 10,Ccm::<Twofish>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Twofish::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Twofish>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Twofish>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_twofish() {
        use cipher::Twofish;
        let mut enc = Ccm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2;14],Twofish::BLOCK_SIZE * 5,Twofish::BLOCK_SIZE * 10,Ccm::<Twofish>::DIGEST_SIZE);
        let mut dec = Ccm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2;14],Twofish::BLOCK_SIZE * 5,Twofish::BLOCK_SIZE * 10,Ccm::<Twofish>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Twofish::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Twofish>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Twofish>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_aes128() {
        use cipher::Aes128;
        let mut enc = Ccm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2;14],Aes128::BLOCK_SIZE * 5,Aes128::BLOCK_SIZE * 10,Ccm::<Aes128>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2;14],Aes128::BLOCK_SIZE * 5,Aes128::BLOCK_SIZE * 10,Ccm::<Aes128>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes128>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_aes128() {
        use cipher::Aes128;
        let mut enc = Ccm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2;14],Aes128::BLOCK_SIZE * 5,Aes128::BLOCK_SIZE * 10,Ccm::<Aes128>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2;14],Aes128::BLOCK_SIZE * 5,Aes128::BLOCK_SIZE * 10,Ccm::<Aes128>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Aes128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes128>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_aes128() {
        use cipher::Aes128;
        let mut enc = Ccm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2;14],Aes128::BLOCK_SIZE * 5,Aes128::BLOCK_SIZE * 10,Ccm::<Aes128>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2;14],Aes128::BLOCK_SIZE * 5,Aes128::BLOCK_SIZE * 10,Ccm::<Aes128>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes128>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_aes192() {
        use cipher::Aes192;
        let mut enc = Ccm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2;14],Aes192::BLOCK_SIZE * 5,Aes192::BLOCK_SIZE * 10,Ccm::<Aes192>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2;14],Aes192::BLOCK_SIZE * 5,Aes192::BLOCK_SIZE * 10,Ccm::<Aes192>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes192>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_aes192() {
        use cipher::Aes192;
        let mut enc = Ccm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2;14],Aes192::BLOCK_SIZE * 5,Aes192::BLOCK_SIZE * 10,Ccm::<Aes192>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2;14],Aes192::BLOCK_SIZE * 5,Aes192::BLOCK_SIZE * 10,Ccm::<Aes192>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Aes192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes192>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_aes192() {
        use cipher::Aes192;
        let mut enc = Ccm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2;14],Aes192::BLOCK_SIZE * 5,Aes192::BLOCK_SIZE * 10,Ccm::<Aes192>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2;14],Aes192::BLOCK_SIZE * 5,Aes192::BLOCK_SIZE * 10,Ccm::<Aes192>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes192>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_aes256() {
        use cipher::Aes256;
        let mut enc = Ccm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2;14],Aes256::BLOCK_SIZE * 5,Aes256::BLOCK_SIZE * 10,Ccm::<Aes256>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2;14],Aes256::BLOCK_SIZE * 5,Aes256::BLOCK_SIZE * 10,Ccm::<Aes256>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes256>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_aes256() {
        use cipher::Aes256;
        let mut enc = Ccm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2;14],Aes256::BLOCK_SIZE * 5,Aes256::BLOCK_SIZE * 10,Ccm::<Aes256>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2;14],Aes256::BLOCK_SIZE * 5,Aes256::BLOCK_SIZE * 10,Ccm::<Aes256>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Aes256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes256>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_aes256() {
        use cipher::Aes256;
        let mut enc = Ccm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2;14],Aes256::BLOCK_SIZE * 5,Aes256::BLOCK_SIZE * 10,Ccm::<Aes256>::DIGEST_SIZE);
        let mut dec = Ccm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2;14],Aes256::BLOCK_SIZE * 5,Aes256::BLOCK_SIZE * 10,Ccm::<Aes256>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Aes256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Aes256>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_camellia128() {
        use cipher::Camellia128;
        let mut enc = Ccm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2;14],Camellia128::BLOCK_SIZE * 5,Camellia128::BLOCK_SIZE * 10,Ccm::<Camellia128>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2;14],Camellia128::BLOCK_SIZE * 5,Camellia128::BLOCK_SIZE * 10,Ccm::<Camellia128>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia128>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_camellia128() {
        use cipher::Camellia128;
        let mut enc = Ccm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2;14],Camellia128::BLOCK_SIZE * 5,Camellia128::BLOCK_SIZE * 10,Ccm::<Camellia128>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2;14],Camellia128::BLOCK_SIZE * 5,Camellia128::BLOCK_SIZE * 10,Ccm::<Camellia128>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Camellia128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia128>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_camellia128() {
        use cipher::Camellia128;
        let mut enc = Ccm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2;14],Camellia128::BLOCK_SIZE * 5,Camellia128::BLOCK_SIZE * 10,Ccm::<Camellia128>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2;14],Camellia128::BLOCK_SIZE * 5,Camellia128::BLOCK_SIZE * 10,Ccm::<Camellia128>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia128>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_camellia192() {
        use cipher::Camellia192;
        let mut enc = Ccm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2;14],Camellia192::BLOCK_SIZE * 5,Camellia192::BLOCK_SIZE * 10,Ccm::<Camellia192>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2;14],Camellia192::BLOCK_SIZE * 5,Camellia192::BLOCK_SIZE * 10,Ccm::<Camellia192>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia192>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_camellia192() {
        use cipher::Camellia192;
        let mut enc = Ccm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2;14],Camellia192::BLOCK_SIZE * 5,Camellia192::BLOCK_SIZE * 10,Ccm::<Camellia192>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2;14],Camellia192::BLOCK_SIZE * 5,Camellia192::BLOCK_SIZE * 10,Ccm::<Camellia192>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Camellia192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia192>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_camellia192() {
        use cipher::Camellia192;
        let mut enc = Ccm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2;14],Camellia192::BLOCK_SIZE * 5,Camellia192::BLOCK_SIZE * 10,Ccm::<Camellia192>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2;14],Camellia192::BLOCK_SIZE * 5,Camellia192::BLOCK_SIZE * 10,Ccm::<Camellia192>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia192>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_camellia256() {
        use cipher::Camellia256;
        let mut enc = Ccm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2;14],Camellia256::BLOCK_SIZE * 5,Camellia256::BLOCK_SIZE * 10,Ccm::<Camellia256>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2;14],Camellia256::BLOCK_SIZE * 5,Camellia256::BLOCK_SIZE * 10,Ccm::<Camellia256>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia256>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_camellia256() {
        use cipher::Camellia256;
        let mut enc = Ccm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2;14],Camellia256::BLOCK_SIZE * 5,Camellia256::BLOCK_SIZE * 10,Ccm::<Camellia256>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2;14],Camellia256::BLOCK_SIZE * 5,Camellia256::BLOCK_SIZE * 10,Ccm::<Camellia256>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Camellia256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia256>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_camellia256() {
        use cipher::Camellia256;
        let mut enc = Ccm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2;14],Camellia256::BLOCK_SIZE * 5,Camellia256::BLOCK_SIZE * 10,Ccm::<Camellia256>::DIGEST_SIZE);
        let mut dec = Ccm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2;14],Camellia256::BLOCK_SIZE * 5,Camellia256::BLOCK_SIZE * 10,Ccm::<Camellia256>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Camellia256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Camellia256>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn round_trip_ccm_serpent() {
        use cipher::Serpent;
        let mut enc = Ccm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2;14],Serpent::BLOCK_SIZE * 5,Serpent::BLOCK_SIZE * 10,Ccm::<Serpent>::DIGEST_SIZE);
        let mut dec = Ccm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2;14],Serpent::BLOCK_SIZE * 5,Serpent::BLOCK_SIZE * 10,Ccm::<Serpent>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Serpent::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Serpent>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Serpent>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert_eq!(digest, output_digest);
    }

    #[test]
    fn modify_ad_ccm_serpent() {
        use cipher::Serpent;
        let mut enc = Ccm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2;14],Serpent::BLOCK_SIZE * 5,Serpent::BLOCK_SIZE * 10,Ccm::<Serpent>::DIGEST_SIZE);
        let mut dec = Ccm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2;14],Serpent::BLOCK_SIZE * 5,Serpent::BLOCK_SIZE * 10,Ccm::<Serpent>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Serpent::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Serpent>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Serpent>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        input_ad[1] = 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert_eq!(input_plaintext, output_plaintext);
        assert!(digest != output_digest);
    }

    #[test]
    fn modify_ciphertext_ccm_serpent() {
        use cipher::Serpent;
        let mut enc = Ccm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2;14],Serpent::BLOCK_SIZE * 5,Serpent::BLOCK_SIZE * 10,Ccm::<Serpent>::DIGEST_SIZE);
        let mut dec = Ccm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2;14],Serpent::BLOCK_SIZE * 5,Serpent::BLOCK_SIZE * 10,Ccm::<Serpent>::DIGEST_SIZE);
        let input_plaintext = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Serpent::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Ccm::<Serpent>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Ccm::<Serpent>::DIGEST_SIZE];

        enc.update(&input_ad);
        enc.encrypt(&mut ciphertext, &input_plaintext);
        enc.digest(&mut digest);

        ciphertext[1] ^= 42;

        dec.update(&input_ad);
        dec.decrypt(&mut output_plaintext, &ciphertext);
        dec.digest(&mut output_digest);

        assert!(input_plaintext != output_plaintext);
        assert!(digest != output_digest);
    }
}
