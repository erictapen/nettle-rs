use nettle_sys::{
    nettle_gcm_encrypt,
    nettle_gcm_decrypt,
    nettle_gcm_update,
    nettle_gcm_digest,
    nettle_gcm_set_key,
    nettle_gcm_set_iv,
    gcm_key,
    gcm_ctx,
};
use std::mem::zeroed;
use Cipher;
use Aead;

pub struct Gcm<C: Cipher> {
    cipher: C,
    key: gcm_key,
    context: gcm_ctx,
}

impl<C: Cipher> Gcm<C> {
    pub const DIGEST_SIZE: usize = ::nettle_sys::GCM_DIGEST_SIZE as usize;

    pub fn with_key_and_nonce(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(C::BLOCK_SIZE, 16);

        let mut ctx = unsafe { zeroed() };
        let mut key_ctx = unsafe { zeroed() };
        let mut cipher = C::with_encrypt_key(key);
        let enc_func = C::raw_encrypt_function().ptr();
        let cipher_ctx = cipher.context();

        unsafe {
            nettle_gcm_set_key(&mut key_ctx as *mut _, cipher_ctx as *const _, enc_func);
            nettle_gcm_set_iv(&mut ctx as *mut _, &key_ctx as *const _, nonce.len(), nonce.as_ptr());
        }

        Gcm{
            cipher: cipher,
            key: key_ctx,
            context: ctx,
        }
    }
}

impl<C: Cipher> Aead for Gcm<C> {
    fn digest_size(&self) -> usize {
        ::nettle_sys::GCM_DIGEST_SIZE as usize
    }

    fn update(&mut self, ad: &[u8]) {
        unsafe {
            nettle_gcm_update(
                &mut self.context as *mut _,
                &self.key as *const _,
                ad.len(),
                ad.as_ptr());
        }
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            nettle_gcm_encrypt(
                &mut self.context as *mut _,
                &self.key as *const _,
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
            nettle_gcm_decrypt(
                &mut self.context as *mut _,
                &self.key as *const _,
                self.cipher.context() as *const _,
                C::raw_encrypt_function().ptr(),
                dst.len(),
                dst.as_mut_ptr(),
                src.as_ptr());
        }
    }

    fn digest(&mut self, digest: &mut [u8]) {
        unsafe {
            nettle_gcm_digest(
                &mut self.context as *mut _,
                &self.key as *const _,
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
    fn round_trip_gcm_twofish() {
        use cipher::Twofish;
        let mut enc = Gcm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2; Twofish::BLOCK_SIZE]);
        let mut dec = Gcm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2; Twofish::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Twofish::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Twofish>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Twofish>::DIGEST_SIZE];

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
    fn modify_ad_gcm_twofish() {
        use cipher::Twofish;
        let mut enc = Gcm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2; Twofish::BLOCK_SIZE]);
        let mut dec = Gcm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2; Twofish::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Twofish::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Twofish>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Twofish>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_twofish() {
        use cipher::Twofish;
        let mut enc = Gcm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2; Twofish::BLOCK_SIZE]);
        let mut dec = Gcm::<Twofish>::with_key_and_nonce(&vec![1; Twofish::KEY_SIZE],&vec![2; Twofish::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Twofish::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Twofish>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Twofish>::DIGEST_SIZE];

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
    fn round_trip_gcm_aes128() {
        use cipher::Aes128;
        let mut enc = Gcm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2; Aes128::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2; Aes128::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes128>::DIGEST_SIZE];

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
    fn modify_ad_gcm_aes128() {
        use cipher::Aes128;
        let mut enc = Gcm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2; Aes128::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2; Aes128::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Aes128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes128>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_aes128() {
        use cipher::Aes128;
        let mut enc = Gcm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2; Aes128::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes128>::with_key_and_nonce(&vec![1; Aes128::KEY_SIZE],&vec![2; Aes128::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes128>::DIGEST_SIZE];

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
    fn round_trip_gcm_aes192() {
        use cipher::Aes192;
        let mut enc = Gcm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2; Aes192::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2; Aes192::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes192>::DIGEST_SIZE];

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
    fn modify_ad_gcm_aes192() {
        use cipher::Aes192;
        let mut enc = Gcm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2; Aes192::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2; Aes192::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Aes192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes192>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_aes192() {
        use cipher::Aes192;
        let mut enc = Gcm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2; Aes192::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes192>::with_key_and_nonce(&vec![1; Aes192::KEY_SIZE],&vec![2; Aes192::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes192>::DIGEST_SIZE];

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
    fn round_trip_gcm_aes256() {
        use cipher::Aes256;
        let mut enc = Gcm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2; Aes256::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2; Aes256::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes256>::DIGEST_SIZE];

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
    fn modify_ad_gcm_aes256() {
        use cipher::Aes256;
        let mut enc = Gcm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2; Aes256::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2; Aes256::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Aes256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes256>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_aes256() {
        use cipher::Aes256;
        let mut enc = Gcm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2; Aes256::BLOCK_SIZE]);
        let mut dec = Gcm::<Aes256>::with_key_and_nonce(&vec![1; Aes256::KEY_SIZE],&vec![2; Aes256::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Aes256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Aes256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Aes256>::DIGEST_SIZE];

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
    fn round_trip_gcm_camellia128() {
        use cipher::Camellia128;
        let mut enc = Gcm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2; Camellia128::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2; Camellia128::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia128>::DIGEST_SIZE];

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
    fn modify_ad_gcm_camellia128() {
        use cipher::Camellia128;
        let mut enc = Gcm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2; Camellia128::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2; Camellia128::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Camellia128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia128>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_camellia128() {
        use cipher::Camellia128;
        let mut enc = Gcm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2; Camellia128::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia128>::with_key_and_nonce(&vec![1; Camellia128::KEY_SIZE],&vec![2; Camellia128::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia128::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia128>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia128>::DIGEST_SIZE];

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
    fn round_trip_gcm_camellia192() {
        use cipher::Camellia192;
        let mut enc = Gcm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2; Camellia192::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2; Camellia192::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia192>::DIGEST_SIZE];

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
    fn modify_ad_gcm_camellia192() {
        use cipher::Camellia192;
        let mut enc = Gcm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2; Camellia192::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2; Camellia192::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Camellia192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia192>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_camellia192() {
        use cipher::Camellia192;
        let mut enc = Gcm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2; Camellia192::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia192>::with_key_and_nonce(&vec![1; Camellia192::KEY_SIZE],&vec![2; Camellia192::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia192::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia192>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia192>::DIGEST_SIZE];

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
    fn round_trip_gcm_camellia256() {
        use cipher::Camellia256;
        let mut enc = Gcm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2; Camellia256::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2; Camellia256::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia256>::DIGEST_SIZE];

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
    fn modify_ad_gcm_camellia256() {
        use cipher::Camellia256;
        let mut enc = Gcm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2; Camellia256::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2; Camellia256::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Camellia256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia256>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_camellia256() {
        use cipher::Camellia256;
        let mut enc = Gcm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2; Camellia256::BLOCK_SIZE]);
        let mut dec = Gcm::<Camellia256>::with_key_and_nonce(&vec![1; Camellia256::KEY_SIZE],&vec![2; Camellia256::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Camellia256::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Camellia256>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Camellia256>::DIGEST_SIZE];

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
    fn round_trip_gcm_serpent() {
        use cipher::Serpent;
        let mut enc = Gcm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2; Serpent::BLOCK_SIZE]);
        let mut dec = Gcm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2; Serpent::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Serpent::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Serpent>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Serpent>::DIGEST_SIZE];

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
    fn modify_ad_gcm_serpent() {
        use cipher::Serpent;
        let mut enc = Gcm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2; Serpent::BLOCK_SIZE]);
        let mut dec = Gcm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2; Serpent::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let mut input_ad = vec![1u8; Serpent::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Serpent>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Serpent>::DIGEST_SIZE];

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
    fn modify_ciphertext_gcm_serpent() {
        use cipher::Serpent;
        let mut enc = Gcm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2; Serpent::BLOCK_SIZE]);
        let mut dec = Gcm::<Serpent>::with_key_and_nonce(&vec![1; Serpent::KEY_SIZE],&vec![2; Serpent::BLOCK_SIZE]);
        let input_plaintext = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let input_ad = vec![1u8; Serpent::BLOCK_SIZE * 5];
        let mut ciphertext = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut digest = vec![2u8; Gcm::<Serpent>::DIGEST_SIZE];
        let mut output_plaintext = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut output_digest = vec![3u8; Gcm::<Serpent>::DIGEST_SIZE];

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
