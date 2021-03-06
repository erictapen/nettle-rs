use nettle_sys::{
    nettle_cbc_encrypt,
    nettle_cbc_decrypt,
};
use Cipher;
use Mode;

/// Cipher block chaining mode.
pub struct Cbc<C: Cipher> {
    cipher: C,
}

impl<C: Cipher> Cbc<C> {
    /// Create a new encrypting CBC instance with `key`.
    pub fn with_encrypt_key(key: &[u8]) -> Self {
        Cbc{ cipher: C::with_encrypt_key(key) }
    }

    /// Create a new decrypting CBC instance with `key`.
    pub fn with_decrypt_key(key: &[u8]) -> Self {
        Cbc{ cipher: C::with_decrypt_key(key) }
    }
}

impl<C: Cipher> Mode for Cbc<C> {
    fn block_size(&self) -> usize { C::BLOCK_SIZE }

    fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            let ptr = C::raw_encrypt_function();
            nettle_cbc_encrypt(self.cipher.context(), ptr.ptr(), C::BLOCK_SIZE, iv.as_mut_ptr(), dst.len(), dst.as_mut_ptr(), src.as_ptr());
        }
    }

    fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            let ptr = C::raw_decrypt_function();
            nettle_cbc_decrypt(self.cipher.context(), ptr.ptr(), C::BLOCK_SIZE, iv.as_mut_ptr(), dst.len(), dst.as_mut_ptr(), src.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_cbc_twofish() {
        use cipher::Twofish;
        let mut enc = Cbc::<Twofish>::with_encrypt_key(&vec![0; Twofish::KEY_SIZE]);
        let mut dec = Cbc::<Twofish>::with_decrypt_key(&vec![0; Twofish::KEY_SIZE]);
        let input = vec![1u8; Twofish::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Twofish::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Twofish::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Twofish::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Twofish::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_serpent() {
        use cipher::Serpent;
        let mut enc = Cbc::<Serpent>::with_encrypt_key(&vec![0; Serpent::KEY_SIZE]);
        let mut dec = Cbc::<Serpent>::with_decrypt_key(&vec![0; Serpent::KEY_SIZE]);
        let input = vec![1u8; Serpent::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Serpent::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Serpent::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Serpent::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Serpent::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_des3() {
        use cipher::Des3;
        let mut enc = Cbc::<Des3>::with_encrypt_key(&vec![0; Des3::KEY_SIZE]);
        let mut dec = Cbc::<Des3>::with_decrypt_key(&vec![0; Des3::KEY_SIZE]);
        let input = vec![1u8; Des3::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Des3::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Des3::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Des3::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Des3::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_cast128() {
        use cipher::Cast128;
        let mut enc = Cbc::<Cast128>::with_encrypt_key(&vec![0; Cast128::KEY_SIZE]);
        let mut dec = Cbc::<Cast128>::with_decrypt_key(&vec![0; Cast128::KEY_SIZE]);
        let input = vec![1u8; Cast128::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Cast128::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Cast128::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Cast128::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Cast128::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_camellia128() {
        use cipher::Camellia128;
        let mut enc = Cbc::<Camellia128>::with_encrypt_key(&vec![0; Camellia128::KEY_SIZE]);
        let mut dec = Cbc::<Camellia128>::with_decrypt_key(&vec![0; Camellia128::KEY_SIZE]);
        let input = vec![1u8; Camellia128::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Camellia128::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Camellia128::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Camellia128::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Camellia128::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_camellia192() {
        use cipher::Camellia192;
        let mut enc = Cbc::<Camellia192>::with_encrypt_key(&vec![0; Camellia192::KEY_SIZE]);
        let mut dec = Cbc::<Camellia192>::with_decrypt_key(&vec![0; Camellia192::KEY_SIZE]);
        let input = vec![1u8; Camellia192::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Camellia192::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Camellia192::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Camellia192::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Camellia192::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_camellia256() {
        use cipher::Camellia256;
        let mut enc = Cbc::<Camellia256>::with_encrypt_key(&vec![0; Camellia256::KEY_SIZE]);
        let mut dec = Cbc::<Camellia256>::with_decrypt_key(&vec![0; Camellia256::KEY_SIZE]);
        let input = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Camellia256::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Camellia256::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_blowfish() {
        use cipher::Blowfish;
        let mut enc = Cbc::<Blowfish>::with_encrypt_key(&vec![0; Blowfish::KEY_SIZE]);
        let mut dec = Cbc::<Blowfish>::with_decrypt_key(&vec![0; Blowfish::KEY_SIZE]);
        let input = vec![1u8; Blowfish::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Blowfish::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Blowfish::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Blowfish::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Blowfish::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_aes128() {
        use cipher::Aes128;
        let mut enc = Cbc::<Aes128>::with_encrypt_key(&vec![0; Aes128::KEY_SIZE]);
        let mut dec = Cbc::<Aes128>::with_decrypt_key(&vec![0; Aes128::KEY_SIZE]);
        let input = vec![1u8; Aes128::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Aes128::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Aes128::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Aes128::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Aes128::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_aes192() {
        use cipher::Aes192;
        let mut enc = Cbc::<Aes192>::with_encrypt_key(&vec![0; Aes192::KEY_SIZE]);
        let mut dec = Cbc::<Aes192>::with_decrypt_key(&vec![0; Aes192::KEY_SIZE]);
        let input = vec![1u8; Aes192::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Aes192::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Aes192::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Aes192::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Aes192::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_aes256() {
        use cipher::Aes256;
        let mut enc = Cbc::<Aes256>::with_encrypt_key(&vec![0; Aes256::KEY_SIZE]);
        let mut dec = Cbc::<Aes256>::with_decrypt_key(&vec![0; Aes256::KEY_SIZE]);
        let input = vec![1u8; Aes256::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Aes256::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Aes256::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Aes256::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Aes256::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_des() {
        use cipher::insecure_do_not_use::Des;
        let mut enc = Cbc::<Des>::with_encrypt_key(&vec![0; Des::KEY_SIZE]);
        let mut dec = Cbc::<Des>::with_decrypt_key(&vec![0; Des::KEY_SIZE]);
        let input = vec![1u8; Des::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Des::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Des::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Des::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Des::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_arctwo() {
        use cipher::insecure_do_not_use::ArcTwo;
        let mut enc = Cbc::<ArcTwo>::with_encrypt_key(&vec![0; ArcTwo::KEY_SIZE]);
        let mut dec = Cbc::<ArcTwo>::with_decrypt_key(&vec![0; ArcTwo::KEY_SIZE]);
        let input = vec![1u8; ArcTwo::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; ArcTwo::BLOCK_SIZE * 10];
        let mut output = vec![3u8; ArcTwo::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; ArcTwo::BLOCK_SIZE];
        let mut iv2 = vec![3u8; ArcTwo::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip_cbc_arcfour() {
        use cipher::insecure_do_not_use::ArcFour;
        let mut enc = Cbc::<ArcFour>::with_encrypt_key(&vec![0; ArcFour::KEY_SIZE]);
        let mut dec = Cbc::<ArcFour>::with_decrypt_key(&vec![0; ArcFour::KEY_SIZE]);
        let input = vec![1u8; ArcFour::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; ArcFour::BLOCK_SIZE * 10];
        let mut output = vec![3u8; ArcFour::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; ArcFour::BLOCK_SIZE];
        let mut iv2 = vec![3u8; ArcFour::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }
}
