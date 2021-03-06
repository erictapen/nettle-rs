use nettle_sys::{
    nettle_cfb_encrypt,
    nettle_cfb_decrypt,
};
use Cipher;
use Mode;

/// Cipher feedback mode.
pub struct Cfb<C: Cipher> {
    cipher: C,
}

impl<C: Cipher> Cfb<C> {
    /// Create a new encrypting CFB instance with `key`.
    pub fn with_encrypt_key(key: &[u8]) -> Self {
        Cfb{ cipher: C::with_encrypt_key(key) }
    }

    /// Create a new decrypting CFB instance with `key`.
    pub fn with_decrypt_key(key: &[u8]) -> Self {
        Cfb{ cipher: C::with_encrypt_key(key) }
    }
}

impl<C: Cipher> Mode for Cfb<C> {
    fn block_size(&self) -> usize { C::BLOCK_SIZE }

    fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            let ptr = C::raw_encrypt_function();
            nettle_cfb_encrypt(self.cipher.context(), ptr.ptr(), C::BLOCK_SIZE, iv.as_mut_ptr(), dst.len(), dst.as_mut_ptr(), src.as_ptr());
        }
    }

    fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            let ptr = C::raw_encrypt_function();
            nettle_cfb_decrypt(self.cipher.context(), ptr.ptr(), C::BLOCK_SIZE, iv.as_mut_ptr(), dst.len(), dst.as_mut_ptr(), src.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_cfb_twofish() {
        use cipher::Twofish;
        let mut enc = Cfb::<Twofish>::with_encrypt_key(&vec![0; Twofish::KEY_SIZE]);
        let mut dec = Cfb::<Twofish>::with_encrypt_key(&vec![0; Twofish::KEY_SIZE]);
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
    fn round_trip_cfb_serpent() {
        use cipher::Serpent;
        let mut enc = Cfb::<Serpent>::with_encrypt_key(&vec![0; Serpent::KEY_SIZE]);
        let mut dec = Cfb::<Serpent>::with_encrypt_key(&vec![0; Serpent::KEY_SIZE]);
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
    fn round_trip_cfb_des3() {
        use cipher::Des3;
        let mut enc = Cfb::<Des3>::with_encrypt_key(&vec![0; Des3::KEY_SIZE]);
        let mut dec = Cfb::<Des3>::with_encrypt_key(&vec![0; Des3::KEY_SIZE]);
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
    fn round_trip_cfb_cast128() {
        use cipher::Cast128;
        let mut enc = Cfb::<Cast128>::with_encrypt_key(&vec![0; Cast128::KEY_SIZE]);
        let mut dec = Cfb::<Cast128>::with_encrypt_key(&vec![0; Cast128::KEY_SIZE]);
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
    fn round_trip_cfb_camellia128() {
        use cipher::Camellia128;
        let mut enc = Cfb::<Camellia128>::with_encrypt_key(&vec![0; Camellia128::KEY_SIZE]);
        let mut dec = Cfb::<Camellia128>::with_encrypt_key(&vec![0; Camellia128::KEY_SIZE]);
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
    fn round_trip_cfb_camellia192() {
        use cipher::Camellia192;
        let mut enc = Cfb::<Camellia192>::with_encrypt_key(&vec![0; Camellia192::KEY_SIZE]);
        let mut dec = Cfb::<Camellia192>::with_encrypt_key(&vec![0; Camellia192::KEY_SIZE]);
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
    fn round_trip_cfb_camellia256() {
        use cipher::Camellia256;
        let mut enc = Cfb::<Camellia256>::with_encrypt_key(&vec![0; Camellia256::KEY_SIZE]);
        let mut dec = Cfb::<Camellia256>::with_encrypt_key(&vec![0; Camellia256::KEY_SIZE]);
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
    fn round_trip_cfb_blowfish() {
        use cipher::Blowfish;
        let mut enc = Cfb::<Blowfish>::with_encrypt_key(&vec![0; Blowfish::KEY_SIZE]);
        let mut dec = Cfb::<Blowfish>::with_encrypt_key(&vec![0; Blowfish::KEY_SIZE]);
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
    fn round_trip_cfb_aes128() {
        use cipher::Aes128;
        let mut enc = Cfb::<Aes128>::with_encrypt_key(&vec![0; Aes128::KEY_SIZE]);
        let mut dec = Cfb::<Aes128>::with_encrypt_key(&vec![0; Aes128::KEY_SIZE]);
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
    fn round_trip_cfb_aes192() {
        use cipher::Aes192;
        let mut enc = Cfb::<Aes192>::with_encrypt_key(&vec![0; Aes192::KEY_SIZE]);
        let mut dec = Cfb::<Aes192>::with_encrypt_key(&vec![0; Aes192::KEY_SIZE]);
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
    fn round_trip_cfb_aes256() {
        use cipher::Aes256;
        let mut enc = Cfb::<Aes256>::with_encrypt_key(&vec![0; Aes256::KEY_SIZE]);
        let mut dec = Cfb::<Aes256>::with_encrypt_key(&vec![0; Aes256::KEY_SIZE]);
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
    fn round_trip_cfb_des() {
        use cipher::insecure_do_not_use::Des;
        let mut enc = Cfb::<Des>::with_encrypt_key(&vec![0; Des::KEY_SIZE]);
        let mut dec = Cfb::<Des>::with_encrypt_key(&vec![0; Des::KEY_SIZE]);
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
    fn round_trip_cfb_arctwo() {
        use cipher::insecure_do_not_use::ArcTwo;
        let mut enc = Cfb::<ArcTwo>::with_encrypt_key(&vec![0; ArcTwo::KEY_SIZE]);
        let mut dec = Cfb::<ArcTwo>::with_encrypt_key(&vec![0; ArcTwo::KEY_SIZE]);
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
    fn round_trip_cfb_arcfour() {
        use cipher::insecure_do_not_use::ArcFour;
        let mut enc = Cfb::<ArcFour>::with_encrypt_key(&vec![0; ArcFour::KEY_SIZE]);
        let mut dec = Cfb::<ArcFour>::with_encrypt_key(&vec![0; ArcFour::KEY_SIZE]);
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
