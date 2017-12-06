use nettle_sys::{
    nettle_cbc_encrypt,
    nettle_cbc_decrypt,
};
use Cipher;

pub struct Cbc<C: Cipher> {
    cipher: C,
}

impl<C: Cipher> Cbc<C> {
    pub fn with_cipher(c: C) -> Self {
        Cbc{ cipher: c }
    }

    pub fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        unsafe {
            let ptr = C::raw_encrypt_function();
            nettle_cbc_encrypt(self.cipher.context(), ptr.ptr(), C::BLOCK_SIZE, iv.as_mut_ptr(), dst.len(), dst.as_mut_ptr(), src.as_ptr());
        }
    }

    pub fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) {
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
        let enc = Twofish::with_encrypt_key(&vec![0; Twofish::KEY_SIZE]);
        let dec = Twofish::with_decrypt_key(&vec![0; Twofish::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
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
        let enc = Serpent::with_encrypt_key(&vec![0; Serpent::KEY_SIZE]);
        let dec = Serpent::with_decrypt_key(&vec![0; Serpent::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
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
        let enc = Des3::with_encrypt_key(&vec![0; Des3::KEY_SIZE]);
        let dec = Des3::with_decrypt_key(&vec![0; Des3::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
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
        let enc = Cast128::with_encrypt_key(&vec![0; Cast128::KEY_SIZE]);
        let dec = Cast128::with_decrypt_key(&vec![0; Cast128::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
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
        let enc = Camellia128::with_encrypt_key(&vec![0; Camellia128::KEY_SIZE]);
        let dec = Camellia128::with_decrypt_key(&vec![0; Camellia128::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
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
        let enc = Camellia192::with_encrypt_key(&vec![0; Camellia192::KEY_SIZE]);
        let dec = Camellia192::with_decrypt_key(&vec![0; Camellia192::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
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
        let enc = Camellia256::with_encrypt_key(&vec![0; Camellia256::KEY_SIZE]);
        let dec = Camellia256::with_decrypt_key(&vec![0; Camellia256::KEY_SIZE]);
        let mut enc = Cbc::with_cipher(enc);
        let mut dec = Cbc::with_cipher(dec);
        let input = vec![1u8; Camellia256::BLOCK_SIZE * 10];
        let mut tmp = vec![2u8; Camellia256::BLOCK_SIZE * 10];
        let mut output = vec![3u8; Camellia256::BLOCK_SIZE * 10];
        let mut iv1 = vec![3u8; Camellia256::BLOCK_SIZE];
        let mut iv2 = vec![3u8; Camellia256::BLOCK_SIZE];

        enc.encrypt(&mut iv1, &mut tmp, &input);
        dec.decrypt(&mut iv2, &mut output, &tmp);

        assert_eq!(input, output);
    }
}
