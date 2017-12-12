use Cipher;

pub trait Mode<C: Cipher> {
    fn with_encrypt_key(key: &[u8]) -> Self;
    fn with_decrypt_key(key: &[u8]) -> Self;

    fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]);
    fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]);
}
