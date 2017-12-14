use Cipher;

pub trait Aead<C: Cipher> {
    const DIGEST_SIZE: usize;

    fn update(&mut self, ad: &[u8]);

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]);
    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]);

    fn digest(&mut self, digest: &mut [u8]);
}
