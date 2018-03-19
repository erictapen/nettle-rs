/// A AEAD mode of operation.
pub trait Aead {
    /// Adds associated data `ad`.
    fn update(&mut self, ad: &[u8]);

    /// Encrypts one block `src` to `dst`.
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]);
    /// Decrypts one block `src` to `dst`.
    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]);

    /// Produce the digest.
    fn digest(&mut self, digest: &mut [u8]);

    /// Length of the digest in bytes.
    fn digest_size(&self) -> usize;
}
