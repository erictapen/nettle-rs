/// Block cipher mode of operation.
///
/// Block modes govern how a block cipher processes data spanning multiple blocks.
pub trait Mode {
    /// Block size of the underlying cipher in bytes.
    fn block_size(&self) -> usize;

    /// Encrypt a single block `src` using the initialization vector `iv` to a ciphertext block `dst`. Both `iv` and dst` are updated.
    ///
    /// # Panics
    /// The buffer `iv`, `dst` and `src` are expected to be at least as large as the block size of
    /// the underlying cipher. The function panics otherwise.
    fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]);

    /// Decrypt a single ciphertext block `src` using the initialization vector `iv` to a plaintext block `dst`. Both `iv` and dst` are updated.
    ///
    /// # Panics
    /// The buffer `iv`, `dst` and `src` are expected to be at least as large as the block size of
    /// the underlying cipher. The function panics otherwise.
    fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]);
}
