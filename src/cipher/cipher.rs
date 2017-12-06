/// Symmetric block or stream cipher.
///
/// Symmetric cipher encrypt and decrypt data using the same key.
pub trait Cipher {
    /// Block size in bytes.
    const BLOCK_SIZE: usize;
    /// Maximal key size in bytes.
    const KEY_SIZE: usize;

    /// Creates a new cipher instance for decryption. The `key` parameter must have size
    /// `KEY_SIZE`.
    fn with_decrypt_key(key: &[u8]) -> Self;

    /// Creates a new cipher instance for encryption. The `key` parameter must have size
    /// `KEY_SIZE`.
    fn with_encrypt_key(key: &[u8]) -> Self;

    /// Decrypt `src` into `dst`. Both must have the same length. That length must be a multiple of
    /// `BLOCK_SIZE`. Blocks are processed in ECB mode.
    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]);

    /// Encrypt `src` into `dst`. Both must have the same length. That length must be a multiple of
    /// `BLOCK_SIZE`. Blocks are processed in ECB mode.
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]);
}
