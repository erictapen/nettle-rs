/// Hash function.
///
/// Cryptographic hash functions compute a fixed length checksum (also called digest) from variable length data.
pub trait Hash {
    /// Size of the digest in bytes
    const DIGEST_SIZE: usize;

    /// Writes data into the hash function.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash function and writes the digest into the provided slice. `digest` must be
    /// at least DIGEST_SIZE bytes large, otherwise the digest will be truncated. Resets the hash
    /// function contexts.
    fn digest(&mut self, digest: &mut [u8]);
}
