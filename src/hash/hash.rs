use nettle_sys::nettle_hash;

/// Hash function.
///
/// Cryptographic hash functions compute a fixed length checksum (also called digest) from variable length data.
pub trait Hash {
    /// Nettle context a.k.a. `<hash>_ctx` of this hash
    type Context: Sized;

    /// Size of the digest in bytes
    const DIGEST_SIZE: usize;

    /// Pointer to the `nettle_hash` structure for this hash.
    unsafe fn nettle_hash() -> &'static nettle_hash;

    /// Writes data into the hash function.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash function and writes the digest into the provided slice. `digest` must be
    /// at least DIGEST_SIZE bytes large, otherwise the digest will be truncated. Resets the hash
    /// function contexts.
    fn digest(&mut self, digest: &mut [u8]);
}
