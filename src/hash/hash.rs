use nettle_sys::nettle_hash;

/// Hash function.
///
/// Cryptographic hash functions compute a fixed length checksum (also called digest) from variable length data.
pub trait Hash {
    /// Size of the digest in bytes
    fn digest_size(&self) -> usize;

    /// Writes data into the hash function.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash function and writes the digest into the provided slice. `digest` must be
    /// at least DIGEST_SIZE bytes large, otherwise the digest will be truncated. Resets the hash
    /// function contexts.
    fn digest(&mut self, digest: &mut [u8]);
}

/// Nettle context a.k.a. `<hash>_ctx` of this hash
pub trait NettleHash: Hash + Default {
    type Context: Sized;

    /// Pointer to the `nettle_hash` structure for this hash.
    unsafe fn nettle_hash() -> &'static nettle_hash;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polymorphic_one_shot() {
        use hash::{Sha224,Sha3_512};

        fn hash_with<H: Hash + Default>(data: &[u8]) -> Vec<u8> {
            let mut h = H::default();
            let mut ret = vec![0u8; h.digest_size()];

            h.update(data);
            h.digest(&mut ret);

            ret
        }

        let test = &b"test123"[..];

        hash_with::<Sha224>(test);
        hash_with::<Sha3_512>(test);
    }

    #[test]
    fn polymorphic_multiple() {
        use hash::{Sha224,Sha3_512};

        fn hash_with<H: Hash>(hash: &mut H, data: &[u8]) {
            hash.update(data);
        }

        let test = &b"test123"[..];

        {
            let mut h = Sha224::default();
            let mut ret = vec![0u8; h.digest_size()];


            hash_with(&mut h,test);
            h.digest(&mut ret);
        }

        {
            let mut h = Sha3_512::default();
            let mut ret = vec![0u8; h.digest_size()];

            hash_with(&mut h,test);
            h.digest(&mut ret);
        }
    }
}
