use nettle_sys::{
    nettle_ecdsa_sign,
    nettle_ecdsa_verify,
};
use std::mem::zeroed;
use {dsa,Random};
use super::{PrivateKey,PublicKey};

/// Signs `digest` using the key `private`. Returns the signature.
pub fn sign<R: Random>(private: &PrivateKey, digest: &[u8], random: &mut R) -> dsa::Signature {
    unsafe {
        let mut ret = zeroed();

        nettle_ecdsa_sign(&private.scalar, random.context(), Some(R::random), digest.len(), digest.as_ptr(), &mut ret as *mut _);
        dsa::Signature{ signature: ret }
    }
}

/// Verify `signature` of `digest` using the key `public`. Returns `true` if the signature is
/// valid.
pub fn verify(public: &PublicKey, digest: &[u8], signature: &dsa::Signature) -> bool {
    unsafe {
        nettle_ecdsa_verify(&public.point, digest.len(), digest.as_ptr(), &signature.signature as *const _) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::generate_keypair;
    use Yarrow;
    use Secp192r1;

    #[test]
    fn sign_verify() {
        let mut rand = Yarrow::default();
        let (public,private) = generate_keypair::<Secp192r1,_>(&mut rand).unwrap();

        for _ in 0..3 {
            let mut msg = [0u8; 160];

            rand.random(&mut msg);
            let sig = sign(&private, &msg, &mut rand);

            assert!(verify(&public, &msg, &sig));
        }

        for _ in 0..3 {
            let mut msg = [0u8; 160];

            rand.random(&mut msg);
            let sig = sign(&private, &msg, &mut rand);
            rand.random(&mut msg);

            assert!(!verify(&public, &msg, &sig));
        }
    }
}
