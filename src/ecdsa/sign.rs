use nettle_sys::{
    nettle_ecdsa_sign,
    nettle_ecdsa_verify,
};
use std::mem::zeroed;
use {dsa,Random};
use super::{PrivateKey,PublicKey};

pub fn sign<R: Random>(private: &PrivateKey, digest: &[u8], random: &mut R) -> dsa::Signature {
    unsafe {
        let mut ret = zeroed();

        nettle_ecdsa_sign(&private.scalar, random.context(), Some(R::random), digest.len(), digest.as_ptr(), &mut ret as *mut _);
        dsa::Signature{ signature: ret }
    }
}

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
        let (mut public,mut private) = generate_keypair::<Secp192r1,_>(&mut rand).unwrap();

        for _ in 0..3 {
            let mut msg = [0u8; 160];

            rand.random(&mut msg);
            let sig = sign(&mut private, &msg, &mut rand);

            assert!(verify(&mut public, &msg, &sig));
        }

        for _ in 0..3 {
            let mut msg = [0u8; 160];

            rand.random(&mut msg);
            let sig = sign(&mut private, &msg, &mut rand);
            rand.random(&mut msg);

            assert!(!verify(&mut public, &msg, &sig));
        }
    }
}
