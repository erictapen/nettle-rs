use nettle_sys::{
    nettle_dsa_sign,
    nettle_dsa_verify,
};
use std::mem::zeroed;
use {Random,Result};
use super::{
    Signature,
    Params,
    PublicKey,
    PrivateKey,
};

/// Sign `digest` using key `private` and ring `params`. Siging may fail if `digest` is larger than
/// `q` or not co-prime to `pq`.
pub fn sign<R: Random>(params: &Params, private: &mut PrivateKey, digest: &[u8], random: &mut R) -> Result<Signature> {
    unsafe {
        let mut ret = zeroed();
        let res = nettle_dsa_sign(&params.params, &mut private.private[0], random.context(), Some(R::random), digest.len(), digest.as_ptr(), &mut ret as *mut _);

        if res == 1 {
            Ok(Signature{ signature: ret })
        } else {
            Err("Signing failed".into())
        }
    }
}

/// Verifies `signature` of `digest` by `public` over ring `params`. Returns `true` if the
/// signature is valid.
pub fn verify(params: &Params, public: &mut PublicKey, digest: &[u8], signature: &Signature) -> bool {
    unsafe {
        nettle_dsa_verify(&params.params, &mut public.public[0], digest.len(), digest.as_ptr(), &signature.signature) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Yarrow;
    use dsa::generate_keypair;

    #[test]
    fn sign_verify() {
        let mut rand = Yarrow::default();
        let params = Params::generate(&mut rand, 1024, 160).unwrap();
        let (mut public,mut private) = generate_keypair(&params, &mut rand);

        for _ in 0..3 {
            let mut msg = [0u8; 160];

            rand.random(&mut msg);
            let sig = sign(&params, &mut private, &msg, &mut rand).unwrap();

            assert!(verify(&params, &mut public, &msg, &sig));
        }

        for _ in 0..3 {
            let mut msg = [0u8; 160];

            rand.random(&mut msg);
            let sig = sign(&params, &mut private, &msg, &mut rand).unwrap();
            rand.random(&mut msg);

            assert!(!verify(&params, &mut public, &msg, &sig));
        }
    }
}
