use nettle_sys::{
    __gmpz_init,
    __gmpz_clear,
    mpz_t,
    nettle_dsa_generate_keypair,
};
use std::mem::zeroed;
use super::Params;
use Random;

pub struct PublicKey {
    pub(crate) public: mpz_t,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            __gmpz_clear(&mut self.public[0] as *mut _);
        }
    }
}

pub struct PrivateKey {
    pub(crate) private: mpz_t,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            __gmpz_clear(&mut self.private[0] as *mut _);
        }
    }
}

pub fn generate_keypair<R: Random>(params: &Params, random: &mut R) -> (PublicKey,PrivateKey) {
    unsafe {
        let mut public: mpz_t = zeroed();
        let mut private: mpz_t = zeroed();

        __gmpz_init(&mut public[0] as *mut _);
        __gmpz_init(&mut private[0] as *mut _);

        nettle_dsa_generate_keypair(&params.params, &mut public[0], &mut private[0], random.context(), Some(R::random));

        let ret_pub = PublicKey{ public: public };
        let ret_key = PrivateKey{ private: private };

        (ret_pub,ret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Yarrow;
    use dsa::Params;

    #[test]
    fn generate_key() {
        let mut rand = Yarrow::default();
        let params = Params::new(&mut rand,1024,160).unwrap();

        for _ in 0..3 {
            let _ = generate_keypair(&params,&mut rand);
        }
    }
}