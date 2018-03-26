use ::nettle_sys::{
    ecc_point,
    ecc_scalar,
    nettle_ecc_scalar_get,
    nettle_ecc_scalar_set,
    nettle_ecc_scalar_init,
    nettle_ecc_scalar_clear,
    nettle_ecc_point_init,
    nettle_ecc_point_get,
    nettle_ecc_point_set,
    nettle_ecc_point_clear,
    nettle_mpz_set_str_256_u,
    nettle_mpz_get_str_256,
    nettle_mpz_sizeinbase_256_u,
    nettle_ecdsa_generate_keypair,
    __gmpz_init,
    __gmpz_clear,
};
use std::mem::zeroed;
use helper::convert_buffer_to_gmpz;
use errors::Error;
use {Curve,Random,Result};

/// Secret scalar.
pub struct PrivateKey {
    pub(crate) scalar: ecc_scalar,
}

impl PrivateKey {
    /// Creates a new private scalar based on the big endian integer `num`.
    pub fn new<C: Curve>(num: &[u8]) -> Result<PrivateKey> {
        unsafe {
            let mut scalar: ecc_scalar = zeroed();

            nettle_ecc_scalar_init(&mut scalar as *mut _, C::get_curve());
            let mut mpz = zeroed();

            __gmpz_init(&mut mpz as *mut _);
            nettle_mpz_set_str_256_u(&mut mpz, num.len(), num.as_ptr());

            if nettle_ecc_scalar_set(&mut scalar as *mut _, &mut mpz) == 1 {
                __gmpz_clear(&mut mpz as *mut _);

                Ok(PrivateKey{ scalar: scalar })
            } else {
                __gmpz_clear(&mut mpz as *mut _);

                Err(Error::InvalidArgument{ argument_name: "num" })
            }
        }
    }

    /// Returns the private scalar as big endian integer.
    pub fn as_bytes(&self) -> Box<[u8]> {
        unsafe {
            let mut mpz = zeroed();

            __gmpz_init(&mut mpz as *mut _);
            nettle_ecc_scalar_get(&self.scalar as *const _, &mut mpz);

            let mut ret = vec![0u8; nettle_mpz_sizeinbase_256_u(&mut mpz)];
            nettle_mpz_get_str_256(ret.len(), ret.as_mut_ptr(), &mut mpz);
            __gmpz_clear(&mut mpz as *mut _);

            ret.into()
        }
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        unsafe {
            // XXX: no nettle_ecc_scalar_copy()
            let buf = self.as_bytes();
            let mut mpz = convert_buffer_to_gmpz(&*buf);
            let mut ret: ecc_scalar = zeroed();

            nettle_ecc_scalar_init(&mut ret, self.scalar.ecc);
            assert_eq!(nettle_ecc_scalar_set(&mut ret, &mut mpz), 1);
            __gmpz_clear(&mut mpz);

            PrivateKey{ scalar: ret }
        }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            nettle_ecc_scalar_clear(&mut self.scalar as *mut _);
        }
    }
}

/// Public point.
pub struct PublicKey {
    pub(crate) point: ecc_point,
}

impl PublicKey {
    /// Creates a new point on `C` with coordinates `x` & `y`. Can fail if the given point is not
    /// on the curve.
    pub fn new<C: Curve>(x: &[u8], y: &[u8]) -> Result<PublicKey> {
        unsafe {
            let mut point: ecc_point = zeroed();
            nettle_ecc_point_init(&mut point as *mut _, C::get_curve());

            let mut x_mpz = zeroed();
            __gmpz_init(&mut x_mpz as *mut _);
            nettle_mpz_set_str_256_u(&mut x_mpz, x.len(), x.as_ptr());

            let mut y_mpz = zeroed();
            __gmpz_init(&mut y_mpz as *mut _);
            nettle_mpz_set_str_256_u(&mut y_mpz, y.len(), y.as_ptr());

            if nettle_ecc_point_set(&mut point as *mut _, &mut x_mpz, &mut y_mpz) == 1 {
                __gmpz_clear(&mut x_mpz as *mut _);
                __gmpz_clear(&mut y_mpz as *mut _);

                Ok(PublicKey{ point: point })
            } else {
                __gmpz_clear(&mut x_mpz as *mut _);
                __gmpz_clear(&mut y_mpz as *mut _);

                Err(Error::InvalidArgument{ argument_name: "x or y" })
            }
        }
    }

    /// Returns the points coordinates as big endian integers.
    pub fn as_bytes(&self) -> (Box<[u8]>,Box<[u8]>) {
        unsafe {
            let mut x_mpz = zeroed();
            let mut y_mpz = zeroed();

            __gmpz_init(&mut x_mpz as *mut _);
            __gmpz_init(&mut y_mpz as *mut _);
            nettle_ecc_point_get(&self.point as *const _, &mut x_mpz, &mut y_mpz);

            let mut x_ret = vec![0u8; nettle_mpz_sizeinbase_256_u(&mut x_mpz)];
            let mut y_ret = vec![0u8; nettle_mpz_sizeinbase_256_u(&mut y_mpz)];
            nettle_mpz_get_str_256(x_ret.len(), x_ret.as_mut_ptr(), &mut x_mpz);
            nettle_mpz_get_str_256(y_ret.len(), y_ret.as_mut_ptr(), &mut y_mpz);
            __gmpz_clear(&mut x_mpz as *mut _);
            __gmpz_clear(&mut y_mpz as *mut _);

            (x_ret.into(),y_ret.into())
        }
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        unsafe {
            // XXX: no nettle_ecc_scalar_copy()
            let (buf_x,buf_y) = self.as_bytes();
            let mut mpz_x = convert_buffer_to_gmpz(&*buf_x);
            let mut mpz_y = convert_buffer_to_gmpz(&*buf_y);
            let mut ret: ecc_point = zeroed();

            nettle_ecc_point_init(&mut ret, self.point.ecc);
            assert_eq!(nettle_ecc_point_set(&mut ret, &mut mpz_x,&mut mpz_y), 1);
            __gmpz_clear(&mut mpz_x);
            __gmpz_clear(&mut mpz_y);

            PublicKey{ point: ret }
        }
    }
}


impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            nettle_ecc_point_clear(&mut self.point as *mut _);
        }
    }
}

/// Generates a new ECDSA key pair for siging.
pub fn generate_keypair<C: Curve, R: Random>(random: &mut R) -> Result<(PublicKey,PrivateKey)> {
    unsafe {
        let mut point = zeroed();
        let mut scalar = zeroed();

        nettle_ecc_point_init(&mut point, C::get_curve());
        nettle_ecc_scalar_init(&mut scalar, C::get_curve());
        nettle_ecdsa_generate_keypair(&mut point, &mut scalar, random.context(), Some(R::random));

        let point = PublicKey{ point: point };
        let scalar = PrivateKey{ scalar: scalar };

        Ok((point,scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::{sign,verify};
    use Yarrow;
    use Secp192r1;

    #[test]
    fn gen_keys() {
        let mut rand = Yarrow::default();

        for _ in 0..3 {
            let _ = generate_keypair::<Secp192r1,_>(&mut rand).unwrap();
        }
    }

    #[test]
    fn clone() {
        let mut rand = Yarrow::default();
        let (public,private) = generate_keypair::<Secp192r1,_>(&mut rand).unwrap();
        let mut msg = [0u8; 160];

        rand.random(&mut msg);
        let sig = sign(&private, &msg, &mut rand);
        let sig = sig.clone();

        assert!(verify(&public, &msg, &sig));
    }
}
