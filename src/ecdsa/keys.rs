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
    nettle_ecdsa_generate_keypair,
    __gmpz_init,
    __gmpz_clear,
    __gmpz_sizeinbase,
};
use std::mem::zeroed;
use {Curve,Random,Result};

pub struct Scalar {
    pub(crate) scalar: ecc_scalar,
}

impl Scalar {
    pub fn new<C: Curve>(num: &[u8]) -> Result<Scalar> {
        unsafe {
            let mut scalar: ecc_scalar = zeroed();

            nettle_ecc_scalar_init(&mut scalar as *mut _, C::get_curve());
            let mut mpz = zeroed();

            __gmpz_init(&mut mpz as *mut _);
            nettle_mpz_set_str_256_u(&mut mpz, num.len(), num.as_ptr());

            if nettle_ecc_scalar_set(&mut scalar as *mut _, &mut mpz) == 1 {
                __gmpz_clear(&mut mpz as *mut _);

                Ok(Scalar{ scalar: scalar })
            } else {
                __gmpz_clear(&mut mpz as *mut _);

                Err("Invalid num".into())
            }
        }
    }

    pub fn get(&self) -> Box<[u8]> {
        unsafe {
            let mut mpz = zeroed();

            __gmpz_init(&mut mpz as *mut _);
            nettle_ecc_scalar_get(&self.scalar as *const _, &mut mpz);

            let mut ret = vec![0u8; __gmpz_sizeinbase(&mpz, 256)];
            nettle_mpz_get_str_256(ret.len(), ret.as_mut_ptr(), &mut mpz);
            __gmpz_clear(&mut mpz as *mut _);

            ret.into()
        }
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        unsafe {
            nettle_ecc_scalar_clear(&mut self.scalar as *mut _);
        }
    }
}

pub struct Point {
    pub(crate) point: ecc_point,
}

impl Point {
    pub fn new<C: Curve>(x: &[u8], y: &[u8]) -> Result<Point> {
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

                Ok(Point{ point: point })
            } else {
                __gmpz_clear(&mut x_mpz as *mut _);
                __gmpz_clear(&mut y_mpz as *mut _);

                Err("Invalid coordinates".into())
            }
        }
    }

    pub fn get(&self) -> (Box<[u8]>,Box<[u8]>) {
        unsafe {
            let mut x_mpz = zeroed();
            let mut y_mpz = zeroed();

            __gmpz_init(&mut x_mpz as *mut _);
            __gmpz_init(&mut y_mpz as *mut _);
            nettle_ecc_point_get(&self.point as *const _, &mut x_mpz, &mut y_mpz);

            let mut x_ret = vec![0u8; __gmpz_sizeinbase(&x_mpz, 256)];
            let mut y_ret = vec![0u8; __gmpz_sizeinbase(&y_mpz, 256)];
            nettle_mpz_get_str_256(x_ret.len(), x_ret.as_mut_ptr(), &mut x_mpz);
            nettle_mpz_get_str_256(y_ret.len(), y_ret.as_mut_ptr(), &mut y_mpz);
            __gmpz_clear(&mut x_mpz as *mut _);
            __gmpz_clear(&mut y_mpz as *mut _);

            (x_ret.into(),y_ret.into())
        }
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        unsafe {
            nettle_ecc_point_clear(&mut self.point as *mut _);
        }
    }
}

pub fn generate_keypair<C: Curve, R: Random>(random: &mut R) -> Result<(Point,Scalar)> {
    unsafe {
        let mut point = zeroed();
        let mut scalar = zeroed();

        nettle_ecc_point_init(&mut point, C::get_curve());
        nettle_ecc_scalar_init(&mut scalar, C::get_curve());
        nettle_ecdsa_generate_keypair(&mut point, &mut scalar, random.context(), Some(R::random));

        let point = Point{ point: point };
        let scalar = Scalar{ scalar: scalar };

        Ok((point,scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Yarrow;
    use Secp192r1;

    #[test]
    fn gen_keys() {
        let mut rand = Yarrow::default();

        for _ in 0..3 {
            let _ = generate_keypair::<Secp192r1,_>(&mut rand).unwrap();
        }
    }
}
