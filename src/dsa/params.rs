use nettle_sys::{
    dsa_params,
    nettle_dsa_params_init,
    nettle_dsa_params_clear,
    nettle_dsa_generate_params,
    __gmpz_init_set,
};
use helper::{
    convert_buffer_to_gmpz,
    convert_gmpz_to_buffer,
};
use std::ptr;
use std::mem::zeroed;
use {
    Random,
    Result
};

pub struct Params {
    pub(crate) params: dsa_params,
}

impl Params {
    pub fn new(p: &[u8], q: &[u8], g: &[u8]) -> Params {
        unsafe {
            let mut ret: dsa_params = zeroed();

            // XXX: probably not needed
            nettle_dsa_params_init(&mut ret as *mut _);

            ret.p[0] = convert_buffer_to_gmpz(p);
            ret.q[0] = convert_buffer_to_gmpz(q);
            ret.g[0] = convert_buffer_to_gmpz(g);

            Params{ params: ret }
        }
    }

    pub fn generate<R: Random>(random: &mut R, p_bits: usize, q_bits: usize) -> Result<Params> {
        unsafe {
            let mut ret = zeroed();

            nettle_dsa_params_init(&mut ret as *mut _);
            if nettle_dsa_generate_params(&mut ret as *mut _, random.context(), Some(R::random), ptr::null_mut(), None, p_bits as u32, q_bits as u32) == 1 {
                Ok(Params{ params: ret })
            } else {
                Err("Invalid q_bits and or p_bits values".into())
            }
        }
    }

    pub fn primes(&self) -> (Box<[u8]>,Box<[u8]>) {
        let p = convert_gmpz_to_buffer(self.params.p[0]);
        let q = convert_gmpz_to_buffer(self.params.q[0]);

        (p,q)
    }

    pub fn g(&self) -> Box<[u8]> {
        convert_gmpz_to_buffer(self.params.g[0])
    }
}

impl Clone for Params {
    fn clone(&self) -> Self {
        unsafe {
            let mut ret = zeroed();

            nettle_dsa_params_init(&mut ret);
            __gmpz_init_set(&mut ret.p[0], &self.params.p[0]);
            __gmpz_init_set(&mut ret.q[0], &self.params.q[0]);
            __gmpz_init_set(&mut ret.g[0], &self.params.g[0]);

            Params{ params: ret }
        }
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        unsafe {
            nettle_dsa_params_clear(&mut self.params as *mut _);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Yarrow;

    #[test]
    fn generate_params() {
        let mut rand = Yarrow::default();
        let _ = Params::generate(&mut rand,1024,160).unwrap();
    }
}
