use nettle_sys::{
    dsa_params,
    nettle_dsa_params_init,
    nettle_dsa_params_clear,
    nettle_dsa_generate_params,
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
        unimplemented!()
    }

    pub fn p(&self) -> Box<[u8]> {
        unimplemented!()
    }

    pub fn q(&self) -> Box<[u8]> {
        unimplemented!()
    }

    pub fn g(&self) -> Box<[u8]> {
        unimplemented!()
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        unsafe {
            nettle_dsa_params_clear(&mut self.params as *mut _);
        }
    }
}

impl Params {
    pub fn new<R: Random>(random: &mut R, p_bits: usize, q_bits: usize) -> Result<Params> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use Yarrow;

    #[test]
    fn generate_params() {
        let mut rand = Yarrow::default();
        let _ = Params::new(&mut rand,1024,160).unwrap();
    }
}
