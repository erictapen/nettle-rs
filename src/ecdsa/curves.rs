use nettle_sys::{
    nettle_get_secp_192r1,
    nettle_get_secp_224r1,
    nettle_get_secp_256r1,
    nettle_get_secp_384r1,
    nettle_get_secp_521r1,
    ecc_curve,
};

pub trait Curve {
    unsafe fn get_curve() -> *const ecc_curve;
}

pub struct Secp192r1;

impl Curve for Secp192r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_192r1()
    }
}

pub struct Secp224r1;

impl Curve for Secp224r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_224r1()
    }
}

pub struct Secp256r1;

impl Curve for Secp256r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_256r1()
    }
}

pub struct Secp384r1;

impl Curve for Secp384r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_384r1()
    }
}

pub struct Secp521r1;

impl Curve for Secp521r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_521r1()
    }
}
