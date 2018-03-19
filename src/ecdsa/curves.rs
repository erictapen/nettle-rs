use nettle_sys::{
    nettle_get_secp_192r1,
    nettle_get_secp_224r1,
    nettle_get_secp_256r1,
    nettle_get_secp_384r1,
    nettle_get_secp_521r1,
    ecc_curve,
};

/// Elliptic curve for ECDSA.
pub trait Curve {
    /// Returns a pointer to the Nettle curve structure.
    unsafe fn get_curve() -> *const ecc_curve;
}

/// NIST secp192r1 a.k.a. P-192.
pub struct Secp192r1;

impl Curve for Secp192r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_192r1()
    }
}

/// NIST secp224r1 a.k.a. P-224.
pub struct Secp224r1;

impl Curve for Secp224r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_224r1()
    }
}

/// NIST secp256r1 a.k.a. P-256.
pub struct Secp256r1;

impl Curve for Secp256r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_256r1()
    }
}

/// NIST secp384r1 a.k.a. P-384.
pub struct Secp384r1;

impl Curve for Secp384r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_384r1()
    }
}

/// NIST secp521r1 a.k.a. P-521.
pub struct Secp521r1;

impl Curve for Secp521r1 {
    unsafe fn get_curve() -> *const ecc_curve {
        nettle_get_secp_521r1()
    }
}
