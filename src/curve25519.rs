//! Elliptic curve Diffie-Hellman using D.J. Bernstein's Curve25519.

use nettle_sys::{
    nettle_curve25519_mul,
    nettle_curve25519_mul_g,
};
use {
    Result,
    Error,
};

/// Size of the public and secret keys in bytes.
pub const CURVE25519_SIZE: usize = ::nettle_sys::CURVE25519_SIZE as usize;

/// Derive DH public key.
///
/// Computes the public key `q` for a given secret `n`. Returns an error if `q` or `n` are not
/// `CURVE25519_SIZE` bytes long.
pub fn mul_g(q: &mut [u8], n: &[u8]) -> Result<()> {
    if q.len() != CURVE25519_SIZE {
        return Err(Error::InvalidArgument{ argument_name: "q" }.into());
    }
    if n.len() != CURVE25519_SIZE {
        return Err(Error::InvalidArgument{ argument_name: "n" }.into());
    }

    unsafe {
        nettle_curve25519_mul_g(q.as_mut_ptr(), n.as_ptr());
    }

    Ok(())
}

/// Derive DH shared secret.
///
/// Computes the shared secret `q` for our secret key `n` and the other parties public key `p`.
/// Results an error if `q`, `n` or `p` are not `CURVE25519_SIZE` bytes long.
pub fn mul(q: &mut [u8], n: &[u8], p: &[u8]) -> Result<()> {
    if q.len() != CURVE25519_SIZE {
        return Err(Error::InvalidArgument{ argument_name: "q" }.into());
    }
    if n.len() != CURVE25519_SIZE {
        return Err(Error::InvalidArgument{ argument_name: "n" }.into());
    }
    if p.len() != CURVE25519_SIZE {
        return Err(Error::InvalidArgument{ argument_name: "p" }.into());
    }

    unsafe {
        nettle_curve25519_mul(q.as_mut_ptr(), n.as_ptr(), p.as_ptr());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7748() {
        let alice_priv = &b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a"[..];
        let alice_pub = &b"\x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a"[..];
        let bob_priv = &b"\x5d\xab\x08\x7e\x62\x4a\x8a\x4b\x79\xe1\x7f\x8b\x83\x80\x0e\xe6\x6f\x3b\xb1\x29\x26\x18\xb6\xfd\x1c\x2f\x8b\x27\xff\x88\xe0\xeb"[..];
        let bob_pub = &b"\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4\xd3\x5b\x61\xc2\xec\xe4\x35\x37\x3f\x83\x43\xc8\x5b\x78\x67\x4d\xad\xfc\x7e\x14\x6f\x88\x2b\x4f"[..];
        let shared = &b"\x4a\x5d\x9d\x5b\xa4\xce\x2d\xe1\x72\x8e\x3b\xf4\x80\x35\x0f\x25\xe0\x7e\x21\xc9\x47\xd1\x9e\x33\x76\xf0\x9b\x3c\x1e\x16\x17\x42"[..];
        let mut tmp = vec![0u8;32];

        assert!(mul_g(&mut tmp,alice_priv).is_ok());
        assert_eq!(tmp, alice_pub);

        assert!(mul_g(&mut tmp,bob_priv).is_ok());
        assert_eq!(tmp, bob_pub);

        assert!(mul(&mut tmp,alice_priv,bob_pub).is_ok());
        assert_eq!(tmp, shared);

        assert!(mul(&mut tmp,bob_priv,alice_pub).is_ok());
        assert_eq!(tmp, shared);
    }
}
