//! Nettle bindings

#![warn(missing_docs)]

extern crate nettle_sys;
extern crate libc;
extern crate rand;
#[macro_use]
extern crate error_chain;

mod errors {
    error_chain! { }
}
use errors::*;

mod helper;

pub mod hash;
pub use hash::{
    Hash,
};

pub mod cipher;
pub use cipher::{
    Cipher,
    BlockSizeIs16,
};

pub mod mode;
pub use mode::{
    Mode,
};

pub mod aead;
pub use aead::{
    Aead
};

pub mod mac;
pub use mac::{
    Mac,
};

pub mod kdf;
pub mod rsa;

pub mod random;
pub use random::{
    Random,
    Yarrow,
};

pub mod curve25519;
pub mod ed25519;
pub mod dsa;
pub mod ecdsa;
pub use ecdsa::{
    Curve,
    Secp192r1,
    Secp224r1,
    Secp256r1,
    Secp384r1,
    Secp521r1,
};
