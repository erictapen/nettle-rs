extern crate nettle_sys;

mod sha1;
pub use sha1::{
    Sha1,
    SHA1_DIGEST_SIZE,
};
