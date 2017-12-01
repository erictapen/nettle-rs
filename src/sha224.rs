use nettle_sys::{
    sha256_ctx,
    nettle_sha224_init,
    nettle_sha224_digest,
    nettle_sha256_update,
};
use std::default::Default;
use std::mem::zeroed;
use Hash;

/// 256 bit variant of the Secure Hash Algorithm 2 (SHA-2) defined in FIPS 180-4, truncated to 224
/// bit.
pub struct Sha224 {
    context: sha256_ctx,
}

impl Default for Sha224 {
    fn default() -> Self {
        let mut ctx = unsafe { zeroed() };

        unsafe { nettle_sha224_init(&mut ctx as *mut _); }

        Sha224{ context: ctx }
    }
}

impl Hash for Sha224 {
    const DIGEST_SIZE: usize = ::nettle_sys::SHA224_DIGEST_SIZE as usize;

    fn update(&mut self, data: &[u8]) {
        unsafe {
            nettle_sha256_update(&mut self.context as *mut _, data.len(), data.as_ptr());
        }
    }

    fn digest(&mut self, digest: &mut [u8]) {
        unsafe {
            nettle_sha224_digest(&mut self.context as *mut _, digest.len(), digest.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_nothing() {
        let _ = Sha224::default();
    }

    //  CAVS 11.0
    //  "SHA-224 ShortMsg" information
    //  SHA-224 tests are configured for BYTE oriented implementations
    //  Generated on Tue Mar 15 08:23:36 2011
    #[test]
    fn nist_cavs_short_msg() {
        let mut digest = vec![0u8; Sha224::DIGEST_SIZE];
        let mut ctx = Sha224::default();

        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9\x47\x61\x02\xbb\x28\x82\x34\xc4\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a\xc5\xb3\xe4\x2f");

        ctx.update(b"\x84");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x3c\xd3\x69\x21\xdf\x5d\x69\x63\xe7\x37\x39\xcf\x4d\x20\x21\x1e\x2d\x88\x77\xc1\x9c\xff\x08\x7a\xde\x9d\x0e\x3a");

        ctx.update(b"\x5c\x7b");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xda\xff\x9b\xce\x68\x5e\xb8\x31\xf9\x7f\xc1\x22\x5b\x03\xc2\x75\xa6\xc1\x12\xe2\xd6\xe7\x6f\x5f\xaf\x7a\x36\xe6");

        ctx.update(b"\x51\xca\x3d");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x2c\x89\x59\x02\x35\x15\x47\x6e\x38\x38\x8a\xbb\x43\x59\x9a\x29\x87\x6b\x4b\x33\xd5\x6a\xdc\x06\x03\x2d\xe3\xa2");

        ctx.update(b"\x60\x84\x34\x7e");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xae\x57\xc0\xa6\xd4\x97\x39\xba\x33\x8a\xdf\xa5\x3b\xda\xe0\x63\xe5\xc0\x91\x22\xb7\x76\x04\x78\x0a\x8e\xea\xa3");

        ctx.update(b"\x49\x3e\x14\x62\x3c");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x7f\x63\x1f\x29\x5e\x02\x4e\x74\x55\x20\x83\x24\x5c\xa8\xf9\x88\xa3\xfb\x65\x68\x0a\xe9\x7c\x30\x40\xd2\xe6\x5c");

        ctx.update(b"\xd7\x29\xd8\xcd\x16\x31");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x34\x2e\x8e\x6b\x23\xc1\xc6\xa5\x49\x10\x63\x1f\x09\x8e\x08\xe8\x36\x25\x9c\x57\xe4\x9c\x1b\x1d\x02\x3d\x16\x6d");

        ctx.update(b"\xcb\xf2\x06\x1e\x10\xfa\xa5");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x3a\xa7\x02\xb1\xb6\x6d\xc5\x7d\x7a\xec\x3c\xcd\xbd\xfb\xd8\x85\x92\xd7\x52\x0f\x84\x3b\xa5\xd0\xfa\x48\x11\x68");

        ctx.update(b"\x5f\x77\xb3\x66\x48\x23\xc3\x3e");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xbd\xf2\x1f\xf3\x25\xf7\x54\x15\x7c\xcf\x41\x7f\x48\x55\x36\x0a\x72\xe8\xfd\x11\x7d\x28\xc8\xfe\x7d\xa3\xea\x38");

        ctx.update(b"\x10\x71\x3b\x89\x4d\xe4\xa7\x34\xc0");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x03\x84\x26\x00\xc8\x6f\x5c\xd6\x0c\x3a\x21\x47\xa0\x67\xcb\x96\x2a\x05\x30\x3c\x34\x88\xb0\x5c\xb4\x53\x27\xbd");

        ctx.update(b"\x00\x64\x70\xd5\x7d\xad\x98\x93\xdc\x03");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xc9\x00\x26\xcd\xa5\xad\x24\x11\x50\x59\xc6\x2a\xe9\xad\xd5\x77\x93\xad\xe4\x45\xd4\x74\x22\x73\x28\x8b\xbc\xe7");

        ctx.update(b"\x6f\x29\xca\x27\x41\x90\x40\x07\x20\xbb\xa2");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xac\x53\x15\x79\x47\xaa\x4b\x2a\x19\x08\x91\x82\x38\x2a\x43\x63\xd1\x82\xdd\x8e\x4c\xa7\x9c\xd8\x57\x13\x90\xbe");

        ctx.update(b"\x17\xe8\x55\x61\x76\xfc\xca\x2a\xdd\xbd\xde\x29");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xcc\x6a\xd0\x48\x8d\xb0\x22\x20\x66\xf7\x40\x55\x7b\x57\x58\xa1\x9b\x30\x37\x2b\x30\x23\x32\x29\x5d\x8c\x3a\xff");

        ctx.update(b"\xdb\xf1\x63\x60\x1d\xb9\xa1\x22\xa4\x02\x68\x24\xde");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x98\x49\x84\x5f\x4e\x47\xe1\xec\xe9\xa1\xc1\xe0\x1a\x0d\x89\x6f\xfe\xa6\x1c\x6c\x88\x94\xa7\x5a\x11\xce\x5f\x49");

        ctx.update(b"\x5e\x1e\xf2\xad\x86\xce\xaf\x54\x39\xfe\x87\xd2\xec\x9b");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x22\x3c\x5d\x5d\x4a\x01\x16\xb3\x2c\xea\x04\x4f\x9a\xf0\xfe\x44\xba\xbe\xa1\xc5\xab\x20\x15\x02\x59\x1b\xcd\x5f");

        ctx.update(b"\x65\xf3\xb9\x86\x6f\xb8\x00\x2b\x53\xcf\xaf\x80\x6f\x70\x2f");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xb1\xe0\x80\x6a\x21\x8d\x59\x38\x21\xfd\xe8\xe9\xea\xcc\x44\xab\x52\x87\xc3\x22\x09\xa9\x4f\x01\x1a\xb6\x6b\x75");

        ctx.update(b"\xb7\x76\x70\x8f\xfb\x91\xb3\x51\x5a\xc4\x65\x98\xab\x9f\xa7\x96");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x42\x73\x11\xb1\xd7\xab\x24\x88\x79\x1c\x4d\xee\xb4\x25\x1d\x78\x3f\xe5\xf9\x80\x6b\xfd\xfb\x51\x88\xc5\x44\x3d");

        ctx.update(b"\xa4\xbc\x10\xb1\xa6\x2c\x96\xd4\x59\xfb\xaf\x3a\x5a\xa3\xfa\xce\x73");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xd7\xe6\x63\x47\x23\xac\x25\xcb\x18\x79\xbd\xb1\x50\x8d\xa0\x53\x13\x53\x04\x19\x01\x3f\xe2\x55\x96\x7a\x39\xe1");

        ctx.update(b"\x9e\x8f\x3c\x66\x45\xc1\x74\x9b\x55\xc5\x0d\x20\x18\xce\x40\xdc\x24\x27");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x2f\x5a\x58\x3b\xf5\x88\xc8\x98\x8a\x57\x2d\x12\x8a\x95\xbe\xa5\xef\x1b\x66\x78\x0a\x7d\x4b\xe9\xc2\x9e\xfc\x31");

        ctx.update(b"\x2d\xb6\xd2\x07\xc0\xb7\xd9\x11\x7f\x24\xd7\x8e\xe5\x9a\xbf\x2f\x31\x69\x78");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x35\x68\x1f\xce\x28\x30\x7c\xae\x19\x52\x2c\x23\xcb\xd4\xa7\x79\x69\x34\x7f\x7d\x8e\xe4\xa3\x08\x8b\xa9\x0a\xda");

        ctx.update(b"\x3d\xf5\xe7\xf3\x99\xf6\xdd\x61\xa1\x2a\x9d\x4e\x94\x64\xfc\x49\x97\xc1\xf3\x7b");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xa3\xe6\x80\x76\xe3\x07\x51\x08\x5a\x84\x3a\x6c\xbf\xbf\x0f\x3d\xee\x63\xd9\xc4\x21\x9c\x91\x43\x72\xe5\x0b\x28");

        ctx.update(b"\x65\x78\x1d\x01\x8f\x27\xca\x0c\x72\xa9\xfa\x9a\xb4\x64\x8e\xd3\x69\x64\x6d\xd3\xce");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xd1\x5e\xf0\xd8\x72\xd0\x2d\xa6\x42\x7b\x8d\x03\x49\xde\xa2\xf2\x04\xe6\x71\x33\xb7\x36\x5b\x4b\x15\x0e\xfc\x3c");

        ctx.update(b"\xaf\x48\xee\xdd\xd9\x3f\xee\x69\xd1\xbd\x7d\xe4\x28\xa6\x39\x86\x01\x1d\x10\x94\x5e\xaf");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xb8\x9d\x42\x8e\xe4\x2e\x39\x7c\xf1\x10\x29\xec\xbb\x27\xba\xdd\xd0\x36\xc8\x93\x8f\x51\xc8\xab\x56\xb8\x75\xac");

        ctx.update(b"\xdf\x2b\xf0\xd5\xf9\xc9\x94\xac\x69\xd7\x8b\xaa\x0d\x51\x2e\xce\xb7\x4d\x8a\x04\x75\x31\xc1");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xdb\x8e\x1c\xe6\x8c\x8c\x6b\x84\xd6\xdb\x75\x5c\x2b\x8b\xf5\x4f\x3c\x4b\x08\x1a\x88\x1e\xfc\xdd\xaf\x30\x32\x94");

        ctx.update(b"\x48\xd2\xf2\x09\x55\xea\x2d\x13\x43\x3c\x20\xbc\x04\x04\xeb\x2e\x6a\xd7\x9e\xd2\x8f\x7c\xb4\xc0");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x36\x17\xcc\x31\x79\xf8\xb5\x9a\xdc\xe1\x81\xee\xbe\xed\x5e\x27\x63\xf6\x26\x50\x94\x92\x24\xa6\x7e\x53\x69\x4b");

        ctx.update(b"\x21\x8f\x74\xa4\x2d\x3a\x47\xef\x3b\x80\x66\x01\xfb\xa0\x24\xb0\x78\xcb\xff\x4e\x4b\x85\x77\x2e\x0e");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xb5\xf4\x0b\x95\xdc\xc3\x63\xb9\x7e\x9d\x00\xb6\x7c\x5d\x7c\x37\xf1\x7a\xb5\x63\x29\x7d\x2d\x67\xa4\xdf\x20\xc9");

        ctx.update(b"\xef\x55\xb1\xe7\x97\x00\x0b\x04\xfc\xdb\x9b\x30\x21\xb0\x93\x27\xe3\xb4\xe2\x69\xd2\x0c\xab\xdf\x41\x8f");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x82\x7b\x22\x3d\x51\x24\x0c\x2e\x32\x71\xc5\x34\xc1\x9c\x56\x37\xb6\xfe\x10\x08\x3e\x85\xbc\xf0\x67\x61\xef\x21");

        ctx.update(b"\x96\xdf\x43\x87\xdc\x2c\x40\x29\x70\x43\xbe\xa3\x64\x83\xf6\x5e\x4e\xb1\xe0\x7e\x93\x35\x9c\xb7\xe6\x86\x10");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x98\xe4\x30\xa6\x3f\xcd\xed\xaf\xc9\x41\x90\x10\xf7\xf5\x9a\x4d\x81\x6a\x45\xb4\xf9\x73\xbe\xb6\x25\x30\xff\x8c");

        ctx.update(b"\x3e\xc0\xaa\x8d\x30\xd5\xed\x82\x5b\x77\xdc\x70\x95\xf4\x21\xb1\xe6\x08\x15\x87\x97\xa3\x77\xff\x8b\xed\x64\x1b");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x31\x08\x32\x1e\xb7\xff\x85\x7f\x6a\xae\x69\x10\x1b\x93\x7f\x32\xa5\x1e\xa2\x79\xa6\xc1\x4b\xa5\x23\x2a\xc8\xc1");

        ctx.update(b"\x8b\x02\x39\x71\x20\x39\xf0\x77\xce\x32\x3b\x35\xf4\xe3\x06\x78\x7b\x9b\x35\x27\x00\x96\xe5\x77\x35\xcf\xf4\x5d\x84");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xa5\xc7\x40\xd3\xce\x46\xbb\x2e\x0a\x04\x84\x88\xf2\xb0\x60\x5c\x6d\x0c\xa0\xea\x2f\x38\x2d\x04\x3d\x13\xdb\x97");

        ctx.update(b"\x04\x4b\xe3\x01\x67\xa9\x75\x8c\x46\xc7\x27\x92\x1d\xc4\xeb\x4e\x0d\xcb\x96\x56\x23\x42\x3e\x6f\xdd\x44\xe7\xa4\xea\x52");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x6e\xb7\x83\x13\xc7\x43\xea\x87\x69\xd8\x34\x0f\x28\x4d\xda\x6d\xed\x64\xa1\xdb\x64\x39\x2f\x21\xab\xb8\x2c\x5c");

        ctx.update(b"\x57\xf6\x11\x8b\xac\xce\x47\xec\xc3\x1c\xe8\xb0\xc0\x83\xd3\xc9\x21\x9e\x0d\xbe\x9e\x4f\xbe\xa1\x54\x53\x7c\x41\x23\x1a\xcc");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x0d\xbb\x53\xc8\x66\xd6\x3a\xf4\x4c\x22\x2c\x76\xc8\x25\xdf\x0e\x37\x9d\xce\xdf\xb9\x58\xdb\x03\xb6\xfd\x29\xa5");

        ctx.update(b"\xfe\x1f\x0f\xb0\x2c\x90\x11\xf4\xc8\xc5\x90\x59\x34\xed\x15\x13\x67\x71\x73\x7c\xe3\x1c\x58\x59\xe6\x7f\x23\x5f\xe5\x94\xf5\xf6");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xbb\xea\xac\xc6\x32\xc2\xa3\xdb\x2a\x9b\x47\xf1\x57\xab\x54\xaa\x27\x77\x6c\x6e\x74\xcf\x0b\xca\xa9\x1b\x06\xd5");

        ctx.update(b"\x14\xfb\x01\xae\x9d\x60\x15\xec\xb3\xe5\x6d\x6e\xcd\xfa\x4b\xc0\x53\x31\x86\xad\xf8\x45\x7f\x5e\x4a\x5c\x57\xc6\x87\x89\x5f\x3d\xb3");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x17\x82\x72\xc7\xd7\xcc\x71\xb1\x50\x74\xc2\x7e\x3b\x79\x97\xd4\xa3\xba\x99\x62\x69\x86\xa1\xa1\x6c\xf3\x00\x30");

        ctx.update(b"\xff\x6c\x49\x71\x2f\x04\x4f\x40\x63\xc1\x41\x25\xc0\xcd\xfb\xa1\x8e\xd8\xb7\x13\x84\x53\x76\x8a\x45\xdf\xa2\xd8\x2a\x05\xf1\xe8\x42\x27");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x40\x32\x84\xc8\x88\xa7\x28\x0b\xc8\xbf\xc2\x5f\x0c\x34\x18\x2c\xd3\x78\x30\x6a\x21\xa1\x40\x4d\x4e\x1c\x40\xcf");

        ctx.update(b"\xf9\x00\xbd\x7e\x01\x17\x24\x7f\x97\xc8\xfc\x7a\x66\x5c\x76\xa3\x5f\x57\x1c\x33\x66\x57\x1d\x6c\x4a\x3e\xe5\xd7\xfb\x93\xf1\xd1\xf7\x26\xe2");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x48\x23\x5b\x98\x20\xd6\x6d\x88\x85\xfa\xab\xf6\xa9\xed\xe6\x3b\xa2\xa2\x1b\x61\x77\xe9\x87\xa3\x32\x42\x37\x3e");

        ctx.update(b"\x42\xd3\x81\x88\xac\x49\x44\x0c\xfe\xfb\x77\xdb\x97\x5e\x08\x3e\x6b\x22\x34\x8c\x4c\x67\xf0\xf8\x69\x2e\x88\xad\x14\x0d\x86\x1d\xc8\x28\xd5\x95");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x61\x53\x44\xf8\x90\xe5\xbc\xf7\x1b\x5e\xfe\x39\xde\x1f\xc9\x42\xba\x1f\xe3\x0d\xd9\xe9\x14\x6a\xdb\x6a\x41\xbf");

        ctx.update(b"\x74\xfd\xd7\xd9\x58\xb8\xae\x7c\x2c\x3c\x5c\xff\x42\x66\xdf\xb2\xb3\xb8\x42\xc9\xf5\x9e\xcb\xbc\xaf\xf5\x75\xed\xcb\xcd\xa0\x8c\xcd\x6e\x08\xb7\x64");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x66\xd7\xd6\xc5\x4f\xc7\x77\x5a\x0b\xa8\x45\xba\x3e\x11\x71\x9f\xa5\x35\xb9\x28\x9f\x20\xb0\x98\xc5\xf7\xa3\x42");

        ctx.update(b"\x93\x44\x16\xdd\x05\x81\xe2\x2f\x2b\xfb\xec\xe7\xbb\x64\xaf\xe8\x20\x45\x1f\xa2\x13\x42\xdf\x7e\x6f\x9f\xb3\x7c\x41\x03\x38\x1a\x1f\x7c\xd3\x79\xbc\xc4");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xfa\xe8\xf1\xaa\x22\xde\xf4\xdb\xaa\x81\x4c\x5b\x0b\xab\xde\xc4\x33\x94\x95\x17\x92\xc9\x37\x05\x0d\x29\x63\xa6");

        ctx.update(b"\x10\x24\x01\xc8\x4a\x71\x6a\xe7\x25\x79\xc6\xae\x79\xc3\x59\xea\x30\x9f\xfd\x95\xab\xff\xae\x4c\x61\x88\x4c\x03\xc9\xe9\x9d\xf7\x7b\x6c\x92\xe4\x92\xca\xcb");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x8f\x34\x81\x2d\x57\xa1\x6e\xf8\xa5\x1a\xd9\x87\x66\x0c\x5f\x86\x23\xe0\xfa\x9d\x89\x84\x6e\x28\xd4\x6d\x14\xd9");

        ctx.update(b"\x79\xbc\x8f\xb6\x0f\x85\xd1\x5a\x23\x86\x56\x6e\x3e\x73\x14\xdf\x28\x45\x33\x08\x5a\xdd\x1c\x7b\xb6\xea\xd3\xff\x76\x0c\x86\xd5\x63\x3a\x66\x40\x47\x61\xb5\x44");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x65\xc5\x40\x14\xcf\xa3\x0f\x0b\xc2\x7d\x1c\x6e\xfa\x96\xae\x84\x81\xf4\xc2\x50\x5b\xff\x27\x29\x56\xea\xb0\xdf");

        ctx.update(b"\xdb\x31\x21\xea\x71\x29\x49\x83\xb1\x85\x20\x7a\x9d\x8d\xe3\xe4\x84\xa6\x6c\x04\x31\xbf\x07\xc9\x62\xeb\x82\x97\x7c\x4f\x83\x4b\x7c\x3f\x1e\x79\x31\xa4\xa7\xf7\xa9");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x93\x16\xd2\xf0\x21\xc2\x91\x3d\x63\xa7\xe6\x69\x24\xc8\x7c\x16\x1c\x3c\xfd\xe0\xea\x7b\xa0\x7f\x54\x77\x28\x62");

        ctx.update(b"\x0d\xd5\x1a\xa6\x60\xc5\xcb\x4b\x7f\x78\xc4\x68\x52\xc1\xdb\x87\x07\xab\x45\x1c\x13\x67\xb6\x18\x73\x88\xc8\xbb\x38\x73\xa1\xaa\x42\x10\xd0\x41\x4c\xc6\x79\x2a\x29\xa7");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x31\x98\x9e\x7a\x62\xa5\x13\x2a\x50\x70\xd7\x72\x50\xd8\x90\x4b\xb8\x2d\x45\x7d\xc6\x34\x69\xd0\x6b\x50\x18\x5e");

        ctx.update(b"\x48\x7f\xd2\xe5\xb6\x94\xb7\x07\x1d\x37\x89\xa2\x58\xa5\x1e\x86\x04\xdc\x0d\x3e\x8f\x5d\x62\xf3\x91\x31\x96\x8e\x60\x2a\xbe\x1d\xdf\x6b\x02\x78\x96\x2a\x51\x24\x08\xb5\x53");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xe7\x98\x68\x34\x38\x28\x46\x26\xd7\x10\x87\x7d\x9e\xea\x3a\x0e\x02\xf3\x49\xfc\x43\xac\xb7\xf9\xf8\xf9\xe8\x1c");

        ctx.update(b"\x11\x18\x3b\xde\xbf\xef\x58\xe4\xda\x5b\x1c\xb7\x3b\xe0\xd3\x0b\x20\xda\x30\x4d\x86\x59\xd9\x21\xda\x2e\x27\x0f\xd1\x46\x26\x79\x95\x37\xe4\xd1\x21\x19\xe8\x09\xee\x97\x00\x4a");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x96\x87\x06\x57\xd6\xcb\x66\x8b\xe3\x99\x5a\xa8\xbd\x31\xdf\x77\x84\x0d\x1d\x19\x15\xd7\x24\x82\xe8\x3b\x6b\x2c");

        ctx.update(b"\xa2\x39\xde\x5c\x8e\x26\x44\xe8\xf0\x30\xd9\x4d\x98\xf1\xa3\x06\x64\xe6\xfd\x96\x1d\xc2\x97\x7a\x9c\x08\xbe\x5c\x31\xd8\xde\x89\x45\x09\x45\xa5\x3d\x79\x29\x9e\xa2\xa1\xed\xde\x7f");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xe9\x97\x43\xd4\xfd\x26\xc8\x80\x0c\x36\xa6\x7b\x67\x62\x24\x7c\x29\xda\x6b\x62\x79\x41\x23\xc5\x9d\xe0\x6d\xc0");

        ctx.update(b"\x91\x7c\x45\x77\xaa\x6b\x0f\x9d\xf4\x99\x99\xfc\x1c\x95\x8c\xb0\x9b\x7f\xd5\xfc\x80\xbe\x94\x96\x70\xf0\x35\x45\xeb\x27\xdc\xae\xd0\x52\x07\x6b\x24\xf9\x6f\x5e\x0f\x2e\x2f\x45\x27\xc0");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x7e\xcd\x69\x3d\x4d\x9c\xf4\x39\x29\x46\x46\x98\xef\xa0\xba\xc3\x3c\x2e\x14\x24\xf8\x16\xed\xc7\x69\x26\x09\x78");

        ctx.update(b"\xc3\xf1\xe7\x35\xa6\x74\x1a\xa4\x81\xad\x57\x7a\x98\xdb\xac\x1f\x03\xcc\x80\xea\x0d\xae\x1b\x94\xdb\x23\x69\xed\x4e\x93\xfa\xcd\x29\xc6\x4e\x4e\x77\xb2\x50\x38\x27\x91\x20\xbd\xfa\x37\x15");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x86\xf0\xd8\x9d\x8e\x14\xfd\x8b\x66\x06\x41\x2d\x71\xa7\xa5\x4a\x34\x7b\x30\x4e\xa5\xd4\x9c\x20\x8f\x22\x66\xab");

        ctx.update(b"\xde\x4f\xbf\xd5\x53\xcd\xf3\x70\x19\xf2\x5a\xfa\x82\xdc\x6b\x99\x70\xf4\xbb\x1e\xbb\xc3\x7f\x80\xd3\x08\x4c\x88\xa7\x07\x22\xcd\xc5\x23\xa9\xe3\xc2\xaf\xba\xd0\xdc\x02\x21\xbf\xde\xc9\xa2\xf9");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x4c\x52\x62\xac\xb4\xa2\xa4\x4e\xaa\x9b\xc6\x75\x70\x24\xfb\x20\x2e\xf4\xd5\xa7\xa1\x6f\xa3\x72\x52\xa4\x22\xb5");

        ctx.update(b"\xdb\x2e\x2e\xb6\x36\x61\x0c\xf4\x2e\x9b\x33\x43\x3a\xcc\xe1\xb3\xb9\x25\x94\x9f\x29\x7d\xd8\x31\x99\xf4\x5d\x28\x61\xd6\x4c\xd9\x10\xc2\xdb\x74\xa6\x0b\x20\x89\x04\x5e\x22\xcb\xa0\xa5\x36\x13\x7d");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x16\xbf\x4e\x45\xbc\xdc\x60\x44\x7c\x68\xdc\xb3\x0e\x6b\x08\xf5\x5c\xe9\xf4\x12\x4a\x29\xcf\x1f\x9a\x9d\x06\x5d");

        ctx.update(b"\xa8\xe7\x29\xd3\x36\xd5\xd6\xac\x50\xe1\xe2\x2f\x0b\x19\x3b\x66\xe2\x60\x42\xfc\x64\x59\x21\x41\x29\x87\x5e\x74\x0a\xb2\xb1\x42\x91\x8c\x13\x8a\xaf\x94\x18\x63\xad\x3b\x7e\x60\x65\x45\x06\x13\xb2\x73");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x45\x2b\xf2\xe5\xeb\xfc\x4e\x45\x1c\xc4\x34\xbc\x09\xe2\xa1\x00\x32\xee\xd0\xb7\x62\x7c\xf5\x5e\x7e\x5e\xd0\xe2");

        ctx.update(b"\xd0\x53\x17\xd4\xb5\x35\xf9\xd1\x0f\x73\x9d\x0c\x2d\xed\xf3\xff\xb0\x90\xc1\xad\x9d\x20\x50\x89\xb1\x34\x66\x93\xf5\x82\x73\xc4\x92\x5c\x0f\xac\xe5\x7b\xa4\x5a\xd6\xfc\x68\x7c\x66\xa8\x8f\xc7\x88\x78\xbe");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x4f\x03\xc4\x39\xe0\x97\xb5\x1b\x00\xe3\x14\xf6\x75\x93\x7c\x4d\x91\x15\x05\x85\x9f\xb7\xab\x16\xad\xc6\x5e\x44");

        ctx.update(b"\x26\xbb\x4e\xd4\xf0\x42\x4c\x60\xfe\x42\x12\xff\x8c\x95\x5e\x89\xe2\xf5\x53\xa7\xd7\x70\x1b\xe5\x94\x16\xd2\x08\x9a\xf5\x9f\xa1\x07\x47\x24\xe2\x14\xe9\x19\xb1\xe3\x0f\x33\xfb\x78\x37\x4b\x4b\x05\x5b\xbc\x9b");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xe7\xc8\x99\xe2\x70\x09\xd4\xdc\x77\xc2\xd3\x00\xf1\x91\xb7\x57\xe5\x2c\x9e\x7e\xac\x4b\x02\x3b\xfa\xb2\xb5\x2a");

        ctx.update(b"\xf0\x15\xec\x83\x94\x4f\x03\x29\x24\x63\xc4\x34\x5f\xdb\x1c\x26\xd1\xea\x07\x64\x5f\xac\xbc\x95\x20\xae\x24\x4b\x6e\xb1\x91\xe5\x3d\xab\xad\xb4\xac\x0f\xb1\x5c\xda\x4e\xd7\x7d\xfb\x9e\x11\x93\xab\xfa\xfb\x1b\x81");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x45\x9e\x40\xb3\xfb\xd6\x12\x91\x2f\x02\x17\xc6\x00\x99\x37\x9c\xe0\x77\xcd\x02\x50\x58\x71\xb0\xc9\xc1\x4e\x7a");

        ctx.update(b"\x07\x86\x70\x6f\x68\x0c\x27\xb7\x92\xd0\x54\xfa\xa6\x3f\x49\x9a\x8e\x6b\x5d\xdb\x90\x50\x29\x46\x23\x5b\xf7\x4c\x02\x2d\x77\x2c\x80\x9c\xb4\x17\x1b\xfa\x47\x91\x53\x9a\xca\x1a\xbd\x91\x90\x0e\x53\xba\x93\xca\x0e\xfd");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xfa\xde\xba\xb7\xc3\xd0\xfb\x8e\x97\xe4\x29\xb7\x90\x83\x08\x77\x35\xe4\xab\x38\x5a\x78\x95\x21\x26\x0e\xf3\xad");

        ctx.update(b"\x44\x5e\x86\x98\xee\xb8\xac\xcb\xaa\xc4\xff\xa7\xd9\x34\xff\xfd\x16\x01\x4a\x43\x0e\xf7\x0f\x3a\x91\x74\xc6\xcf\xe9\x6d\x1e\x3f\x6a\xb1\x37\x7f\x4a\x72\x12\xdb\xb3\x01\x46\xdd\x17\xd9\xf4\x70\xc4\xdf\xfc\x45\xb8\xe8\x71");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x4c\x7a\xe0\x28\xc0\xfe\x61\xf2\xa9\xca\xda\x61\xfa\xe3\x06\x85\xb7\x7f\x04\xc6\x44\x25\x76\xe9\x12\xaf\x9f\xa6");

        ctx.update(b"\x52\x83\x9f\x2f\x08\x53\xa3\x0d\xf1\x4e\xc8\x97\xa1\x91\x4c\x68\x5c\x1a\xc2\x14\x70\xd0\x06\x54\xc8\xc3\x76\x63\xbf\xb6\x5f\xa7\x32\xdb\xb6\x94\xd9\xdd\x09\xce\xd7\x23\xb4\x8d\x8f\x54\x58\x46\xba\x16\x89\x88\xb6\x1c\xc7\x24");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x2f\x75\x5a\x57\x67\x4b\x49\xd5\xc2\x5c\xb3\x73\x48\xf3\x5b\x6f\xd2\xde\x25\x52\xc7\x49\xf2\x64\x5b\xa6\x3d\x20");

        ctx.update(b"\x5f\xe8\xc2\x07\x2d\x89\x00\x28\x7c\xca\xf0\x7f\x3f\x66\xb0\xc2\x2a\xcd\x3e\x0b\xb9\x1d\x95\x73\x75\x4e\x19\xe3\x73\xac\x35\x27\x1d\x8b\x43\x44\x34\x36\xac\x0c\x16\x28\x50\xef\x3d\x7f\x28\x14\x09\xad\x29\xa9\xbf\x71\x6c\x77\xd1");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x42\x90\x97\x57\xf6\xe2\x29\xf6\x9f\x04\xcc\x7a\x86\x3c\x4e\x70\xe4\x8c\x7c\x35\x75\x05\x7b\x45\x5c\x95\x97\x75");

        ctx.update(b"\xe8\x06\x4d\x83\xf3\xd6\x43\xaf\x87\x18\xc8\x7e\x3c\xcd\x6a\x97\x33\x68\x5e\xac\x61\xd5\x72\xa2\x2a\xb9\x43\xf2\x32\xfc\xb0\x4f\x70\x85\x8e\x89\x84\x44\x9d\xb1\x4a\x76\xbb\x7e\xaf\x24\x58\xef\xc3\xed\x2a\x32\x10\x06\x22\xc5\x2b\x7f");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x1a\x1d\x8e\xd5\x4c\xb4\x5c\x97\xbc\x97\x07\x54\xb4\x3e\xb9\x3d\x9e\xab\xde\x4c\x7b\x07\xf7\x6a\xd8\x2d\x8e\xde");

        ctx.update(b"\x87\xc9\xa5\x17\xe2\x8d\x1b\xb5\x4a\xd2\x0f\xca\x76\x46\x0e\xfd\x89\x4d\x77\x86\xe6\x8e\xe8\xd7\x46\xb2\xf6\x82\x08\x68\x21\x57\xc8\xad\x06\xcc\x32\x4a\xd7\xa3\x18\x9e\x09\xc6\xc3\x9d\x4c\x76\x87\x19\xc0\xa4\x9a\x41\x66\x9f\x27\x67\xd5");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x60\x59\x77\xcf\x87\xb9\xb3\x09\xbb\xdd\xaa\xa6\x4e\x52\x8a\xce\x66\xb0\x4d\xf9\xf7\x2c\x0e\x7e\xc8\x8b\xe1\xda");

        ctx.update(b"\x59\xfd\xac\x3b\x6b\x32\x03\x92\x91\x80\x1c\x7d\x6f\x46\xed\xe8\xd2\x6d\xc5\xb7\xa1\x92\xe0\x07\x11\x67\x39\xb6\x17\x56\x9f\x25\x23\x68\x0b\x3c\x0b\x66\x31\xaf\x45\x3e\x55\x80\x5a\xa7\x60\xc6\x97\x08\x33\xac\x06\x96\x3b\xbc\x9d\xbd\x45\x5e");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xe9\xf0\xcb\x1d\xc8\x33\x7e\x90\x63\x85\x89\x2f\x23\x48\xa8\xba\x44\x12\x31\x8e\xca\xd9\xb9\x6e\x37\x11\x53\x1f");

        ctx.update(b"\x30\x35\x0a\x4d\xf0\xb5\x8f\xf4\x9c\x0f\xa0\x9e\x42\x6f\xcd\x70\x07\xb2\x90\xc7\x60\xc8\x25\xc1\x85\x5d\x9b\x00\x23\xb8\x2c\xaa\x51\xe3\xca\xb4\xc6\x0c\xfa\x61\x49\x2b\xe5\x05\x68\xe5\xac\x0f\x6d\xb0\xfd\x46\x8e\x39\xe4\x53\x64\x03\xe3\x80\x9f");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x77\x6c\xc6\x63\x6c\x02\x40\x8f\xbf\x65\xac\xe7\x3a\xe8\x00\x17\x10\x8b\x91\x7c\x16\xc5\xa9\x12\xfd\x86\x02\x41");

        ctx.update(b"\xef\x79\x7a\x0d\x43\xc3\x0b\x4f\xe1\x01\x4b\xdb\x94\x20\x87\x9c\x2f\xf8\x45\xd2\x7e\x73\xd5\x5a\x7d\xf2\x29\x30\xc8\xec\xe7\x32\x53\xd8\xbb\x26\x5b\x4e\xf2\xff\x9c\x69\x45\x5c\xc5\x6f\xf2\x52\x29\xb4\x12\x6b\xb7\xbb\x26\xee\x2c\x9f\xf3\x61\x87\xb1");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xf5\xb9\xff\xb1\x02\xaf\xfa\xc3\x52\xa4\xa5\x35\xa0\x0f\x89\xb0\x6c\x26\x8c\xf4\x88\x1d\x71\x26\x68\x90\x60\x25");

        ctx.update(b"\x71\x69\x44\xde\x41\x71\x0c\x29\xb6\x59\xbe\x10\x48\x0b\xb2\x5a\x35\x1a\x39\xe5\x77\xee\x30\xe8\xf4\x22\xd5\x7c\xf6\x2a\xd9\x5b\xda\x39\xb6\xe7\x0c\x61\x42\x6e\x33\xfd\x84\xac\xa8\x4c\xc7\x91\x2d\x5e\xee\x45\xdc\x34\x07\x6a\x5d\x23\x23\xa1\x5c\x79\x64");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\x61\x64\x5a\xc7\x48\xdb\x56\x7a\xc8\x62\x79\x6b\x8d\x06\xa4\x7a\xfe\xbf\xa2\xe1\x78\x3d\x5c\x5f\x3b\xcd\x81\xe2");

        ctx.update(b"\xa3\x31\x0b\xa0\x64\xbe\x2e\x14\xad\x32\x27\x6e\x18\xcd\x03\x10\xc9\x33\xa6\xe6\x50\xc3\xc7\x54\xd0\x24\x3c\x6c\x61\x20\x78\x65\xb4\xb6\x52\x48\xf6\x6a\x08\xed\xf6\xe0\x83\x26\x89\xa9\xdc\x3a\x2e\x5d\x20\x95\xee\xea\x50\xbd\x86\x2b\xac\x88\xc8\xbd\x31\x8d");
        ctx.digest(&mut digest);
        assert_eq!(digest, b"\xb2\xa5\x58\x6d\x9c\xbf\x0b\xaa\x99\x91\x57\xb4\xaf\x06\xd8\x8a\xe0\x8d\x7c\x9f\xaa\xb4\xbc\x1a\x96\x82\x9d\x65");
    }
}
