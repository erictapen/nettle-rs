use nettle_sys::{
    sha3_512_ctx,
    nettle_sha3_512_init,
    nettle_sha3_512_digest,
    nettle_sha3_512_update,
    nettle_hash,
    nettle_sha3_512,
};
use std::default::Default;
use std::mem::zeroed;
use Hash;
use hash::NettleHash;

#[allow(non_camel_case_types)]
/// 512 bit variant of the Secure Hash Algorithm 3 (SHA-3) defined in FIPS 202.
pub struct Sha3_512 {
    context: sha3_512_ctx,
}

impl Default for Sha3_512 {
    fn default() -> Self {
        let mut ctx = unsafe { zeroed() };

        unsafe { nettle_sha3_512_init(&mut ctx as *mut _); }

        Sha3_512{ context: ctx }
    }
}

impl Hash for Sha3_512 {
    fn digest_size(&self) -> usize { ::nettle_sys::SHA3_512_DIGEST_SIZE as usize }

    fn update(&mut self, data: &[u8]) {
        unsafe {
            nettle_sha3_512_update(&mut self.context as *mut _, data.len(), data.as_ptr());
        }
    }

    fn digest(&mut self, digest: &mut [u8]) {
        unsafe {
            nettle_sha3_512_digest(&mut self.context as *mut _, digest.len(), digest.as_mut_ptr());
        }
    }
}

impl NettleHash for Sha3_512 {
    type Context = sha3_512_ctx;

    unsafe fn nettle_hash() -> &'static nettle_hash { &nettle_sha3_512 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_nothing() {
        let _ = Sha3_512::default();
    }

    //  CAVS 19.0
    //  "SHA3-512 ShortMsg" information for "SHA3AllBytes1-28-16"
    //  Length values represented in bits
    //  Generated on Thu Jan 28 13:32:47 2016
    #[test]
    fn nist_cavs_short_msg() {
        let mut ctx = Sha3_512::default();
        let mut digest = vec![0u8; ctx.digest_size()];

        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xa6\x9f\x73\xcc\xa2\x3a\x9a\xc5\xc8\xb5\x67\xdc\x18\x5a\x75\x6e\x97\xc9\x82\x16\x4f\xe2\x58\x59\xe0\xd1\xdc\xc1\x47\x5c\x80\xa6\x15\xb2\x12\x3a\xf1\xf5\xf9\x4c\x11\xe3\xe9\x40\x2c\x3a\xc5\x58\xf5\x00\x19\x9d\x95\xb6\xd3\xe3\x01\x75\x85\x86\x28\x1d\xcd\x26"[..]);

        ctx.update(b"\xe5");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x15\x02\x40\xba\xf9\x5f\xb3\x6f\x8c\xcb\x87\xa1\x9a\x41\x76\x7e\x7a\xed\x95\x12\x50\x75\xa2\xb2\xdb\xba\x6e\x56\x5e\x1c\xe8\x57\x5f\x2b\x04\x2b\x62\xe2\x9a\x04\xe9\x44\x03\x14\xa8\x21\xc6\x22\x41\x82\x96\x4d\x8b\x55\x7b\x16\xa4\x92\xb3\x80\x6f\x4c\x39\xc1"[..]);

        ctx.update(b"\xef\x26");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x80\x9b\x41\x24\xd2\xb1\x74\x73\x1d\xb1\x45\x85\xc2\x53\x19\x4c\x86\x19\xa6\x82\x94\xc8\xc4\x89\x47\x87\x93\x16\xfe\xf2\x49\xb1\x57\x5d\xa8\x1a\xb7\x2a\xad\x8f\xae\x08\xd2\x4e\xce\x75\xca\x1b\xe4\x6d\x06\x34\x14\x37\x05\xd7\x9d\x2f\x51\x77\x85\x6a\x04\x37"[..]);

        ctx.update(b"\x37\xd5\x18");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x4a\xa9\x6b\x15\x47\xe6\x40\x2c\x0e\xee\x78\x1a\xca\xa6\x60\x79\x7e\xfe\x26\xec\x00\xb4\xf2\xe0\xae\xc4\xa6\xd1\x06\x88\xdd\x64\xcb\xd7\xf1\x2b\x3b\x6c\x7f\x80\x2e\x20\x96\xc0\x41\x20\x8b\x92\x89\xae\xc3\x80\xd1\xa7\x48\xfd\xfc\xd4\x12\x85\x53\xd7\x81\xe3"[..]);

        ctx.update(b"\xfc\x7b\x8c\xda");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x58\xa5\x42\x2d\x6b\x15\xeb\x1f\x22\x3e\xbe\x4f\x4a\x52\x81\xbc\x68\x24\xd1\x59\x9d\x97\x9f\x4c\x6f\xe4\x56\x95\xca\x89\x01\x42\x60\xb8\x59\xa2\xd4\x6e\xbf\x75\xf5\x1f\xf2\x04\x92\x79\x32\xc7\x92\x70\xdd\x7a\xef\x97\x56\x57\xbb\x48\xfe\x09\xd8\xea\x00\x8e"[..]);

        ctx.update(b"\x47\x75\xc8\x6b\x1c");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xce\x96\xda\x8b\xcd\x6b\xc9\xd8\x14\x19\xf0\xdd\x33\x08\xe3\xef\x54\x1b\xc7\xb0\x30\xee\xe1\x33\x9c\xf8\xb3\xc4\xe8\x42\x0c\xd3\x03\x18\x0f\x8d\xa7\x70\x37\xc8\xc1\xae\x37\x5c\xab\x81\xee\x47\x57\x10\x92\x3b\x95\x19\xad\xbd\xde\xdb\x36\xdb\x0c\x19\x9f\x70"[..]);

        ctx.update(b"\x71\xa9\x86\xd2\xf6\x62");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xde\xf6\xaa\xc2\xb0\x8c\x98\xd5\x6a\x05\x01\xa8\xcb\x93\xf5\xb4\x7d\x63\x22\xda\xf9\x9e\x03\x25\x54\x57\xc3\x03\x32\x63\x95\xf7\x65\x57\x69\x30\xf8\x57\x1d\x89\xc0\x1e\x72\x7c\xc7\x9c\x2d\x44\x97\xf8\x5c\x45\x69\x1b\x55\x4e\x20\xda\x81\x0c\x2b\xc8\x65\xef"[..]);

        ctx.update(b"\xec\x83\xd7\x07\xa1\x41\x4a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x84\xfd\x37\x75\xba\xc5\xb8\x7e\x55\x0d\x03\xec\x6f\xe4\x90\x5c\xc6\x0e\x85\x1a\x4c\x33\xa6\x18\x58\xd4\xe7\xd8\xa3\x4d\x47\x1f\x05\x00\x8b\x9a\x1d\x63\x04\x44\x45\xdf\x5a\x9f\xce\x95\x8c\xb0\x12\xa6\xac\x77\x8e\xcf\x45\x10\x4b\x0f\xcb\x97\x9a\xa4\x69\x2d"[..]);

        ctx.update(b"\xaf\x53\xfa\x3f\xf8\xa3\xcf\xb2");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x03\xc2\xac\x02\xde\x17\x65\x49\x7a\x0a\x6a\xf4\x66\xfb\x64\x75\x8e\x32\x83\xed\x83\xd0\x2c\x0e\xdb\x39\x04\xfd\x3c\xf2\x96\x44\x2e\x79\x00\x18\xd4\xbf\x4c\xe5\x5b\xc8\x69\xce\xbb\x4a\xa1\xa7\x99\xaf\xc9\xd9\x87\xe7\x76\xfe\xf5\xdf\xe6\x62\x8e\x24\xde\x97"[..]);

        ctx.update(b"\x3d\x60\x93\x96\x69\x50\xab\xd8\x46");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x53\xe3\x0d\xa8\xb7\x4a\xe7\x6a\xbf\x1f\x65\x76\x16\x53\xeb\xfb\xe8\x78\x82\xe9\xea\x0e\xa5\x64\xad\xdd\x7c\xfd\x5a\x65\x24\x57\x8a\xd6\xbe\x01\x4d\x77\x99\x79\x9e\xf5\xe1\x5c\x67\x95\x82\xb7\x91\x15\x9a\xdd\x82\x3b\x95\xc9\x1e\x26\xde\x62\xdc\xb7\x4c\xfa"[..]);

        ctx.update(b"\x1c\xa9\x84\xdc\xc9\x13\x34\x43\x70\xcf");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x69\x15\xea\x0e\xef\xfb\x99\xb9\xb2\x46\xa0\xe3\x4d\xaf\x39\x47\x85\x26\x84\xc3\xd6\x18\x26\x01\x19\xa2\x28\x35\x65\x9e\x4f\x23\xd4\xeb\x66\xa1\x5d\x0a\xff\xb8\xe9\x37\x71\x57\x8f\x5e\x8f\x25\xb7\xa5\xf2\xa5\x5f\x51\x1f\xb8\xb9\x63\x25\xba\x2c\xd1\x48\x16"[..]);

        ctx.update(b"\xfc\x7b\x8c\xda\xde\xbe\x48\x58\x8f\x68\x51");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xc8\x43\x9b\xb1\x28\x51\x20\xb3\xc4\x36\x31\xa0\x0a\x3b\x5a\xc0\xba\xdb\x41\x13\x58\x6a\x3d\xd4\xf7\xc6\x6c\x5d\x81\x01\x2f\x74\x12\x61\x7b\x16\x9f\xa6\xd7\x0f\x8e\x0a\x19\xe5\xe2\x58\xe9\x9a\x0e\xd2\xdc\xfa\x77\x4c\x86\x4c\x62\xa0\x10\xe9\xb9\x0c\xa0\x0d"[..]);

        ctx.update(b"\xec\xb9\x07\xad\xfb\x85\xf9\x15\x4a\x3c\x23\xe8");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x94\xae\x34\xfe\xd2\xef\x51\xa3\x83\xfb\x85\x32\x96\xe4\xb7\x97\xe4\x8e\x00\xca\xd2\x7f\x09\x4d\x2f\x41\x1c\x40\x0c\x49\x60\xca\x4c\x61\x0b\xf3\xdc\x40\xe9\x4e\xcf\xd0\xc7\xa1\x8e\x41\x88\x77\xe1\x82\xca\x3a\xe5\xca\x51\x36\xe2\x85\x6a\x55\x31\x71\x0f\x48"[..]);

        ctx.update(b"\xd9\x1a\x9c\x32\x4e\xce\x84\xb0\x72\xd0\x75\x36\x18");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xfb\x1f\x06\xc4\xd1\xc0\xd0\x66\xbd\xd8\x50\xab\x1a\x78\xb8\x32\x96\xeb\xa0\xca\x42\x3b\xb1\x74\xd7\x42\x83\xf4\x66\x28\xe6\x09\x55\x39\x21\x4a\xdf\xd8\x2b\x46\x2e\x8e\x92\x04\xa3\x97\xa8\x3c\x68\x42\xb7\x21\xa3\x2e\x8b\xb0\x30\x92\x7a\x56\x8f\x3c\x29\xe6"[..]);

        ctx.update(b"\xc6\x1a\x91\x88\x81\x2a\xe7\x39\x94\xbc\x0d\x6d\x40\x21");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x06\x9e\x6a\xb1\x67\x5f\xed\x8d\x44\x10\x5f\x3b\x62\xbb\xf5\xb8\xff\x7a\xe8\x04\x09\x89\x86\x87\x9b\x11\xe0\xd7\xd9\xb1\xb4\xcb\x7b\xc4\x7a\xeb\x74\x20\x1f\x50\x9d\xdc\x92\xe5\x63\x3a\xbd\x2c\xbe\x0d\xdc\xa2\x48\x0e\x99\x08\xaf\xa6\x32\xc8\xc8\xd5\xaf\x2a"[..]);

        ctx.update(b"\xa6\xe7\xb2\x18\x44\x98\x40\xd1\x34\xb5\x66\x29\x0d\xc8\x96");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x36\x05\xa2\x1c\xe0\x0b\x28\x90\x22\x19\x3b\x70\xb5\x35\xe6\x62\x6f\x32\x47\x39\x54\x29\x78\xf5\xb3\x07\x19\x4f\xcf\x0a\x59\x88\xf5\x42\xc0\x83\x8a\x04\x43\xbb\x9b\xb8\xff\x92\x2a\x6a\x17\x7f\xdb\xd1\x2c\xf8\x05\xf3\xed\x80\x9c\x48\xe9\x76\x9c\x8b\xbd\x91"[..]);

        ctx.update(b"\x05\x40\x95\xba\x53\x1e\xec\x22\x11\x3c\xc3\x45\xe8\x37\x95\xc7");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xf3\xad\xf5\xcc\xf2\x83\x0c\xd6\x21\x95\x80\x21\xef\x99\x82\x52\xf2\xb6\xbc\x4c\x13\x50\x96\x83\x95\x86\xd5\x06\x4a\x29\x78\x15\x4e\xa0\x76\xc6\x00\xa9\x73\x64\xbc\xe0\xe9\xaa\xb4\x3b\x7f\x1f\x2d\xa9\x35\x37\x08\x9d\xe9\x50\x55\x76\x74\xae\x62\x51\xca\x4d"[..]);

        ctx.update(b"\x5b\x1e\xc1\xc4\xe9\x20\xf5\xb9\x95\xb6\xa7\x88\xb6\xe9\x89\xac\x29");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x13\x5e\xea\x17\xca\x47\x85\x48\x2c\x19\xcd\x66\x8b\x8d\xd2\x91\x32\x16\x90\x33\x11\xfa\x21\xf6\xb6\x70\xb9\xb5\x73\x26\x4f\x88\x75\xb5\xd3\xc0\x71\xd9\x2d\x63\x55\x65\x49\xe5\x23\xb2\xaf\x1f\x1a\x50\x8b\xd1\xf1\x05\xd2\x9a\x43\x6f\x45\x5c\xd2\xca\x16\x04"[..]);

        ctx.update(b"\x13\x3b\x49\x7b\x00\x93\x27\x73\xa5\x3b\xa9\xbf\x8e\x61\xd5\x9f\x05\xf4");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x78\x39\x64\xa1\xcf\x41\xd6\xd2\x10\xa8\xd7\xc8\x1c\xe6\x97\x0a\xa6\x2c\x90\x53\xcb\x89\xe1\x5f\x88\x05\x39\x57\xec\xf6\x07\xf4\x2a\xf0\x88\x04\xe7\x6f\x2f\xbd\xbb\x31\x80\x9c\x9e\xef\xc6\x0e\x23\x3d\x66\x24\x36\x7a\x3b\x9c\x30\xf8\xee\x5f\x65\xbe\x56\xac"[..]);

        ctx.update(b"\x88\xc0\x50\xea\x6b\x66\xb0\x12\x56\xbd\xa2\x99\xf3\x99\x39\x8e\x1e\x31\x62");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x6b\xf7\xfc\x8e\x90\x14\xf3\x5c\x4b\xde\x6a\x2c\x7c\xe1\x96\x5d\x9c\x17\x93\xf2\x5c\x14\x10\x21\xcc\x1c\x69\x7d\x11\x13\x63\xb3\x85\x49\x53\xc2\xb4\x00\x9d\xf4\x18\x78\xb5\x55\x8e\x78\xa9\xa9\x09\x2c\x22\xb8\xba\xa0\xed\x6b\xac\xa0\x05\x45\x5c\x6c\xca\x70"[..]);

        ctx.update(b"\xd7\xd5\x36\x33\x50\x70\x9e\x96\x93\x9e\x6b\x68\xb3\xbb\xde\xf6\x99\x9a\xc8\xd9");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x7a\x46\xbe\xca\x55\x3f\xff\xa8\x02\x1b\x09\x89\xf4\x0a\x65\x63\xa8\xaf\xb6\x41\xe8\x13\x30\x90\xbc\x03\x4a\xb6\x76\x3e\x96\xd7\xb7\xa0\xda\x4d\xe3\xab\xd5\xa6\x7d\x80\x85\xf7\xc2\x8b\x21\xa2\x4a\xef\xb3\x59\xc3\x7f\xac\x61\xd3\xa5\x37\x4b\x4b\x1f\xb6\xbb"[..]);

        ctx.update(b"\x54\x74\x6a\x7b\xa2\x8b\x5f\x26\x3d\x24\x96\xbd\x00\x80\xd8\x35\x20\xcd\x2d\xc5\x03");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xd7\x70\x48\xdf\x60\xe2\x0d\x03\xd3\x36\xbf\xa6\x34\xbc\x99\x31\xc2\xd3\xc1\xe1\x06\x5d\x3a\x07\xf1\x4a\xe0\x1a\x08\x5f\xe7\xe7\xfe\x6a\x89\xdc\x4c\x78\x80\xf1\x03\x89\x38\xaa\x8f\xcd\x99\xd2\xa7\x82\xd1\xbb\xe5\xee\xc7\x90\x85\x81\x73\xc7\x83\x0c\x87\xa2"[..]);

        ctx.update(b"\x73\xdf\x78\x85\x83\x06\x33\xfc\x66\xc9\xeb\x16\x94\x0b\x01\x7e\x9c\x6f\x9f\x87\x19\x78");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x0e\xde\xe1\xea\x01\x9a\x5c\x00\x4f\xd8\xae\x9d\xc8\xc2\xdd\x38\xd4\x33\x1a\xbe\x29\x68\xe1\xe9\xe0\xc1\x28\xd2\x50\x6d\xb9\x81\xa3\x07\xc0\xf1\x9b\xc2\xe6\x24\x87\xa9\x29\x92\xaf\x77\x58\x8d\x3a\xb7\x85\x4f\xe1\xb6\x83\x02\xf7\x96\xb9\xdc\xd9\xf3\x36\xdf"[..]);

        ctx.update(b"\x14\xcb\x35\xfa\x93\x3e\x49\xb0\xd0\xa4\x00\x18\x3c\xbb\xea\x09\x9c\x44\x99\x5f\xae\x11\x63");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xaf\x2e\xf4\xb0\xc0\x1e\x38\x1b\x4c\x38\x22\x08\xb6\x6a\xd9\x5d\x75\x9e\xc9\x1e\x38\x6e\x95\x39\x84\xaa\x5f\x07\x77\x46\x32\xd5\x3b\x58\x1e\xba\x32\xed\x1d\x36\x9c\x46\xb0\xa5\x7f\xee\x64\xa0\x2a\x0e\x51\x07\xc2\x2f\x14\xf2\x22\x7b\x1d\x11\x42\x4b\xec\xb5"[..]);

        ctx.update(b"\x75\xa0\x68\x69\xca\x2a\x6e\xa8\x57\xe2\x6e\x78\xbb\x78\xa1\x39\xa6\x71\xcc\xb0\x98\xd8\x20\x5a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x88\xbe\x19\x34\x38\x55\x22\xae\x1d\x73\x96\x66\xf3\x95\xf1\xd7\xf9\x99\x78\xd6\x28\x83\xa2\x61\xad\xf5\xd6\x18\xd0\x12\xdf\xab\x52\x24\x57\x56\x34\x44\x68\x76\xb8\x6b\x3e\x5f\x76\x09\xd3\x97\xd3\x38\xa7\x84\xb4\x31\x10\x27\xb1\x02\x4d\xdf\xd4\x99\x5a\x0a"[..]);

        ctx.update(b"\xb4\x13\xab\x36\x4d\xd4\x10\x57\x3b\x53\xf4\xc2\xf2\x89\x82\xca\x07\x06\x17\x26\xe5\xd9\x99\xf3\xc2");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x28\x9e\x88\x9b\x25\xf9\xf3\x8f\xac\xfc\xcf\x3b\xdb\xce\xea\x06\xef\x3b\xaa\xd6\xe9\x61\x2b\x72\x32\xcd\x55\x3f\x48\x84\xa7\xa6\x42\xf6\x58\x3a\x1a\x58\x9d\x4d\xcb\x2d\xc7\x71\xf1\xff\x6d\x71\x1b\x85\xf7\x31\x14\x5a\x89\xb1\x00\x68\x0f\x9a\x55\xdc\xbb\x3f"[..]);

        ctx.update(b"\xd7\xf9\x05\x39\x84\x21\x3e\xba\xbc\x84\x2f\xd8\xce\x48\x36\x09\xa9\xaf\x5d\xc1\x40\xec\xdb\xe6\x33\x36");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xf1\x67\xcb\x30\xe4\xba\xcb\xdc\x5e\xd5\x3b\xc6\x15\xf8\xc9\xea\x19\xad\x4f\x6b\xd8\x5c\xa0\xff\x5f\xb1\xf1\xcb\xe5\xb5\x76\xbd\xa4\x92\x76\xaa\x58\x14\x29\x1a\x7e\x32\x0f\x1d\x68\x7b\x16\xba\x8d\x7d\xaa\xb2\xb3\xd7\xe9\xaf\x3c\xd9\xf8\x4a\x1e\x99\x79\xa1"[..]);

        ctx.update(b"\x9b\x7f\x9d\x11\xbe\x48\xe7\x86\xa1\x1a\x47\x2a\xb2\x34\x4c\x57\xad\xf6\x2f\x7c\x1d\x4e\x6d\x28\x20\x74\xb6");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x82\xfa\x52\x5d\x5e\xfa\xa3\xcc\xe3\x9b\xff\xef\x8e\xee\x01\xaf\xb5\x20\x67\x09\x7f\x89\x65\xcd\xe7\x17\x03\x34\x53\x22\x64\x5e\xae\x59\xdb\xae\xbe\xd0\x80\x56\x93\x10\x4d\xfb\x0c\x58\x11\xc5\x82\x8d\xa9\xa7\x5d\x81\x2e\x55\x62\x61\x52\x48\xc0\x3f\xf8\x80"[..]);

        ctx.update(b"\x11\x57\x84\xb1\xfc\xcf\xab\xca\x45\x7c\x4e\x27\xa2\x4a\x78\x32\x28\x0b\x7e\x7d\x6a\x12\x3f\xfc\xe5\xfd\xab\x72");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xec\x12\xc4\xed\x5a\xe8\x48\x08\x88\x3c\x53\x51\x00\x3f\x7e\x26\xe1\xea\xf5\x09\xc8\x66\xb3\x57\xf9\x74\x72\xe5\xe1\x9c\x84\xf9\x9f\x16\xdb\xbb\x8b\xff\xf0\x60\xd6\xc0\xfe\x0c\xa9\xc3\x4a\x21\x0c\x90\x9b\x05\xf6\xa8\x1f\x44\x16\x27\xce\x8e\x66\x6f\x6d\xc7"[..]);

        ctx.update(b"\xc3\xb1\xad\x16\xb2\x87\x7d\xef\x8d\x08\x04\x77\xd8\xb5\x91\x52\xfe\x5e\x84\xf3\xf3\x38\x0d\x55\x18\x2f\x36\xeb\x5f");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x4b\x91\x44\xed\xee\xec\x28\xfd\x52\xba\x41\x76\xa7\x8e\x08\x0e\x57\x78\x2d\x23\x29\xb6\x7d\x8a\xc8\x78\x0b\xb6\xe8\xc2\x05\x75\x83\x17\x2a\xf1\xd0\x68\x92\x2f\xea\xaf\xf7\x59\xbe\x5a\x6e\xa5\x48\xf5\xdb\x51\xf4\xc3\x4d\xfe\x72\x36\xca\x09\xa6\x79\x21\xc7"[..]);

        ctx.update(b"\x4c\x66\xca\x7a\x01\x12\x9e\xac\xa1\xd9\x9a\x08\xdd\x72\x26\xa5\x82\x4b\x84\x0d\x06\xd0\x05\x9c\x60\xe9\x7d\x29\x1d\xc4");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x56\x7c\x46\xf2\xf6\x36\x22\x3b\xd5\xed\x3d\xc9\x8c\x3f\x7a\x73\x9b\x42\x89\x8e\x70\x88\x6f\x13\x2e\xac\x43\xc2\xa6\xfa\xda\xbe\x0d\xd9\xf1\xb6\xbc\x4a\x93\x65\xe5\x23\x22\x95\xac\x1a\xc3\x47\x01\xb0\xfb\x18\x1d\x2f\x7f\x07\xa7\x9d\x03\x3d\xd4\x26\xd5\xa2"[..]);

        ctx.update(b"\x48\x10\x41\xc2\xf5\x66\x62\x31\x6e\xe8\x5a\x10\xb9\x8e\x10\x3c\x8d\x48\x80\x4f\x6f\x95\x02\xcf\x1b\x51\xcf\xa5\x25\xce\xc1");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x46\xf0\x05\x8a\xbe\x67\x81\x95\xb5\x76\xdf\x5c\x7e\xb8\xd7\x39\x46\x8c\xad\x19\x08\xf7\x95\x3e\xa3\x9c\x93\xfa\x1d\x96\x84\x5c\x38\xa2\x93\x4d\x23\x80\x48\x64\xa8\x36\x8d\xae\x38\x19\x1d\x98\x30\x53\xcc\xd0\x45\xa9\xab\x87\xef\x26\x19\xe9\xdd\x50\xc8\xc1"[..]);

        ctx.update(b"\x7c\x16\x88\x21\x7b\x31\x32\x78\xb9\xea\xe8\xed\xcf\x8a\xa4\x27\x16\x14\x29\x6d\x0c\x1e\x89\x16\xf9\xe0\xe9\x40\xd2\x8b\x88\xc5");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x62\x7b\xa4\xde\x74\xd0\x5b\xb6\xdf\x89\x91\x11\x2e\x4d\x37\x3b\xfc\xed\x37\xac\xde\x13\x04\xe0\xf6\x64\xf2\x9f\xa1\x26\xcb\x49\x7c\x8a\x1b\x71\x7b\x99\x29\x12\x08\x83\xec\x88\x98\x96\x8e\x46\x49\x01\x3b\x76\x0a\x21\x80\xa9\xdc\x0f\xc9\xb2\x7f\x5b\x7f\x3b"[..]);

        ctx.update(b"\x78\x5f\x65\x13\xfc\xd9\x2b\x67\x4c\x45\x0e\x85\xda\x22\x25\x7b\x8e\x85\xbf\xa6\x5e\x5d\x9b\x1b\x1f\xfc\x5c\x46\x9a\xd3\x37\xd1\xe3");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x5c\x11\xd6\xe4\xc5\xc5\xf7\x6d\x26\x87\x6c\x59\x76\xb6\xf5\x55\xc2\x55\xc7\x85\xb2\xf2\x8b\x67\x00\xca\x2d\x8b\x3b\x3f\xa5\x85\x63\x62\x39\x27\x77\x73\x33\x0f\x4c\xf8\xc5\xd5\x20\x3b\xcc\x09\x1b\x8d\x47\xe7\x74\x3b\xbc\x0b\x5a\x2c\x54\x44\x4e\xe2\xac\xce"[..]);

        ctx.update(b"\x34\xf4\x46\x8e\x2d\x56\x7b\x1e\x32\x6c\x09\x42\x97\x0e\xfa\x32\xc5\xca\x2e\x95\xd4\x2c\x98\xeb\x5d\x3c\xab\x28\x89\x49\x0e\xa1\x6e\xe5");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x49\xad\xfa\x33\x5e\x18\x3c\x94\xb3\x16\x01\x54\xd6\x69\x8e\x31\x8c\x8b\x5d\xd1\x00\xb0\x22\x7e\x3e\x34\xca\xbe\xa1\xfe\x0f\x74\x53\x26\x22\x0f\x64\x26\x39\x61\x34\x99\x96\xbb\xe1\xaa\xe9\x05\x4d\xe6\x40\x6e\x8b\x35\x04\x08\xab\x0b\x9f\x65\x6b\xb8\xda\xf7"[..]);

        ctx.update(b"\x53\xa0\x12\x1c\x89\x93\xb6\xf6\xee\xc9\x21\xd2\x44\x50\x35\xdd\x90\x65\x4a\xdd\x12\x98\xc6\x72\x7a\x2a\xed\x9b\x59\xba\xfb\x7d\xd6\x20\x70");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x91\x8b\x4d\x92\xe1\xfc\xb6\x5a\x4c\x1f\xa0\xbd\x75\xc5\x62\xac\x9d\x83\x18\x6b\xb2\xfb\xfa\xe5\xc4\x78\x4d\xe3\x1a\x14\x65\x45\x46\xe1\x07\xdf\x0e\x79\x07\x6b\x86\x87\xbb\x38\x41\xc8\x3b\xa9\x18\x1f\x99\x56\xcd\x43\x42\x8b\xa7\x2f\x60\x38\x81\xb3\x3a\x71"[..]);

        ctx.update(b"\xd3\x0f\xa4\xb4\x0c\x9f\x84\xac\x9b\xcb\xb5\x35\xe8\x69\x89\xec\x6d\x1b\xec\x9b\x1b\x22\xe9\xb0\xf9\x73\x70\xed\x0f\x0d\x56\x60\x82\x89\x9d\x96");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x39\xf1\x04\xc1\xda\x4a\xf3\x14\xd6\xbc\xeb\x34\xec\xa1\xdf\xe4\xe6\x74\x84\x51\x9e\xb7\x6b\xa3\x8e\x47\x01\xe1\x13\xe6\xcb\xc0\x20\x0d\xf8\x6e\x44\x39\xd6\x74\xb0\xf4\x2c\x72\x23\x33\x60\x47\x8b\xa5\x24\x43\x84\xd2\x8e\x38\x8c\x87\xaa\xa8\x17\x00\x7c\x69"[..]);

        ctx.update(b"\xf3\x4d\x10\x02\x69\xae\xe3\xea\xd1\x56\x89\x5e\x86\x44\xd4\x74\x94\x64\xd5\x92\x1d\x61\x57\xdf\xfc\xbb\xad\xf7\xa7\x19\xae\xe3\x5a\xe0\xfd\x48\x72");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x56\x5a\x1d\xd9\xd4\x9f\x8d\xde\xfb\x79\xa3\xc7\xa2\x09\xf5\x3f\x0b\xc9\xf5\x39\x62\x69\xb1\xce\x2a\x2b\x28\x3a\x3c\xb4\x5e\xe3\xae\x65\x2e\x4c\xa1\x0b\x26\xce\xd7\xe5\x23\x62\x27\x00\x6c\x94\xa3\x75\x53\xdb\x1b\x6f\xe5\xc0\xc2\xed\xed\x75\x6c\x89\x6b\xb1"[..]);

        ctx.update(b"\x12\x52\x97\x69\xfe\x51\x91\xd3\xfc\xe8\x60\xf4\x34\xab\x11\x30\xce\x38\x9d\x34\x0f\xca\x23\x2c\xc5\x0b\x75\x36\xe6\x2a\xd6\x17\x74\x2e\x02\x2e\xa3\x8a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xda\xee\x10\xe8\x15\xff\xf0\xf0\x98\x5d\x20\x88\x86\xe2\x2f\x9b\xf2\x0a\x36\x43\xeb\x9a\x29\xfd\xa4\x69\xb6\xa7\xdc\xd5\x4b\x52\x13\xc8\x51\xd6\xf1\x93\x38\xd6\x36\x88\xfe\x1f\x02\x93\x6c\x5d\xae\x1b\x7c\x6d\x59\x06\xa1\x3a\x9e\xeb\x93\x44\x00\xb6\xfe\x8c"[..]);

        ctx.update(b"\xb2\xe3\xa0\xeb\x36\xbf\x16\xaf\xb6\x18\xbf\xd4\x2a\x56\x78\x91\x79\x14\x7e\xff\xec\xc6\x84\xd8\xe3\x9f\x03\x7e\xc7\xb2\xd2\x3f\x3f\x57\xf6\xd7\xa7\xd0\xbb");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x04\x02\x9d\x6d\x9e\x8e\x39\x4a\xfa\x38\x7f\x1d\x03\xab\x6b\x8a\x0a\x6c\xba\xb4\xb6\xb3\xc8\x6e\xf6\x2f\x71\x42\xab\x3c\x10\x83\x88\xd4\x2c\xb8\x72\x58\xb9\xe6\xd3\x6e\x58\x14\xd8\xa6\x62\x65\x7c\xf7\x17\xb3\x5a\x57\x08\x36\x5e\x8e\xc0\x39\x6e\xc5\x54\x6b"[..]);

        ctx.update(b"\x25\xc4\xa5\xf4\xa0\x7f\x2b\x81\xe0\x53\x33\x13\x66\x4b\xf6\x15\xc7\x32\x57\xe6\xb2\x93\x0e\x75\x2f\xe5\x05\x0e\x25\xff\x02\x73\x1f\xd2\x87\x2f\x4f\x56\xf7\x27");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xec\x2d\x38\xe5\xbb\x5d\x7b\x18\x43\x8d\x5f\x20\x29\xc8\x6d\x05\xa0\x35\x10\xdb\x0e\x66\xaa\x29\x9c\x28\x63\x5a\xbd\x09\x88\xc5\x8b\xe2\x03\xf0\x4b\x7e\x0c\xc2\x54\x51\xd1\x8f\x23\x41\xcd\x46\xf8\x70\x5d\x46\xc2\x06\x6d\xaf\xab\x30\xd9\x0d\x63\xbf\x3d\x2c"[..]);

        ctx.update(b"\x13\x4b\xb8\xe7\xea\x5f\xf9\xed\xb6\x9e\x8f\x6b\xbd\x49\x8e\xb4\x53\x75\x80\xb7\xfb\xa7\xad\x31\xd0\xa0\x99\x21\x23\x7a\xcd\x7d\x66\xf4\xda\x23\x48\x0b\x9c\x12\x22");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x8f\x96\x6a\xef\x96\x83\x1a\x14\x99\xd6\x35\x60\xb2\x57\x80\x21\xad\x97\x0b\xf7\x55\x7b\x8b\xf8\x07\x8b\x3e\x12\xce\xfa\xb1\x22\xfe\x71\xb1\x21\x2d\xc7\x04\xf7\x09\x4a\x40\xb3\x6b\x71\xd3\xad\x7c\xe2\xd3\x0f\x72\xc1\xba\xa4\xd4\xbb\xcc\xb3\x25\x11\x98\xac"[..]);

        ctx.update(b"\xf7\x93\x25\x6f\x03\x9f\xad\x11\xaf\x24\xce\xe4\xd2\x23\xcd\x2a\x77\x15\x98\x28\x99\x95\xab\x80\x2b\x59\x30\xba\x5c\x66\x6a\x24\x18\x84\x53\xdc\xd2\xf0\x84\x2b\x81\x52");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x22\xc3\xd9\x71\x25\x35\x15\x3a\x3e\x20\x6b\x10\x33\x92\x9c\x0f\xd9\xd9\x37\xc3\x9b\xa1\x3c\xf1\xa6\x54\x4d\xfb\xd6\x8e\xbc\x94\x86\x7b\x15\xfd\xa3\xf1\xd3\x0b\x00\xbf\x47\xf2\xc4\xbf\x41\xda\xbd\xea\xa5\xc3\x97\xda\xe9\x01\xc5\x7d\xb9\xcd\x77\xdd\xbc\xc0"[..]);

        ctx.update(b"\x23\xcc\x7f\x90\x52\xd5\xe2\x2e\x67\x12\xfa\xb8\x8e\x8d\xfa\xa9\x28\xb6\xe0\x15\xca\x58\x9c\x3b\x89\xcb\x74\x5b\x75\x6c\xa7\xc7\x63\x4a\x50\x3b\xf0\x22\x8e\x71\xc2\x8e\xe2");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x6e\xcf\x3a\xd6\x06\x42\x18\xee\x10\x1a\x55\x5d\x20\xfa\xb6\xcb\xeb\x6b\x14\x5b\x4e\xeb\x9c\x8c\x97\x1f\xc7\xce\x05\x58\x1a\x34\xb3\xc5\x21\x79\x59\x0e\x8a\x13\x4b\xe2\xe8\x8c\x7e\x54\x98\x75\xf4\xff\x89\xb9\x63\x74\xc6\x99\x59\x60\xde\x3a\x50\x98\xcc\xed"[..]);

        ctx.update(b"\xa6\x0b\x7b\x3d\xf1\x5b\x3f\x1b\x19\xdb\x15\xd4\x80\x38\x8b\x0f\x3b\x00\x83\x73\x69\xaa\x2c\xc7\xc3\xd7\x31\x57\x75\xd7\x30\x9a\x2d\x6f\x6d\x13\x71\xd9\xc8\x75\x35\x0d\xec\x0a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x8d\x65\x16\x05\xc6\xb3\x2b\xf0\x22\xea\x06\xce\x63\x06\xb2\xca\x6b\x5b\xa2\x78\x1a\xf8\x7c\xa2\x37\x58\x60\x31\x5c\x83\xad\x88\x74\x30\x30\xd1\x48\xed\x8d\x73\x19\x4c\x46\x1e\xc1\xe8\x4c\x04\x5f\xc9\x14\x70\x57\x47\x61\x4c\x04\xc8\x86\x5b\x51\xda\x94\xf7"[..]);

        ctx.update(b"\x27\x45\xdd\x2f\x1b\x21\x5e\xa5\x09\xa9\x12\xe5\x76\x1c\xcc\xc4\xf1\x9f\xa9\x3b\xa3\x84\x45\xc5\x28\xcb\x2f\x09\x9d\xe9\x9a\xb9\xfa\xc9\x55\xba\xa2\x11\xfd\x85\x39\xa6\x71\xcd\xb6");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x4a\xf9\x18\xeb\x67\x6c\xe2\x78\xc7\x30\x21\x2e\xf7\x9d\x81\x87\x73\xa7\x6a\x43\xc7\x4d\x64\x3f\x23\x8e\x9b\x61\xac\xaf\x40\x30\xc6\x17\xc4\xd6\xb3\xb7\x51\x4c\x59\xb3\xe5\xe9\x5d\x82\xe1\xe1\xe3\x54\x43\xe8\x51\x71\x8b\x13\xb6\x3e\x70\xb1\x23\xd1\xb7\x2c"[..]);

        ctx.update(b"\x88\xad\xee\x4b\x46\xd2\xa1\x09\xc3\x6f\xcf\xb6\x60\xf1\x7f\x48\x06\x2f\x7a\x74\x67\x9f\xb0\x7e\x86\xca\xd8\x4f\x79\xfd\x57\xc8\x6d\x42\x63\x56\xec\x8e\x68\xc6\x5b\x3c\xaa\x5b\xc7\xba");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x62\x57\xac\xb9\xf5\x89\xc9\x19\xc9\x3c\x0a\xdc\x4e\x90\x7f\xe0\x11\xbe\xf6\x01\x8f\xbb\x18\xe6\x18\xba\x6f\xcc\x8c\xbc\x5e\x40\x64\x1b\xe5\x89\xe8\x6d\xbb\x0c\xf7\xd7\xd6\xbf\x33\xb9\x8d\x84\x58\xcc\xe0\xaf\x78\x57\xf5\xa7\xc7\x64\x7c\xf3\x50\xe2\x5a\xf0"[..]);

        ctx.update(b"\x7d\x40\xf2\xdc\x4a\xf3\xcf\xa1\x2b\x00\xd6\x49\x40\xdc\x32\xa2\x2d\x66\xd8\x1c\xb6\x28\xbe\x2b\x8d\xda\x47\xed\x67\x28\x02\x0d\x55\xb6\x95\xe7\x52\x60\xf4\xec\x18\xc6\xd7\x48\x39\x08\x6a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x5c\x46\xc8\x4a\x0a\x02\xd8\x98\xed\x58\x85\xce\x99\xc4\x7c\x77\xaf\xd2\x9a\xe0\x15\xd0\x27\xf2\x48\x5d\x63\x0f\x9b\x41\xd0\x0b\x7c\x1f\x1f\xaf\x6c\xe5\x7a\x08\xb6\x04\xb3\x50\x21\xf7\xf7\x96\x00\x38\x19\x94\xb7\x31\xbd\x8e\x6a\x5b\x01\x0a\xeb\x90\xe1\xeb"[..]);

        ctx.update(b"\x36\x89\xd8\x83\x6a\xf0\xdc\x13\x2f\x85\xb2\x12\xeb\x67\x0b\x41\xec\xf9\xd4\xab\xa1\x41\x09\x2a\x0a\x8e\xca\x2e\x6d\x5e\xb0\xba\x4b\x7e\x61\xaf\x92\x73\x62\x4d\x14\x19\x2d\xf7\x38\x8a\x84\x36");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x17\x35\x5e\x61\xd6\x6e\x40\xf7\x50\xd0\xa9\xa8\xe8\xa8\x8c\xd6\xf9\xbf\x60\x70\xb7\xef\xa7\x64\x42\x69\x87\x40\xb4\x48\x7e\xa6\xc6\x44\xd1\x65\x4e\xf1\x6a\x26\x52\x04\xe0\x30\x84\xa1\x4c\xaf\xdc\xcf\x8f\xf2\x98\xcd\x54\xc0\xb4\x00\x99\x67\xb6\xdd\x47\xcc"[..]);

        ctx.update(b"\x58\xff\x23\xde\xe2\x29\x8c\x2c\xa7\x14\x62\x27\x78\x9c\x1d\x40\x93\x55\x10\x47\x19\x2d\x86\x2f\xc3\x4c\x11\x12\xd1\x3f\x1f\x74\x44\x56\xce\xcc\x4d\x4a\x02\x41\x05\x23\xb4\xb1\x5e\x59\x8d\xf7\x5a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xac\xa8\x9a\xa5\x47\xc4\x61\x73\xb4\xb2\xa3\x80\xba\x98\x0d\xa6\xf9\xac\x08\x4f\x46\xac\x9d\xde\xa5\xe4\x16\x4a\xee\xf3\x1a\x99\x55\xb8\x14\xa4\x5a\xec\x1d\x8c\xe3\x40\xbd\x37\x68\x09\x52\xc5\xd6\x82\x26\xdd\xa1\xca\xc2\x67\x7f\x73\xc9\xfd\x91\x74\xfd\x13"[..]);

        ctx.update(b"\x67\xf3\xf2\x3d\xf3\xbd\x8e\xbe\xb0\x09\x64\x52\xfe\x47\x75\xfd\x9c\xc7\x1f\xbb\x6e\x72\xfd\xcc\x7e\xb8\x09\x4f\x42\xc9\x03\x12\x1d\x08\x17\xa9\x27\xbc\xba\xbd\x31\x09\xd5\xa7\x04\x20\x25\x3d\xea\xb2");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xf4\x20\x7c\xc5\x65\xf2\x66\xa2\x45\xf2\x9b\xf2\x0b\x95\xb5\xd9\xa8\x3e\x1b\xb6\x8a\xd9\x88\xed\xc9\x1f\xaa\x25\xf2\x52\x86\xc8\x39\x8b\xac\x7d\xd6\x62\x82\x59\xbf\xf9\x8f\x28\x36\x0f\x26\x3d\xfc\x54\xc4\x22\x8b\xc4\x37\xc5\x69\x1d\xe1\x21\x9b\x75\x8d\x9f"[..]);

        ctx.update(b"\xa2\x25\x07\x0c\x2c\xb1\x22\xc3\x35\x4c\x74\xa2\x54\xfc\x7b\x84\x06\x1c\xba\x33\x00\x5c\xab\x88\xc4\x09\xfb\xd3\x73\x8f\xf6\x7c\xe2\x3c\x41\xeb\xef\x46\xc7\xa6\x16\x10\xf5\xb9\x3f\xa9\x2a\x5b\xda\x95\x69");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xe8\x15\xa9\xa4\xe4\x88\x7b\xe0\x14\x63\x5e\x97\x95\x83\x41\xe0\x51\x93\x14\xb3\xa3\x28\x9e\x18\x35\x12\x1b\x15\x3b\x46\x22\x72\xb0\xac\xa4\x18\xbe\x96\xd6\x0e\x5a\xb3\x55\xd3\xeb\x46\x36\x97\xc0\x19\x1e\xb5\x22\xb6\x0b\x84\x63\xd8\x9f\x4c\x3f\x1b\xf1\x42"[..]);

        ctx.update(b"\x6a\xa0\x88\x67\x77\xe9\x9c\x9a\xcd\x5f\x1d\xb6\xe1\x2b\xda\x59\xa8\x07\xf9\x24\x11\xae\x99\xc9\xd4\x90\xb5\x65\x6a\xcb\x4b\x11\x5c\x57\xbe\xb3\xc1\x80\x7a\x1b\x02\x9a\xd6\x4b\xe1\xf0\x3e\x15\xba\xfd\x91\xec");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x24\x1f\x2e\xba\xf7\xad\x09\xe1\x73\xb1\x84\x24\x4e\x69\xac\xd7\xeb\xc9\x47\x74\xd0\xfa\x39\x02\xcb\xf2\x67\xd4\x80\x60\x63\xb0\x44\x13\x1b\xcf\x4a\xf4\xcf\x18\x0e\xb7\xbd\x4e\x79\x60\xce\x5f\xe3\xdc\x6a\xeb\xfc\x6b\x90\xee\xc4\x61\xf4\x14\xf7\x9a\x67\xd9"[..]);

        ctx.update(b"\x6a\x06\x09\x2a\x3c\xd2\x21\xae\x86\xb2\x86\xb3\x1f\x32\x62\x48\x27\x04\x72\xc5\xea\x51\x0c\xb9\x06\x4d\x60\x24\xd1\x0e\xfe\xe7\xf5\x9e\x98\x78\x5d\x4f\x09\xda\x55\x4e\x97\xcd\xec\x7b\x75\x42\x9d\x78\x8c\x11\x2f");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xd1\x4a\x1a\x47\xf2\xbe\xf9\xe0\xd4\xb3\xe9\x0a\x6b\xe9\xab\x58\x93\xe1\x11\x0b\x12\xdb\x38\xd3\x3f\xfb\x9a\x61\xe1\x66\x1a\xec\xc4\xea\x10\x08\x39\xcf\xee\x58\xa1\xc5\xaf\xf7\x29\x15\xc1\x41\x70\xdd\x99\xe1\x3f\x71\xb0\xa5\xfc\x19\x85\xbf\x43\x41\x5c\xb0"[..]);

        ctx.update(b"\xdf\xc3\xfa\x61\xf7\xff\xfc\x7c\x88\xed\x90\xe5\x1d\xfc\x39\xa4\xf2\x88\xb5\x0d\x58\xac\x83\x38\x5b\x58\xa3\xb2\xa3\xa3\x9d\x72\x98\x62\xc4\x0f\xca\xf9\xbc\x30\x8f\x71\x3a\x43\xee\xcb\x0b\x72\xbb\x94\x58\xd2\x04\xba");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x94\x7b\xc8\x73\xdc\x41\xdf\x19\x5f\x80\x45\xde\xb6\xea\x1b\x84\x0f\x63\x39\x17\xe7\x9c\x70\xa8\x8d\x38\xb8\x86\x21\x97\xdc\x2a\xb0\xcc\x63\x14\xe9\x74\xfb\x5b\xa7\xe1\x70\x3b\x22\xb1\x30\x9e\x37\xbd\x43\x08\x79\x05\x6b\xdc\x16\x65\x73\x07\x5a\x9c\x5e\x04"[..]);

        ctx.update(b"\x52\x95\x8b\x1f\xf0\x04\x9e\xfa\x5d\x05\x0a\xb3\x81\xec\x99\x73\x2e\x55\x4d\xcd\x03\x72\x5d\xa9\x91\xa3\x7a\x80\xbd\x47\x56\xcf\x65\xd3\x67\xc5\x47\x21\xe9\x3f\x1e\x0a\x22\xf7\x0d\x36\xe9\xf8\x41\x33\x69\x56\xd3\xc5\x23");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x9c\xc5\xaa\xd0\xf5\x29\xf4\xba\xc4\x91\xd7\x33\x53\x7b\x69\xc8\xec\x70\x0f\xe3\x8a\xb4\x23\xd8\x15\xe0\x92\x7c\x86\x57\xf9\xcb\x8f\x42\x07\x76\x2d\x81\x6a\xb6\x97\x58\x01\x22\x06\x6b\xc2\xb6\x8f\x41\x77\x33\x5d\x0a\x6e\x90\x81\x54\x07\x79\xe5\x72\xc4\x1f"[..]);

        ctx.update(b"\x30\x2f\xa8\x4f\xda\xa8\x20\x81\xb1\x19\x2b\x84\x7b\x81\xdd\xea\x10\xa9\xf0\x5a\x0f\x04\x13\x8f\xd1\xda\x84\xa3\x9b\xa5\xe1\x8e\x18\xbc\x3c\xea\x06\x2e\x6d\xf9\x2f\xf1\xac\xe8\x9b\x3c\x5f\x55\x04\x31\x30\x10\x8a\xbf\x63\x1e");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x8c\x8e\xaa\xe9\xa4\x45\x64\x3a\x37\xdf\x34\xcf\xa6\xa7\xf0\x9d\xec\xca\xb2\xa2\x22\xc4\x21\xd2\xfc\x57\x4b\xbc\x56\x41\xe5\x04\x35\x43\x91\xe8\x1e\xb5\x13\x02\x80\xb1\x22\x68\x12\x55\x6d\x47\x4e\x95\x1b\xb7\x8d\xbd\xd9\xb7\x7d\x19\xf6\x47\xe2\xe7\xd7\xbe"[..]);

        ctx.update(b"\xb8\x2f\x50\x0d\x6b\xc2\xdd\xdc\xdc\x16\x2d\x46\xcb\xfa\xa5\xae\x64\x02\x5d\x5c\x1c\xd7\x24\x72\xdc\xd2\xc4\x21\x61\xc9\x87\x1c\xe3\x29\xf9\x4d\xf4\x45\xf0\xc8\xac\xee\xca\xfd\x03\x44\xf6\x31\x7e\xcb\xb6\x2f\x0e\xc2\x22\x3a\x35");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x55\xc6\x9d\x7a\xcc\xd1\x79\xd5\xd9\xfc\xc5\x22\xf7\x94\xe7\xaf\x5f\x0e\xec\x71\x98\xff\xa3\x9f\x80\xfb\x55\xb8\x66\xc0\x85\x7f\xf3\xe7\xae\xef\x33\xe1\x30\xd9\xc7\x4e\xf9\x06\x06\xca\x82\x1d\x20\xb7\x60\x8b\x12\xe6\xe5\x61\xf9\xe6\xc7\x12\x2a\xce\x3d\xb0"[..]);

        ctx.update(b"\x86\xda\x91\x07\xca\x3e\x16\xa2\xb5\x89\x50\xe6\x56\xa1\x5c\x08\x5b\x88\x03\x3e\x79\x31\x3e\x2c\x0f\x92\xf9\x9f\x06\xfa\x18\x7e\xfb\xa5\xb8\xfe\xa0\x8e\xb7\x14\x5f\x84\x76\x30\x41\x80\xdd\x28\x0f\x36\xa0\x72\xb7\xea\xc1\x97\xf0\x85");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x0d\x3b\x1a\x04\x59\xb4\xec\xa8\x01\xe0\x73\x7f\xf9\xea\x4a\x12\xb9\xa4\x83\xa7\x3a\x8a\x92\x74\x2a\x93\xc2\x97\xb7\x14\x93\x26\xbd\x92\xc1\x64\x3c\x81\x77\xc8\x92\x44\x82\xab\x3b\xbd\x91\x6c\x41\x75\x80\xcc\x75\xd3\xd3\xae\x09\x6d\xe5\x31\xbc\x5d\xc3\x55"[..]);

        ctx.update(b"\x14\x1a\x6e\xaf\xe1\x57\x05\x3e\x78\x0a\xc7\xa5\x7b\x97\x99\x06\x16\xce\x17\x59\xed\x13\x2c\xb4\x53\xbc\xdf\xca\xbd\xbb\x70\xb3\x76\x7d\xa4\xeb\x94\x12\x5d\x9c\x2a\x8d\x6d\x20\xbf\xae\xac\xc1\xff\xbe\x49\xc4\xb1\xbb\x5d\xa7\xe9\xb5\xc6");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xbd\xbd\xd5\xb9\x4c\xdc\x89\x46\x6e\x76\x70\xc6\x3b\xa6\xa5\x5b\x58\x29\x4e\x93\xb3\x51\x26\x1a\x54\x57\xbf\x5a\x40\xf1\xb5\xb2\xe0\xac\xc7\xfc\xeb\x1b\xfb\x4c\x88\x72\x77\x7e\xee\xaf\xf7\x92\x7f\xd3\x63\x5c\xa1\x8c\x99\x6d\x87\x0b\xf8\x6b\x12\xb8\x9b\xa5"[..]);

        ctx.update(b"\x6e\x0c\x65\xee\x09\x43\xe3\x4d\x9b\xbd\x27\xa8\x54\x76\x90\xf2\x29\x1f\x5a\x86\xd7\x13\xc2\xbe\x25\x8e\x6a\xc1\x69\x19\xfe\x9c\x4d\x49\x18\x95\xd3\xa9\x61\xbb\x97\xf5\xfa\xc2\x55\x89\x1a\x0e\xaa\x18\xf8\x0e\x1f\xa1\xeb\xcb\x63\x9f\xcf\xc1");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x39\xeb\xb9\x92\xb8\xd3\x9d\xaa\xe9\x73\xe3\x81\x3a\x50\xe9\xe7\x9a\x67\xd8\x45\x8a\x6f\x17\xf9\x7a\x6d\xd3\x0d\xd7\xd1\x1d\x95\x70\x1a\x11\x12\x9f\xfe\xaf\x7d\x45\x78\x1b\x21\xca\xc0\xc4\xc0\x34\xe3\x89\xd7\x59\x0d\xf5\xbe\xeb\x98\x05\x07\x2d\x01\x83\xb9"[..]);

        ctx.update(b"\x57\x78\x0b\x1c\x79\xe6\x7f\xc3\xbe\xaa\xbe\xad\x4a\x67\xa8\xcc\x98\xb8\x3f\xa7\x64\x7e\xae\x50\xc8\x79\x8b\x96\xa5\x16\x59\x7b\x44\x88\x51\xe9\x3d\x1a\x62\xa0\x98\xc4\x76\x73\x33\xfc\xf7\xb4\x63\xce\x91\xed\xde\x2f\x3a\xd0\xd9\x8f\x70\x71\x6d");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x3e\xf3\x6c\x3e\xff\xad\x6e\xb5\xad\x2d\x0a\x67\x78\x0f\x80\xd1\xb9\x0e\xfc\xb7\x4d\xb2\x04\x10\xc2\x26\x1a\x3a\xb0\xf7\x84\x42\x9d\xf8\x74\x81\x47\x48\xdc\x1b\x6e\xfa\xab\x3d\x06\xdd\x0a\x41\xba\x54\xfc\xe5\x9b\x67\xd4\x58\x38\xea\xa4\xaa\x1f\xad\xfa\x0f"[..]);

        ctx.update(b"\xbc\xc9\x84\x9d\xa4\x09\x1d\x0e\xdf\xe9\x08\xe7\xc3\x38\x6b\x0c\xad\xad\xb2\x85\x98\x29\xc9\xdf\xee\x3d\x8e\xcf\x9d\xec\x86\x19\x6e\xb2\xce\xb0\x93\xc5\x55\x1f\x7e\x9a\x49\x27\xfa\xab\xcf\xaa\x74\x78\xf7\xc8\x99\xcb\xef\x47\x27\x41\x77\x38\xfc\x06");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x1f\xcd\x8a\x2c\x7b\x4f\xd9\x8f\xcd\xc5\xfa\x66\x5b\xab\x49\xbd\xe3\xf9\xf5\x56\xaa\x66\xb3\x64\x66\x38\xf5\xa2\xd3\x80\x61\x92\xf8\xa3\x31\x45\xd8\xd0\xc5\x35\xc8\x5a\xdf\xf3\xcc\x0e\xa3\xc2\x71\x5b\x33\xce\xc9\xf8\x88\x6e\x9f\x43\x77\xb3\x63\x2e\x90\x55"[..]);

        ctx.update(b"\x05\xa3\x28\x29\x64\x2e\xd4\x80\x8d\x65\x54\xd1\x6b\x9b\x80\x23\x35\x3c\xe6\x5a\x93\x5d\x12\x66\x02\x97\x0d\xba\x79\x16\x23\x00\x4d\xed\xe9\x0b\x52\xac\x7f\x0d\x43\x35\x13\x0a\x63\xcb\xa6\x8c\x65\x6c\x13\x99\x89\x61\x4d\xe2\x09\x13\xe8\x3d\xb3\x20\xdb");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x49\xd8\x74\x7b\xb5\x3d\xdd\xe6\xd1\x48\x59\x65\x20\x86\x70\xd1\x13\x0b\xf3\x56\x19\xd7\x50\x6a\x2f\x20\x40\xd1\x12\x9f\xcf\x03\x20\x20\x7e\x5b\x36\xfe\xa0\x83\xe8\x4f\xfc\x98\x75\x5e\x69\x1a\xd8\xbd\x5d\xc6\x6f\x89\x72\xcb\x98\x57\x38\x93\x44\xe1\x1a\xad"[..]);

        ctx.update(b"\x56\xac\x4f\x68\x45\xa4\x51\xda\xc3\xe8\x88\x6f\x97\xf7\x02\x4b\x64\xb1\xb1\xe9\xc5\x18\x1c\x05\x9b\x57\x55\xb9\xa6\x04\x2b\xe6\x53\xa2\xa0\xd5\xd5\x6a\x9e\x1e\x77\x4b\xe5\xc9\x31\x2f\x48\xb4\x79\x80\x19\x34\x5b\xea\xe2\xff\xcc\x63\x55\x4a\x3c\x69\x86\x2e");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x5f\xde\x5c\x57\xa3\x1f\xeb\xb9\x80\x61\xf2\x7e\x45\x06\xfa\x5c\x24\x55\x06\x33\x6e\xe9\x0d\x59\x5c\x91\xd7\x91\xa5\x97\x5c\x71\x2b\x3a\xb9\xb3\xb5\x86\x8f\x94\x1d\xb0\xae\xb4\xc6\xd2\x83\x7c\x44\x47\x44\x2f\x84\x02\xe0\xe1\x50\xa9\xdc\x0e\xf1\x78\xdc\xa8"[..]);

        ctx.update(b"\x8a\x22\x9f\x8d\x02\x94\xfe\x90\xd4\xcc\x8c\x87\x54\x60\xd5\xd6\x23\xf9\x32\x87\xf9\x05\xa9\x99\xa2\xab\x0f\x9a\x47\x04\x6f\x78\xef\x88\xb0\x94\x45\xc6\x71\x18\x9c\x59\x38\x8b\x30\x17\xcc\xa2\xaf\x8b\xdf\x59\xf8\xa6\xf0\x43\x22\xb1\x70\x1e\xc0\x86\x24\xab\x63");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x16\xb0\xfd\x23\x9c\xc6\x32\x84\x2c\x44\x3e\x1b\x92\xd2\x86\xdd\x51\x9c\xfc\x61\x6a\x41\xf2\x45\x6d\xd5\xcd\xde\xbd\x10\x70\x3c\x3e\x9c\xb6\x69\x00\x4b\x7f\x16\x9b\xb4\xf9\x9f\x35\x0e\xc9\x69\x04\xb0\xe8\xdd\x4d\xe8\xe6\xbe\x99\x53\xdc\x89\x2c\x65\x09\x9f"[..]);

        ctx.update(b"\x87\xd6\xaa\x99\x79\x02\x5b\x24\x37\xea\x81\x59\xea\x1d\x3e\x5d\x6f\x17\xf0\xa5\xb9\x13\xb5\x69\x70\x21\x2f\x56\xde\x78\x84\x84\x0c\x0d\xa9\xa7\x28\x65\xe1\x89\x2a\xa7\x80\xb8\xb8\xf5\xf5\x7b\x46\xfc\x07\x0b\x81\xca\x5f\x00\xee\xe0\x47\x0a\xce\x89\xb1\xe1\x46\x6a");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xd8\x16\xac\xf1\x79\x7d\xec\xfe\x34\xf4\xcc\x49\xe5\x2a\xa5\x05\xcc\x59\xbd\x17\xfe\x69\xdc\x95\x43\xfa\xd8\x2e\x9c\xf9\x62\x98\x18\x30\x21\xf7\x04\x05\x4d\x3d\x06\xad\xde\x2b\xf5\x4e\x82\xa0\x90\xa5\x7b\x23\x9e\x88\xda\xa0\x4c\xb7\x6c\x4f\xc9\x12\x78\x43"[..]);

        ctx.update(b"\x08\x23\x61\x6a\xb8\x7e\x49\x04\x30\x86\x28\xc2\x22\x6e\x72\x1b\xb4\x16\x9b\x7d\x34\xe8\x74\x4a\x07\x00\xb7\x21\xe3\x8f\xe0\x5e\x3f\x81\x3f\xe4\x07\x5d\x4c\x1a\x93\x6d\x3a\x33\xda\x20\xcf\xb3\xe3\xac\x72\x2e\x7d\xf7\x86\x53\x30\xb8\xf6\x2a\x73\xd9\x11\x9a\x1f\x21\x99");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xe1\xda\x6b\xe4\x40\x3a\x4f\xd7\x84\xc5\x9b\xe4\xe7\x1c\x65\x8a\x78\xbb\x8c\x5d\x7d\x57\x1c\x5e\x81\x6f\xbb\x3e\x21\x8a\x41\x62\xf6\x2d\xe1\xc2\x85\xf3\x77\x97\x81\xcb\x55\x06\xe2\x9c\x94\xe1\xb7\xc7\xd6\x5a\xf2\xaa\x71\xea\x5c\x96\xd9\x58\x5b\x5e\x45\xd5"[..]);

        ctx.update(b"\x7d\x2d\x91\x3c\x24\x60\xc0\x98\x98\xb2\x03\x66\xae\x34\x77\x5b\x15\x64\xf1\x0e\xde\xa4\x9c\x07\x3c\xeb\xe4\x19\x89\xbb\x93\xf3\x8a\x53\x3a\xf1\xf4\x25\xd3\x38\x2f\x8a\xa4\x01\x59\xb5\x67\x35\x8e\xe5\xa7\x3b\x67\xdf\x6d\x0d\xc0\x9c\x1c\x92\xbf\x3f\x9a\x28\x12\x4a\xb0\x7f");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x3a\xa1\xe1\x9a\x52\xb8\x6c\xf4\x14\xd9\x77\x76\x8b\xb5\x35\xb7\xe5\x81\x71\x17\xd4\x36\xb4\x42\x5e\xc8\xd7\x75\xe8\xcb\x0e\x0b\x53\x80\x72\x21\x38\x84\xc7\xff\x1b\xb9\xca\x99\x84\xc8\x2d\x65\xcb\x01\x15\xcc\x07\x33\x2b\x0e\xa9\x03\xe3\xb3\x86\x50\xe8\x8e"[..]);

        ctx.update(b"\xfc\xa5\xf6\x8f\xd2\xd3\xa5\x21\x87\xb3\x49\xa8\xd2\x72\x6b\x60\x8f\xcc\xea\x7d\xb4\x2e\x90\x6b\x87\x18\xe8\x5a\x0e\xc6\x54\xfa\xc7\x0f\x5a\x83\x9a\x8d\x3f\xf9\x0c\xfe\xd7\xae\xb5\xea\x9b\x08\xf4\x87\xfc\x84\xe1\xd9\xf7\xfb\x83\x1d\xea\x25\x44\x68\xa6\x5b\xa1\x8c\xc5\xa1\x26");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x2c\x74\xf8\x46\xec\xc7\x22\xea\x4a\x1e\xb1\x16\x2e\x23\x1b\x69\x03\x29\x1f\xff\xa9\x5d\xd5\xe1\xd1\x7d\xbc\x2c\x2b\xe7\xdf\xe5\x49\xa8\x0d\xd3\x44\x87\xd7\x14\x13\x0d\xdc\x99\x24\xae\xd9\x04\xad\x55\xf4\x9c\x91\xc8\x0c\xeb\x05\xc0\xc0\x34\xda\xe0\xa0\xa4"[..]);

        ctx.update(b"\x88\x1f\xf7\x0c\xa3\x4a\x3e\x1a\x0e\x86\x4f\xd2\x61\x5c\xa2\xa0\xe6\x3d\xef\x25\x4e\x68\x8c\x37\xa2\x0e\xf6\x29\x7c\xb3\xae\x4c\x76\xd7\x46\xb5\xe3\xd6\xbb\x41\xbd\x0d\x05\xd7\xdf\x3e\xed\xed\x74\x35\x1f\x4e\xb0\xac\x80\x1a\xbe\x6d\xc1\x0e\xf9\xb6\x35\x05\x5e\xe1\xdf\xbf\x41\x44");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x9a\x10\xa7\xce\x23\xc0\x49\x7f\xe8\x78\x39\x27\xf8\x33\x23\x2a\xe6\x64\xf1\xe1\xb9\x13\x02\x26\x6b\x6a\xce\x25\xa9\xc2\x53\xd1\xec\xab\x1a\xaa\xa6\x2f\x86\x54\x69\x48\x0b\x21\x45\xed\x0e\x48\x9a\xe3\xf3\xf9\xf7\xe6\xda\x27\x49\x2c\x81\xb0\x7e\x60\x6f\xb6"[..]);

        ctx.update(b"\xb0\xde\x04\x30\xc2\x00\xd7\x4b\xf4\x1e\xa0\xc9\x2f\x8f\x28\xe1\x1b\x68\x00\x6a\x88\x4e\x0d\x4b\x0d\x88\x45\x33\xee\x58\xb3\x8a\x43\x8c\xc1\xa7\x57\x50\xb6\x43\x4f\x46\x7e\x2d\x0c\xd9\xaa\x40\x52\xce\xb7\x93\x29\x1b\x93\xef\x83\xfd\x5d\x86\x20\x45\x6c\xe1\xaf\xf2\x94\x1b\x36\x05\xa4");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\x9e\x9e\x46\x9c\xa9\x22\x6c\xd0\x12\xf5\xc9\xcc\x39\xc9\x6a\xdc\x22\xf4\x20\x03\x0f\xce\xe3\x05\xa0\xed\x27\x97\x4e\x3c\x80\x27\x01\x60\x3d\xac\x87\x3a\xe4\x47\x6e\x9c\x3d\x57\xe5\x55\x24\x48\x3f\xc0\x1a\xda\xef\x87\xda\xa9\xe3\x04\x07\x8c\x59\x80\x27\x57"[..]);

        ctx.update(b"\x0c\xe9\xf8\xc3\xa9\x90\xc2\x68\xf3\x4e\xfd\x9b\xef\xdb\x0f\x7c\x4e\xf8\x46\x6c\xfd\xb0\x11\x71\xf8\xde\x70\xdc\x5f\xef\xa9\x2a\xcb\xe9\x3d\x29\xe2\xac\x1a\x5c\x29\x79\x12\x9f\x1a\xb0\x8c\x0e\x77\xde\x79\x24\xdd\xf6\x8a\x20\x9c\xdf\xa0\xad\xc6\x2f\x85\xc1\x86\x37\xd9\xc6\xb3\x3f\x4f\xf8");
        ctx.digest(&mut digest);
        assert_eq!(digest, &b"\xb0\x18\xa2\x0f\xcf\x83\x1d\xde\x29\x0e\x4f\xb1\x8c\x56\x34\x2e\xfe\x13\x84\x72\xcb\xe1\x42\xda\x6b\x77\xee\xa4\xfc\xe5\x25\x88\xc0\x4c\x80\x8e\xb3\x29\x12\xfa\xa3\x45\x24\x5a\x85\x03\x46\xfa\xec\x46\xc3\xa1\x6d\x39\xbd\x2e\x1d\xdb\x18\x16\xbc\x57\xd2\xda"[..]);
    }
}
