extern crate nettle;
extern crate rand;

use nettle::hash::{Hash,Sha224,Sha256};
use nettle::Mac;
use nettle::mac::Hmac;

struct Fubar {
    foo: Foo,
    bar: Bar,
    baz: Baz,
}

impl Default for Fubar {
    fn default() -> Fubar {
        Fubar{
            foo: Foo::default(),
            bar: Bar::default(),
            baz: Baz::default(),
        }
    }
}

impl Fubar {
    pub fn produce_hash(&self) -> Vec<u8> {
        let mut h = self.init_hash();

        self.foo.hash(&mut h);
        self.bar.hash(&mut h);
        self.baz.hash(&mut h);

        let mut ret = vec![0u8; h.digest_size()];
        h.digest(&mut ret);

        ret
    }

    pub fn produce_mac(&self) -> Vec<u8> {
        let mut h = self.init_mac();

        self.foo.mac(&mut h);
        self.bar.mac(&mut h);
        self.baz.mac(&mut h);

        let mut ret = vec![0u8; h.mac_size()];
        h.digest(&mut ret);

        ret
    }

    fn init_hash(&self) -> Box<Hash> {
        if rand::random::<bool>() {
            Box::new(Sha224::default())
        } else {
            Box::new(Sha256::default())
        }
    }

    fn init_mac(&self) -> Box<Mac> {
        if rand::random::<bool>() {
            Box::new(Hmac::<Sha224>::with_key(&b"123"[..]))
        } else {
            Box::new(Hmac::<Sha256>::with_key(&b"123"[..]))
        }
    }
}

struct Foo {
    num_foos: usize,
}

impl Default for Foo {
    fn default() -> Foo { Foo{ num_foos: 42 } }
}

impl Foo {
    pub fn hash<H: AsMut<Hash>>(&self, h: &mut H) {
        h.as_mut().update(format!("{}",self.num_foos).as_bytes());
    }

    pub fn mac<H: AsMut<Mac>>(&self, h: &mut H) {
        h.as_mut().update(format!("{}",self.num_foos).as_bytes());
    }
}

struct Bar {
    bar: &'static str,
}

impl Default for Bar {
    fn default() -> Bar {
        Bar{ bar: "Hallo, I bims bar vong foo her" }
    }
}

impl Bar {
    pub fn hash<H: AsMut<Hash>>(&self, h: &mut H) {
        h.as_mut().update(self.bar.as_bytes());
    }

    pub fn mac<H: AsMut<Mac>>(&self, h: &mut H) {
        h.as_mut().update(self.bar.as_bytes());
    }
}

enum Baz {
    One,
    Two,
    Three
}

impl Default for Baz {
    fn default() -> Baz {
        if rand::random::<bool>() {
            if rand::random::<bool>() {
                Baz::One
            } else {
                Baz::Two
            }
        } else {
            Baz::Three
        }
    }
}

impl Baz {
    pub fn hash<H: AsMut<Hash>>(&self, h: &mut H) {
        match self {
            &Baz::One => h.as_mut().update(&b"Hello"[..]),
            &Baz::Two => h.as_mut().update(&b"Hallo"[..]),
            &Baz::Three => h.as_mut().update("こにちわ".as_bytes()),
        }
    }

    pub fn mac<H: AsMut<Mac>>(&self, h: &mut H) {
        match self {
            &Baz::One => h.as_mut().update(&b"Hello"[..]),
            &Baz::Two => h.as_mut().update(&b"Hallo"[..]),
            &Baz::Three => h.as_mut().update("こにちわ".as_bytes()),
        }
    }
}

fn main() {
    let fubar = Fubar::default();

    println!("Fubar hash: {:?}",fubar.produce_hash());
    println!("Fubar mac: {:?}",fubar.produce_mac());
}
