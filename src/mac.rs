pub trait Mac {
    fn update(&mut self, data: &[u8]);
    fn digest(&mut self, digest: &mut [u8]);
}
