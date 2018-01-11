pub trait Mac {
    fn mac_size(&self) -> usize;
    fn update(&mut self, data: &[u8]);
    fn digest(&mut self, digest: &mut [u8]);
}
