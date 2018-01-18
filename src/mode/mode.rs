pub trait Mode {
    fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]);
    fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]);
}
