/// A message authentication code.
///
/// A MAC is a symmetric signature primitive.
pub trait Mac {
    /// Size of the MAC tag i.e. the signature in bytes.
    fn mac_size(&self) -> usize;
    /// Add data to be signed.
    fn update(&mut self, data: &[u8]);
    /// Produce the MAC tag `digest` for all data fed via `update()`.
    ///
    /// # Panics
    /// The `digest` parameter must be exactly `max_size()` bytes long, otherwise the function
    /// panics.
    fn digest(&mut self, digest: &mut [u8]);
}
