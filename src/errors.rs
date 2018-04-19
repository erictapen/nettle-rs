use failure;

#[derive(Debug,Fail)]
/// Nettle error type.
pub enum Error {
    #[fail(display = "invalid argument name: {}", argument_name)]
    /// Invalid input argument.
    InvalidArgument{
        /// Name of the invalid argument.
        argument_name: &'static str
    },
    #[fail(display = "signing failed")]
    /// Signing failed
    SigningFailed,
    #[fail(display = "encryption failed")]
    /// Encryption failed,
    EncryptionFailed,
    #[fail(display = "decryption failed")]
    /// Decryption failed,
    DecryptionFailed,
    #[fail(display = "key generation failed")]
    /// Key generation failed,
    KeyGenerationFailed,
    #[fail(display = "invalid q_bits and/or p_bits values")]
    /// Invalid q_bits and/or p_bits values.
    InvalidBitSizes,
}

/// Specialized Result type.
pub type Result<T> = ::std::result::Result<T,failure::Error>;
