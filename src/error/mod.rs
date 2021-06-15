use hex::FromHexError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidSeed(SeedError),
    InvalidPath(PathError),
    SerializeError,
    DeseializeError(DeserializationError),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PathError {

    /// path index out of bounds.
    IndexOutOfBounds(u32),

    /// path not start with 'm'.
    InvalidHead,

    /// hardened derivation not allowed from xpub.
    HardenedNotAllowed,

    /// unparsable character is included.
    Unparsable,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SeedError {
    
    /// seed must be hex string.
    NotHexString,

    /// seed length must be in the range [16, 64] in bytes.
    OutOfBounds(usize),
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Error::InvalidSeed(SeedError::NotHexString)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DeserializationError {
    WrongCheckSum,
    InvalidSize,
}