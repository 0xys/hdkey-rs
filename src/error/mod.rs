use hex::FromHexError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidSeed(SeedError),
    InvalidPath(PathError),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PathError {
    IndexOutOfBounds(u32),
    InvalidHead,
    HardenedNotAllowed,
    Unparsable,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SeedError {
    
    /// seed must be hex string.
    NotHexString,

    /// seed length must be in the range [16, 64] in bytes.
    OutOfBounds,
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Error::InvalidSeed(SeedError::NotHexString)
    }
}