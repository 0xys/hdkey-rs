use std::convert::TryInto;
use crate::bip32::serialize::{Serialize, Deserialize};
use crate::error::Error;


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ChildNumber(pub [u8; 4]);

/// child number
/// 
impl ChildNumber {
    pub fn from_u32(x: u32) -> Self {
        let b1: u8 = ((x >> 24) & 0xff) as u8;
        let b2: u8 = ((x >> 16) & 0xff) as u8;
        let b3: u8 = ((x >> 8) & 0xff) as u8;
        let b4: u8 = (x & 0xff) as u8;
        ChildNumber([b1, b2, b3, b4])
    }
}

impl Serialize<[u8; 4]> for ChildNumber {
    fn serialize(&self) -> [u8; 4] {
        self.0
    }
}

impl Deserialize<&[u8], Error> for ChildNumber {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 {
            return Err(Error::DeseializeError);
        }

        let bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
        Ok(ChildNumber(bytes))
    }
}