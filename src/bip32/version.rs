use crate::bip32::serialize::{Serialize, Deserialize};
use crate::error::Error;

use std::convert::TryInto;

/// version of extended key
/// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Version {
    MainNet(KeyType),
    TestNet(KeyType),
    Custom([u8; 4])
}

impl Version {
    pub fn to_pub(&self) -> Self {
        let result = match self {
            Version::MainNet(_) => Version::MainNet(KeyType::Public), 
            Version::TestNet(_) => Version::TestNet(KeyType::Public),
            Version::Custom(bytes) => Version::Custom(*bytes)
        };
        result
    }

    pub fn to_priv(&self) -> Self {
        let result = match self {
            Version::MainNet(_) => Version::MainNet(KeyType::Private), 
            Version::TestNet(_) => Version::TestNet(KeyType::Private),
            Version::Custom(bytes) => Version::Custom(*bytes)
        };
        result
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyType {
    Public,
    Private
}

impl Serialize<[u8; 4]> for Version {
    fn serialize(&self) -> [u8; 4] {
        let result = match self {
            Version::MainNet(key_type) => match key_type {
                KeyType::Public => [0x04, 0x88, 0xb2, 0x1e],
                KeyType::Private => [0x04, 0x88, 0xad, 0xe4],
            },
            Version::TestNet(key_type) => match key_type {
                KeyType::Public => [0x04, 0x35, 0x87, 0xcf],
                KeyType::Private => [0x04, 0x35, 0x83, 0x94],
            },
            Version::Custom(bytes) => *bytes
        };
        result
    }
}

impl Deserialize<&[u8], Error> for Version {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 {
            return Err(Error::DeseializeError);
        }

        let bytes: [u8; 4] = bytes[0..4].try_into().unwrap();

        let result = match bytes {
            [0x04, 0x88, 0xb2, 0x1e] => Version::MainNet(KeyType::Public),
            [0x04, 0x88, 0xad, 0xe4] => Version::MainNet(KeyType::Private),
            [0x04, 0x35, 0x87, 0xcf] => Version::TestNet(KeyType::Public),
            [0x04, 0x35, 0x83, 0x94] => Version::TestNet(KeyType::Private),
            _ => Version::Custom(bytes),
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::bip32::serialize::Deserialize;
    use crate::bip32::version::{Version, KeyType};

    #[test]
    fn test_version_deserialize() {
        let bytes: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
        let version = Version::deserialize(&bytes).unwrap();
        assert_eq!(Version::MainNet(KeyType::Public), version);

        let bytes: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
        let version = Version::deserialize(&bytes).unwrap();
        assert_eq!(Version::MainNet(KeyType::Private), version);

        let bytes: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
        let version = Version::deserialize(&bytes).unwrap();
        assert_eq!(Version::TestNet(KeyType::Public), version);

        let bytes: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
        let version = Version::deserialize(&bytes).unwrap();
        assert_eq!(Version::TestNet(KeyType::Private), version);

        let bytes: [u8; 4] = [0,1,2,3];
        let version = Version::deserialize(&bytes).unwrap();
        assert_eq!(Version::Custom([0,1,2,3]), version);
    }
}