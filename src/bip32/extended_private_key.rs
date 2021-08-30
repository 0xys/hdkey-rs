use k256::ecdsa::SigningKey;
use k256::Scalar;
use k256::elliptic_curve::ops::Add;

use sha2::{Sha256, Digest as Sha256Digest};
use ripemd160::{Ripemd160};
use hmac_sha512::{HMAC};

use base58::{ToBase58, FromBase58};
use generic_array::GenericArray;
use hex::FromHex;

use crate::keys::{PublicKey, PrivateKey};
use crate::error::{Error, PathError, SeedError, DeserializationError};
use crate::serializer::{Serialize, Deserialize};
use crate::bip32::extended_public_key::{ExtendedPublicKey};
use crate::bip32::checksum::verify_checksum;
use crate::bip32::helpers::{Node, valiidate_path};
use crate::bip32::version::{Version, KeyType};

#[derive(Debug, Clone)]
pub struct ExtendedPrivateKey {
    pub bytes: [u8; 82]
}

const RANGE_VERSION: std::ops::Range<usize> = 0..4;
const RANGE_DEPTH: std::ops::Range<usize> = 4..4;
const RANGE_FINGERPRINT: std::ops::Range<usize> = 5..9;
const RANGE_CHILD_NUMBER: std::ops::Range<usize> = 9..13;
const RANGE_CHAIN_CODE: std::ops::Range<usize> = 13..45;
const RANGE_PRIVATE_KEY: std::ops::Range<usize> = 46..78;
const RANGE_CHECKSUM: std::ops::Range<usize> = 78..82;

impl ExtendedPrivateKey {

    /// generate master private key from seed.
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidSeed(SeedError::OutOfBounds(seed.len())));
        }
        let key = b"Bitcoin seed";

        let mut bytes = [0u8; 82];

        let i = HMAC::mac(seed, key);
        bytes[RANGE_CHAIN_CODE].copy_from_slice(&i[32..]);
        bytes[RANGE_PRIVATE_KEY].copy_from_slice(&i[..32]);

        let v = Version::MainNet(KeyType::Private);
        bytes[RANGE_VERSION].copy_from_slice(&v.serialize());
        Self::_add_checksum(&mut bytes);

        let master_key = ExtendedPrivateKey {
            bytes
        };

        Ok(master_key)
    }

    /// Construct extended private key from seed hex string.
    /// 
    pub fn from_seed_hex<T: AsRef<str>>(seed_hex_str: T) -> Result<Self, Error> {
        let seed = Vec::from_hex(seed_hex_str.as_ref())?;
        Self::from_seed(seed.as_slice())
    }

    /// Base58-Encode extended private key.
    ///
    pub fn to_base58(&self) -> String {
        let bytes = self.serialize();
        bytes.to_base58()
    }

    /// Base58-Decode extended private key.
    ///
    pub fn from_base58<T: AsRef<str>>(base58_str: T) -> ExtendedPrivateKey {
        let bytes = base58_str.as_ref().from_base58().unwrap();
        ExtendedPrivateKey::deserialize(bytes.as_slice()).unwrap()
    }

    /// Derive hardened child node at index. 
    /// 
    pub fn derive_hardended_child(&self, index: u32) -> Result<Self, Error> {
        let mut bytes = [0u8; 82];
        bytes.copy_from_slice(&self.bytes);

        Self::_derive_hardened_child(index, &mut bytes)?;
        Self::_add_checksum(&mut bytes);
        let key = ExtendedPrivateKey {
            bytes
        };
        Ok(key)
    }

    fn _derive_hardened_child(index: u32, bytes: &mut [u8]) -> Result<(), Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        // for hardened index.
        let index = index + 2147483648;

        bytes[4] += 1; // increment depth
        Self::_update_childnumber(index, bytes);
        Self::_update_fingerprint(bytes);
        
        let mut data = vec![0u8;37];
        data[1..33].copy_from_slice(&bytes[RANGE_PRIVATE_KEY]);
        data[33..].copy_from_slice(&bytes[RANGE_CHILD_NUMBER]);

        let i = HMAC::mac(data, &bytes[RANGE_CHAIN_CODE]);
        bytes[RANGE_CHAIN_CODE].copy_from_slice(&i[32..]);
        Self::_add_scalar_be(&mut bytes[RANGE_PRIVATE_KEY], &i[..32]);

        Ok(())
    }

    /// Derive child node at index. 
    /// 
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        let mut bytes = [0u8; 82];
        bytes.copy_from_slice(&self.bytes);

        Self::_derive_child(index, &mut bytes)?;
        Self::_add_checksum(&mut bytes);

        let key = ExtendedPrivateKey {
            bytes
        };
        Ok(key)
    }

    fn _derive_child(index: u32, bytes: &mut [u8]) -> Result<(), Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        bytes[4] += 1; // increment depth
        Self::_update_childnumber(index, bytes);
        Self::_update_fingerprint(bytes);

        let mut data = vec![0u8;37];
        let sk = SigningKey::from_bytes(&bytes[RANGE_PRIVATE_KEY]).unwrap();
        data[0..33].copy_from_slice(&sk.verify_key().to_bytes());
        data[33..].copy_from_slice(&bytes[RANGE_CHILD_NUMBER]);

        let i = HMAC::mac(data, &bytes[RANGE_CHAIN_CODE]);
        bytes[RANGE_CHAIN_CODE].copy_from_slice(&i[32..]);
        Self::_add_scalar_be(&mut bytes[RANGE_PRIVATE_KEY], &i[..32]);

        Ok(())
    }

    /// Derive child node by path from current node.
    /// 
    pub fn derive<T: AsRef<str>>(&self, path: T) -> Result<Self, Error> {
        let nodes = match valiidate_path(path.as_ref(), true) {
            Err(err) => return Err(err),
            Ok(x) => x
        };

        let mut bytes = [0u8; 82];
        bytes.copy_from_slice(&self.bytes);

        Self::_derive(&nodes, &mut bytes)?;
        Self::_add_checksum(&mut bytes);

        let key = ExtendedPrivateKey {
            bytes
        };
        Ok(key)
    }

    fn _derive(nodes: &[Node], bytes: &mut [u8]) -> Result<(), Error> {
        if nodes.len() == 0 {
            return Ok(());
        }
        
        if nodes[0].hardened {
            Self::_derive_hardened_child(nodes[0].index, bytes)?;
        }else{
            Self::_derive_child(nodes[0].index, bytes)?;
        }

        Self::_derive(&nodes[1..], bytes)?;
        Ok(())
    }

    /// Construct extended public key from current node.
    /// 
    pub fn to_xpub(&self) -> ExtendedPublicKey {
        ExtendedPublicKey::from_xprv(self)
    }

    /// Set last four bytes the checksum of the body
    /// 
    /// `bytes[78..82] = Sha256(Sha256(bytes[0..78]))[..4]`
    fn _add_checksum(bytes: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[0..78]);
        let hashed = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hashed);

        let finalized = hasher.finalize();
        bytes[RANGE_CHECKSUM].copy_from_slice(&finalized[0..4]);
    }

    /// Overwrite fingerprint
    /// 
    /// `bytes[5..9] = Ripemd160(Sha256(bytes[pubkey(self)]))[..4]`
    fn _update_fingerprint(bytes: &mut [u8]) {
        let sk = SigningKey::from_bytes(&bytes[RANGE_PRIVATE_KEY]).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&sk.verify_key().to_bytes());
        let sha256ed = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(&sha256ed);
        let rip160ed = hasher.finalize();
        
        let x = rip160ed.as_slice();
        bytes[RANGE_FINGERPRINT].copy_from_slice(&x[0..4]);
    }

    /// add two scalars, each represented by u8 array in big-endian format. 
    fn _add_scalar_be(a: &mut [u8], b: &[u8]) {
        let lhs = Scalar::from_bytes_reduced(GenericArray::from_slice(a));
        let rhs = Scalar::from_bytes_reduced(GenericArray::from_slice(b));
        let sum = lhs.add(rhs).to_bytes();
        a.copy_from_slice(sum.as_slice());
    }

    /// Overwrite child number
    /// 
    /// `bytes[9..12] = child number as u32`
    #[inline(always)]
    fn _update_childnumber(c: u32, bytes: &mut [u8]){
        bytes[9] = ((c >> 24) & 0xff) as u8;
        bytes[10] = ((c >> 16) & 0xff) as u8;
        bytes[11] = ((c >> 8) & 0xff) as u8;
        bytes[12] = (c & 0xff) as u8;
    }
}

impl PublicKey for ExtendedPrivateKey {
    fn public_key(&self) -> [u8;33] {
        let sk = SigningKey::from_bytes(&self.private_key()).unwrap();
        sk.verify_key().to_bytes()
    }
}

impl PrivateKey for ExtendedPrivateKey {
    fn private_key(&self) -> [u8;32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.bytes[RANGE_PRIVATE_KEY]);
        k
    }
}

impl Serialize<[u8; 82]> for ExtendedPrivateKey {
    fn serialize(&self) -> [u8; 82] {
        self.bytes
    }
}

impl Deserialize<&[u8], Error> for ExtendedPrivateKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 82 {
            return Err(Error::DeseializeError(DeserializationError::InvalidSize));
        }
        if !verify_checksum(&bytes) {
            return Err(Error::DeseializeError(DeserializationError::WrongCheckSum));
        }

        let mut tmp = [0u8; 82];
        tmp.copy_from_slice(bytes);
        let res = ExtendedPrivateKey {
            bytes: tmp
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::bip32::extended_private_key::ExtendedPrivateKey;

    #[test]
    fn test_xpriv_base58() {
        let bs58 = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
        let xprv = ExtendedPrivateKey::from_base58(bs58);
        assert_eq!(bs58, xprv.to_base58());
    }
}