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
use crate::bip32::checksum::{get_checksum, verify_checksum};
use crate::bip32::helpers::{split_i};
use crate::bip32::helpers::{Node, valiidate_path};
use crate::bip32::version::{Version, KeyType};
use crate::bip32::fingerprint::{Fingerprint};
use crate::bip32::child_number::{ChildNumber};

#[derive(Debug, Clone)]
pub struct ExtendedPrivateKey {
    // version: Version,
    // depth: u8,
    // fingerprint: Fingerprint,
    // child_number: ChildNumber,
    // chain_code: [u8;32],
    // k: [u8;33],
    bytes: [u8; 82]
}

const RANGE_VERSION: std::ops::Range<usize> = 0..4;
const RANGE_DEPTH: std::ops::Range<usize> = 4..4;
const RANGE_FINGERPRINT: std::ops::Range<usize> = 5..9;
const RANGE_CHILD_NUMBER: std::ops::Range<usize> = 9..13;
const RANGE_CHAIN_CODE: std::ops::Range<usize> = 13..45;
const RANGE_PRIVATE_KEY: std::ops::Range<usize> = 46..78;
const RANGE_CHECKSUM: std::ops::Range<usize> = 78..82;

impl ExtendedPrivateKey {
    // pub fn version(&self) -> &Version {
    //     &self.version
    // }
    // pub fn depth(&self) -> &u8 {
    //     &self.depth
    // }
    // pub fn fingerprint(&self) -> &Fingerprint {
    //     &self.fingerprint
    // }
    // pub fn child_number(&self) -> &ChildNumber {
    //     &self.child_number
    // }
    // pub fn chain_code(&self) -> &[u8;32] {
    //     &self.chain_code
    // }

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

        let master_key = ExtendedPrivateKey {
            // version: Version::MainNet(KeyType::Private),
            // depth: 0x00,
            // fingerprint: Fingerprint([0x00, 0x00, 0x00, 0x00]),
            // child_number: ChildNumber([0x00, 0x00, 0x00, 0x00]),
            // k: k,
            // chain_code: c,
            bytes
        };

        Ok(master_key)
    }

    pub fn from_seed_hex<T: AsRef<str>>(seed_hex_str: T) -> Result<Self, Error> {
        let seed = Vec::from_hex(seed_hex_str.as_ref())?;
        Self::from_seed(seed.as_slice())
    }

    pub fn to_base58(&self) -> String {
        let bytes = self.serialize();
        let checksum = get_checksum(&bytes);

        let mut full_bytes = [0u8; 82];
        full_bytes[0..78].copy_from_slice(&bytes);
        full_bytes[78..].copy_from_slice(&checksum);

        full_bytes.to_base58()
    }

    pub fn from_base58<T: AsRef<str>>(base58_str: T) -> ExtendedPrivateKey {
        let bytes = base58_str.as_ref().from_base58().unwrap();
        ExtendedPrivateKey::deserialize(bytes.as_slice()).unwrap()
    }

    pub fn derive_hardended_child(&self, index: u32) -> Result<Self, Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        // for hardened index.
        let index = index + 2147483648;

        Self::update_fingerprint(&mut self.bytes);
        Self::update_childnumber(index, &mut self.bytes);
        
        let mut data = vec![0u8;37];
        data[1..33].copy_from_slice(&self.bytes[RANGE_PRIVATE_KEY]);
        data[33..].copy_from_slice(&self.bytes[RANGE_CHILD_NUMBER]);

        let i = HMAC::mac(data, &self.bytes[RANGE_CHAIN_CODE]);
        self.bytes[RANGE_CHAIN_CODE].copy_from_slice(&i[32..]);
        add_scalar_be(&mut self.bytes[RANGE_PRIVATE_KEY], &i[..32]);

        Self::add_checksum(&mut self.bytes);

        let key = ExtendedPrivateKey {
            // version: self.version,
            // depth: self.depth + 1,
            // fingerprint: Fingerprint::from_xpriv(&self),
            // child_number: ChildNumber::from_u32(index),
            // k: k,
            // chain_code: c,
            bytes: self.bytes
            
        };
        Ok(key)
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    pub fn _derive_hardended_child(&self, index: u32) -> Result<Self, Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        // for hardened index.
        let index = index + 2147483648;
        
        let mut data = vec![0u8;37];
        data[1..33].copy_from_slice(&self.private_key());
        data[33..].copy_from_slice(&ChildNumber::from_u32(index).0[..]);

        let i = HMAC::mac(data, self.chain_code);
        let (k, c) = self.transform_i_to_k_and_c(&i);

        let key = ExtendedPrivateKey {
            version: self.version,
            depth: self.depth + 1,
            fingerprint: Fingerprint::from_xpriv(&self),
            child_number: ChildNumber::from_u32(index),
            k: k,
            chain_code: c
        };
        Ok(key)
    }

    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        Self::update_fingerprint(&mut self.bytes);
        Self::update_childnumber(index, &mut self.bytes);
        
        let mut data = vec![0u8;37];
        let sk = SigningKey::from_bytes(&self.private_key()).unwrap();
        data[0..33].copy_from_slice(&sk.verify_key().to_bytes());
        data[33..].copy_from_slice(&self.bytes[RANGE_CHILD_NUMBER]);

        let i = HMAC::mac(data, &self.bytes[RANGE_CHAIN_CODE]);
        self.bytes[RANGE_CHAIN_CODE].copy_from_slice(&i[32..]);
        add_scalar_be(&mut self.bytes[RANGE_PRIVATE_KEY], &i[..32]);

        Self::add_checksum(&mut self.bytes);

        let key = ExtendedPrivateKey {
            // version: self.version,
            // depth: self.depth + 1,
            // fingerprint: Fingerprint::from_xpriv(&self),
            // child_number: ChildNumber::from_u32(index),
            // k: k,
            // chain_code: c,
            bytes: self.bytes
        };
        Ok(key)
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    pub fn _derive_child(&self, index: u32) -> Result<Self, Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }
        
        let mut data = vec![0u8;37];
        data[0..33].copy_from_slice(&self.public_key());
        data[33..].copy_from_slice(&ChildNumber::from_u32(index).0[..]);

        let i = HMAC::mac(data, self.chain_code);
        let (k, c) = self.transform_i_to_k_and_c(&i);

        let key = ExtendedPrivateKey {
            version: self.version,
            depth: self.depth + 1,
            fingerprint: Fingerprint::from_xpriv(&self),
            child_number: ChildNumber::from_u32(index),
            k: k,
            chain_code: c
        };
        Ok(key)
    }

    pub fn _derive<T: AsRef<str>>(&self, path: T) -> Result<Self, Error> {
        let nodes = match valiidate_path(path.as_ref(), true) {
            Err(err) => return Err(err),
            Ok(x) => x
        };

        Self::derive_from(&self, &nodes)
    }

    pub fn to_x_pub(&self) -> ExtendedPublicKey {
        ExtendedPublicKey::from_x_priv(self)
    }

    fn _derive_from(current: &Self, nodes: &[Node]) -> Result<Self, Error> {
        if nodes.len() == 0 {
            return Ok(current.clone());
        }else{
            let child = match nodes[0].hardened {
                false => current.derive_child(nodes[0].index)?,
                true => current.derive_hardended_child(nodes[0].index)?,
            };
            return Self::derive_from(&child, &nodes[1..]);
        }
    }

    /// Set last four bytes the checksum of the body
    /// 
    /// `bytes[78..82] = Sha256(Sha256(bytes[0..78]))[..4]`
    fn add_checksum(bytes: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[0..78]);
        let hashed = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hashed);

        let finalized = hasher.finalize();
        bytes[78..].copy_from_slice(&finalized[0..4]);
    }

    /// Overwrite fingerprint
    /// 
    /// `bytes[5..9] = Ripemd160(Sha256(bytes[45..78]))`
    fn update_fingerprint(bytes: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[45..78]);
        let sha256ed = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(&sha256ed);
        let rip160ed = hasher.finalize();
        
        let x = rip160ed.as_slice();
        bytes[5..9].copy_from_slice(&x[0..4]);
    }

    /// Overwrite child number
    /// 
    /// `bytes[9..12] = child number as u32`
    #[inline(always)]
    fn update_childnumber(c: u32, bytes: &mut [u8]){
        bytes[9] = ((c >> 24) & 0xff) as u8;
        bytes[10] = ((c >> 16) & 0xff) as u8;
        bytes[11] = ((c >> 8) & 0xff) as u8;
        bytes[12] = (c & 0xff) as u8;
    }

    fn transform_i_to_k_and_c(&self, i: &[u8; 64]) -> ([u8; 33], [u8; 32]) {
        let (i_left, i_right) = split_i(&i);
    
        let u8vec = add_scalar_be(&self.private_key(), &i_left);
    
        let mut k = [0u8; 33];
        let mut k_vec = vec![0u8;33];
        k_vec[1..33].copy_from_slice(&u8vec);
        k.copy_from_slice(k_vec.as_slice());

        (k, i_right)
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
        k.copy_from_slice(&self.k[1..33]);
        k
    }
}

fn transform_master_i_to_k_and_c(i: &[u8; 64]) -> ([u8; 33], [u8; 32]) {
    let mut c = [0u8; 32];
    c.copy_from_slice(&i[32..]);

    let mut tmp = vec![0u8;33];
    tmp[1..].copy_from_slice(&i[..32]);
    
    let mut k = [0u8;33];
    k.copy_from_slice(tmp.as_slice());

    (k, c)
}

/// add two scalars, each represented by u8 array in big-endian format. 
fn add_scalar_be(a: &mut [u8], b: &[u8]) {
    let lhs = Scalar::from_bytes_reduced(GenericArray::from_slice(a));
    let rhs = Scalar::from_bytes_reduced(GenericArray::from_slice(b));
    let sum = lhs.add(rhs).to_bytes();
    a.copy_from_slice(sum.as_slice());
}

impl Serialize<[u8; 78]> for ExtendedPrivateKey {
    fn serialize(&self) -> [u8; 78] {
        let mut bytes = [0u8; 78];
        bytes[0..4].copy_from_slice(&self.version.serialize());
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.fingerprint.serialize());
        bytes[9..13].copy_from_slice(&self.child_number.serialize());
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.k);
        bytes
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

        let mut c = [0u8; 32];
        c.copy_from_slice(&bytes[13..45]);

        let mut k = [0u8; 33];
        k.copy_from_slice(&bytes[45..78]);        

        let res = ExtendedPrivateKey {
            version: Version::deserialize(&bytes[0..4]).unwrap(),
            depth: bytes[4],
            fingerprint: Fingerprint::deserialize(&bytes[5..9]).unwrap(),
            child_number: ChildNumber::deserialize(&bytes[9..13]).unwrap(),
            k: k,
            chain_code: c
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
        let xpub = ExtendedPrivateKey::from_base58(bs58);
        assert_eq!(bs58, xpub.to_base58());
    }
}