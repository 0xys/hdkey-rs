use k256::ecdsa::SigningKey;
use k256::Scalar;
use k256::elliptic_curve::ops::Add;

use hmac_sha512::{HMAC};
use sha2::{Sha256, Digest as Sha256Digest};

use base58::{ToBase58, FromBase58};
use generic_array::GenericArray;
use hex::FromHex;

use crate::keys::{PublicKey, PrivateKey};
use crate::error::{Error, PathError, SeedError};
use crate::bip32::serialize::{Serialize, Deserialize};
use crate::bip32::extended_public_key::{ExtendedPublicKey};
use crate::bip32::helpers::{split_i};
use crate::bip32::helpers::{Node, valiidate_path};
use crate::bip32::version::{Version, KeyType};
use crate::bip32::fingerprint::{Fingerprint};
use crate::bip32::child_number::{ChildNumber};

#[derive(Debug, Clone)]
pub struct ExtendedPrivateKey {
    version: Version,
    depth: u8,
    fingerprint: Fingerprint,
    child_number: ChildNumber,
    chain_code: [u8;32],
    k: [u8;33],
}

impl ExtendedPrivateKey {
    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn depth(&self) -> &u8 {
        &self.depth
    }
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
    pub fn child_number(&self) -> &ChildNumber {
        &self.child_number
    }
    pub fn chain_code(&self) -> &[u8;32] {
        &self.chain_code
    }

    /// generate master private key from seed.
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidSeed(SeedError::OutOfBounds(seed.len())));
        }
        let key = b"Bitcoin seed";
        let i = HMAC::mac(seed, key);
        let (k, c) = transform_master_i_to_k_and_c(&i);

        let master_key = ExtendedPrivateKey {
            version: Version::MainNet(KeyType::Private),
            depth: 0x00,
            fingerprint: Fingerprint([0x00, 0x00, 0x00, 0x00]),
            child_number: ChildNumber([0x00, 0x00, 0x00, 0x00]),
            k: k,
            chain_code: c
        };

        Ok(master_key)
    }

    pub fn from_seed_hex(seed_hex_str: &str) -> Result<Self, Error> {
        let seed = Vec::from_hex(seed_hex_str)?;
        Self::from_seed(seed.as_slice())
    }

    pub fn to_base58(&self) -> String {
        let mut hasher = Sha256::new();
        let bytes = self.serialize();
        hasher.update(&bytes);
        let hashed = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hashed);
        let checksum = hasher.finalize();

        let mut full_bytes = [0u8; 82];
        full_bytes[0..78].copy_from_slice(&bytes);
        full_bytes[78..].copy_from_slice(&checksum[0..4]);

        full_bytes.to_base58()
    }

    pub fn from_base58(base58_str: &str) -> ExtendedPrivateKey {
        let bytes = base58_str.from_base58().unwrap();
        ExtendedPrivateKey::deserialize(bytes.as_slice()).unwrap()
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    pub fn derive_hardended_child(&self, index: u32) -> Result<Self, Error> {
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
            fingerprint: Fingerprint::from_xpiv(&self),
            child_number: ChildNumber::from_u32(index),
            k: k,
            chain_code: c
        };
        Ok(key)
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
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
            fingerprint: Fingerprint::from_xpiv(&self),
            child_number: ChildNumber::from_u32(index),
            k: k,
            chain_code: c
        };
        Ok(key)
    }

    pub fn derive(&self, path: &str) -> Result<Self, Error> {
        let nodes = match valiidate_path(path, true) {
            Err(err) => return Err(err),
            Ok(x) => x
        };

        Self::derive_from(&self, &nodes)
    }

    pub fn to_x_pub(&self) -> ExtendedPublicKey {
        ExtendedPublicKey::from_x_priv(self)
    }

    fn derive_from(current: &Self, nodes: &[Node]) -> Result<Self, Error> {
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
fn add_scalar_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let lhs = Scalar::from_bytes_reduced(GenericArray::from_slice(a));
    let rhs = Scalar::from_bytes_reduced(GenericArray::from_slice(b));
    let tmp = lhs.add(rhs).to_bytes();
    let sum = tmp.as_slice();
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&sum);
    ret
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
            return Err(Error::DeseializeError);
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