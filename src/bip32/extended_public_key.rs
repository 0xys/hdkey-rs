use hmac_sha512::{HMAC};
use sha2::{Sha256, Digest as Sha256Digest};
use ripemd160::{Ripemd160, Digest as Ripemd160Digest};
use k256::ecdsa::SigningKey;
use base58::{ToBase58, FromBase58};

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::EncodedPoint;
use k256::ProjectivePoint;
use core::ops::Add;

use std::convert::TryInto;

use crate::keys::{PublicKey};
use crate::error::{Error, PathError, SeedError};
use crate::bip32::serialize::{Serialize, Deserialize};
use crate::bip32::extended_private_key::ExtendedPrivateKey;
use crate::bip32::helpers::{split_i, transform_u32_to_u8a};
use crate::bip32::helpers::{Node, valiidate_path};
use crate::bip32::version::{Version};
use crate::bip32::fingerprint::{Fingerprint};

#[derive(Debug, Clone)]
pub struct ExtendedPublicKey {
    version: Version,
    depth: u8,
    fingerprint: Fingerprint,
    child_number: [u8;4],
    chain_code: [u8;32],
    k: [u8;33],
}

impl ExtendedPublicKey {
    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn depth(&self) -> &u8 {
        &self.depth
    }
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
    pub fn child_number(&self) -> &[u8;4] {
        &self.child_number
    }
    pub fn chain_code(&self) -> &[u8;32] {
        &self.chain_code
    }

    pub fn to_raw_bytes(&self) -> [u8; 78] {
        let mut bytes = vec![0u8; 78];
        bytes[0..4].copy_from_slice(&self.version.serialize());
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.fingerprint.0);
        bytes[9..13].copy_from_slice(&self.child_number);
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.k);

        let mut res = [0u8; 78];
        res.copy_from_slice(bytes.as_slice());
        res
    }

    pub fn to_base58(&self) -> String {
        let mut hasher = Sha256::new();
        let bytes = self.to_raw_bytes();
        hasher.update(&bytes);
        let hashed = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hashed);
        let checksum = hasher.finalize();

        let mut full_bytes = [0u8; 82];
        full_bytes[0..78].copy_from_slice(&self.to_raw_bytes());
        full_bytes[78..].copy_from_slice(&checksum[0..4]);

        full_bytes.to_base58()
    }

    pub fn from_base58(base58_str: &str) -> Self {
        let bytes = base58_str.from_base58().unwrap();

        let mut version = [0u8; 4];
        version.copy_from_slice(&bytes[0..4]);

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&bytes[5..9]);

        let mut child_number = [0u8; 4];
        child_number.copy_from_slice(&bytes[9..13]);

        let mut k = [0u8; 33];
        k.copy_from_slice(&bytes[13..46]);

        let mut c = [0u8; 32];
        c.copy_from_slice(&bytes[46..78]);

        ExtendedPublicKey {
            version: Version::deserialize(&version).unwrap(),
            depth: bytes[4],
            fingerprint: Fingerprint(fingerprint),
            child_number: child_number,
            k: k,
            chain_code: c
        }
    }

    pub fn from_x_priv(ext_priv_key: &ExtendedPrivateKey) -> Self {
        ExtendedPublicKey {
            version: ext_priv_key.version().to_pub(),
            depth: *ext_priv_key.depth(),
            fingerprint: *ext_priv_key.fingerprint(),
            child_number: ext_priv_key.child_number()[..].try_into().unwrap(),
            k: ext_priv_key.public_key(),
            chain_code: ext_priv_key.chain_code()[..].try_into().unwrap()
        }
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }
        
        let mut data = vec![0u8;37];
        data[0..33].copy_from_slice(&self.public_key());
        data[33..].copy_from_slice(&transform_u32_to_u8a(index));

        let i = HMAC::mac(data, self.chain_code);
        let (k, c) = self.transform_i_to_k_and_c(&i);

        let child = ExtendedPublicKey {
            version: self.version,
            depth: self.depth + 1,
            fingerprint: Fingerprint::from_xpub(&self),
            child_number: transform_u32_to_u8a(index),
            k: k,
            chain_code: c
        };

        Ok(child)
    }

    pub fn derive(&self, path: &str) -> Result<Self, Error> {
        let nodes = match valiidate_path(path, false) {
            Err(err) => return Err(err),
            Ok(x) => x
        };

        Self::derive_from(&self, &nodes)
    }

    fn derive_from(current: &Self, nodes: &[Node]) -> Result<Self, Error> {
        if nodes.len() == 0 {
            return Ok(current.clone());
        }else{
            let next = current.derive_child(nodes[0].index)?;
            return Self::derive_from(&next, &nodes[1..]);
        }
    }

    fn add_pubkeys_bytes(&self, pk1: &[u8; 33], pk2: &[u8; 33]) -> [u8; 33] {
        let point1 = EncodedPoint::from_bytes(pk1).unwrap();
        let point1 = ProjectivePoint::from_encoded_point(&point1).unwrap();
    
        let point2 = EncodedPoint::from_bytes(pk2).unwrap();
        let point2 = ProjectivePoint::from_encoded_point(&point2).unwrap();
    
        let point = point1.add(point2);
        let encoded = point.to_affine().to_encoded_point(true);
    
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    fn transform_i_to_k_and_c(&self, i: &[u8; 64]) -> ([u8; 33], [u8; 32]) {
        let (i_left, i_right) = split_i(&i);
        let sk = SigningKey::from_bytes(&i_left).unwrap();
        let sum = self.add_pubkeys_bytes(&self.k, &sk.verify_key().to_bytes());
        
        (sum, i_right)
    }
}

impl PublicKey for ExtendedPublicKey {
    fn public_key(&self) -> [u8;33] {
        self.k
    }
}


