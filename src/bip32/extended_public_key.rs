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
use crate::bip32::extended_private_key::ExtendedPrivateKey;
use crate::bip32::helpers::{split_i, transform_u32_to_u8a};


pub struct ExtendedPublicKey {
    version: [u8;4],
    depth: u8,
    fingerprint: [u8;4],
    child_number: [u8;4],
    chain_code: [u8;32],
    k: [u8;33],
}

impl ExtendedPublicKey {
    pub fn version(&self) -> &[u8;4] {
        &self.version
    }
    pub fn depth(&self) -> &u8 {
        &self.depth
    }
    pub fn fingerprint(&self) -> &[u8;4] {
        &self.fingerprint
    }
    pub fn child_number(&self) -> &[u8;4] {
        &self.child_number
    }
    pub fn chain_code(&self) -> &[u8;32] {
        &self.chain_code
    }

    pub fn to_base58(&self) -> String {
        let mut bytes = vec![0u8; 78];
        bytes[0..4].copy_from_slice(&self.version);
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.fingerprint);
        bytes[9..13].copy_from_slice(&self.child_number);
        bytes[13..45].copy_from_slice(&self.k);
        bytes[45..78].copy_from_slice(&self.chain_code);
        bytes.to_base58()
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
            version: version,
            depth: bytes[4],
            fingerprint: fingerprint,
            child_number: child_number,
            k: k,
            chain_code: c
        }
    }

    pub fn from_x_priv(ext_priv_key: &ExtendedPrivateKey) -> Self {
        ExtendedPublicKey {
            version: ext_priv_key.version()[..].try_into().unwrap(),
            depth: *ext_priv_key.depth(),
            fingerprint: ext_priv_key.fingerprint()[..].try_into().unwrap(),
            child_number: ext_priv_key.child_number()[..].try_into().unwrap(),
            k: ext_priv_key.public_key(),
            chain_code: ext_priv_key.chain_code()[..].try_into().unwrap()
        }
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
    pub fn derive_child(&self, index: u32) -> Result<Self, String> {
        if index >= 2147483648 {
            let message = format!("too large index. {}", index);
            return Err(message);
        }
        
        let mut data = vec![0u8;37];
        data[0..33].copy_from_slice(&self.public_key());
        data[33..].copy_from_slice(&transform_u32_to_u8a(index));

        let i = HMAC::mac(data, self.chain_code);
        let (k, c) = self.transform_i_to_k_and_c(&i);

        let child = ExtendedPublicKey {
            version: self.version,
            depth: self.depth + 1,
            fingerprint: self.calc_fingerprint(),
            child_number: transform_u32_to_u8a(index),
            k: k,
            chain_code: c
        };

        Ok(child)
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

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers
    fn calc_fingerprint(&self) -> [u8; 4] {
        let mut hasher = Sha256::new();
        let pubkey = self.public_key();
        hasher.update(pubkey);
        let sha256ed = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(&sha256ed);
        let rip160ed = hasher.finalize();
        
        let x: [u8; 20] = rip160ed.as_slice().try_into().unwrap();
        
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&x[0..4]);
        fingerprint
    }
}

impl PublicKey for ExtendedPublicKey {
    fn public_key(&self) -> [u8;33] {
        self.k
    }
}


