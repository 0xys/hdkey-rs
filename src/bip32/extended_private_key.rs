use k256::ecdsa::SigningKey;
use k256::Scalar;
use k256::elliptic_curve::ops::Add;

use hmac_sha512::{HMAC};
use sha2::{Sha256, Digest as Sha256Digest};
use ripemd160::{Ripemd160, Digest as Ripemd160Digest};

use base58::{ToBase58, FromBase58};
use std::convert::TryInto;
use generic_array::GenericArray;

use crate::bip32::extended_public_key::{ExtendedPublicKey};
use crate::bip32::helpers::{split_i, transform_u32_to_u8a};
use crate::keys::{PublicKey, PrivateKey};


pub struct ExtendedPrivateKey {
    version: [u8;4],
    depth: u8,
    fingerprint: [u8;4],
    child_number: [u8;4],
    chain_code: [u8;32],
    k: [u8;33],
}

impl ExtendedPrivateKey {
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

    /// generate master private key from seed.
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        if seed.len() < 16 || seed.len() > 64 {
            let message = format!("seed length must be in the range [16, 64]");
            return Err(message);
        }
        let key = b"Bitcoin seed";
        let i = HMAC::mac(seed, key);
        let (k, c) = transform_master_i_to_k_and_c(&i);

        let master_key = ExtendedPrivateKey {
            version: [0x04, 0x88, 0xad, 0xe4],
            depth: 0x00,
            fingerprint: [0x00, 0x00, 0x00, 0x00],
            child_number: [0x00, 0x00, 0x00, 0x00],
            k: k,
            chain_code: c
        };

        Ok(master_key)
    }

    pub fn to_base58(&self) -> String {
        let mut bytes = vec![0u8; 78];
        bytes[0..4].copy_from_slice(&self.version);
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.fingerprint);
        bytes[9..13].copy_from_slice(&self.child_number);
        bytes[13..46].copy_from_slice(&self.k);
        bytes[46..78].copy_from_slice(&self.chain_code);
        bytes.to_base58()
    }

    pub fn from_base58(base58_str: &str) -> ExtendedPrivateKey {
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

        ExtendedPrivateKey {
            version: version,
            depth: bytes[4],
            fingerprint: fingerprint,
            child_number: child_number,
            k: k,
            chain_code: c
        }
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    pub fn derive_hardended_child(&self, index: u32) -> Result<ExtendedPrivateKey, String> {
        if index >= 2147483648 {
            let message = format!("too large index. {}", index);
            return Err(message);
        }

        // for hardened index.
        let index = index + 2147483648;
        
        let mut data = vec![0u8;37];
        data[1..33].copy_from_slice(&self.private_key());
        data[33..].copy_from_slice(&transform_u32_to_u8a(index));

        let i = HMAC::mac(data, self.chain_code);
        let (k, c) = self.transform_i_to_k_and_c(&i);

        let key = ExtendedPrivateKey {
            version: self.version,
            depth: self.depth + 1,
            fingerprint: self.calc_fingerprint(),
            child_number: transform_u32_to_u8a(index),
            k: k,
            chain_code: c
        };
        Ok(key)
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    pub fn derive_child(&self, index: u32) -> Result<ExtendedPrivateKey, String> {
        if index >= 2147483648 {
            let message = format!("too large index. {}", index);
            return Err(message);
        }
        
        let mut data = vec![0u8;37];
        data[0..33].copy_from_slice(&self.public_key());
        data[33..].copy_from_slice(&transform_u32_to_u8a(index));

        let i = HMAC::mac(data, self.chain_code);
        let (k, c) = self.transform_i_to_k_and_c(&i);

        let key = ExtendedPrivateKey {
            version: self.version,
            depth: self.depth + 1,
            fingerprint: self.calc_fingerprint(),
            child_number: transform_u32_to_u8a(index),
            k: k,
            chain_code: c
        };
        Ok(key)
    }

    pub fn to_x_pub(&self) -> ExtendedPublicKey {
        ExtendedPublicKey::from_x_priv(self)
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
pub fn add_scalar_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let lhs = Scalar::from_bytes_reduced(GenericArray::from_slice(a));
    let rhs = Scalar::from_bytes_reduced(GenericArray::from_slice(b));
    let tmp = lhs.add(rhs).to_bytes();
    let sum = tmp.as_slice();
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&sum);
    ret
}