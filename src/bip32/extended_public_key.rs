use hmac_sha512::{HMAC};
use k256::ecdsa::SigningKey;
use base58::{ToBase58, FromBase58};

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::EncodedPoint;
use k256::ProjectivePoint;
use core::ops::Add;

use sha2::{Sha256, Digest as Sha256Digest};
use ripemd160::{Ripemd160};

use std::convert::TryInto;

use crate::keys::{PublicKey};
use crate::error::{Error, PathError, DeserializationError};
use crate::serializer::{Serialize, Deserialize};
use crate::bip32::extended_private_key::ExtendedPrivateKey;
use crate::bip32::checksum::{get_checksum, verify_checksum};
use crate::bip32::helpers::{split_i};
use crate::bip32::helpers::{Node, valiidate_path};
use crate::bip32::version::{Version};
use crate::bip32::fingerprint::{Fingerprint};
use crate::bip32::child_number::{ChildNumber};

#[derive(Debug, Clone)]
pub struct ExtendedPublicKey {
    // version: Version,
    // depth: u8,
    // fingerprint: Fingerprint,
    // child_number: ChildNumber,
    // chain_code: [u8;32],
    // k: [u8;33],
    bytes: [u8;82]
}

impl ExtendedPublicKey {
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

    pub fn to_base58(&self) -> String {
        let bytes = self.serialize();
        let checksum = get_checksum(&bytes);

        let mut full_bytes = [0u8; 82];
        full_bytes[0..78].copy_from_slice(&bytes);
        full_bytes[78..].copy_from_slice(&checksum);

        full_bytes.to_base58()
    }

    pub fn to_base58_2(&self) -> String {
        let bytes = self.serialize();
        println!("normal  {:?}", hex::encode(&bytes));
        let checksum = get_checksum(&bytes);

        let mut full_bytes = [0u8; 82];
        full_bytes[0..78].copy_from_slice(&bytes);
        full_bytes[78..].copy_from_slice(&checksum);

        full_bytes.to_base58()
    }

    pub fn with_checksum(bytes: &[u8]) -> [u8; 82] {
        // let bytes = self.serialize();
        println!("inplace {:?}", hex::encode(&bytes));
        let checksum = get_checksum(&bytes);

        let mut full_bytes = [0u8; 82];
        full_bytes[0..78].copy_from_slice(&bytes);
        full_bytes[78..].copy_from_slice(&checksum);
        full_bytes
    }

    pub fn from_base58(base58_str: &str) -> Self {
        let bytes = base58_str.from_base58().unwrap();
        ExtendedPublicKey::deserialize(bytes.as_slice()).unwrap()
    }

    pub fn from_x_priv(ext_priv_key: &ExtendedPrivateKey) -> Self {
        let mut bytes = [0u8; 82];
        
        let tmp = ext_priv_key.version().to_pub();
        bytes[0..4].copy_from_slice(&tmp.serialize());

        bytes[4] = *ext_priv_key.depth();

        let tmp = ext_priv_key.fingerprint();
        bytes[5..9].copy_from_slice(&tmp.serialize());

        let tmp = ext_priv_key.child_number();
        bytes[9..13].copy_from_slice(&tmp.serialize());

        let tmp = ext_priv_key.chain_code();
        bytes[13..45].copy_from_slice(tmp);

        let tmp = ext_priv_key.public_key();
        bytes[45..78].copy_from_slice(&tmp);

        ExtendedPublicKey {
            bytes: bytes
        }
        // ExtendedPublicKey {
        //     version: ext_priv_key.version().to_pub(),
        //     depth: *ext_priv_key.depth(),
        //     fingerprint: *ext_priv_key.fingerprint(),
        //     child_number: *ext_priv_key.child_number(),
        //     k: ext_priv_key.public_key(),
        //     chain_code: ext_priv_key.chain_code()[..].try_into().unwrap()
        // }
    }

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
    // pub fn _derive_child(&self, index: u32) -> Result<Self, Error> {
    //     if index >= 2147483648 {
    //         return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
    //     }
        
    //     let mut data = vec![0u8;37];
    //     data[0..33].copy_from_slice(&self.public_key());
    //     data[33..].copy_from_slice(&ChildNumber::from_u32(index).0[..]);

    //     let i = HMAC::mac(data, self.chain_code);
    //     let (k, c) = self.transform_i_to_k_and_c(&i);

    //     let child = ExtendedPublicKey {
    //         version: self.version,
    //         depth: self.depth + 1,
    //         fingerprint: Fingerprint::from_xpub(&self),
    //         child_number: ChildNumber::from_u32(index),
    //         k: k,
    //         chain_code: c
    //     };

    //     Ok(child)
    // }

    pub fn derive(&mut self, path: &str) -> Result<Self, Error> {
        let nodes = match valiidate_path(path, false) {
            Err(err) => return Err(err),
            Ok(x) => x
        };

        Self::derive_from(&nodes, &mut self.bytes)?;
        Self::add_checksum(&mut self.bytes);
        let result = ExtendedPublicKey{
            bytes: self.bytes
        };
        Ok(result)
    }

    fn derive_from(nodes: &[Node], bytes: &mut [u8]) -> Result<(), Error> {
        if nodes.len() == 0 {
            return Ok(());
        }else{
            Self::derive_next(nodes[0].index, bytes)?;
            Self::derive_from(&nodes[1..], bytes)?;
            Ok(())
        }
    }

    pub fn derive_child(&mut self, index: u32) -> Result<Self, Error> {
        Self::derive_next(index, &mut self.bytes)?;
        Self::add_checksum(&mut self.bytes);
        let result = ExtendedPublicKey{
            bytes: self.bytes
        };
        Ok(result)
    }

    fn derive_next(index: u32, bytes: &mut [u8]) -> Result<(), Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        bytes[4] += 1; // increment depth        
        Self::update_fingerprint(bytes);
        Self::update_childnumber(index, bytes);

        let mut data = [0u8;37];
        data[0..33].copy_from_slice(&bytes[45..78]);
        data[33..].copy_from_slice(&bytes[9..13]);
        let hash = HMAC::mac(&data, &bytes[13..45]);

        let sk = SigningKey::from_bytes(&hash[..32]).unwrap();
        Self::add_pubkeys(&mut bytes[45..78], &sk.verify_key().to_bytes());
        bytes[13..45].copy_from_slice(&hash[32..]);
        Ok(())
    }

    fn add_checksum(bytes: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[0..78]);
        let hashed = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hashed);

        let finalized = hasher.finalize();
        bytes[78..].copy_from_slice(&finalized[0..4]);
    }

    // pub fn _derive(&self, path: &str) -> Result<Self, Error> {
    //     let nodes = match valiidate_path(path, false) {
    //         Err(err) => return Err(err),
    //         Ok(x) => x
    //     };

    //     Self::derive_from(&self, &nodes)
    // }

    // pub fn _derive2(path: &str, bytes: &mut [u8]) -> Result<Self, Error> {
    //     let nodes = match valiidate_path(path, false) {
    //         Err(err) => return Err(err),
    //         Ok(x) => x
    //     };

    //     Self::derive_in_place(&nodes, bytes)?;
    //     let bytes = Self::with_checksum(bytes);
    //     Self::deserialize(&bytes)
    // }

    // fn _derive_from(current: &Self, nodes: &[Node]) -> Result<Self, Error> {
    //     if nodes.len() == 0 {
    //         return Ok(current.clone());
    //     }else{
    //         let next = current.derive_child(nodes[0].index)?;
    //         return Self::derive_from(&next, &nodes[1..]);
    //     }
    // }

    // fn _derive_in_place(nodes: &[Node], bytes: &mut [u8]) -> Result<(), Error> {
    //     if nodes.len() == 0 {
    //         return Ok(());
    //     }else{
    //         Self::derive_child_in_place(nodes[0].index, bytes)?;
    //         Self::derive_in_place(&nodes[1..], bytes)?;
    //         return Ok(());
    //     }
    // }

    // fn _derive_child_in_place(&self, index: u32, bytes: &mut [u8]) -> Result<(), Error> {
    //     if index >= 2147483648 {
    //         return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
    //     }

    //     Self::update_fingerprint(&mut self.bytes);
    //     println!("3       {:?}", hex::encode(&bytes));

    //     let mut data = [0u8;37];
    //     data[0..33].copy_from_slice(&bytes[45..78]);
    //     data[33..].copy_from_slice(&bytes[9..13]);
    //     let hash = HMAC::mac(&data, &bytes[13..45]);
    //     println!("0       {:?}", hex::encode(&bytes));

    //     let sk = SigningKey::from_bytes(&hash[..32]).unwrap();
    //     Self::add_pubkeys(&mut bytes[45..78], &sk.verify_key().to_bytes());
    //     bytes[13..45].copy_from_slice(&hash[32..]);
    //     println!("1       {:?}", hex::encode(&bytes));


    //     bytes[4] += 1; // increment depth
    //     println!("2       {:?}", hex::encode(&bytes));

        
    //     Self::update_childnumber(index, bytes);
    //     println!("4       {:?}", hex::encode(&bytes));

    //     Ok(())
    // }

    fn add_pubkeys(a: &mut [u8], b: &[u8]) {
        let point1 = EncodedPoint::from_bytes(&a).unwrap();
        let point1 = ProjectivePoint::from_encoded_point(&point1).unwrap();
    
        let point2 = EncodedPoint::from_bytes(&b).unwrap();
        let point2 = ProjectivePoint::from_encoded_point(&point2).unwrap();

        let point = point1.add(point2);
        let encoded = point.to_affine().to_encoded_point(true);

        a[0..].copy_from_slice(encoded.as_bytes());
    }

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

    #[inline(always)]
    fn update_childnumber(c: u32, data: &mut [u8]){
        data[9] = ((c >> 24) & 0xff) as u8;
        data[10] = ((c >> 16) & 0xff) as u8;
        data[11] = ((c >> 8) & 0xff) as u8;
        data[12] = (c & 0xff) as u8;
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

    // fn transform_i_to_k_and_c(&self, i: &[u8; 64]) -> ([u8; 33], [u8; 32]) {
    //     let (i_left, i_right) = split_i(&i);
    //     let sk = SigningKey::from_bytes(&i[..32]).unwrap();
    //     let sum = self.add_pubkeys_bytes(&self.k, &sk.verify_key().to_bytes());
        
    //     (sum, i_right)
    // }
}

impl PublicKey for ExtendedPublicKey {
    fn public_key(&self) -> [u8;33] {
        let mut result = [0u8; 33];
        result.copy_from_slice(&self.bytes[45..78]);
        result
    }
}

impl Serialize<[u8; 78]> for ExtendedPublicKey {
    fn serialize(&self) -> [u8; 78] {
        let mut result = [0u8; 78];
        result.copy_from_slice(&self.bytes[0..78]);
        result

        // bytes[0..4].copy_from_slice(&self.version.serialize());
        // bytes[4] = self.depth;
        // bytes[5..9].copy_from_slice(&self.fingerprint.0);
        // bytes[9..13].copy_from_slice(&self.child_number.0);
        // bytes[13..45].copy_from_slice(&self.chain_code);
        // bytes[45..78].copy_from_slice(&self.k);
        // bytes
    }
}

impl Deserialize<&[u8], Error> for ExtendedPublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 82 {
            return Err(Error::DeseializeError(DeserializationError::InvalidSize));
        }
        if !verify_checksum(&bytes) {
            return Err(Error::DeseializeError(DeserializationError::WrongCheckSum));
        }

        // let mut c = [0u8; 32];
        // c.copy_from_slice(&bytes[13..45]);

        // let mut k = [0u8; 33];
        // k.copy_from_slice(&bytes[45..78]);        
        let mut tmp = [0u8; 82];
        tmp.copy_from_slice(&bytes);
        let result = ExtendedPublicKey {
            // version: Version::deserialize(&bytes[0..4]).unwrap(),
            // depth: bytes[4],
            // fingerprint: Fingerprint::deserialize(&bytes[5..9]).unwrap(),
            // child_number: ChildNumber::deserialize(&bytes[9..13]).unwrap(),
            // k: k,
            // chain_code: c
            bytes: tmp
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::bip32::extended_public_key::ExtendedPublicKey;
    use crate::bip32::extended_private_key::ExtendedPrivateKey;
    use crate::serializer::Serialize;

    #[test]
    fn test_xpub_base58() {
        let bs58 = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let xpub = ExtendedPublicKey::from_base58(bs58);
        assert_eq!(bs58, xpub.to_base58());
    }

    #[test]
    fn test_from_xprv(){
        let seed_hex_str = "000102030405060708090a0b0c0d0e0f";

        let xpriv = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
        let xpub_0 = xpriv.to_x_pub();
        let xpub_1 = ExtendedPublicKey::from_x_priv(&xpriv);

        // xpub_0
        let bs58 = xpub_0.to_base58();
        assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bs58);

        // xpub_1
        let bs58 = xpub_1.to_base58();
        assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bs58);        
    }

    #[test]
    fn test_xpub_derivation(){
        let seed_hex_str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

        let xpriv = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
        let mut xpub_0 = xpriv.to_x_pub();
        let mut xpub_1 = ExtendedPublicKey::from_x_priv(&xpriv);

        let xpub_0 = xpub_0.derive("m/0").unwrap();
        let xpub_1 = xpub_1.derive("m/0").unwrap();

        // xpub_0
        let bs58 = xpub_0.to_base58();
        assert_eq!("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", bs58);

        // xpub_1
        let bs58 = xpub_1.to_base58();
        assert_eq!("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", bs58);        
    }

    // #[test]
    // fn test_in_place_derivation(){
    //     let seed_hex_str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    //     let xpriv = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
    //     let xpub_0 = xpriv.to_x_pub();
    //     let xpub_1 = ExtendedPublicKey::from_x_priv(&xpriv);

    //     let mut bytes = xpub_0.serialize();

    //     println!("original {:?}", xpub_0.to_base58());

    //     // let xpub_0 = xpub_0.derive("m/0").unwrap();
    //     let xpub_0 = ExtendedPublicKey::derive2("m/0", &mut bytes).unwrap();
    //     let xpub_1 = xpub_1.derive("m/0").unwrap();

    //     // xpub_1
    //     let bs58 = xpub_1.to_base58_2();
    //     assert_eq!("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", bs58);

    //     // xpub_0
    //     let bs58 = xpub_0.to_base58();
    //     assert_eq!("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", bs58);
    // }
}