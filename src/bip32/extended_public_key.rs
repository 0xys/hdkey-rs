use hmac_sha512::{HMAC};
use k256::ecdsa::SigningKey;
use base58::{ToBase58, FromBase58};

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::EncodedPoint;
use k256::ProjectivePoint;
use core::ops::Add;

use sha2::{Sha256, Digest as Sha256Digest};
use ripemd160::{Ripemd160};

use crate::keys::{PublicKey};
use crate::error::{Error, PathError, DeserializationError};
use crate::serializer::{Serialize, Deserialize};
use crate::bip32::extended_private_key::ExtendedPrivateKey;
use crate::bip32::checksum::{get_checksum, verify_checksum};
use crate::bip32::helpers::{Node, valiidate_path};

#[derive(Debug, Clone)]
pub struct ExtendedPublicKey {
    bytes: [u8;82]
}

const RANGE_VERSION: std::ops::Range<usize> = 0..4;
const RANGE_DEPTH: std::ops::Range<usize> = 4..4;
const RANGE_FINGERPRINT: std::ops::Range<usize> = 5..9;
const RANGE_CHILD_NUMBER: std::ops::Range<usize> = 9..13;
const RANGE_CHAIN_CODE: std::ops::Range<usize> = 13..45;
const RANGE_PUBLIC_KEY: std::ops::Range<usize> = 45..78;
const RANGE_CHECKSUM: std::ops::Range<usize> = 78..82;

impl ExtendedPublicKey {
    pub fn to_base58(&self) -> String {
        self.bytes.to_base58()
    }

    pub fn from_base58<T: AsRef<str>>(base58_str: T) -> Self {
        let bytes = base58_str.as_ref().from_base58().unwrap();
        ExtendedPublicKey::deserialize(bytes.as_slice()).unwrap()
    }

    pub fn from_x_priv(xprv: &ExtendedPrivateKey) -> Self {
        let mut bytes = [0u8; 82];
        
        bytes[RANGE_VERSION].copy_from_slice(&xprv.bytes[RANGE_VERSION]);
        bytes[4] = xprv.bytes[4];
        bytes[RANGE_FINGERPRINT].copy_from_slice(&xprv.bytes[RANGE_FINGERPRINT]);
        bytes[RANGE_CHILD_NUMBER].copy_from_slice(&xprv.bytes[RANGE_CHILD_NUMBER]);
        bytes[RANGE_CHAIN_CODE].copy_from_slice(&xprv.bytes[RANGE_CHAIN_CODE]);
        bytes[RANGE_PUBLIC_KEY].copy_from_slice(&xprv.public_key());
        Self::add_checksum(&mut bytes);

        ExtendedPublicKey {
            bytes: bytes
        }
    }

    pub fn derive<T: AsRef<str>>(&mut self, path: T) -> Result<Self, Error> {
        let nodes = match valiidate_path(path.as_ref(), false) {
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
            Self::derive_index(nodes[0].index, bytes)?;
            Self::derive_from(&nodes[1..], bytes)?;
            Ok(())
        }
    }

    pub fn derive_child(&mut self, index: u32) -> Result<Self, Error> {
        Self::derive_index(index, &mut self.bytes)?;
        Self::add_checksum(&mut self.bytes);
        let result = ExtendedPublicKey{
            bytes: self.bytes
        };
        Ok(result)
    }

    /// Derive child at index without checksum
    fn derive_index(index: u32, bytes: &mut [u8]) -> Result<(), Error> {
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

    /// Add two secp256k1 pubkeys and store sum in `a`
    fn add_pubkeys(a: &mut [u8], b: &[u8]) {
        let point1 = EncodedPoint::from_bytes(&a).unwrap();
        let point1 = ProjectivePoint::from_encoded_point(&point1).unwrap();
    
        let point2 = EncodedPoint::from_bytes(&b).unwrap();
        let point2 = ProjectivePoint::from_encoded_point(&point2).unwrap();

        let point = point1.add(point2);
        let encoded = point.to_affine().to_encoded_point(true);

        a[0..].copy_from_slice(encoded.as_bytes());
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

        let mut tmp = [0u8; 82];
        tmp.copy_from_slice(&bytes);
        let result = ExtendedPublicKey {
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
}