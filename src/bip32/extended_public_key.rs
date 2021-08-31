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
use crate::bip32::checksum::{verify_checksum};
use crate::bip32::helpers::{Node, valiidate_path};
use crate::bip32::version::Version;

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
    /// Base58-Encode extended public key.
    /// 
    pub fn to_base58(&self) -> String {
        self.bytes.to_base58()
    }

    /// Base58-Decode extended public key.
    /// 
    pub fn from_base58<T: AsRef<str>>(base58_str: T) -> Self {
        let bytes = base58_str.as_ref().from_base58().unwrap();
        ExtendedPublicKey::deserialize(bytes.as_slice()).unwrap()
    }

    /// Construct extended public key from extended private key.
    /// 
    pub fn from_xprv(xprv: &ExtendedPrivateKey) -> Self {
        let mut bytes = [0u8; 82];
        
        let version = Self::_get_pub_version_of(&xprv.bytes[RANGE_VERSION]);
        bytes[RANGE_VERSION].copy_from_slice(&version);

        bytes[4..45].copy_from_slice(&xprv.bytes[4..45]);
        bytes[RANGE_PUBLIC_KEY].copy_from_slice(&xprv.public_key());
        Self::_add_checksum(&mut bytes);

        ExtendedPublicKey {
            bytes: bytes
        }
    }

    /// Derive child node by path from current node.
    /// 
    pub fn derive<T: AsRef<str>>(&self, path: T) -> Result<Self, Error> {       
        let nodes = match valiidate_path(path.as_ref(), false) {
            Err(err) => return Err(err),
            Ok(x) => x
        };

        let mut bytes = [0u8; 82];
        bytes.copy_from_slice(&self.bytes);

        Self::_derive(&nodes, &mut bytes)?;
        Self::_add_checksum(&mut bytes);

        let result = ExtendedPublicKey{
            bytes
        };
        Ok(result)
    }

    fn _derive(nodes: &[Node], bytes: &mut [u8]) -> Result<(), Error> {
        if nodes.len() == 0 {
            return Ok(());
        }
        Self::_derive_child(nodes[0].index, bytes)?;
        Self::_derive(&nodes[1..], bytes)?;
        Ok(())
    }

    /// Derive child node at index. 
    /// 
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        let mut bytes = [0u8; 82];
        bytes.copy_from_slice(&self.bytes);

        Self::_derive_child(index, &mut bytes)?;
        Self::_add_checksum(&mut bytes);

        let result = ExtendedPublicKey{
            bytes
        };
        Ok(result)
    }

    /// Derive child node at index without checksum
    fn _derive_child(index: u32, bytes: &mut [u8]) -> Result<(), Error> {
        if index >= 2147483648 {
            return Err(Error::InvalidPath(PathError::IndexOutOfBounds(index)));
        }

        bytes[4] += 1; // increment depth
        Self::_update_fingerprint(bytes);
        Self::_update_childnumber(index, bytes);

        let mut data = [0u8;37];
        data[0..33].copy_from_slice(&bytes[RANGE_PUBLIC_KEY]);
        data[33..].copy_from_slice(&bytes[RANGE_CHILD_NUMBER]);
        let hash = HMAC::mac(&data, &bytes[RANGE_CHAIN_CODE]);

        let sk = SigningKey::from_bytes(&hash[..32]).unwrap();
        Self::_add_pubkeys(&mut bytes[RANGE_PUBLIC_KEY], &sk.verify_key().to_bytes());
        bytes[RANGE_CHAIN_CODE].copy_from_slice(&hash[32..]);
        Ok(())
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

    /// Add two secp256k1 pubkeys and store sum in `a`
    fn _add_pubkeys(a: &mut [u8], b: &[u8]) {
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
    fn _update_fingerprint(bytes: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[RANGE_PUBLIC_KEY]);
        let sha256ed = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(&sha256ed);
        let rip160ed = hasher.finalize();
        
        let x = rip160ed.as_slice();
        bytes[RANGE_FINGERPRINT].copy_from_slice(&x[0..4]);
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

    #[inline(always)]
    fn _get_pub_version_of(bytes: &[u8]) -> [u8; 4] {
        let a = match *bytes {
            [0x04, 0x88, 0xb2, 0x1e] => [0x04, 0x88, 0xb2, 0x1e],
            [0x04, 0x88, 0xad, 0xe4] => [0x04, 0x88, 0xb2, 0x1e],
            [0x04, 0x35, 0x87, 0xcf] => [0x04, 0x35, 0x87, 0xcf],
            [0x04, 0x35, 0x83, 0x94] => [0x04, 0x35, 0x87, 0xcf],
            _ => [0x04, 0x88, 0xb2, 0x1e]
        };
        a
    }
}

impl PublicKey for ExtendedPublicKey {
    fn public_key(&self) -> [u8;33] {
        let mut result = [0u8; 33];
        result.copy_from_slice(&self.bytes[RANGE_PUBLIC_KEY]);
        result
    }
}

impl Serialize<[u8; 82]> for ExtendedPublicKey {
    fn serialize(&self) -> [u8; 82] {
        self.bytes
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
        let xpub_0 = xpriv.to_xpub();
        let xpub_1 = ExtendedPublicKey::from_xprv(&xpriv);

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
        let xpub_0 = xpriv.to_xpub();
        let xpub_1 = ExtendedPublicKey::from_xprv(&xpriv);

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