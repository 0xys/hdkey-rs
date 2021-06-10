use sha2::{Sha256, Digest as Sha256Digest};
use ripemd160::{Ripemd160};
use std::convert::TryInto;

use crate::keys::{PublicKey};
use crate::bip32::extended_private_key::ExtendedPrivateKey;
use crate::bip32::extended_public_key::ExtendedPublicKey;

/// fingerprint of public key
/// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Fingerprint(pub [u8; 4]);

impl Fingerprint {

    /// calculate fingerprint from ExtendedPublicKey
    pub fn from_xpub(xpub: &ExtendedPublicKey) -> Self {
        let mut hasher = Sha256::new();
        let pubkey = xpub.public_key();
        hasher.update(pubkey);
        let sha256ed = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(&sha256ed);
        let rip160ed = hasher.finalize();
        
        let x: [u8; 20] = rip160ed.as_slice().try_into().unwrap();
        
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&x[0..4]);
        Fingerprint(fingerprint)
    }

    /// calculate fingerprint from ExtendedPrivateKey
    pub fn from_xpiv(xpriv: &ExtendedPrivateKey) -> Self {
        let mut hasher = Sha256::new();
        let pubkey = xpriv.public_key();
        hasher.update(pubkey);
        let sha256ed = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(&sha256ed);
        let rip160ed = hasher.finalize();
        
        let x: [u8; 20] = rip160ed.as_slice().try_into().unwrap();
        
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&x[0..4]);
        Fingerprint(fingerprint)
    }
}