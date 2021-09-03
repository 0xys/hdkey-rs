pub mod extended_public_key;
pub mod extended_private_key;
pub mod version;
pub mod checksum;

pub mod helpers;

pub trait Bip32 {
    fn derive_child(i: u32);
    fn derive_hardened_child(i: u32);
}
