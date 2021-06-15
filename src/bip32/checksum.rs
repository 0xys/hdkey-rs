use sha2::{Sha256, Digest as Sha256Digest};

pub fn get_checksum(payload: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hashed = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hashed);

    let finalized = hasher.finalize();

    let mut checksum = [0u8; 4];
    checksum[0..4].copy_from_slice(&finalized[0..4]);
    checksum
}

pub fn verify_checksum(packet: &[u8; 82]) -> bool {
    let checksum = get_checksum(&packet[0..78]);
    checksum == packet[78..]
}