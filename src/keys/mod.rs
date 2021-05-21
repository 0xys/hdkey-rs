
pub trait PublicKey {
    fn public_key(&self) -> [u8;33];
}

pub trait PrivateKey {
    fn private_key(&self) -> [u8;32];
}