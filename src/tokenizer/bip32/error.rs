
pub enum Bip32TokenizeError {
    UnparsableAt(usize, char),
    IncoherentAt(usize, String),
    Unknown
}