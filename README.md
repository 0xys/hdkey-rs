# bip32 HD Wallet implementation in Rust
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## status
- passed all test vectors in official [bip32 repo](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors).

## Usage
```rs
let seed_hex_str = "000102030405060708090a0b0c0d0e0f";

// from path
let xpriv_master = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
let xpriv = xpriv_master.derive("m/0'/1/2'").unwrap();
let xpub = xpriv.to_x_pub();

let bs58 = xpriv.to_base58();
let bs58 = bs58.as_str();
assert_eq!("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", bs58);

let bs58 = xpub.to_base58();
let bs58 = bs58.as_str();
assert_eq!("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", bs58);

```