# bip32 HD Wallet implementation in Rust
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## status
- passed all test vectors in official [bip32 repo](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors).

## Usage
```rs
let seed_hex_str = "000102030405060708090a0b0c0d0e0f";

let xpriv = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
let xpub = xpriv.to_x_pub();

// base58 encoding
let bs58 = xpub.to_base58();
let bs58 = bs58.as_str();
assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bs58);

// xpriv derivation
let xpriv = xpriv.derive_hardended_child(0).unwrap();
let xpriv = xpriv.derive(0).unwrap();

```