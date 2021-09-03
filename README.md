# bip32 HD Wallet implementation in Rust
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## status
- passed all test vectors in official [bip32 repo](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors).

## Usage
```rs
let seed = "000102030405060708090a0b0c0d0e0f";
let master_prv = ExtendedPrivateKey::from_seed_hex(seed).unwrap();

// xprv derivation
let xprv = master_prv.derive("m/0/1'/123'/456").unwrap();
let xprv_1 = xprv.to_base58();

let xprv = master_prv.derive_child(0).unwrap();
let xprv = xprv.derive_hardened_child(1).unwrap();
let xprv = xprv.derive_hardened_child(123).unwrap();
let xprv = xprv.derive_child(456).unwrap();
let xprv_2 = xprv.to_base58();

assert_eq!(xprv_1, xprv_2);

// xpub derivation
let xpub = ExtendedPublicKey::from_xprv(&xprv);
let xpub_1 = xpub.to_base58();

let xprv = master_prv.derive("m/0/1'/123'").unwrap();
let xpub = ExtendedPublicKey::from_xprv(&xprv);
let xpub = xpub.derive_child(456).unwrap();
let xpub_2 = xpub.to_base58();

assert_eq!(xpub_1, xpub_2);

// base58
let xprv = ExtendedPrivateKey::from_base58(xprv_1);
let xprv = xprv.derive_child(789).unwrap();
let xpub = ExtendedPublicKey::from_xprv(&xprv);
let xpub_3 = xpub.to_base58();

let xpub = ExtendedPublicKey::from_base58(xpub_1);
let xpub = xpub.derive_child(789).unwrap();
let xpub_4 = xpub.to_base58();

assert_eq!(xpub_3, xpub_4);

```