mod bip32;
mod keys;

#[cfg(test)]
mod tests {
    use crate::bip32::extended_private_key::ExtendedPrivateKey;
    use crate::bip32::extended_public_key::ExtendedPublicKey;

    #[test]
    fn it_works() {
        let seed_hex_str = "000102030405060708090a0b0c0d0e0f";

        let xpriv = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        println!("xpriv: {:?}", xpriv.to_raw_bytes());
        assert_eq!("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", bs58);

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        // println!("xpub: {:?}", xpriv.to_raw_bytes());
        assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bs58);
    }
}
