mod bip32;
mod keys;

#[cfg(test)]
mod tests {
    use crate::bip32::extended_private_key::ExtendedPrivateKey;

    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
    #[test]
    fn test_vector_1() {
        let seed_hex_str = "000102030405060708090a0b0c0d0e0f";

        //  --------------------------------------------------------------------------------------------------------------------------------
        //  m
        //  --------------------------------------------------------------------------------------------------------------------------------
        let xpriv = ExtendedPrivateKey::from_seed_hex(seed_hex_str).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bs58);

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", bs58);        


        // --------------------------------------------------------------------------------------------------------------------------------
        // m/0'
        // --------------------------------------------------------------------------------------------------------------------------------
        let xpriv = xpriv.derive_hardended_child(0).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", bs58);

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", bs58);


        // --------------------------------------------------------------------------------------------------------------------------------
        // m/0'/1
        // --------------------------------------------------------------------------------------------------------------------------------
        let xpriv = xpriv.derive_child(1).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", bs58);

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", bs58);


        // --------------------------------------------------------------------------------------------------------------------------------
        // m/0'/1/2'
        // --------------------------------------------------------------------------------------------------------------------------------
        let xpriv = xpriv.derive_hardended_child(2).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", bs58);

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", bs58);


        // --------------------------------------------------------------------------------------------------------------------------------
        // m/0'/1/2'/2
        // --------------------------------------------------------------------------------------------------------------------------------
        let xpriv = xpriv.derive_child(2).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", bs58);

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", bs58);


        // --------------------------------------------------------------------------------------------------------------------------------
        // m/0'/1/2'/2/1000000000
        // --------------------------------------------------------------------------------------------------------------------------------
        let xpriv = xpriv.derive_child(1000000000).unwrap();
        let xpub = xpriv.to_x_pub();

        // xpub
        let bs58 = xpub.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", bs58);

        // xpriv
        let bs58 = xpriv.to_base58();
        let bs58 = bs58.as_str();
        assert_eq!("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", bs58);
    }
}
