use rcs_rs::acs::verify_mls_participant_proof;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

#[test]
fn independent_labeled_signatures_require_the_exact_nonce_and_public_key() {
    let random = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random).unwrap();
    let mut public = include_bytes!("fixtures/consent-public-key.der")[..26].to_vec();
    public.extend_from_slice(key.public_key().as_ref());
    // Independent literal label and three length encodings, without the production encoder.
    for (nonce, length) in [
        ("nonce".to_owned(), vec![5]),
        (" nonce ".to_owned(), vec![7]),
        ("n".repeat(64), vec![0x40, 0x40]),
        ("n".repeat(16384), vec![0x80, 0, 0x40, 0]),
        ("n".repeat(65536), vec![0x80, 1, 0, 0]),
    ] {
        let mut input = b"\x21MLS 1.0 ACS_Participant_Key_Proof".to_vec();
        input.extend_from_slice(&length);
        input.extend_from_slice(nonce.as_bytes());
        let signature = key.sign(&random, &input).unwrap();
        verify_mls_participant_proof(&nonce, &public, signature.as_ref()).unwrap();
        assert!(
            verify_mls_participant_proof(&(nonce.clone() + "x"), &public, signature.as_ref())
                .is_err()
        );
        assert!(
            verify_mls_participant_proof(
                &nonce,
                include_bytes!("fixtures/consent-public-key.der"),
                signature.as_ref(),
            )
            .is_err()
        );
        let mut changed = signature.as_ref().to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(verify_mls_participant_proof(&nonce, &public, &changed).is_err());
    }
    assert!(verify_mls_participant_proof("", &public, b"invalid").is_err());
    assert!(verify_mls_participant_proof(&"n".repeat(65537), &public, b"invalid").is_err());
    assert!(verify_mls_participant_proof("nonce", &public[..90], b"invalid").is_err());
    assert!(verify_mls_participant_proof("nonce", &public, &[0; 129]).is_err());
}
