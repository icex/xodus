//! The package header's own signature.
//!
//! An XVD package's header is its first page. The first 0x200 bytes of that
//! page are an RSA-4096 signature, written big-endian, over the rest of the
//! page, bytes 0x200..0x1000: RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a
//! 32-byte salt. Everything the client takes from the header -- the identity
//! fields, the volume flags, the section sizes and the top hash of the hash
//! tree -- lies in that range, and the hash tree hangs every other page of the
//! package from the top hash. Nothing past the first page is signed: bytes
//! 0x1000 onwards are not covered by this signature, and are believed only
//! where the hash tree covers them.
//!
//! This crate carries no Microsoft key. The key that signs retail PC game
//! headers is found at run time on the user's machine (see `xodus-cli xvd-key`)
//! and is used only if the SHA-256 of its `BCRYPT_RSAPUBLIC_BLOB` is
//! [`GAME_PACKAGE_KEY_SHA256`], which is compiled in. The SHA-256 is a
//! fingerprint, not the key.

use std::fmt;

use rsa::pss::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Bytes of the header taken by the signature.
pub const SIGNATURE_LEN: usize = 0x200;
/// The end of the signed range, which starts at [`SIGNATURE_LEN`].
pub const SIGNED_END: usize = 0x1000;
/// The PSS salt length the header signature uses.
pub const SALT_LEN: usize = 32;

/// `BCRYPT_RSAPUBLIC_MAGIC`, as it appears in a blob.
pub const BLOB_MAGIC: &[u8; 4] = b"RSA1";
/// The fixed part of a `BCRYPT_RSAKEY_BLOB`: magic, bit length, then the
/// lengths of the public exponent, the modulus and the two primes.
pub const BLOB_HEADER_LEN: usize = 24;
const MODULUS_LEN: usize = 512;

/// SHA-256 of the `BCRYPT_RSAPUBLIC_BLOB` of the key that signs retail PC game
/// package headers. Found in Microsoft Gaming Services; verified against a
/// retail package header. The only key this client accepts for packages.
pub const GAME_PACKAGE_KEY_SHA256: [u8; 32] =
    hex32("183F0AE05431E4AD91554E88946967C872997227DBE6C85116F5FD2FD2D1229E");

const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// Lower-case hex, for messages.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The length of the RSA-4096 `BCRYPT_RSAPUBLIC_BLOB` whose fixed part starts
/// `data`, or `None` when `data` does not start with one.
///
/// Only a public blob of a 4096-bit key qualifies: magic `RSA1`, 4096 bits, a
/// public exponent of one to eight bytes, a 512-byte modulus and no primes.
pub fn rsa4096_public_blob_len(data: &[u8]) -> Option<usize> {
    if data.len() < BLOB_HEADER_LEN || &data[..4] != BLOB_MAGIC {
        return None;
    }
    let field = |i: usize| u32::from_le_bytes(data[4 * i..4 * i + 4].try_into().unwrap());
    let (bits, exponent, modulus, prime1, prime2) =
        (field(1), field(2), field(3), field(4), field(5));
    if bits != 4096
        || !(1..=8).contains(&exponent)
        || modulus as usize != MODULUS_LEN
        || prime1 != 0
        || prime2 != 0
    {
        return None;
    }
    Some(BLOB_HEADER_LEN + exponent as usize + MODULUS_LEN)
}

/// Why a key was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error(
        "the key's fingerprint is {}, not the pinned {}",
        hex(found),
        hex(expected)
    )]
    NotPinned { found: [u8; 32], expected: [u8; 32] },
    #[error("not an RSA-4096 public key blob")]
    Malformed,
}

/// A key a package header may be verified with: an RSA-4096 public key whose
/// blob hashed to the fingerprint it was required to have.
#[derive(Clone)]
pub struct XvdSigningKey {
    key: RsaPublicKey,
    fingerprint: [u8; 32],
}

impl fmt::Debug for XvdSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XvdSigningKey({})", hex(&self.fingerprint))
    }
}

impl XvdSigningKey {
    /// Accept `blob` only if it is a well-formed RSA-4096
    /// `BCRYPT_RSAPUBLIC_BLOB` whose SHA-256 is `pin`. The hash is checked
    /// first, over exactly the bytes given, so nothing else about an unpinned
    /// blob is looked at.
    pub fn from_blob(blob: &[u8], pin: &[u8; 32]) -> Result<Self, KeyError> {
        let found: [u8; 32] = Sha256::digest(blob).into();
        if found != *pin {
            return Err(KeyError::NotPinned {
                found,
                expected: *pin,
            });
        }
        let len = rsa4096_public_blob_len(blob).ok_or(KeyError::Malformed)?;
        if len != blob.len() {
            return Err(KeyError::Malformed);
        }
        let exponent_len = blob.len() - BLOB_HEADER_LEN - MODULUS_LEN;
        let exponent = &blob[BLOB_HEADER_LEN..BLOB_HEADER_LEN + exponent_len];
        let modulus = &blob[BLOB_HEADER_LEN + exponent_len..];
        // A 4096-bit modulus has its top bit set; anything shorter is not one.
        if modulus[0] & 0x80 == 0 {
            return Err(KeyError::Malformed);
        }
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(exponent),
        )
        .map_err(|_| KeyError::Malformed)?;
        Ok(XvdSigningKey {
            key,
            fingerprint: found,
        })
    }

    /// The SHA-256 of the blob this key came from.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

/// Why a header's signature was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("the package header is shorter than the page its signature covers")]
    Truncated,
    #[error("the package header is not signed (its signature is all zeros)")]
    Unsigned,
    #[error("the package header's signature does not verify with key {}", hex(.0))]
    Invalid([u8; 32]),
}

/// Check the signature at the start of `header`, which must hold at least the
/// header's first page.
pub fn verify_header(header: &[u8], key: &XvdSigningKey) -> Result<(), SignatureError> {
    if header.len() < SIGNED_END {
        return Err(SignatureError::Truncated);
    }
    let signature = &header[..SIGNATURE_LEN];
    if signature.iter().all(|&b| b == 0) {
        return Err(SignatureError::Unsigned);
    }
    let invalid = || SignatureError::Invalid(key.fingerprint);
    let signature = Signature::try_from(signature).map_err(|_| invalid())?;
    VerifyingKey::<rsa::sha2::Sha256>::new_with_salt_len(key.key.clone(), SALT_LEN)
        .verify(&header[SIGNATURE_LEN..SIGNED_END], &signature)
        .map_err(|_| invalid())
}

/// Synthetic keys and signed headers for tests here and in the crates that use
/// this one. The keys are throwaway RSA-4096 keys generated for these tests and
/// sign nothing real. Not part of the API.
#[cfg(any(test, feature = "test-signing"))]
#[doc(hidden)]
pub mod testing {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pss::BlindedSigningKey;
    use rsa::rand_core::{CryptoRng, RngCore};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};

    use super::{SALT_LEN, SIGNATURE_LEN, SIGNED_END, XvdSigningKey};

    /// TEST ONLY: a throwaway key made for these tests, not anyone's.
    const TEST_KEY_PEM: &str = include_str!("testdata/TEST-ONLY-xvd-signing-key-1.pkcs8");
    /// TEST ONLY: a second throwaway key, for "signed by someone else".
    const OTHER_KEY_PEM: &str = include_str!("testdata/TEST-ONLY-xvd-signing-key-2.pkcs8");

    pub fn test_key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).unwrap()
    }

    pub fn other_key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(OTHER_KEY_PEM).unwrap()
    }

    /// The key's public half as a `BCRYPT_RSAPUBLIC_BLOB`.
    pub fn public_blob(key: &RsaPublicKey) -> Vec<u8> {
        let e = key.e().to_bytes_be();
        let n = key.n().to_bytes_be();
        let mut blob = Vec::new();
        for field in [0x3141_5352u32, 4096, e.len() as u32, n.len() as u32, 0, 0] {
            blob.extend_from_slice(&field.to_le_bytes());
        }
        blob.extend_from_slice(&e);
        blob.extend_from_slice(&n);
        blob
    }

    pub fn blob_sha256(blob: &[u8]) -> [u8; 32] {
        Sha256::digest(blob).into()
    }

    /// The test key's public half, pinned to itself.
    pub fn test_verifying_key() -> XvdSigningKey {
        let blob = public_blob(&test_key().to_public_key());
        XvdSigningKey::from_blob(&blob, &blob_sha256(&blob)).unwrap()
    }

    /// The other key's public half, pinned to itself.
    pub fn other_verifying_key() -> XvdSigningKey {
        let blob = public_blob(&other_key().to_public_key());
        XvdSigningKey::from_blob(&blob, &blob_sha256(&blob)).unwrap()
    }

    /// Deterministic, and only for making test signatures.
    struct TestRng(u64);
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            // splitmix64
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    /// Sign `header` in place, the way a package header is signed, with
    /// `salt_len` bytes of salt.
    pub fn sign_with(header: &mut [u8], key: &RsaPrivateKey, salt_len: usize) {
        let signer =
            BlindedSigningKey::<rsa::sha2::Sha256>::new_with_salt_len(key.clone(), salt_len);
        let signature = signer
            .sign_with_rng(&mut TestRng(0x5eed), &header[SIGNATURE_LEN..SIGNED_END])
            .to_vec();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        header[..SIGNATURE_LEN].copy_from_slice(&signature);
    }

    /// Sign `header` in place with the test key.
    pub fn sign(header: &mut [u8]) {
        sign_with(header, &test_key(), SALT_LEN);
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{
        blob_sha256, other_key, other_verifying_key, public_blob, sign, sign_with, test_key,
        test_verifying_key,
    };
    use super::*;

    fn header() -> Vec<u8> {
        let mut h: Vec<u8> = (0..0x3000).map(|i| (i * 31 % 251) as u8).collect();
        h[0x200..0x208].copy_from_slice(b"msft-xvd");
        sign(&mut h);
        h
    }

    #[test]
    fn the_pinned_fingerprint_is_the_game_package_key() {
        assert_eq!(
            hex(&GAME_PACKAGE_KEY_SHA256),
            "183f0ae05431e4ad91554e88946967c872997227dbe6c85116f5fd2fd2d1229e"
        );
    }

    #[test]
    fn a_signed_header_verifies() {
        assert_eq!(verify_header(&header(), &test_verifying_key()), Ok(()));
        // The first page is all that is needed.
        assert_eq!(
            verify_header(&header()[..SIGNED_END], &test_verifying_key()),
            Ok(())
        );
    }

    #[test]
    fn a_changed_signed_byte_fails() {
        let key = test_verifying_key();
        for offset in [0x0, 0x1FF, 0x200, 0x208, 0x218, 0x240, 0x288, 0x3AC, 0xFFF] {
            let mut h = header();
            h[offset] ^= 0x01;
            assert_eq!(
                verify_header(&h, &key),
                Err(SignatureError::Invalid(*key.fingerprint())),
                "offset {offset:#x}"
            );
        }
    }

    #[test]
    fn bytes_past_the_first_page_are_not_signed() {
        let key = test_verifying_key();
        for offset in [0x1000, 0x1234, 0x2000, 0x2FFF] {
            let mut h = header();
            h[offset] ^= 0x01;
            assert_eq!(verify_header(&h, &key), Ok(()), "offset {offset:#x}");
        }
    }

    #[test]
    fn another_key_or_salt_fails() {
        let h = header();
        let other = other_verifying_key();
        assert_eq!(
            verify_header(&h, &other),
            Err(SignatureError::Invalid(*other.fingerprint()))
        );
        let mut signed_by_other = header();
        sign_with(&mut signed_by_other, &other_key(), SALT_LEN);
        assert!(verify_header(&signed_by_other, &test_verifying_key()).is_err());
        for salt in [0, 20, 64] {
            let mut h = header();
            sign_with(&mut h, &test_key(), salt);
            assert!(
                verify_header(&h, &test_verifying_key()).is_err(),
                "salt {salt}"
            );
        }
    }

    #[test]
    fn an_all_zero_signature_is_unsigned_and_a_short_header_is_refused() {
        let mut h = header();
        h[..SIGNATURE_LEN].fill(0);
        assert_eq!(
            verify_header(&h, &test_verifying_key()),
            Err(SignatureError::Unsigned)
        );
        assert_eq!(
            verify_header(&header()[..SIGNED_END - 1], &test_verifying_key()),
            Err(SignatureError::Truncated)
        );
        // A signature that is not a number below the modulus.
        let mut h = header();
        h[..SIGNATURE_LEN].fill(0xFF);
        assert!(matches!(
            verify_header(&h, &test_verifying_key()),
            Err(SignatureError::Invalid(_))
        ));
    }

    #[test]
    fn only_the_pinned_blob_is_accepted() {
        let blob = public_blob(&test_key().to_public_key());
        let pin = blob_sha256(&blob);
        assert!(XvdSigningKey::from_blob(&blob, &pin).is_ok());
        assert_eq!(rsa4096_public_blob_len(&blob), Some(blob.len()));

        let other = public_blob(&other_key().to_public_key());
        assert!(matches!(
            XvdSigningKey::from_blob(&other, &pin),
            Err(KeyError::NotPinned { .. })
        ));
        // The real pin accepts neither test key.
        assert!(matches!(
            XvdSigningKey::from_blob(&blob, &GAME_PACKAGE_KEY_SHA256),
            Err(KeyError::NotPinned { found, .. }) if found == pin
        ));
        // One byte changed is another blob.
        let mut changed = blob.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            XvdSigningKey::from_blob(&changed, &pin),
            Err(KeyError::NotPinned { .. })
        ));
        // Pinned, but not a key: still refused.
        let mut short = blob.clone();
        short.truncate(blob.len() - 1);
        assert!(matches!(
            XvdSigningKey::from_blob(&short, &blob_sha256(&short)),
            Err(KeyError::Malformed)
        ));
    }

    #[test]
    fn blob_headers_are_recognised_strictly() {
        let blob = public_blob(&test_key().to_public_key());
        assert_eq!(
            rsa4096_public_blob_len(&blob[..BLOB_HEADER_LEN]),
            Some(blob.len())
        );
        for (field, value) in [
            (0usize, 0x3241_5352u32),
            (1, 2048),
            (2, 0),
            (2, 9),
            (3, 256),
            (4, 1),
        ] {
            let mut b = blob.clone();
            b[4 * field..4 * field + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(rsa4096_public_blob_len(&b), None, "field {field} = {value}");
        }
        assert_eq!(rsa4096_public_blob_len(&blob[..BLOB_HEADER_LEN - 1]), None);
    }
}
