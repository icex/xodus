//! Xbox Live request signing.
//!
//! Most Xbox Live endpoints carry a signature policy: the request must be
//! accompanied by a `Signature` header proving it came from the holder of the
//! key the token was issued against. Without it those services answer 401, which
//! is why a title can sign in and still fail to load a profile.
//!
//! Two halves. The key pair is generated once and its public half travels as the
//! `ProofKey` of the user-authenticate request, binding the resulting token to
//! it. Thereafter each request is signed over a canonical serialisation of its
//! own method, path, authorization header and body, so a signature cannot be
//! replayed onto a different request.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::Serialize;

/// The JWK the service expects as `ProofKey`.
#[derive(Debug, Serialize, Clone)]
pub struct ProofKey {
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kty: String,
    pub x: String,
    pub y: String,
}

/// The client's signing identity: a P-256 key plus the JWK describing it.
#[derive(Clone)]
pub struct RequestSigner {
    key: SigningKey,
}

impl RequestSigner {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::random(&mut rand_core06::OsRng),
        }
    }

    /// Restore a signer from a previously stored PKCS#8 DER blob.
    pub fn from_pkcs8(der: &[u8]) -> Option<Self> {
        use p256::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_der(der).ok().map(|key| Self { key })
    }

    pub fn to_pkcs8(&self) -> Option<Vec<u8>> {
        use p256::pkcs8::EncodePrivateKey;
        self.key
            .to_pkcs8_der()
            .ok()
            .map(|d| d.as_bytes().to_vec())
    }

    /// The public half, in the shape the authenticate request wants.
    pub fn proof_key(&self) -> ProofKey {
        let point = self.key.verifying_key().to_encoded_point(false);
        ProofKey {
            crv: "P-256".to_string(),
            alg: "ES256".to_string(),
            use_: "sig".to_string(),
            kty: "EC".to_string(),
            x: URL_SAFE_NO_PAD.encode(point.x().map(|x| x.as_slice()).unwrap_or_default()),
            y: URL_SAFE_NO_PAD.encode(point.y().map(|y| y.as_slice()).unwrap_or_default()),
        }
    }

    /// Build the `Signature` header for one request.
    ///
    /// The signed message is the policy version, the timestamp, the method, the
    /// path and query, the authorization header and the body, each terminated
    /// by a NUL. The header itself is the version and timestamp again followed
    /// by the raw r||s signature, so a server can reconstruct exactly what was
    /// signed.
    /// A stable device identity for this key, formatted as a GUID. Derived
    /// from the public key so the machine keeps one identity for as long as
    /// the key lives, rather than looking like a new device every launch.
    pub fn device_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let pk = self.proof_key();
        let mut h = Sha256::new();
        h.update(pk.x.as_bytes());
        h.update(pk.y.as_bytes());
        let d = h.finalize();
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]
        )
    }

    pub fn sign(
        &self,
        policy_version: u32,
        method: &str,
        path_and_query: &str,
        authorization: &str,
        body: &[u8],
        max_body_bytes: usize,
    ) -> String {
        // Xbox timestamps are Windows FILETIME: 100ns ticks since 1601-01-01.
        let now = chrono::Utc::now().timestamp();
        let filetime = ((now + 11_644_473_600) as u64) * 10_000_000;

        let body = if body.len() > max_body_bytes {
            &body[..max_body_bytes]
        } else {
            body
        };

        let mut message = Vec::with_capacity(128 + body.len());
        message.extend_from_slice(&policy_version.to_be_bytes());
        message.push(0);
        message.extend_from_slice(&filetime.to_be_bytes());
        message.push(0);
        message.extend_from_slice(method.to_uppercase().as_bytes());
        message.push(0);
        message.extend_from_slice(path_and_query.as_bytes());
        message.push(0);
        message.extend_from_slice(authorization.as_bytes());
        message.push(0);
        message.extend_from_slice(body);
        message.push(0);

        let signature: Signature = self.key.sign(&message);

        let mut header = Vec::with_capacity(76);
        header.extend_from_slice(&policy_version.to_be_bytes());
        header.extend_from_slice(&filetime.to_be_bytes());
        header.extend_from_slice(&signature.to_bytes());
        STANDARD.encode(header)
    }
}

/// The path-and-query part of a URL, which is what gets signed (not the host).
pub fn path_and_query(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => {
            let mut s = u.path().to_string();
            if let Some(q) = u.query() {
                s.push('?');
                s.push_str(q);
            }
            s
        }
        Err(_) => "/".to_string(),
    }
}
