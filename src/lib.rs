//! # native-trust-verify
//!
//! Embeddable signature verifier for desktop apps that need to validate
//! cloud-issued cryptographic receipts against a compiled-in trust bundle.
//!
//! ## The problem
//!
//! I have a desktop app where the cloud runtime generates legal documents and
//! signs them with Ed25519. The desktop has to verify those signatures before
//! promoting the document into the user's canonical workspace. If the cloud
//! gets compromised, or someone intercepts the response and tampers with it,
//! the signature check has to catch it. No exceptions, no "verify later."
//!
//! The trust bundle (a JSON file containing the cloud's public keys) is compiled
//! into the binary at build time via `include!()`, so it can't be swapped out
//! at runtime. Each key has a `purpose` (what it's allowed to sign), an `issuer`
//! identity, and a capability digest that the signature must match.
//!
//! I also needed P-256 ECDSA support because one of our cloud providers uses
//! that instead of Ed25519. So this crate handles both.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use native_trust_verify::{TrustBundle, verify_signature};
//! use serde_json::json;
//!
//! // Load your trust bundle (normally compiled in at build time)
//! let bundle_json = r#"{"version":1,"keys":[...]}"#;
//! let bundle: TrustBundle = serde_json::from_str(bundle_json).unwrap();
//!
//! // The signed payload from the cloud
//! let receipt = json!({
//!     "issuer": "cloud-runtime",
//!     "signingKeyId": "key-001",
//!     "issuerCapabilityDigest": "sha256:abc...",
//!     "signatureAlgorithm": "ed25519",
//!     "signedPayloadDigest": "sha256:def...",
//!     "signature": "<base64url-encoded>"
//! });
//!
//! verify_signature(&bundle, "runtime", &receipt).unwrap();
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdKey};
use p256::{
    ecdsa::{Signature as P256Signature, VerifyingKey as P256Key},
    EncodedPoint,
};
use serde::Deserialize;
use serde_json::Value;

/// A trust bundle containing one or more public keys, each scoped to a
/// specific purpose and issuer.
#[derive(Debug, Deserialize)]
pub struct TrustBundle {
    pub version: u32,
    pub keys: Vec<TrustKey>,
}

/// A single trusted public key with its metadata.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustKey {
    pub purpose: String,
    pub issuer: String,
    pub signing_key_id: String,
    pub issuer_capability_digest: String,
    pub signature_algorithm: String,
    pub public_jwk: Value,
}

/// Verify a cryptographic signature against a trust bundle.
///
/// The `purpose` parameter scopes which keys are eligible (e.g., "runtime",
/// "billing"). This prevents a key intended for one subsystem from being used
/// to forge receipts for another.
///
/// Returns `Ok(())` if the signature is valid, `Err` with a description if
/// anything fails. The error messages are deliberately vague about *what*
/// specifically went wrong — you don't want to give an attacker a detailed
/// oracle about which part of the verification chain failed.
///
/// ...okay, they're not *that* vague. I added slightly more detail after
/// spending too long debugging a "signature verification failed" error that
/// turned out to be a base64url padding issue. But they don't leak key material.
pub fn verify_signature(bundle: &TrustBundle, purpose: &str, value: &Value) -> Result<(), String> {
    if bundle.version != 1 {
        return Err("trust bundle version unsupported".into());
    }

    let issuer = field(value, "issuer")?;
    let key_id = field(value, "signingKeyId")?;
    let capability = field(value, "issuerCapabilityDigest")?;
    let algorithm = field(value, "signatureAlgorithm")?;

    // Find exactly one matching key. Zero matches = untrusted.
    // Multiple matches = ambiguous bundle, also reject.
    let matches: Vec<_> = bundle
        .keys
        .iter()
        .filter(|k| {
            k.purpose == purpose
                && k.issuer == issuer
                && k.signing_key_id == key_id
                && k.issuer_capability_digest == capability
                && k.signature_algorithm == algorithm
        })
        .collect();

    if matches.len() != 1 {
        return Err("signing key is not trusted".into());
    }

    let key = matches[0];
    let signature_bytes = decode_b64url(field(value, "signature")?)?;
    let message = field(value, "signedPayloadDigest")?.as_bytes();

    match algorithm {
        "ed25519" => verify_ed25519(&key.public_jwk, &signature_bytes, message),
        "ecdsa-p256-sha256" => verify_p256(&key.public_jwk, &signature_bytes, message),
        _ => Err("signature algorithm unsupported".into()),
    }
}

fn verify_ed25519(jwk: &Value, signature: &[u8], message: &[u8]) -> Result<(), String> {
    let x = decode_b64url(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or("Ed25519 JWK missing x")?,
    )?;
    let bytes: [u8; 32] = x.try_into().map_err(|_| "Ed25519 key length invalid")?;
    let public = EdKey::from_bytes(&bytes).map_err(|_| "Ed25519 key invalid")?;
    let sig = EdSignature::from_slice(signature).map_err(|_| "Ed25519 signature invalid")?;
    public
        .verify(message, &sig)
        .map_err(|_| "Ed25519 signature verification failed".into())
}

fn verify_p256(jwk: &Value, signature: &[u8], message: &[u8]) -> Result<(), String> {
    let x = decode_b64url(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or("P-256 JWK missing x")?,
    )?;
    let y = decode_b64url(
        jwk.get("y")
            .and_then(Value::as_str)
            .ok_or("P-256 JWK missing y")?,
    )?;
    if x.len() != 32 || y.len() != 32 {
        return Err("P-256 key coordinates invalid length".into());
    }
    let point =
        EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    let public = P256Key::from_encoded_point(&point).map_err(|_| "P-256 key invalid")?;

    // Try raw (r || s) format first, fall back to DER. Different cloud
    // providers serialize ECDSA signatures differently because of course
    // they do.
    let sig = P256Signature::from_slice(signature)
        .or_else(|_| P256Signature::from_der(signature))
        .map_err(|_| "P-256 signature invalid")?;

    public
        .verify(message, &sig)
        .map_err(|_| "P-256 signature verification failed".into())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("required field '{key}' missing"))
}

fn decode_b64url(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "base64url value invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey as EdSigning};
    use p256::ecdsa::SigningKey as P256Signing;

    fn make_bundle(_purpose: &str, keys_json: Value) -> TrustBundle {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "keys": keys_json
        }))
        .unwrap()
    }

    fn receipt(
        issuer: &str,
        key_id: &str,
        cap: &str,
        alg: &str,
        digest: &str,
        sig: String,
    ) -> Value {
        serde_json::json!({
            "issuer": issuer,
            "signingKeyId": key_id,
            "issuerCapabilityDigest": cap,
            "signatureAlgorithm": alg,
            "signedPayloadDigest": digest,
            "signature": sig
        })
    }

    #[test]
    fn ed25519_valid_signature_passes() {
        let cap = format!("sha256:{}", "a".repeat(64));
        let digest = format!("sha256:{}", "b".repeat(64));

        let signing = EdSigning::from_bytes(&[3u8; 32]);
        let pub_x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());

        let bundle = make_bundle(
            "runtime",
            serde_json::json!([{
                "purpose": "runtime",
                "issuer": "cloud",
                "signingKeyId": "ed-key",
                "issuerCapabilityDigest": cap,
                "signatureAlgorithm": "ed25519",
                "publicJwk": {"x": pub_x}
            }]),
        );

        let sig = URL_SAFE_NO_PAD.encode(signing.sign(digest.as_bytes()).to_bytes());
        let payload = receipt("cloud", "ed-key", &cap, "ed25519", &digest, sig);

        assert!(verify_signature(&bundle, "runtime", &payload).is_ok());
    }

    #[test]
    fn ed25519_tampered_digest_fails() {
        let cap = format!("sha256:{}", "a".repeat(64));
        let signing = EdSigning::from_bytes(&[3u8; 32]);
        let pub_x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());

        let bundle = make_bundle(
            "runtime",
            serde_json::json!([{
                "purpose": "runtime",
                "issuer": "cloud",
                "signingKeyId": "ed-key",
                "issuerCapabilityDigest": cap,
                "signatureAlgorithm": "ed25519",
                "publicJwk": {"x": pub_x}
            }]),
        );

        // Sign one digest, present a different one
        let real_digest = format!("sha256:{}", "b".repeat(64));
        let sig = URL_SAFE_NO_PAD.encode(signing.sign(real_digest.as_bytes()).to_bytes());
        let payload = receipt("cloud", "ed-key", &cap, "ed25519", "sha256:tampered", sig);

        assert!(verify_signature(&bundle, "runtime", &payload).is_err());
    }

    #[test]
    fn p256_valid_signature_passes() {
        let cap = format!("sha256:{}", "a".repeat(64));
        let digest = format!("sha256:{}", "b".repeat(64));

        let signing = P256Signing::from_bytes((&[4u8; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let px = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let py = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let bundle = make_bundle(
            "runtime",
            serde_json::json!([{
                "purpose": "runtime",
                "issuer": "cloud",
                "signingKeyId": "p-key",
                "issuerCapabilityDigest": cap,
                "signatureAlgorithm": "ecdsa-p256-sha256",
                "publicJwk": {"x": px, "y": py}
            }]),
        );

        let sig: p256::ecdsa::Signature = signing.sign(digest.as_bytes());
        let payload = receipt(
            "cloud",
            "p-key",
            &cap,
            "ecdsa-p256-sha256",
            &digest,
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        );

        assert!(verify_signature(&bundle, "runtime", &payload).is_ok());
    }

    #[test]
    fn wrong_purpose_is_rejected() {
        let cap = format!("sha256:{}", "a".repeat(64));
        let digest = format!("sha256:{}", "b".repeat(64));
        let signing = EdSigning::from_bytes(&[3u8; 32]);
        let pub_x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());

        let bundle = make_bundle(
            "billing",
            serde_json::json!([{
                "purpose": "billing",
                "issuer": "cloud",
                "signingKeyId": "ed-key",
                "issuerCapabilityDigest": cap,
                "signatureAlgorithm": "ed25519",
                "publicJwk": {"x": pub_x}
            }]),
        );

        let sig = URL_SAFE_NO_PAD.encode(signing.sign(digest.as_bytes()).to_bytes());
        let payload = receipt("cloud", "ed-key", &cap, "ed25519", &digest, sig);

        // Key is for "billing", but we're verifying "runtime" — should fail
        assert!(verify_signature(&bundle, "runtime", &payload).is_err());
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let bundle = make_bundle("runtime", serde_json::json!([]));
        let payload = receipt("x", "y", "z", "rsa-4096", "digest", "sig".into());
        assert!(verify_signature(&bundle, "runtime", &payload).is_err());
    }
}
