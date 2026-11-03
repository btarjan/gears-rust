//! `jwt::encode` must assemble the JWS over a facade signature. A poisoned
//! jsonwebtoken provider proves no jsonwebtoken signer or verifier runs.
#![cfg(feature = "jwt")]

use std::sync::atomic::{AtomicUsize, Ordering};

use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtVerifier};
use jsonwebtoken::signature::Verifier;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde_json::{Value, json};
use toolkit_security::crypto::signature::EcdsaP256KeyPair;

struct ForbiddenVerifier(Algorithm);

impl Verifier<Vec<u8>> for ForbiddenVerifier {
    fn verify(&self, _: &[u8], _: &Vec<u8>) -> Result<(), jsonwebtoken::signature::Error> {
        panic!("claim-validation pass must never execute a second crypto backend")
    }
}

impl JwtVerifier for ForbiddenVerifier {
    fn algorithm(&self) -> Algorithm {
        self.0
    }
}

static CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);

// The claims pass constructs a verifier (and never calls it); a signer must
// never be constructed at all. The counter proves this provider is the one
// jsonwebtoken consulted, not a silently ignored install.
static POISON: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| panic!("encode must not construct a jsonwebtoken signer"),
    verifier_factory: |algorithm, _| {
        CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ForbiddenVerifier(*algorithm)))
    },
    jwk_utils: JwkUtils::new_unimplemented(),
};

#[test]
fn encode_and_decode_run_entirely_through_the_facade() {
    POISON.install_default().unwrap();
    let key = EcdsaP256KeyPair::generate().unwrap();
    let claims = json!({"sub": "svc", "iss": "issuer", "aud": "audience",
        "exp": jsonwebtoken::get_current_timestamp() + 60});
    let token =
        toolkit_security::jwt::encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["issuer"]);
    validation.set_audience(&["audience"]);
    let decoded = toolkit_security::jwt::decode::<Value>(
        &token,
        &DecodingKey::from_ec_der(key.public_key()),
        &validation,
    )
    .unwrap();
    assert_eq!(decoded.claims, claims);
    assert_eq!(CONSTRUCTIONS.load(Ordering::SeqCst), 1);
}
