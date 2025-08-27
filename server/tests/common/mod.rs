use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestClaims {
    pub sub: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

/// Generate a valid JWT token for testing
pub fn generate_test_token() -> String {
    generate_test_token_with_options("test-user-id", "test-client", vec!["read", "write"], false)
}

/// Generate a JWT token with custom options
pub fn generate_test_token_with_options(
    user_id: &str,
    client_id: &str,
    scopes: Vec<&str>,
    expired: bool,
) -> String {
    let now = Utc::now();
    let exp = if expired {
        (now - Duration::hours(2)).timestamp()
    } else {
        (now + Duration::hours(1)).timestamp()
    };

    // Ensure user_id is a valid UUID string
    let user_id = if let Ok(uuid) = Uuid::parse_str(user_id) {
        uuid.to_string()
    } else {
        // Use a default UUID if the provided one is invalid
        Uuid::new_v4().to_string()
    };

    let claims = TestClaims {
        sub: user_id,
        client_id: client_id.to_string(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        exp,
        iat: now.timestamp(),
    };

    // Use the same secret as the test environment
    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "development_secret_change_in_production".to_string());

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}

/// Create an Authorization header value with a Bearer token
#[allow(dead_code)]
pub fn auth_header(token: &str) -> (&'static str, String) {
    ("authorization", format!("Bearer {}", token))
}
