use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String, // Argon2 hash
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret_hash: Option<String>, // Optional for public clients
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub is_confidential: bool, // false for public clients (e.g., SPAs, mobile apps)
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,        // For PKCE
    pub code_challenge_method: Option<String>, // S256
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>, // Optional expiry
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Client {
    pub fn new(
        client_id: String,
        client_secret_hash: Option<String>,
        name: String,
        redirect_uris: Vec<String>,
        scopes: Vec<String>,
        is_confidential: bool,
    ) -> Self {
        Self {
            client_id,
            client_secret_hash,
            name,
            redirect_uris,
            scopes,
            is_confidential,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
        Argon2,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_user_creation() {
        let password = "test_password123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            password_hash.clone(),
        );

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, password_hash);
        assert_eq!(user.created_at, user.updated_at);
    }

    #[test]
    fn test_password_verification() {
        let password = "secure_password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Verify correct password
        let parsed_hash = PasswordHash::new(&password_hash).unwrap();
        assert!(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok());

        // Verify incorrect password
        assert!(argon2
            .verify_password(b"wrong_password", &parsed_hash)
            .is_err());
    }

    #[test]
    fn test_client_creation() {
        let client_id = "test_client_id".to_string();
        let name = "Test Application".to_string();
        let redirect_uris = vec!["http://localhost:3001/callback".to_string()];
        let scopes = vec!["read".to_string(), "write".to_string()];

        // Test confidential client (with secret)
        let confidential_client = Client::new(
            client_id.clone(),
            Some("hashed_secret".to_string()),
            name.clone(),
            redirect_uris.clone(),
            scopes.clone(),
            true,
        );

        assert_eq!(confidential_client.client_id, client_id);
        assert!(confidential_client.client_secret_hash.is_some());
        assert!(confidential_client.is_confidential);
        assert_eq!(confidential_client.redirect_uris, redirect_uris);

        // Test public client (no secret)
        let public_client = Client::new(
            "public_client".to_string(),
            None,
            "Public App".to_string(),
            redirect_uris.clone(),
            scopes.clone(),
            false,
        );

        assert!(public_client.client_secret_hash.is_none());
        assert!(!public_client.is_confidential);
    }

    #[test]
    fn test_authorization_code_with_pkce() {
        let code = AuthorizationCode {
            code: "auth_code_123".to_string(),
            client_id: "client_123".to_string(),
            user_id: Uuid::new_v4(),
            redirect_uri: "http://localhost:3001/callback".to_string(),
            scopes: vec!["read".to_string()],
            code_challenge: Some("challenge_string".to_string()),
            code_challenge_method: Some("S256".to_string()),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            created_at: Utc::now(),
        };

        assert!(code.code_challenge.is_some());
        assert_eq!(code.code_challenge_method.as_deref(), Some("S256"));
    }
}
