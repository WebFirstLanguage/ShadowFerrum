use super::models::{AuthorizationCode, RefreshToken};
use super::storage::OAuthStorage;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid request")]
    InvalidRequest,

    #[error("Invalid client")]
    InvalidClient,

    #[error("Invalid grant")]
    InvalidGrant,

    #[error("Unauthorized client")]
    UnauthorizedClient,

    #[error("Unsupported grant type")]
    UnsupportedGrantType,

    #[error("Invalid scope")]
    InvalidScope,

    #[error("Invalid redirect URI")]
    InvalidRedirectUri,

    #[error("Invalid PKCE verifier")]
    InvalidPkceVerifier,

    #[error("Storage error: {0}")]
    StorageError(#[from] super::storage::OAuthStorageError),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub client_id: String,
    pub scopes: Vec<String>,
    pub exp: i64, // Expiration time
    pub iat: i64, // Issued at
}

pub struct OAuthService {
    storage: Arc<OAuthStorage>,
    jwt_secret: String,
}

impl OAuthService {
    pub fn new(storage: Arc<OAuthStorage>) -> Self {
        // In production, this should be loaded from secure configuration
        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "development_secret_change_in_production".to_string());

        Self {
            storage,
            jwt_secret,
        }
    }

    pub fn generate_random_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn verify_pkce_challenge(verifier: &str, challenge: &str, method: &str) -> bool {
        match method {
            "S256" => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let result = hasher.finalize();
                let computed_challenge = URL_SAFE_NO_PAD.encode(result);
                computed_challenge == challenge
            }
            "plain" => verifier == challenge,
            _ => false,
        }
    }

    pub async fn create_authorization_code(
        &self,
        client_id: String,
        user_id: Uuid,
        redirect_uri: String,
        scopes: Vec<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<String> {
        let code = Self::generate_random_token();

        let authorization_code = AuthorizationCode {
            code: code.clone(),
            client_id,
            user_id,
            redirect_uri,
            scopes,
            code_challenge,
            code_challenge_method,
            expires_at: Utc::now() + Duration::minutes(10),
            created_at: Utc::now(),
        };

        self.storage
            .store_authorization_code(authorization_code)
            .await?;

        Ok(code)
    }

    pub async fn exchange_authorization_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<(String, String)> {
        // Get and remove the authorization code
        let auth_code = self.storage.get_and_remove_authorization_code(code).await?;

        // Validate the authorization code
        if auth_code.client_id != client_id {
            return Err(AuthError::InvalidClient);
        }

        if auth_code.redirect_uri != redirect_uri {
            return Err(AuthError::InvalidRedirectUri);
        }

        if Utc::now() > auth_code.expires_at {
            return Err(AuthError::InvalidGrant);
        }

        // Verify PKCE if present
        if let (Some(challenge), Some(method)) =
            (&auth_code.code_challenge, &auth_code.code_challenge_method)
        {
            let verifier = code_verifier.ok_or(AuthError::InvalidPkceVerifier)?;
            if !Self::verify_pkce_challenge(verifier, challenge, method) {
                return Err(AuthError::InvalidPkceVerifier);
            }
        } else if code_verifier.is_some() {
            // Verifier provided but no challenge stored
            return Err(AuthError::InvalidPkceVerifier);
        }

        // Create access token
        let access_token = self.create_access_token(
            auth_code.user_id,
            auth_code.client_id.clone(),
            auth_code.scopes.clone(),
        )?;

        // Create refresh token
        let refresh_token = Self::generate_random_token();
        let refresh_token_model = RefreshToken {
            token: refresh_token.clone(),
            client_id: auth_code.client_id,
            user_id: auth_code.user_id,
            scopes: auth_code.scopes,
            expires_at: Some(Utc::now() + Duration::days(30)),
            created_at: Utc::now(),
        };

        self.storage
            .store_refresh_token(refresh_token_model)
            .await?;

        Ok((access_token, refresh_token))
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<String> {
        let token = self.storage.get_refresh_token(refresh_token).await?;

        if token.client_id != client_id {
            return Err(AuthError::InvalidClient);
        }

        if let Some(expires_at) = token.expires_at {
            if Utc::now() > expires_at {
                self.storage.remove_refresh_token(refresh_token).await?;
                return Err(AuthError::InvalidGrant);
            }
        }

        // Create new access token
        let access_token =
            self.create_access_token(token.user_id, token.client_id, token.scopes)?;

        Ok(access_token)
    }

    fn create_access_token(
        &self,
        user_id: Uuid,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let expiration = now + Duration::hours(1);

        let claims = Claims {
            sub: user_id.to_string(),
            client_id,
            scopes,
            exp: expiration.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )?;

        Ok(token)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )?;

        Ok(token_data.claims)
    }

    pub async fn validate_client_redirect_uri(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<()> {
        let client = self.storage.get_client(client_id).await?;

        if !client.redirect_uris.contains(&redirect_uri.to_string()) {
            return Err(AuthError::InvalidRedirectUri);
        }

        Ok(())
    }

    pub async fn validate_scopes(
        &self,
        client_id: &str,
        requested_scopes: &[String],
    ) -> Result<()> {
        let client = self.storage.get_client(client_id).await?;

        for scope in requested_scopes {
            if !client.scopes.contains(scope) {
                return Err(AuthError::InvalidScope);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn setup_test_service() -> (OAuthService, Arc<OAuthStorage>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(
            OAuthStorage::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let service = OAuthService::new(Arc::clone(&storage));
        (service, storage, temp_dir)
    }

    #[test]
    fn test_pkce_verification() {
        let verifier = "test_verifier_string";

        // Test S256 method
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let result = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(result);

        assert!(OAuthService::verify_pkce_challenge(
            verifier, &challenge, "S256"
        ));

        assert!(!OAuthService::verify_pkce_challenge(
            "wrong_verifier",
            &challenge,
            "S256"
        ));

        // Test plain method
        assert!(OAuthService::verify_pkce_challenge(
            "plain_verifier",
            "plain_verifier",
            "plain"
        ));
    }

    #[tokio::test]
    async fn test_authorization_code_flow() {
        let (service, storage, _temp) = setup_test_service().await;

        // Create a user and client
        let user = storage
            .create_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "password",
            )
            .await
            .unwrap();

        let client = storage
            .create_client(
                "test_client".to_string(),
                Some("secret"),
                "Test App".to_string(),
                vec!["http://localhost:3001/callback".to_string()],
                vec!["read".to_string(), "write".to_string()],
            )
            .await
            .unwrap();

        // Create authorization code
        let code = service
            .create_authorization_code(
                client.client_id.clone(),
                user.id,
                "http://localhost:3001/callback".to_string(),
                vec!["read".to_string()],
                None,
                None,
            )
            .await
            .unwrap();

        // Exchange code for tokens
        let (access_token, refresh_token) = service
            .exchange_authorization_code(
                &code,
                &client.client_id,
                "http://localhost:3001/callback",
                None,
            )
            .await
            .unwrap();

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());

        // Verify the access token
        let claims = service.verify_access_token(&access_token).unwrap();
        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.client_id, client.client_id);
        assert_eq!(claims.scopes, vec!["read".to_string()]);

        // Try to use the code again (should fail)
        let result = service
            .exchange_authorization_code(
                &code,
                &client.client_id,
                "http://localhost:3001/callback",
                None,
            )
            .await;

        assert!(matches!(result, Err(AuthError::StorageError(_))));
    }

    #[tokio::test]
    async fn test_authorization_code_flow_with_pkce() {
        let (service, storage, _temp) = setup_test_service().await;

        let user = storage
            .create_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "password",
            )
            .await
            .unwrap();

        let client = storage
            .create_client(
                "public_client".to_string(),
                None, // Public client
                "Public App".to_string(),
                vec!["myapp://callback".to_string()],
                vec!["read".to_string()],
            )
            .await
            .unwrap();

        // Generate PKCE challenge
        let verifier = "test_verifier_43_chars_minimum_required_for_pkce";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let result = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(result);

        // Create authorization code with PKCE
        let code = service
            .create_authorization_code(
                client.client_id.clone(),
                user.id,
                "myapp://callback".to_string(),
                vec!["read".to_string()],
                Some(challenge),
                Some("S256".to_string()),
            )
            .await
            .unwrap();

        // Exchange code with correct verifier
        let (access_token, refresh_token) = service
            .exchange_authorization_code(
                &code,
                &client.client_id,
                "myapp://callback",
                Some(verifier),
            )
            .await
            .unwrap();

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_refresh_token_flow() {
        let (service, storage, _temp) = setup_test_service().await;

        let user = storage
            .create_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "password",
            )
            .await
            .unwrap();

        let client = storage
            .create_client(
                "test_client".to_string(),
                Some("secret"),
                "Test App".to_string(),
                vec!["http://localhost:3001/callback".to_string()],
                vec!["read".to_string()],
            )
            .await
            .unwrap();

        // Create authorization code and exchange for tokens
        let code = service
            .create_authorization_code(
                client.client_id.clone(),
                user.id,
                "http://localhost:3001/callback".to_string(),
                vec!["read".to_string()],
                None,
                None,
            )
            .await
            .unwrap();

        let (_access_token, refresh_token) = service
            .exchange_authorization_code(
                &code,
                &client.client_id,
                "http://localhost:3001/callback",
                None,
            )
            .await
            .unwrap();

        // Use refresh token to get new access token
        let new_access_token = service
            .refresh_access_token(&refresh_token, &client.client_id)
            .await
            .unwrap();

        // Verify the new access token
        let claims = service.verify_access_token(&new_access_token).unwrap();
        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.client_id, client.client_id);

        // Try to refresh with wrong client_id
        let result = service
            .refresh_access_token(&refresh_token, "wrong_client")
            .await;
        assert!(matches!(result, Err(AuthError::InvalidClient)));
    }

    #[tokio::test]
    async fn test_validate_redirect_uri() {
        let (_service, storage, _temp) = setup_test_service().await;
        let service = OAuthService::new(Arc::clone(&storage));

        storage
            .create_client(
                "test_client".to_string(),
                Some("secret"),
                "Test App".to_string(),
                vec![
                    "http://localhost:3001/callback".to_string(),
                    "http://localhost:3002/auth".to_string(),
                ],
                vec!["read".to_string()],
            )
            .await
            .unwrap();

        // Valid redirect URI
        service
            .validate_client_redirect_uri("test_client", "http://localhost:3001/callback")
            .await
            .unwrap();

        // Invalid redirect URI
        let result = service
            .validate_client_redirect_uri("test_client", "http://evil.com/callback")
            .await;
        assert!(matches!(result, Err(AuthError::InvalidRedirectUri)));
    }

    #[tokio::test]
    async fn test_validate_scopes() {
        let (_service, storage, _temp) = setup_test_service().await;
        let service = OAuthService::new(Arc::clone(&storage));

        storage
            .create_client(
                "test_client".to_string(),
                Some("secret"),
                "Test App".to_string(),
                vec!["http://localhost:3001/callback".to_string()],
                vec!["read".to_string(), "write".to_string()],
            )
            .await
            .unwrap();

        // Valid scopes
        service
            .validate_scopes("test_client", &["read".to_string()])
            .await
            .unwrap();

        service
            .validate_scopes("test_client", &["read".to_string(), "write".to_string()])
            .await
            .unwrap();

        // Invalid scope
        let result = service
            .validate_scopes("test_client", &["admin".to_string()])
            .await;
        assert!(matches!(result, Err(AuthError::InvalidScope)));
    }
}
