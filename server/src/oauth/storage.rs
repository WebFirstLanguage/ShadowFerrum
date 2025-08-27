use super::models::{AuthorizationCode, Client, RefreshToken, User};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum OAuthStorageError {
    #[error("User not found")]
    UserNotFound,

    #[error("Client not found")]
    ClientNotFound,

    #[error("Authorization code not found")]
    AuthorizationCodeNotFound,

    #[error("Refresh token not found")]
    RefreshTokenNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Client already exists")]
    ClientAlreadyExists,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Password hash error")]
    PasswordHashError,
}

pub type Result<T> = std::result::Result<T, OAuthStorageError>;

pub struct OAuthStorage {
    data_root: PathBuf,
    users_cache: Arc<RwLock<HashMap<String, User>>>, // username -> User
    clients_cache: Arc<RwLock<HashMap<String, Client>>>, // client_id -> Client
    auth_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>, // code -> AuthorizationCode
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>, // token -> RefreshToken
}

impl OAuthStorage {
    pub async fn new(data_root: PathBuf) -> Result<Self> {
        // Create OAuth-specific directories
        fs::create_dir_all(data_root.join("users")).await?;
        fs::create_dir_all(data_root.join("clients")).await?;

        let storage = Self {
            data_root,
            users_cache: Arc::new(RwLock::new(HashMap::new())),
            clients_cache: Arc::new(RwLock::new(HashMap::new())),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing users and clients
        storage.load_users().await?;
        storage.load_clients().await?;

        Ok(storage)
    }

    async fn load_users(&self) -> Result<()> {
        let users_dir = self.data_root.join("users");

        if !users_dir.exists() {
            return Ok(());
        }

        let mut dir = fs::read_dir(users_dir).await?;
        let mut users = self.users_cache.write().await;

        while let Some(entry) = dir.next_entry().await? {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read(entry.path()).await?;
                let user: User = serde_json::from_slice(&content)?;
                users.insert(user.username.clone(), user);
            }
        }

        Ok(())
    }

    async fn load_clients(&self) -> Result<()> {
        let clients_dir = self.data_root.join("clients");

        if !clients_dir.exists() {
            return Ok(());
        }

        let mut dir = fs::read_dir(clients_dir).await?;
        let mut clients = self.clients_cache.write().await;

        while let Some(entry) = dir.next_entry().await? {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read(entry.path()).await?;
                let client: Client = serde_json::from_slice(&content)?;
                clients.insert(client.client_id.clone(), client);
            }
        }

        Ok(())
    }

    pub async fn create_user(
        &self,
        username: String,
        email: String,
        password: &str,
    ) -> Result<User> {
        // Check if user already exists
        {
            let users = self.users_cache.read().await;
            if users.contains_key(&username) {
                return Err(OAuthStorageError::UserAlreadyExists);
            }
        }

        // Hash the password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| OAuthStorageError::PasswordHashError)?
            .to_string();

        let user = User::new(username.clone(), email, password_hash);

        // Save to disk
        let user_path = self
            .data_root
            .join("users")
            .join(format!("{}.json", user.id));
        let json = serde_json::to_vec_pretty(&user)?;
        fs::write(user_path, json).await?;

        // Add to cache
        let mut users = self.users_cache.write().await;
        users.insert(username, user.clone());

        Ok(user)
    }

    pub async fn verify_user_password(&self, username: &str, password: &str) -> Result<User> {
        let users = self.users_cache.read().await;
        let user = users
            .get(username)
            .ok_or(OAuthStorageError::UserNotFound)?
            .clone();

        // Verify password
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| OAuthStorageError::PasswordHashError)?;

        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| OAuthStorageError::InvalidCredentials)?;

        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let users = self.users_cache.read().await;
        users
            .get(username)
            .cloned()
            .ok_or(OAuthStorageError::UserNotFound)
    }

    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<User> {
        let users = self.users_cache.read().await;
        users
            .values()
            .find(|u| u.id == *user_id)
            .cloned()
            .ok_or(OAuthStorageError::UserNotFound)
    }

    pub async fn create_client(
        &self,
        client_id: String,
        client_secret: Option<&str>,
        name: String,
        redirect_uris: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<Client> {
        // Check if client already exists
        {
            let clients = self.clients_cache.read().await;
            if clients.contains_key(&client_id) {
                return Err(OAuthStorageError::ClientAlreadyExists);
            }
        }

        // Hash client secret if provided
        let client_secret_hash = if let Some(secret) = client_secret {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            Some(
                argon2
                    .hash_password(secret.as_bytes(), &salt)
                    .map_err(|_| OAuthStorageError::PasswordHashError)?
                    .to_string(),
            )
        } else {
            None
        };

        let is_confidential = client_secret.is_some();
        let client = Client::new(
            client_id.clone(),
            client_secret_hash,
            name,
            redirect_uris,
            scopes,
            is_confidential,
        );

        // Save to disk
        let client_path = self
            .data_root
            .join("clients")
            .join(format!("{}.json", client.client_id));
        let json = serde_json::to_vec_pretty(&client)?;
        fs::write(client_path, json).await?;

        // Add to cache
        let mut clients = self.clients_cache.write().await;
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    pub async fn get_client(&self, client_id: &str) -> Result<Client> {
        let clients = self.clients_cache.read().await;
        clients
            .get(client_id)
            .cloned()
            .ok_or(OAuthStorageError::ClientNotFound)
    }

    pub async fn verify_client_secret(&self, client_id: &str, client_secret: &str) -> Result<()> {
        let client = self.get_client(client_id).await?;

        if let Some(secret_hash) = &client.client_secret_hash {
            let parsed_hash =
                PasswordHash::new(secret_hash).map_err(|_| OAuthStorageError::PasswordHashError)?;

            let argon2 = Argon2::default();
            argon2
                .verify_password(client_secret.as_bytes(), &parsed_hash)
                .map_err(|_| OAuthStorageError::InvalidCredentials)?;

            Ok(())
        } else {
            Err(OAuthStorageError::InvalidCredentials)
        }
    }

    pub async fn store_authorization_code(&self, code: AuthorizationCode) -> Result<()> {
        let mut codes = self.auth_codes.write().await;
        codes.insert(code.code.clone(), code);
        Ok(())
    }

    pub async fn get_and_remove_authorization_code(&self, code: &str) -> Result<AuthorizationCode> {
        let mut codes = self.auth_codes.write().await;
        codes
            .remove(code)
            .ok_or(OAuthStorageError::AuthorizationCodeNotFound)
    }

    pub async fn store_refresh_token(&self, token: RefreshToken) -> Result<()> {
        let mut tokens = self.refresh_tokens.write().await;
        tokens.insert(token.token.clone(), token);
        Ok(())
    }

    pub async fn get_refresh_token(&self, token: &str) -> Result<RefreshToken> {
        let tokens = self.refresh_tokens.read().await;
        tokens
            .get(token)
            .cloned()
            .ok_or(OAuthStorageError::RefreshTokenNotFound)
    }

    pub async fn remove_refresh_token(&self, token: &str) -> Result<()> {
        let mut tokens = self.refresh_tokens.write().await;
        tokens.remove(token);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    async fn setup_test_storage() -> (OAuthStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = OAuthStorage::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();
        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_create_and_verify_user() {
        let (storage, _temp) = setup_test_storage().await;

        // Create user
        let user = storage
            .create_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "password123",
            )
            .await
            .unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");

        // Verify correct password
        let verified_user = storage
            .verify_user_password("testuser", "password123")
            .await
            .unwrap();
        assert_eq!(verified_user.id, user.id);

        // Verify incorrect password
        let result = storage
            .verify_user_password("testuser", "wrong_password")
            .await;
        assert!(matches!(result, Err(OAuthStorageError::InvalidCredentials)));

        // Verify non-existent user
        let result = storage
            .verify_user_password("nonexistent", "password")
            .await;
        assert!(matches!(result, Err(OAuthStorageError::UserNotFound)));
    }

    #[tokio::test]
    async fn test_duplicate_user_creation() {
        let (storage, _temp) = setup_test_storage().await;

        storage
            .create_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "password123",
            )
            .await
            .unwrap();

        // Try to create user with same username
        let result = storage
            .create_user(
                "testuser".to_string(),
                "other@example.com".to_string(),
                "password456",
            )
            .await;

        assert!(matches!(result, Err(OAuthStorageError::UserAlreadyExists)));
    }

    #[tokio::test]
    async fn test_create_and_get_client() {
        let (storage, _temp) = setup_test_storage().await;

        // Create confidential client
        let client = storage
            .create_client(
                "test_client".to_string(),
                Some("client_secret"),
                "Test App".to_string(),
                vec!["http://localhost:3001/callback".to_string()],
                vec!["read".to_string(), "write".to_string()],
            )
            .await
            .unwrap();

        assert_eq!(client.client_id, "test_client");
        assert!(client.is_confidential);
        assert!(client.client_secret_hash.is_some());

        // Get client
        let retrieved_client = storage.get_client("test_client").await.unwrap();
        assert_eq!(retrieved_client.client_id, client.client_id);
        assert_eq!(retrieved_client.redirect_uris, client.redirect_uris);

        // Verify client secret
        storage
            .verify_client_secret("test_client", "client_secret")
            .await
            .unwrap();

        // Verify wrong secret
        let result = storage
            .verify_client_secret("test_client", "wrong_secret")
            .await;
        assert!(matches!(result, Err(OAuthStorageError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_public_client() {
        let (storage, _temp) = setup_test_storage().await;

        // Create public client (no secret)
        let client = storage
            .create_client(
                "public_client".to_string(),
                None,
                "Public App".to_string(),
                vec!["myapp://callback".to_string()],
                vec!["read".to_string()],
            )
            .await
            .unwrap();

        assert!(!client.is_confidential);
        assert!(client.client_secret_hash.is_none());

        // Verify secret on public client should fail
        let result = storage
            .verify_client_secret("public_client", "any_secret")
            .await;
        assert!(matches!(result, Err(OAuthStorageError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_authorization_code_storage() {
        let (storage, _temp) = setup_test_storage().await;

        let code = AuthorizationCode {
            code: "auth_code_123".to_string(),
            client_id: "client_123".to_string(),
            user_id: Uuid::new_v4(),
            redirect_uri: "http://localhost:3001/callback".to_string(),
            scopes: vec!["read".to_string()],
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            created_at: Utc::now(),
        };

        storage
            .store_authorization_code(code.clone())
            .await
            .unwrap();

        // Get and remove code
        let retrieved_code = storage
            .get_and_remove_authorization_code("auth_code_123")
            .await
            .unwrap();
        assert_eq!(retrieved_code.code, code.code);
        assert_eq!(retrieved_code.client_id, code.client_id);

        // Try to get code again (should fail as it was removed)
        let result = storage
            .get_and_remove_authorization_code("auth_code_123")
            .await;
        assert!(matches!(
            result,
            Err(OAuthStorageError::AuthorizationCodeNotFound)
        ));
    }

    #[tokio::test]
    async fn test_refresh_token_storage() {
        let (storage, _temp) = setup_test_storage().await;

        let token = RefreshToken {
            token: "refresh_token_123".to_string(),
            client_id: "client_123".to_string(),
            user_id: Uuid::new_v4(),
            scopes: vec!["read".to_string()],
            expires_at: None,
            created_at: Utc::now(),
        };

        storage.store_refresh_token(token.clone()).await.unwrap();

        // Get token
        let retrieved_token = storage
            .get_refresh_token("refresh_token_123")
            .await
            .unwrap();
        assert_eq!(retrieved_token.token, token.token);
        assert_eq!(retrieved_token.client_id, token.client_id);

        // Remove token
        storage
            .remove_refresh_token("refresh_token_123")
            .await
            .unwrap();

        // Try to get token again
        let result = storage.get_refresh_token("refresh_token_123").await;
        assert!(matches!(
            result,
            Err(OAuthStorageError::RefreshTokenNotFound)
        ));
    }

    #[tokio::test]
    async fn test_persistence_across_instances() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Create first instance and add user/client
        {
            let storage = OAuthStorage::new(path.clone()).await.unwrap();

            storage
                .create_user(
                    "persistuser".to_string(),
                    "persist@example.com".to_string(),
                    "password",
                )
                .await
                .unwrap();

            storage
                .create_client(
                    "persist_client".to_string(),
                    Some("secret"),
                    "Persist App".to_string(),
                    vec!["http://localhost/callback".to_string()],
                    vec!["read".to_string()],
                )
                .await
                .unwrap();
        }

        // Create second instance and verify data persisted
        {
            let storage = OAuthStorage::new(path).await.unwrap();

            let user = storage.get_user_by_username("persistuser").await.unwrap();
            assert_eq!(user.username, "persistuser");

            let client = storage.get_client("persist_client").await.unwrap();
            assert_eq!(client.client_id, "persist_client");
        }
    }
}
