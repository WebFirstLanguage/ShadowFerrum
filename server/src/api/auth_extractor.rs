use crate::oauth::auth::Claims;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Vec<String>,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: Uuid::parse_str(&claims.sub).unwrap_or_default(),
            client_id: claims.client_id,
            scopes: claims.scopes,
        }
    }
}

#[async_trait]
impl FromRequestParts<crate::api::AppState> for AuthenticatedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::api::AppState,
    ) -> Result<Self, Self::Rejection> {
        // Get Authorization header
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Extract Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Verify token and get claims using the state directly
        let claims = state
            .oauth_service
            .verify_access_token(token)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Convert claims to AuthenticatedUser
        Ok(AuthenticatedUser::from(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::oauth::auth::OAuthService;
    use crate::oauth::storage::OAuthStorage;
    use crate::storage::StorageEngine;
    use axum::http::Request;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::sync::Arc;
    use tempfile::TempDir;

    async fn setup_test_state() -> (AppState, TempDir, String) {
        let temp_dir = TempDir::new().unwrap();
        let data_root = temp_dir.path().to_path_buf();

        let storage = Arc::new(StorageEngine::new(data_root.clone()).await.unwrap());
        let oauth_storage = Arc::new(OAuthStorage::new(data_root.clone()).await.unwrap());

        // Use a test JWT secret
        std::env::set_var("JWT_SECRET", "test_secret_for_unit_tests");
        let oauth_service = Arc::new(OAuthService::new(oauth_storage.clone()));

        let state = AppState {
            storage,
            oauth_storage,
            oauth_service,
        };

        (state, temp_dir, "test_secret_for_unit_tests".to_string())
    }

    fn create_test_token(secret: &str, expired: bool, wrong_secret: bool) -> String {
        let now = Utc::now();
        let exp = if expired {
            (now - Duration::hours(2)).timestamp()
        } else {
            (now + Duration::hours(1)).timestamp()
        };

        let claims = Claims {
            sub: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            client_id: "test_client".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            exp,
            iat: now.timestamp(),
        };

        let secret_to_use = if wrong_secret { "wrong_secret" } else { secret };

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret_to_use.as_ref()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_valid_jwt_extraction() {
        let (state, _temp, secret) = setup_test_state().await;
        let token = create_test_token(&secret, false, false);

        // Test by directly extracting from request parts
        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();

        // Extract AuthenticatedUser directly
        let user = AuthenticatedUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap();

        assert_eq!(
            user.user_id.to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(user.client_id, "test_client");
        assert_eq!(user.scopes, vec!["read", "write"]);
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let (state, _temp, _) = setup_test_state().await;

        let request = Request::builder().uri("/test").body(()).unwrap();

        let (mut parts, _) = request.into_parts();

        // Try to extract AuthenticatedUser without auth header
        let result = AuthenticatedUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_malformed_authorization_header() {
        let (state, _temp, _) = setup_test_state().await;

        // Test with missing "Bearer " prefix
        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "invalid_token")
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let result = AuthenticatedUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);

        // Test with wrong auth scheme
        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let result = AuthenticatedUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_expired_jwt() {
        let (state, _temp, secret) = setup_test_state().await;
        let expired_token = create_test_token(&secret, true, false);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", expired_token))
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let result = AuthenticatedUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_with_wrong_signature() {
        let (state, _temp, secret) = setup_test_state().await;
        let wrong_sig_token = create_test_token(&secret, false, true);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", wrong_sig_token))
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let result = AuthenticatedUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authenticated_user_extraction() {
        let (state, _temp, secret) = setup_test_state().await;
        let token = create_test_token(&secret, false, false);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let user = AuthenticatedUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap();

        // Verify the extracted data
        assert_eq!(
            user.user_id.to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(user.client_id, "test_client");
        assert_eq!(user.scopes, vec!["read", "write"]);
    }
}
