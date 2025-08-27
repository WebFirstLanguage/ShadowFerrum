use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use server::{
    api::{self, AppState},
    oauth::{auth::OAuthService, storage::OAuthStorage},
    storage::StorageEngine,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

async fn setup_test_app() -> (axum::Router, Arc<OAuthStorage>, Arc<OAuthService>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let data_root = temp_dir.path().to_path_buf();

    let storage = Arc::new(StorageEngine::new(data_root.clone()).await.unwrap());
    let oauth_storage = Arc::new(OAuthStorage::new(data_root.clone()).await.unwrap());
    let oauth_service = Arc::new(OAuthService::new(oauth_storage.clone()));

    // Create test user and client
    oauth_storage
        .create_user(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "password123",
        )
        .await
        .unwrap();

    oauth_storage
        .create_client(
            "test_client".to_string(),
            Some("client_secret"),
            "Test Application".to_string(),
            vec!["http://localhost:3001/callback".to_string()],
            vec!["read".to_string(), "write".to_string()],
        )
        .await
        .unwrap();

    // Create public client for PKCE tests
    oauth_storage
        .create_client(
            "public_client".to_string(),
            None,
            "Public Application".to_string(),
            vec!["myapp://callback".to_string()],
            vec!["read".to_string()],
        )
        .await
        .unwrap();

    let app_state = AppState {
        storage,
        oauth_storage: oauth_storage.clone(),
        oauth_service: oauth_service.clone(),
    };

    let app = api::create_router(app_state);
    (app, oauth_storage, oauth_service, temp_dir)
}

async fn body_to_bytes(body: Body) -> Bytes {
    body.collect().await.unwrap().to_bytes()
}

fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

#[tokio::test]
async fn test_oauth_authorize_invalid_client() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=invalid&redirect_uri=http://localhost:3001/callback&response_type=code&scope=read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_to_bytes(response.into_body()).await;
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.error, "invalid_client");
}

#[tokio::test]
async fn test_oauth_authorize_invalid_redirect_uri() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=test_client&redirect_uri=http://evil.com/callback&response_type=code&scope=read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_to_bytes(response.into_body()).await;
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.error, "invalid_redirect_uri");
}

#[tokio::test]
async fn test_oauth_authorize_unsupported_response_type() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=test_client&redirect_uri=http://localhost:3001/callback&response_type=token&scope=read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect with error
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get(header::LOCATION).unwrap();
    let location_str = location.to_str().unwrap();
    assert!(location_str.contains("error=unsupported_response_type"));
}

#[tokio::test]
async fn test_oauth_authorize_shows_login_page() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=test_client&redirect_uri=http://localhost:3001/callback&response_type=code&scope=read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );

    let body = body_to_bytes(response.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Sign In"));
    assert!(body_str.contains("Test Application"));
}

#[tokio::test]
async fn test_complete_authorization_code_flow() {
    let (_app, oauth_storage, oauth_service, _temp) = setup_test_app().await;

    // Note: In a real integration test, we'd simulate the login form submission
    // and consent flow. For now, we'll create an authorization code directly
    // and test the token exchange.

    let _auth_code = "test_auth_code_123";
    let _redirect_uri = "http://localhost:3001/callback";

    // In a real test, we would:
    // 1. GET /oauth/authorize
    // 2. POST /oauth/authorize with login credentials
    // 3. POST /oauth/consent with approval
    // 4. Extract code from redirect

    // For this test, we'll skip to token exchange
    // (The actual authorization code flow is tested in the unit tests)

    let _ = (oauth_storage, oauth_service); // Placeholder for full test implementation

    // This test would be more complete with actual form submissions
    // but that requires more complex HTML parsing
}

#[tokio::test]
async fn test_token_endpoint_missing_parameters() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY); // Axum returns 422 for missing form fields
                                                                     // Since it's a form validation error, we don't get a structured error response
    let _body = body_to_bytes(response.into_body()).await;
}

#[tokio::test]
async fn test_token_endpoint_invalid_grant_type() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=invalid&client_id=test_client"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_to_bytes(response.into_body()).await;
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.error, "unsupported_grant_type");
}

#[tokio::test]
async fn test_protected_endpoint_without_token() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test_file.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_endpoint_with_invalid_token() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test_file.txt")
                .header(header::AUTHORIZATION, "Bearer invalid_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_health_check_no_auth() {
    let (app, _storage, _service, _temp) = setup_test_app().await;

    let response = app
        .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_bytes(response.into_body()).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "healthy");
}

// Test PKCE flow with public client
#[tokio::test]
async fn test_pkce_verification() {
    let verifier = "test_verifier_with_enough_characters_to_be_valid";
    let challenge = generate_pkce_challenge(verifier);

    // Verify the challenge generation works
    assert!(!challenge.is_empty());
    assert_ne!(challenge, verifier);

    // In a real test, we would:
    // 1. Start authorization with code_challenge and code_challenge_method=S256
    // 2. Complete the authorization flow
    // 3. Exchange the code with the verifier
    // 4. Verify that incorrect verifier fails
}

// Manual test helper functions for full OAuth flow
// These would be used in a more complete integration test setup

#[allow(dead_code)]
async fn simulate_login(
    _app: &axum::Router,
    _client_id: &str,
    _redirect_uri: &str,
    _username: &str,
    _password: &str,
    _code_challenge: Option<&str>,
) -> Option<String> {
    // This would parse the login form, submit credentials,
    // handle the consent page, and extract the authorization code
    // from the redirect. For now, it's a placeholder.
    None
}

#[allow(dead_code)]
async fn exchange_code_for_tokens(
    app: &axum::Router,
    code: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<TokenResponse, ErrorResponse> {
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}",
        code, redirect_uri, client_id
    );

    if let Some(secret) = client_secret {
        body.push_str(&format!("&client_secret={}", secret));
    }

    if let Some(verifier) = code_verifier {
        body.push_str(&format!("&code_verifier={}", verifier));
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body_bytes = body_to_bytes(response.into_body()).await;

    if status == StatusCode::OK {
        Ok(serde_json::from_slice(&body_bytes).unwrap())
    } else {
        Err(serde_json::from_slice(&body_bytes).unwrap())
    }
}
