use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use server::{
    api::{self, AppState},
    oauth::{auth::OAuthService, storage::OAuthStorage},
    storage::StorageEngine,
};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

async fn setup_test_app() -> (axum::Router, TempDir, String) {
    let temp_dir = TempDir::new().unwrap();
    let data_root = temp_dir.path().to_path_buf();

    let storage = Arc::new(StorageEngine::new(data_root.clone()).await.unwrap());
    let oauth_storage = Arc::new(OAuthStorage::new(data_root.clone()).await.unwrap());
    let oauth_service = Arc::new(OAuthService::new(oauth_storage.clone()));

    // Create a test user and client for authenticated tests
    oauth_storage
        .create_user(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "password123",
        )
        .await
        .unwrap();

    let app_state = AppState {
        storage,
        oauth_storage,
        oauth_service,
    };

    let app = api::create_router(app_state);
    let token = common::generate_test_token();
    (app, temp_dir, token)
}

async fn body_to_bytes(body: Body) -> Bytes {
    body.collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn test_health_check_no_auth_required() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_bytes(response.into_body()).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "healthy");
}

#[tokio::test]
async fn test_put_and_get_file_with_auth() {
    let (app, _temp, token) = setup_test_app().await;

    let content = b"Hello, World!";

    // PUT with auth
    let put_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(content.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(put_response.status(), StatusCode::CREATED);

    // GET with auth
    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(get_response.status(), StatusCode::OK);
    assert_eq!(
        get_response.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );

    let body = body_to_bytes(get_response.into_body()).await;
    assert_eq!(body.as_ref(), content);
}

#[tokio::test]
async fn test_put_without_auth_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .body(Body::from(b"data".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_without_auth_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_head_without_auth_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_without_auth_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_directory_without_auth_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_token_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(header::AUTHORIZATION, "Bearer invalid_token_here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_expired_token_returns_401() {
    let (app, _temp, _token) = setup_test_app().await;
    let expired_token = common::generate_test_token_with_options(
        "test-user-id",
        "test-client",
        vec!["read", "write"],
        true, // expired
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", expired_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_full_crud_with_auth() {
    let (app, _temp, token) = setup_test_app().await;

    // Create directory
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Create file in directory
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test_dir/file.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(b"content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Read file
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test_dir/file.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Get metadata
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test_dir/file.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Delete file
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test_dir/file.txt")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Delete directory
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test_dir")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
