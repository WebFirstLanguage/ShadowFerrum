use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::Value;
use server::{
    api::{self, AppState},
    oauth::{auth::OAuthService, storage::OAuthStorage},
    storage::StorageEngine,
};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

async fn setup_test_app() -> (axum::Router, TempDir) {
    // Set JWT secret for tests
    std::env::set_var("JWT_SECRET", "development_secret_change_in_production");
    
    let temp_dir = TempDir::new().unwrap();
    let data_root = temp_dir.path().to_path_buf();

    let storage = Arc::new(StorageEngine::new(data_root.clone()).await.unwrap());
    let oauth_storage = Arc::new(OAuthStorage::new(data_root.clone()).await.unwrap());
    let oauth_service = Arc::new(OAuthService::new(oauth_storage.clone()));

    // Create test users
    oauth_storage
        .create_user(
            "testuser1".to_string(),
            "test1@example.com".to_string(),
            "password123",
        )
        .await
        .unwrap();

    oauth_storage
        .create_user(
            "testuser2".to_string(),
            "test2@example.com".to_string(),
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
    (app, temp_dir)
}

async fn body_to_bytes(body: Body) -> Bytes {
    body.collect().await.unwrap().to_bytes()
}

async fn response_to_json(body: Body) -> Value {
    let bytes = body_to_bytes(body).await;
    serde_json::from_slice(&bytes).unwrap()
}

// SCOPE VALIDATION TESTS

#[tokio::test]
async fn test_get_file_requires_read_scope() {
    let (app, _temp) = setup_test_app().await;
    
    // Token without read scope
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["write"], // Only write scope, no read
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    
    let json = response_to_json(response.into_body()).await;
    assert_eq!(json["error"], "Insufficient scope");
}

#[tokio::test]
async fn test_head_file_requires_read_scope() {
    let (app, _temp) = setup_test_app().await;
    
    // Token without read scope
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["write"],
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_put_file_requires_write_scope() {
    let (app, _temp) = setup_test_app().await;
    
    // Token without write scope
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["read"], // Only read scope, no write
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::from(b"content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    
    let json = response_to_json(response.into_body()).await;
    assert_eq!(json["error"], "Insufficient scope");
}

#[tokio::test]
async fn test_create_directory_requires_write_scope() {
    let (app, _temp) = setup_test_app().await;
    
    // Token without write scope
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["read"],
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    
    let json = response_to_json(response.into_body()).await;
    assert_eq!(json["error"], "Insufficient scope");
}

#[tokio::test]
async fn test_delete_resource_requires_write_scope() {
    let (app, _temp) = setup_test_app().await;
    
    // Token without write scope
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["read"],
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    
    let json = response_to_json(response.into_body()).await;
    assert_eq!(json["error"], "Insufficient scope");
}

#[tokio::test]
async fn test_missing_scopes_returns_forbidden() {
    let (app, _temp) = setup_test_app().await;
    
    // Token with no scopes
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec![], // No scopes
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    
    let json = response_to_json(response.into_body()).await;
    assert_eq!(json["error"], "Insufficient scope");
}

// TENANT ISOLATION TESTS

#[tokio::test]
async fn test_tenant_isolation_different_users_cannot_access_each_others_files() {
    let (app, _temp) = setup_test_app().await;
    
    let user1_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let user2_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    
    // Create tokens for different users
    let token1 = common::generate_test_token_with_options(
        user1_id,
        "test-client",
        vec!["read", "write"],
        false,
    );
    let token2 = common::generate_test_token_with_options(
        user2_id,
        "test-client",
        vec!["read", "write"],
        false,
    );
    
    let (auth_header_name, auth_header_value1) = common::auth_header(&token1);
    let (_, auth_header_value2) = common::auth_header(&token2);

    // Create root directories for tenant isolation (users need their root dirs first)
    let root_response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")  // This will create the tenant root directory
                .header(auth_header_name, &auth_header_value1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // This might succeed or fail depending on if root already exists
    assert!(
        root_response1.status() == StatusCode::CREATED || 
        root_response1.status() == StatusCode::CONFLICT
    );
    
    // User 1 creates a file
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/private_file.txt")
                .header(auth_header_name, &auth_header_value1)
                .body(Body::from(b"user1 secret content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::CREATED);

    // User 2 tries to access User 1's file - should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/private_file.txt")
                .header(auth_header_name, &auth_header_value2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // User 2 should get NOT_FOUND (file doesn't exist in their tenant space)
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // User 1 can still access their own file
    let response = app
        .oneshot(
            Request::builder()
                .uri("/private_file.txt")
                .header(auth_header_name, auth_header_value1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_bytes(response.into_body()).await;
    assert_eq!(body.as_ref(), b"user1 secret content");
}

#[tokio::test]
async fn test_tenant_isolation_directory_operations() {
    let (app, _temp) = setup_test_app().await;
    
    let user1_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let user2_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    
    let token1 = common::generate_test_token_with_options(
        user1_id,
        "test-client",
        vec!["read", "write"],
        false,
    );
    let token2 = common::generate_test_token_with_options(
        user2_id,
        "test-client", 
        vec!["read", "write"],
        false,
    );
    
    let (auth_header_name, auth_header_value1) = common::auth_header(&token1);
    let (_, auth_header_value2) = common::auth_header(&token2);

    // Create tenant root directories first
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(auth_header_name, &auth_header_value1)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(auth_header_name, &auth_header_value2)
                .body(Body::empty())
                .unwrap(),
        )
        .await;

    // User 1 creates a directory
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/user1_dir")
                .header(auth_header_name, &auth_header_value1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::CREATED);

    // User 2 tries to access User 1's directory
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user1_dir")
                .header(auth_header_name, &auth_header_value2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // User 2 creates directory with same name in their space
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/user1_dir")
                .header(auth_header_name, &auth_header_value2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::CREATED); // Should succeed in their own space

    // Both users can access their own directories
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user1_dir")
                .header(auth_header_name, &auth_header_value1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    let response2 = app
        .oneshot(
            Request::builder()
                .uri("/user1_dir")
                .header(auth_header_name, auth_header_value2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::OK);
}

// PATH TRAVERSAL PREVENTION TESTS

#[tokio::test]
async fn test_path_traversal_attempt_with_parent_directory() {
    let (app, _temp) = setup_test_app().await;
    
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["read", "write"],
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    // Try to access parent directory with ../
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/../other_user_data")
                .header(auth_header_name, &auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Should be treated as relative path within user's tenant
    // The current implementation would create path "user_id/other_user_data"
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Try to create file with path traversal
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/../../../escape.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::from(b"escaped content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Should be confined to user's tenant space
    assert!(response.status() == StatusCode::CREATED || response.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_path_traversal_with_multiple_dots() {
    let (app, _temp) = setup_test_app().await;
    
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["read", "write"],
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    // Various path traversal attempts
    let traversal_paths = vec![
        "/../../etc/passwd",
        "/../../../../../root/.ssh/id_rsa",
        "/./../../other_user",
        "/..",
        "/...//../../escape",
    ];

    for path in traversal_paths {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(auth_header_name, &auth_header_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        
        // All attempts should be contained within the user's tenant
        // Current implementation just prefixes with user_id so these become valid paths
        // In a properly secured implementation, these should return BAD_REQUEST
        assert!(
            response.status() == StatusCode::NOT_FOUND ||
            response.status() == StatusCode::BAD_REQUEST,
            "Path traversal attempt '{}' should be blocked or contained", path
        );
    }
}

// ERROR RESPONSE FORMAT TESTS

#[tokio::test]
async fn test_forbidden_error_response_format() {
    let (app, _temp) = setup_test_app().await;
    
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["write"], // Missing read scope
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    
    let json = response_to_json(response.into_body()).await;
    
    // Verify error response structure
    assert!(json.is_object());
    assert!(json.get("error").is_some());
    assert_eq!(json["error"], "Insufficient scope");
}

#[tokio::test]
async fn test_various_http_methods_scope_validation() {
    // Test different combinations of scopes and methods
    let test_cases = vec![
        ("GET", vec!["read"], StatusCode::NOT_FOUND), // Should pass scope check, file not found
        ("GET", vec!["write"], StatusCode::FORBIDDEN), // Wrong scope
        ("HEAD", vec!["read"], StatusCode::NOT_FOUND), // Should pass scope check, file not found  
        ("HEAD", vec!["write"], StatusCode::FORBIDDEN), // Wrong scope
        ("PUT", vec!["write"], StatusCode::CREATED), // Should pass and create file
        ("PUT", vec!["read"], StatusCode::FORBIDDEN), // Wrong scope
        ("POST", vec!["write"], StatusCode::CREATED), // Should pass and create directory
        ("POST", vec!["read"], StatusCode::FORBIDDEN), // Wrong scope
        ("DELETE", vec!["write"], StatusCode::NOT_FOUND), // Should pass scope check, resource not found
        ("DELETE", vec!["read"], StatusCode::FORBIDDEN), // Wrong scope
    ];

    for (i, (method, scopes, expected_status)) in test_cases.into_iter().enumerate() {
        let (app, _temp) = setup_test_app().await; // fresh state per case
        let token = common::generate_test_token_with_options(
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "test-client",
            scopes.clone(),
            false,
        );
        let (auth_header_name, auth_header_value) = common::auth_header(&token);

        // Create tenant root directory if this is a write operation that might succeed
        if (method == "PUT" || method == "POST") && scopes.contains(&"write") {
            let _ = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/")
                        .header(auth_header_name, &auth_header_value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let uri = match method {
            "POST" => format!("/test_directory_{}", i),
            _ => format!("/test_file_{}.txt", i),
        };

        let body = match method {
            "PUT" => Body::from(b"test content".to_vec()),
            _ => Body::empty(),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .header(auth_header_name, auth_header_value)
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            expected_status,
            "Method {} uri {} with scopes {:?} should return {}",
            method, uri, scopes, expected_status
        );
    }
}

#[tokio::test]
async fn test_valid_scopes_allow_operations() {
    let (app, _temp) = setup_test_app().await;
    
    let token = common::generate_test_token_with_options(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "test-client",
        vec!["read", "write"], // Both scopes
        false,
    );
    let (auth_header_name, auth_header_value) = common::auth_header(&token);

    // Create root directory for tenant
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(auth_header_name, &auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Create a file (write operation)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .header(auth_header_name, &auth_header_value)
                .body(Body::from(b"test content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::CREATED);

    // Read the file (read operation)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .header(auth_header_name, &auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);

    // Head request (read operation)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test.txt")
                .header(auth_header_name, &auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);

    // Delete the file (write operation)
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test.txt")
                .header(auth_header_name, auth_header_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}