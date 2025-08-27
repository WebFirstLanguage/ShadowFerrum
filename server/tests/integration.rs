use axum::{
    body::Body,
    http::{Request, StatusCode},
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

async fn setup_test_app() -> (axum::Router, TempDir) {
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
    (app, temp_dir)
}

async fn body_to_bytes(body: Body) -> Bytes {
    body.collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn test_health_check() {
    let (app, _temp) = setup_test_app().await;

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
async fn test_put_and_get_file() {
    let (app, _temp) = setup_test_app().await;

    let content = b"Hello, World!";

    let put_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .body(Body::from(content.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(put_response.status(), StatusCode::CREATED);

    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
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
async fn test_overwrite_existing_file() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .body(Body::from(b"original".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .body(Body::from(b"updated".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_to_bytes(get_response.into_body()).await;
    assert_eq!(body.as_ref(), b"updated");
}

#[tokio::test]
async fn test_create_directory() {
    let (app, _temp) = setup_test_app().await;

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

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_get_directory_listing() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test_dir/file1.txt")
                .body(Body::from(b"content1".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test_dir/file2.txt")
                .body(Body::from(b"content2".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_bytes(response.into_body()).await;
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    assert_eq!(entries.len(), 2);

    let names: Vec<String> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"file1.txt".to_string()));
    assert!(names.contains(&"file2.txt".to_string()));
}

#[tokio::test]
async fn test_head_file() {
    let (app, _temp) = setup_test_app().await;

    let content = b"test content";

    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .body(Body::from(content.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

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

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-length").unwrap(),
        &content.len().to_string()
    );
    assert_eq!(response.headers().get("x-file-type").unwrap(), "file");
}

#[tokio::test]
async fn test_head_directory() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-file-type").unwrap(), "directory");
}

#[tokio::test]
async fn test_delete_file() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test.txt")
                .body(Body::from(b"content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_empty_directory() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_non_empty_directory_fails() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test_dir/file.txt")
                .body(Body::from(b"content".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_non_existent_resource() {
    let (app, _temp) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_create_duplicate_directory() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

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

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_nested_file_operations() {
    let (app, _temp) = setup_test_app().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dir1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dir1/dir2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let content = b"nested content";
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/dir1/dir2/file.txt")
                .body(Body::from(content.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dir1/dir2/file.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_bytes(response.into_body()).await;
    assert_eq!(body.as_ref(), content);
}
