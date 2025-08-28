use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;

use crate::{
    api::{AppState, AuthenticatedUser},
    error::{AppError, Result},
    storage::FileType,
};

// Scope constants for performance optimization
const READ_SCOPE: &str = "read";
const WRITE_SCOPE: &str = "write";

pub async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy"
    }))
}

pub async fn get_resource(
    user: AuthenticatedUser,
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    // Check read scope
    if !user.scopes.iter().any(|s| s == READ_SCOPE) {
        return Err(AppError::Forbidden("Insufficient scope".to_string()));
    }

    let path = if path.is_empty() { "/" } else { &path };
    // Add tenant isolation
    let tenant_path = format!("{}/{}", user.user_id, path.trim_start_matches('/'));

    let attrs = state.storage.get_attributes(&tenant_path).await?;

    match attrs.file_type {
        FileType::File => {
            let content = state.storage.read_file(&tenant_path).await?;
            Ok((
                [(header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response())
        }
        FileType::Directory => {
            let entries = state.storage.list_directory(&tenant_path).await?;
            Ok(Json(entries).into_response())
        }
    }
}

pub async fn head_resource(
    user: AuthenticatedUser,
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    // Check read scope
    if !user.scopes.iter().any(|s| s == READ_SCOPE) {
        return Err(AppError::Forbidden("Insufficient scope".to_string()));
    }

    let path = if path.is_empty() { "/" } else { &path };
    // Add tenant isolation
    let tenant_path = format!("{}/{}", user.user_id, path.trim_start_matches('/'));

    let attrs = state.storage.get_attributes(&tenant_path).await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_LENGTH,
        attrs.size.to_string().parse().unwrap(),
    );

    let file_type = match attrs.file_type {
        FileType::File => "file",
        FileType::Directory => "directory",
    };
    headers.insert("X-File-Type", file_type.parse().unwrap());

    if let Ok(modified) = attrs.modified.duration_since(std::time::UNIX_EPOCH) {
        let _timestamp = modified.as_secs();
        if let Ok(value) = httpdate::fmt_http_date(std::time::UNIX_EPOCH + modified).parse() {
            headers.insert(header::LAST_MODIFIED, value);
        }
    }

    Ok((StatusCode::OK, headers).into_response())
}

pub async fn put_file(
    user: AuthenticatedUser,
    Path(path): Path<String>,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response> {
    // Check write scope
    if !user.scopes.iter().any(|s| s == WRITE_SCOPE) {
        return Err(AppError::Forbidden("Insufficient scope".to_string()));
    }

    let path = if path.is_empty() { "/" } else { &path };
    // Add tenant isolation
    let tenant_path = format!("{}/{}", user.user_id, path.trim_start_matches('/'));

    let exists = state.storage.get_attributes(&tenant_path).await.is_ok();

    state.storage.create_file(&tenant_path, &body).await?;

    if exists {
        Ok(StatusCode::OK.into_response())
    } else {
        Ok(StatusCode::CREATED.into_response())
    }
}

pub async fn create_directory(
    user: AuthenticatedUser,
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    // Check write scope
    if !user.scopes.iter().any(|s| s == WRITE_SCOPE) {
        return Err(AppError::Forbidden("Insufficient scope".to_string()));
    }

    let path = if path.is_empty() { "/" } else { &path };
    // Add tenant isolation
    let tenant_path = format!("{}/{}", user.user_id, path.trim_start_matches('/'));

    state.storage.create_directory(&tenant_path).await?;

    Ok(StatusCode::CREATED.into_response())
}

pub async fn delete_resource(
    user: AuthenticatedUser,
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    // Check write scope
    if !user.scopes.iter().any(|s| s == WRITE_SCOPE) {
        return Err(AppError::Forbidden("Insufficient scope".to_string()));
    }

    let path = if path.is_empty() { "/" } else { &path };
    // Add tenant isolation
    let tenant_path = format!("{}/{}", user.user_id, path.trim_start_matches('/'));

    state.storage.delete(&tenant_path).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
