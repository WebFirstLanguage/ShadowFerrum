use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;

use crate::{api::AppState, error::Result, storage::FileType};

pub async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy"
    }))
}

pub async fn get_resource(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    let path = if path.is_empty() { "/" } else { &path };

    let attrs = state.storage.get_attributes(path).await?;

    match attrs.file_type {
        FileType::File => {
            let content = state.storage.read_file(path).await?;
            Ok((
                [(header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response())
        }
        FileType::Directory => {
            let entries = state.storage.list_directory(path).await?;
            Ok(Json(entries).into_response())
        }
    }
}

pub async fn head_resource(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    let path = if path.is_empty() { "/" } else { &path };

    let attrs = state.storage.get_attributes(path).await?;

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
    Path(path): Path<String>,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response> {
    let path = if path.is_empty() { "/" } else { &path };

    let exists = state.storage.get_attributes(path).await.is_ok();

    state.storage.create_file(path, &body).await?;

    if exists {
        Ok(StatusCode::OK.into_response())
    } else {
        Ok(StatusCode::CREATED.into_response())
    }
}

pub async fn create_directory(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    let path = if path.is_empty() { "/" } else { &path };

    state.storage.create_directory(path).await?;

    Ok(StatusCode::CREATED.into_response())
}

pub async fn delete_resource(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    let path = if path.is_empty() { "/" } else { &path };

    state.storage.delete(path).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
