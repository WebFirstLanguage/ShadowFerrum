use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::engine::StorageError),

    #[error("Internal server error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Storage(ref e) => {
                use crate::storage::engine::StorageError;
                match e {
                    StorageError::NotFound(_) => (StatusCode::NOT_FOUND, "Resource not found"),
                    StorageError::AlreadyExists(_) => {
                        (StatusCode::CONFLICT, "Resource already exists")
                    }
                    StorageError::DirectoryNotEmpty(_) => {
                        (StatusCode::BAD_REQUEST, "Directory not empty")
                    }
                    StorageError::InvalidPath(_) => (StatusCode::BAD_REQUEST, "Invalid path"),
                    StorageError::NotADirectory(_) => (StatusCode::BAD_REQUEST, "Not a directory"),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
                }
            }
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
