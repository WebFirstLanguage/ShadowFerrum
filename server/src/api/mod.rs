pub mod handlers;

use axum::{
    routing::{delete, get, head, post, put},
    Router,
};
use std::sync::Arc;

use crate::storage::StorageEngine;

pub fn create_router(storage: Arc<StorageEngine>) -> Router {
    Router::new()
        .route("/ping", get(handlers::health_check))
        .route("/*path", get(handlers::get_resource))
        .route("/*path", head(handlers::head_resource))
        .route("/*path", put(handlers::put_file))
        .route("/*path", post(handlers::create_directory))
        .route("/*path", delete(handlers::delete_resource))
        .with_state(storage)
}