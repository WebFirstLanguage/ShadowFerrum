use crate::oauth::{auth::OAuthService, storage::OAuthStorage};
use crate::storage::StorageEngine;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<StorageEngine>,
    pub oauth_storage: Arc<OAuthStorage>,
    pub oauth_service: Arc<OAuthService>,
}
