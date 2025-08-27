pub mod auth_extractor;
pub mod handlers;
pub mod oauth_handlers;
pub mod state;

pub use auth_extractor::AuthenticatedUser;
pub use state::AppState;

use axum::{
    routing::{delete, get, head, post, put},
    Router,
};

pub fn create_router(state: AppState) -> Router {
    // Create OAuth routes (unprotected)
    let oauth_routes = Router::new()
        .route(
            "/oauth/authorize",
            get(oauth_handlers::OAuthHandlers::authorize_get),
        )
        .route(
            "/oauth/authorize",
            post(oauth_handlers::OAuthHandlers::authorize_post),
        )
        .route(
            "/oauth/consent",
            post(oauth_handlers::OAuthHandlers::consent_post),
        )
        .route(
            "/oauth/token",
            post(oauth_handlers::OAuthHandlers::token_post),
        )
        .with_state(state.clone());

    // Create protected API routes (AuthenticatedUser extractor handles auth per-handler)
    let protected_routes = Router::new()
        .route("/*path", get(handlers::get_resource))
        .route("/*path", head(handlers::head_resource))
        .route("/*path", put(handlers::put_file))
        .route("/*path", post(handlers::create_directory))
        .route("/*path", delete(handlers::delete_resource))
        .with_state(state.clone());

    // Combine routes
    Router::new()
        .route("/ping", get(handlers::health_check)) // Health check doesn't need auth
        .merge(oauth_routes)
        .merge(protected_routes)
}
