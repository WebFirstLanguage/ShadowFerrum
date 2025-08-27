use std::path::PathBuf;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use server::{api, storage::StorageEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let data_root = PathBuf::from(
        std::env::var("DATA_ROOT").unwrap_or_else(|_| "./data".to_string())
    );
    
    tracing::info!("Initializing storage engine at {:?}", data_root);
    let storage = Arc::new(StorageEngine::new(data_root).await?);
    
    let app = api::create_router(storage)
        .layer(TraceLayer::new_for_http());
    
    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    tracing::info!("Server listening on {}", addr);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}