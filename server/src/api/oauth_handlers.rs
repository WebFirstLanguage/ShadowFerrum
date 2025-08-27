use crate::api::AppState;
use crate::oauth::auth::AuthError;
use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    error: Option<String>,
    action_url: String,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    scopes: Vec<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    user_id: String,
    username: String,
    action_url: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    consent: String, // "approve" or "deny"
    client_id: String,
    redirect_uri: String,
    #[allow(dead_code)]
    response_type: String, // Kept for future use
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    scope: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: String,
    error_description: String,
}

pub struct OAuthHandlers;

impl OAuthHandlers {
    pub async fn authorize_get(
        Query(params): Query<AuthorizeParams>,
        State(state): State<AppState>,
    ) -> Result<Html<String>, Response> {
        // Validate client and redirect URI
        let client = match state.oauth_storage.get_client(&params.client_id).await {
            Ok(c) => c,
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_client".to_string(),
                        error_description: "Client not found".to_string(),
                    }),
                )
                    .into_response());
            }
        };

        if !client.redirect_uris.contains(&params.redirect_uri) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_redirect_uri".to_string(),
                    error_description: "Redirect URI not registered".to_string(),
                }),
            )
                .into_response());
        }

        // Validate response type
        if params.response_type != "code" {
            return Err(redirect_with_error(
                &params.redirect_uri,
                "unsupported_response_type",
                "Only authorization code flow is supported",
                params.state.as_deref(),
            ));
        }

        // Render login page
        let template = LoginTemplate {
            client_id: params.client_id,
            client_name: client.name,
            redirect_uri: params.redirect_uri,
            response_type: params.response_type,
            scope: params.scope,
            state: params.state,
            code_challenge: params.code_challenge,
            code_challenge_method: params.code_challenge_method,
            error: None,
            action_url: "/oauth/authorize".to_string(),
        };

        Ok(Html(template.render().unwrap()))
    }

    pub async fn authorize_post(
        State(state): State<AppState>,
        Form(form): Form<LoginForm>,
    ) -> Result<Html<String>, Response> {
        // Get client
        let client = match state.oauth_storage.get_client(&form.client_id).await {
            Ok(c) => c,
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_client".to_string(),
                        error_description: "Client not found".to_string(),
                    }),
                )
                    .into_response());
            }
        };

        // Verify user credentials
        let user = match state
            .oauth_storage
            .verify_user_password(&form.username, &form.password)
            .await
        {
            Ok(u) => u,
            Err(_) => {
                // Re-render login page with error
                let template = LoginTemplate {
                    client_id: form.client_id,
                    client_name: client.name,
                    redirect_uri: form.redirect_uri,
                    response_type: form.response_type,
                    scope: form.scope,
                    state: form.state,
                    code_challenge: form.code_challenge,
                    code_challenge_method: form.code_challenge_method,
                    error: Some("Invalid username or password".to_string()),
                    action_url: "/oauth/authorize".to_string(),
                };
                return Ok(Html(template.render().unwrap()));
            }
        };

        // Show consent page
        let scopes: Vec<String> = form.scope.split(' ').map(|s| s.to_string()).collect();

        let template = ConsentTemplate {
            client_id: form.client_id,
            client_name: client.name,
            redirect_uri: form.redirect_uri,
            response_type: form.response_type,
            scope: form.scope,
            scopes,
            state: form.state,
            code_challenge: form.code_challenge,
            code_challenge_method: form.code_challenge_method,
            user_id: user.id.to_string(),
            username: user.username,
            action_url: "/oauth/consent".to_string(),
        };

        Ok(Html(template.render().unwrap()))
    }

    pub async fn consent_post(
        State(state): State<AppState>,
        Form(form): Form<ConsentForm>,
    ) -> Response {
        if form.consent != "approve" {
            return redirect_with_error(
                &form.redirect_uri,
                "access_denied",
                "User denied access",
                form.state.as_deref(),
            );
        }

        let user_id = match Uuid::parse_str(&form.user_id) {
            Ok(id) => id,
            Err(_) => {
                return redirect_with_error(
                    &form.redirect_uri,
                    "server_error",
                    "Invalid user ID",
                    form.state.as_deref(),
                );
            }
        };

        let scopes: Vec<String> = form.scope.split(' ').map(|s| s.to_string()).collect();

        // Create authorization code
        let code = match state
            .oauth_service
            .create_authorization_code(
                form.client_id,
                user_id,
                form.redirect_uri.clone(),
                scopes,
                form.code_challenge,
                form.code_challenge_method,
            )
            .await
        {
            Ok(c) => c,
            Err(_) => {
                return redirect_with_error(
                    &form.redirect_uri,
                    "server_error",
                    "Failed to create authorization code",
                    form.state.as_deref(),
                );
            }
        };

        // Redirect with code
        let mut redirect_url = form.redirect_uri.clone();
        redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
        redirect_url.push_str(&format!("code={}", code));

        if let Some(state) = form.state {
            redirect_url.push_str(&format!("&state={}", state));
        }

        Redirect::to(&redirect_url).into_response()
    }

    pub async fn token_post(
        State(state): State<AppState>,
        Form(request): Form<TokenRequest>,
    ) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
        // Verify client credentials if confidential client
        if let Some(client_secret) = &request.client_secret {
            if state
                .oauth_storage
                .verify_client_secret(&request.client_id, client_secret)
                .await
                .is_err()
            {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid_client".to_string(),
                        error_description: "Invalid client credentials".to_string(),
                    }),
                ));
            }
        }

        match request.grant_type.as_str() {
            "authorization_code" => {
                let code = request.code.ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_request".to_string(),
                            error_description: "Missing authorization code".to_string(),
                        }),
                    )
                })?;

                let redirect_uri = request.redirect_uri.ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_request".to_string(),
                            error_description: "Missing redirect URI".to_string(),
                        }),
                    )
                })?;

                let (access_token, refresh_token) = state
                    .oauth_service
                    .exchange_authorization_code(
                        &code,
                        &request.client_id,
                        &redirect_uri,
                        request.code_verifier.as_deref(),
                    )
                    .await
                    .map_err(|e| match e {
                        AuthError::InvalidClient => (
                            StatusCode::UNAUTHORIZED,
                            Json(ErrorResponse {
                                error: "invalid_client".to_string(),
                                error_description: "Invalid client".to_string(),
                            }),
                        ),
                        AuthError::InvalidGrant => (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: "invalid_grant".to_string(),
                                error_description: "Invalid or expired authorization code"
                                    .to_string(),
                            }),
                        ),
                        AuthError::InvalidPkceVerifier => (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: "invalid_grant".to_string(),
                                error_description: "Invalid PKCE verifier".to_string(),
                            }),
                        ),
                        _ => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Internal server error".to_string(),
                            }),
                        ),
                    })?;

                Ok(Json(TokenResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 3600, // 1 hour
                    refresh_token: Some(refresh_token),
                    scope: "read write".to_string(), // TODO: Get from auth code
                }))
            }
            "refresh_token" => {
                let refresh_token = request.refresh_token.ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_request".to_string(),
                            error_description: "Missing refresh token".to_string(),
                        }),
                    )
                })?;

                let access_token = state
                    .oauth_service
                    .refresh_access_token(&refresh_token, &request.client_id)
                    .await
                    .map_err(|e| match e {
                        AuthError::InvalidClient => (
                            StatusCode::UNAUTHORIZED,
                            Json(ErrorResponse {
                                error: "invalid_client".to_string(),
                                error_description: "Invalid client".to_string(),
                            }),
                        ),
                        AuthError::InvalidGrant => (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: "invalid_grant".to_string(),
                                error_description: "Invalid or expired refresh token".to_string(),
                            }),
                        ),
                        _ => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Internal server error".to_string(),
                            }),
                        ),
                    })?;

                Ok(Json(TokenResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                    refresh_token: None, // Don't rotate refresh token
                    scope: "read write".to_string(),
                }))
            }
            _ => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "unsupported_grant_type".to_string(),
                    error_description: "Grant type not supported".to_string(),
                }),
            )),
        }
    }
}

fn redirect_with_error(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut url = redirect_uri.to_string();
    url.push_str(if url.contains('?') { "&" } else { "?" });
    url.push_str(&format!(
        "error={}&error_description={}",
        error,
        urlencoding::encode(description)
    ));

    if let Some(state) = state {
        url.push_str(&format!("&state={}", state));
    }

    Redirect::to(&url).into_response()
}

// Middleware to check Bearer token on protected routes
use axum::{extract::Request, middleware::Next};

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(auth_value) = auth_header {
        if let Some(token) = auth_value.strip_prefix("Bearer ") {
            match state.oauth_service.verify_access_token(token) {
                Ok(claims) => {
                    // Add claims to request extensions for use in handlers
                    request.extensions_mut().insert(claims);
                    return Ok(next.run(request).await);
                }
                Err(_) => {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
