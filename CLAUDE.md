# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShadowFerrum is a secure, self-contained FUSE-backed file server written in Rust. The system consists of two main components:
- **Server**: A monolithic async Rust binary serving as both Resource Server (file API) and OAuth 2.0 Authorization Server
- **Client**: A FUSE filesystem client that transparently mounts remote storage as a local volume

## Architecture

### Core Components
- **Server**: Dual-role as Resource Server (RESTful API over HTTPS) and Authorization Server (OAuth 2.0 provider)
- **Client**: FUSE-based filesystem that translates OS filesystem operations into authenticated HTTPS API calls
- **Authentication**: OAuth 2.0 Authorization Code flow with PKCE, JWT-based access tokens

### Technology Stack
- **Web Framework**: Axum (tower ecosystem for modularity)
- **TLS**: rustls (memory-safe TLS implementation)
- **OAuth Provider**: oauth-provider-rs (alpha stage - requires careful testing)
- **FUSE**: fuser (Rust FUSE implementation)
- **JWT**: jsonwebtoken
- **Password Hashing**: argon2
- **Token Storage**: keyring (cross-platform secure credential storage)

## Development Setup

Since this is a Rust project, ensure Cargo is installed. The project is currently in planning phase with no implementation yet.

### Future Build Commands (once implemented)
```bash
# Build the server
cargo build --bin server --release

# Build the client  
cargo build --bin client --release

# Run tests
cargo test

# Security audit
cargo audit

# Check for dependency issues
cargo deny check
```

## API Endpoints

The server will expose these REST endpoints (all require Bearer token auth):

- `GET /{path}` - Get file content or directory listing
- `HEAD /{path}` - Get file/directory metadata
- `PUT /{path}` - Create/overwrite file
- `POST /{path}` - Create directory
- `DELETE /{path}` - Delete file/directory

OAuth 2.0 endpoints:
- `/authorize` - Authorization endpoint
- `/token` - Token exchange endpoint

## Implementation Phases

1. **Phase 1**: Core API and Storage - Unauthenticated CRUD endpoints
2. **Phase 2**: OAuth 2.0 Authorization Server
3. **Phase 3**: API Security Integration (JWT validation)
4. **Phase 4**: FUSE Client (read-only operations)
5. **Phase 5**: FUSE Client (write operations)
6. **Phase 6**: Security hardening and finalization

## Security Considerations

- **No unsafe code** unless absolutely necessary (FFI in FUSE client)
- **Path traversal protection** - Canonicalize and validate all paths
- **Rate limiting** on auth endpoints
- **Secure config management** - Never hardcode secrets
- **Enable overflow checks** in release builds
- **Use strong typing** (newtype wrappers for IDs)

## Internal Storage Structure

```
<data_root>/
├── users/        # User accounts (JSON files)
├── clients/      # OAuth client configs
├── inodes/       # File metadata (inode-based)
└── content/      # Actual file content
```

## Important Notes

- The oauth-provider-rs crate is in alpha stage and requires thorough testing and potential upstream contributions
- All communication must use TLS (HTTPS)
- The system is designed to be completely self-contained within Rust ecosystem
- FUSE client operations map to authenticated API calls with automatic token refresh