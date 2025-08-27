# ShadowFerrum Server - Phase 1

## Overview
This is Phase 1 implementation of the ShadowFerrum secure file server. This phase provides:
- Core file-based storage engine with inode-based metadata
- Unauthenticated REST API for CRUD operations
- Full Test-Driven Development (TDD) implementation

## Features
- **Storage Engine**: File-based storage with separate inode metadata and content storage
- **REST API**: Full CRUD operations for files and directories
- **Path Safety**: Canonicalized paths with traversal protection
- **Async I/O**: All operations use async Tokio for non-blocking I/O

## API Endpoints

| Method | Path      | Description                           | Request Body | Response |
|--------|-----------|---------------------------------------|-------------|----------|
| GET    | /ping     | Health check                          | None        | JSON status |
| GET    | /{path}   | Get file content or directory listing | None        | Binary/JSON |
| HEAD   | /{path}   | Get metadata only                    | None        | Headers |
| PUT    | /{path}   | Create/overwrite file                | Binary data | 201/200 |
| POST   | /{path}   | Create directory                      | None        | 201 |
| DELETE | /{path}   | Delete file or empty directory       | None        | 204 |

## Running the Server

```bash
# Build the server
cargo build --package server --release

# Run the server (default port 3000, data directory ./data)
cargo run --package server --release

# Or with custom data directory
DATA_ROOT=/custom/path cargo run --package server --release
```

## Testing

```bash
# Run all tests
cargo test --package server

# Run with logging
RUST_LOG=debug cargo test --package server -- --nocapture
```

## Storage Structure

```
data/
├── inodes/     # JSON files with metadata (1.json, 2.json, etc.)
└── content/    # Binary file content (1, 2, etc.)
```

## Next Phases
- Phase 2: OAuth 2.0 Authorization Server integration
- Phase 3: JWT-based API security
- Phase 4-5: FUSE client implementation
- Phase 6: Security hardening