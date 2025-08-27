### Phase 1: Core API Server and Storage Engine (Unauthenticated)

**Goal:** Establish the server's foundational components: the file-based storage logic and the unauthenticated Axum web API that exposes it.

* [ ] **Project Setup**
    * [ ] Initialize a Cargo workspace with two members: `server` and `client`.
    * [ ] Add initial dependencies to `server/Cargo.toml`: `tokio`, `axum`, `serde`, `serde_json`, `tracing`.

* [ ] **Internal Storage Engine (TDD)**
    * [ ] **Define Data Structures:** In a new `storage` module, define the `InodeAttributes` struct and other necessary types for representing files and directories.
    * [ ] **Write Tests First:** Create unit tests for the storage engine that mock the filesystem (`tokio::fs`).
        * [ ] Test `create_inode_and_content` (for a new file).
        * [ ] Test `create_directory_inode`.
        * [ ] Test `read_content` for a given inode.
        * [ ] Test `read_directory_listing`.
        * [ ] Test `delete_inode_and_content`.
        * [ ] Test `get_attributes` for an inode.
    * [ ] **Implement Storage Logic:** Write the asynchronous functions that interact with the data directories (`/inodes`, `/content`, etc.) to make the unit tests pass.

* [ ] **Axum API Handlers (TDD)**
    * [ ] **Setup Basic Server:** Create the main Axum `Router` and a simple health-check endpoint (e.g., `/ping`) to verify the server runs.
    * [ ] **Write Integration Tests:** Create an integration test module that uses `axum::http::Request` to test the API endpoints against a temporary storage directory.
        * [ ] Test `PUT /{path}`: Should create a file and return `201 Created`. A follow-up `GET` should return the content.
        * [ ] Test `POST /{path}`: Should create a directory and return `201 Created`.
        * [ ] Test `GET /{path}` (File): Should return `200 OK` with `application/octet-stream`.
        * [ ] Test `GET /{path}` (Directory): Should return `200 OK` with a JSON array of entries.
        * [ ] Test `HEAD /{path}`: Should return `200 OK` with correct `Content-Length` and custom headers.
        * [ ] Test `DELETE /{path}`: Should delete the resource and return `204 No Content`.
        * [ ] Test error cases: `404 Not Found`, `409 Conflict` (creating an existing directory), etc.
    * [ ] **Implement API Handlers:** Write the Axum handler functions for each route, calling the corresponding functions from your `storage` module to make the integration tests pass.

---

### Phase 2: Integrated OAuth 2.0 Authorization Server

**Goal:** Integrate `oauth-provider-rs` to handle user authentication and token issuance. This phase is critical and requires rigorous testing due to the crate's alpha status.

* [ ] **Dependency Integration**
    * [ ] Add `oauth-provider-rs`, `argon2`, and `jsonwebtoken` to `server/Cargo.toml`.

* [ ] **Storage Backend Implementation (TDD)**
    * [ ] **Define User/Client Structs:** Create structs for `User` (with hashed password) and `Client` (with `client_id`, `redirect_uris`).
    * [ ] **Write Tests First:** Create unit tests for the OAuth storage traits.
        * [ ] Test user creation and password verification (using `argon2`).
        * [ ] Test client registration and lookup.
        * [ ] Test storage and retrieval of authorization codes and refresh tokens.
    * [ ] **Implement Storage Traits:** Implement the `oauth-provider-rs` storage traits to interface with the file-based backend (`/users`, `/clients`).

* [ ] **UI and Endpoint Setup**
    * [ ] Create basic HTML templates for the user login and consent pages.
    * [ ] Write Axum handlers to serve the login/consent UI.
    * [ ] Configure and mount the `/authorize` and `/token` routes from `oauth-provider-rs`.

* [ ] **Full-Flow Integration Testing (TDD)**
    * [ ] **Write Comprehensive Tests:** Create a new integration test suite specifically for the OAuth 2.0 flow. This is the **most important** step in this phase.
        * [ ] Test the complete Authorization Code + PKCE flow: Simulate a client's request to `/authorize`, a user login, and the final code-for-token exchange at the `/token` endpoint. Assert that a valid JWT access token and a refresh token are returned.
        * [ ] Test failure conditions: Invalid `client_id`, mismatched `redirect_uri`, incorrect PKCE verifier, reuse of an authorization code. Each should result in the correct OAuth 2.0 error response.
        * [ ] Test the `refresh_token` grant flow.

---

### Phase 3: Securing the API

**Goal:** Connect the Authorization Server (Phase 2) to the Resource Server API (Phase 1) by requiring valid JWTs for all file operations.

* [ ] **JWT Authorization Extractor (TDD)**
    * [ ] **Write Tests First:** Create unit tests for the `AuthenticatedUser` extractor.
        * [ ] Test with a valid, correctly signed JWT. The extractor should succeed.
        * [ ] Test with a malformed `Authorization` header. It should be rejected (leading to a `401`).
        * [ ] Test with an expired JWT. It should be rejected.
        * [ ] Test with a JWT signed by a different key. It should be rejected.
    * [ ] **Implement the Extractor:** Implement `axum::extract::FromRequestParts` for an `AuthenticatedUser` struct that validates the bearer token using `jsonwebtoken` and extracts the user's ID (`sub` claim).

* [ ] **API Integration (TDD)**
    * [ ] **Update Handlers:** Add the `AuthenticatedUser` extractor to the signature of every file API handler from Phase 1.
    * [ ] **Update Integration Tests:**
        * Modify the Phase 1 integration tests. They should now all fail with `401 Unauthorized`.
        * Create a test helper function that generates a valid access token for a test user.
        * Update the tests to include a valid `Authorization: Bearer <token>` header in each request and assert that they now pass.
        * Keep a few tests that explicitly *don't* send a token to ensure they still fail with `401`.

---

### Phase 4: FUSE Client Implementation (Read-Only)

**Goal:** Create a client that can successfully authenticate, mount a filesystem, and perform all read operations.

* [ ] **Project Setup**
    * [ ] Add dependencies to `client/Cargo.toml`: `fuser`, `tokio`, `reqwest`, `keyring`, `url`.

* [ ] **Authentication and Token Management (TDD)**
    * [ ] **Write Tests First:**
        * [ ] Test the browser-based auth flow orchestration (mocking the local server and user interaction).
        * [ ] Test the secure token storage logic using the `keyring` crate. Write tests to set, get, and delete tokens for a given service name.
    * [ ] **Implement Auth Flow:** Implement the logic to start a local server, print the authorization URL, handle the callback, and exchange the code for tokens.
    * [ ] **Implement Secure Storage:** Use the `keyring` crate to securely store and retrieve the access and refresh tokens.

* [ ] **FUSE Read Operations (TDD with Mocking)**
    * [ ] **Setup Mock Server:** Use a library like `wiremock` to mock the remote API server in your tests.
    * [ ] **Write Tests First:** For each read operation, write a test that simulates a kernel call and asserts that the correct API request is made to the mock server.
        * [ ] Test `getattr`: Should trigger a `HEAD /{path}` request.
        * [ ] Test `lookup`: Should also trigger a `HEAD /{path}` request.
        * [ ] Test `readdir`: Should trigger a `GET /{path}` and correctly parse the JSON response.
        * [ ] Test `read`: Should trigger a `GET /{path}` with the correct `Range` header.
    * [ ] **Implement `fuser::Filesystem` Trait:** Implement the read-only methods (`getattr`, `lookup`, `readdir`, `read`) on your FUSE struct. The implementation will use `reqwest` to call the real server API.

---

### Phase 5: FUSE Client Implementation (Read-Write)

**Goal:** Extend the FUSE client with full CRUD capabilities and robust token refresh logic.

* [ ] **Token Refresh Logic (TDD)**
    * [ ] **Write Tests First:**
        * [ ] Write an integration test for the API client where the mock server first responds with `401 Unauthorized`. The test should assert that the client then makes a request to the `/token` endpoint with the refresh token and then retries the original request with the new access token.
    * [ ] **Implement Refresh Logic:** Build a wrapper around your `reqwest` client that transparently handles 401 errors and performs the token refresh flow.

* [ ] **FUSE Write Operations (TDD with Mocking)**
    * [ ] **Write Tests First:** Continue using the mock server to test the write operations.
        * [ ] Test `mknod`/`create`: Should trigger a `PUT /{path}`.
        * [ ] Test `mkdir`: Should trigger a `POST /{path}`.
        * [ ] Test `write`: Should trigger a `PUT /{path}` with the file's content.
        * [ ] Test `unlink`: Should trigger a `DELETE /{path}`.
        * [ ] Test `rmdir`: Should trigger a `DELETE /{path}`.
        * [ ] Test `rename`: Should trigger a `MOVE /{source}` with a `Destination` header.
    * [ ] **Implement Write Methods:** Implement the remaining methods on the `fuser::Filesystem` trait.

---

### Phase 6: System Hardening and Finalization

**Goal:** Conduct a final security review, add production-grade features, and prepare for deployment.

* [ ] **Security Hardening (TDD where applicable)**
    * [ ] **Implement Path Traversal Protection:** Add tests to the server to ensure requests with `..` or other malicious path components are rejected with `400 Bad Request`.
    * [ ] **Implement Rate Limiting:** Add `tower-http` rate-limiting middleware to sensitive endpoints (`/login`, `/token`). Write integration tests to verify it works.
    * [ ] **Review Configuration:** Refactor to ensure all secrets (TLS keys, JWT keys) are loaded from environment variables or a secure configuration file, not source code.
    * [ ] **Review Rust Safety:**
        * Add `overflow-checks = true` to `[profile.release]` in `Cargo.toml`.
        * Search for and justify any `unsafe` code blocks.
        * Refactor to use newtype wrappers for IDs (`UserId`, `InodeId`) to improve type safety.

* [ ] **CI/CD and Automation**
    * [ ] Set up a CI pipeline (e.g., GitHub Actions).
    * [ ] Add `cargo-audit` to the pipeline to check for vulnerable dependencies.
    * [ ] Add `cargo-deny` to enforce license policies.
    * [ ] Ensure `cargo fmt` and `cargo clippy` run on every commit.

* [ ] **Documentation and Final Polish**
    * [ ] Write a comprehensive `README.md` for both the server and client.
    * [ ] Add Rustdoc comments to all public functions and structs.
    * [ ] Perform a final end-to-end manual test of the entire system.