//! Finite Identity Authority HTTP contract and SQLite store.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension, params};
use secp256k1::rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{hex, nip98, npub};

#[derive(Debug, Clone)]
pub struct AuthorityConfig {
    pub external_base_url: String,
    pub finite_vip_domain: String,
    pub email_challenge_ttl_seconds: u64,
}

impl AuthorityConfig {
    fn normalized_base_url(&self) -> String {
        self.external_base_url.trim_end_matches('/').to_owned()
    }
}

pub trait Mailer: Send + Sync + 'static {
    fn send_email_challenge(&self, email: &str, token: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Default)]
pub struct DevMailer;

impl Mailer for DevMailer {
    fn send_email_challenge(&self, email: &str, token: &str) -> Result<(), String> {
        eprintln!("finite-identityd dev email challenge for {email}: {token}");
        Ok(())
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> u64;
}

#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(now > 0);
        now as u64
    }
}

#[derive(Debug, Clone)]
pub struct FixedClock {
    now: Arc<AtomicU64>,
}

impl FixedClock {
    pub fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }

    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct AuthorityState {
    store: IdentityStore,
    mailer: Arc<dyn Mailer>,
    clock: Arc<dyn Clock>,
    config: AuthorityConfig,
}

impl AuthorityState {
    pub fn new(
        store: IdentityStore,
        mailer: Arc<dyn Mailer>,
        clock: impl Clock,
        config: AuthorityConfig,
    ) -> Self {
        Self {
            store,
            mailer,
            clock: Arc::new(clock),
            config,
        }
    }
}

#[derive(Clone)]
pub struct IdentityStore {
    conn: Arc<Mutex<Connection>>,
}

impl IdentityStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
        }
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_memory() -> Result<Self, StoreError> {
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn bind_vip_email(&self, email: &str, pubkey: &str, now: u64) -> Result<(), StoreError> {
        if !hex::is_hex32(pubkey) {
            return Err(StoreError::Validation("malformed pubkey"));
        }
        let parsed = parse_email(email).ok_or(StoreError::Validation("malformed email"))?;
        let mut conn = self.conn.lock().expect("store mutex never poisoned");
        let tx = conn.transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT pubkey FROM vip_email_bindings WHERE email = ?1",
                params![parsed.email],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_pubkey) = existing {
            if existing_pubkey != pubkey {
                return Err(StoreError::Conflict("vip_email_already_bound"));
            }
        } else {
            tx.execute(
                "INSERT INTO vip_email_bindings
                   (email, localpart, domain, pubkey, created_at, disabled_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![parsed.email, parsed.localpart, parsed.domain, pubkey, now],
            )?;
        }
        tx.execute(
            "INSERT INTO native_principals (pubkey, created_at)
             VALUES (?1, ?2)
             ON CONFLICT(pubkey) DO NOTHING",
            params![pubkey, now],
        )?;
        tx.execute(
            "INSERT INTO principal_links (email, pubkey, verified_at, revoked_at)
             VALUES (?1, ?2, ?3, NULL)
             ON CONFLICT(email) DO UPDATE SET
                pubkey = excluded.pubkey,
                verified_at = excluded.verified_at,
                revoked_at = NULL",
            params![parsed.email, pubkey, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn disable_vip_email(&self, email: &str, now: u64) -> Result<(), StoreError> {
        let parsed = parse_email(email).ok_or(StoreError::Validation("malformed email"))?;
        self.conn
            .lock()
            .expect("store mutex never poisoned")
            .execute(
                "UPDATE vip_email_bindings
             SET disabled_at = COALESCE(disabled_at, ?2)
             WHERE email = ?1",
                params![parsed.email, now],
            )?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn
            .lock()
            .expect("store mutex never poisoned")
            .execute_batch(
                "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS native_principals (
              pubkey TEXT PRIMARY KEY,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vip_email_bindings (
              email TEXT PRIMARY KEY,
              localpart TEXT NOT NULL,
              domain TEXT NOT NULL,
              pubkey TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              disabled_at INTEGER
            );
            CREATE UNIQUE INDEX IF NOT EXISTS vip_email_bindings_name
              ON vip_email_bindings(localpart, domain);
            CREATE TABLE IF NOT EXISTS principal_links (
              email TEXT PRIMARY KEY,
              pubkey TEXT NOT NULL,
              verified_at INTEGER NOT NULL,
              revoked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS email_challenges (
              token_hash TEXT PRIMARY KEY,
              email TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at INTEGER,
              created_at INTEGER NOT NULL
            );
            ",
            )?;
        Ok(())
    }

    fn create_email_challenge(
        &self,
        email: &str,
        token_hash: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.conn
            .lock()
            .expect("store mutex never poisoned")
            .execute(
                "INSERT INTO email_challenges (token_hash, email, expires_at, used_at, created_at)
             VALUES (?1, ?2, ?3, NULL, ?4)",
                params![token_hash, email, expires_at, now],
            )?;
        Ok(())
    }

    fn redeem_email_challenge(&self, token_hash: &str, now: u64) -> Result<String, StoreError> {
        let mut conn = self.conn.lock().expect("store mutex never poisoned");
        let tx = conn.transaction()?;
        let row: Option<(String, u64, Option<u64>)> = tx
            .query_row(
                "SELECT email, expires_at, used_at
                 FROM email_challenges
                 WHERE token_hash = ?1",
                params![token_hash],
                |row| Ok((row.get(0)?, row.get::<_, u64>(1)?, row.get(2)?)),
            )
            .optional()?;
        let (email, expires_at, used_at) =
            row.ok_or(StoreError::Validation("unknown_or_expired_email_challenge"))?;
        if used_at.is_some() || now > expires_at {
            return Err(StoreError::Validation("unknown_or_expired_email_challenge"));
        }
        tx.execute(
            "UPDATE email_challenges SET used_at = ?1 WHERE token_hash = ?2",
            params![now, token_hash],
        )?;
        tx.commit()?;
        Ok(email)
    }

    fn nip05_pubkey(&self, localpart: &str, domain: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .lock()
            .expect("store mutex never poisoned")
            .query_row(
                "SELECT pubkey FROM vip_email_bindings
                 WHERE localpart = ?1 AND domain = ?2 AND disabled_at IS NULL",
                params![localpart, domain],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    fn active_binding_pubkey(&self, email: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .lock()
            .expect("store mutex never poisoned")
            .query_row(
                "SELECT pubkey FROM vip_email_bindings
                 WHERE email = ?1 AND disabled_at IS NULL",
                params![email],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("validation error: {0}")]
    Validation(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
}

pub fn router(state: AuthorityState) -> Router {
    Router::new()
        .route("/.well-known/nostr.json", get(nip05))
        .route("/api/v1/email-challenges", post(request_email_challenge))
        .route(
            "/api/v1/vip-email-bindings/redeem",
            post(redeem_vip_email_binding),
        )
        .route(
            "/api/v1/principal-resolution/satisfies-grant",
            post(satisfies_grant),
        )
        .with_state(state)
}

async fn nip05(
    State(state): State<AuthorityState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(name) = query.get("name") else {
        return Json(serde_json::json!({ "names": {} }));
    };
    if !valid_nip05_localpart(name) {
        return Json(serde_json::json!({ "names": {} }));
    }
    match state
        .store
        .nip05_pubkey(name, &state.config.finite_vip_domain.to_ascii_lowercase())
    {
        Ok(Some(pubkey)) => Json(serde_json::json!({ "names": { name: pubkey } })),
        Ok(None) => Json(serde_json::json!({ "names": {} })),
        Err(_) => Json(serde_json::json!({ "names": {} })),
    }
}

async fn request_email_challenge(
    State(state): State<AuthorityState>,
    Json(request): Json<EmailChallengeRequest>,
) -> impl IntoResponse {
    let Some(email) = normalize_finite_vip_email(&request.email, &state.config.finite_vip_domain)
    else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_finite_vip_email");
    };
    let token = random_token();
    let now = state.clock.now();
    let token_hash = token_hash(&token);
    if let Err(error) = state.store.create_email_challenge(
        &email,
        &token_hash,
        now + state.config.email_challenge_ttl_seconds,
        now,
    ) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, store_error_code(&error));
    }
    if state.mailer.send_email_challenge(&email, &token).is_err() {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "mail_delivery_failed");
    }
    Json(EmailChallengeResponse { email }).into_response()
}

async fn redeem_vip_email_binding(
    State(state): State<AuthorityState>,
    original_uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let actor = match authenticate(&state, &headers, "POST", &original_uri, Some(&body)) {
        Ok(actor) => actor,
        Err(error) => return api_error(error.status, error.code),
    };
    let request: VipEmailRedeemRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    let Some(email) = normalize_finite_vip_email(&request.email, &state.config.finite_vip_domain)
    else {
        return api_error(StatusCode::BAD_REQUEST, "invalid_finite_vip_email");
    };
    let now = state.clock.now();
    let token_email = match state
        .store
        .redeem_email_challenge(&token_hash(&request.token), now)
    {
        Ok(token_email) => token_email,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, store_error_code(&error)),
    };
    if token_email != email {
        return api_error(StatusCode::BAD_REQUEST, "email_challenge_mismatch");
    }
    match state.store.bind_vip_email(&email, &actor, now) {
        Ok(()) => Json(VipEmailRedeemResponse {
            email: email.clone(),
            pubkey: actor,
            nip05: email,
        })
        .into_response(),
        Err(StoreError::Conflict(code)) => api_error(StatusCode::CONFLICT, code),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, store_error_code(&error)),
    }
}

async fn satisfies_grant(
    State(state): State<AuthorityState>,
    Json(request): Json<SatisfiesGrantRequest>,
) -> impl IntoResponse {
    if !hex::is_hex32(&request.actor_pubkey) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_actor_pubkey");
    }
    let satisfied =
        resolve_grant(&state, &request.grant, &request.actor_pubkey).unwrap_or_default();
    let principal = if satisfied {
        Some(PrincipalResponse {
            kind: "native",
            pubkey: request.actor_pubkey,
        })
    } else {
        None
    };
    Json(SatisfiesGrantResponse {
        satisfied,
        principal,
    })
    .into_response()
}

fn authenticate(
    state: &AuthorityState,
    headers: &HeaderMap,
    method: &str,
    original_uri: &OriginalUri,
    body: Option<&[u8]>,
) -> Result<String, ApiFailure> {
    let Some(header_value) = headers.get(header::AUTHORIZATION) else {
        return Err(ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "missing_authorization",
        ));
    };
    let Ok(header_value) = header_value.to_str() else {
        return Err(ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "malformed_authorization",
        ));
    };
    let path_and_query = original_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.config.normalized_base_url(), path_and_query);
    nip98::verify_auth_header(header_value, &url, method, body, state.clock.now())
        .map_err(|_| ApiFailure::new(StatusCode::UNAUTHORIZED, "nip98_rejected"))
}

fn resolve_grant(
    state: &AuthorityState,
    grant: &str,
    actor_pubkey: &str,
) -> Result<bool, StoreError> {
    let trimmed = grant.trim();
    if let Ok(pubkey) = npub::decode(trimmed) {
        return Ok(hex::encode(&pubkey) == actor_pubkey);
    }
    if hex::is_hex32(trimmed) {
        return Ok(trimmed.eq_ignore_ascii_case(actor_pubkey));
    }
    let Some(email) = parse_email(trimmed) else {
        return Ok(false);
    };
    if email.domain != state.config.finite_vip_domain.to_ascii_lowercase() {
        return Ok(false);
    }
    Ok(state
        .store
        .active_binding_pubkey(&email.email)?
        .is_some_and(|pubkey| pubkey == actor_pubkey))
}

fn api_error(status: StatusCode, code: &'static str) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({
            "error": code,
        })),
    )
        .into_response()
}

struct ApiFailure {
    status: StatusCode,
    code: &'static str,
}

impl ApiFailure {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
}

fn store_error_code(error: &StoreError) -> &'static str {
    match error {
        StoreError::Validation(code) | StoreError::Conflict(code) => code,
        StoreError::Sqlite(_) | StoreError::Io(_) => "store_error",
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

fn token_hash(token: &str) -> String {
    hex::encode(&Sha256::digest(token.as_bytes()))
}

fn normalize_finite_vip_email(email: &str, finite_vip_domain: &str) -> Option<String> {
    let parsed = parse_email(email)?;
    (parsed.domain == finite_vip_domain.to_ascii_lowercase()).then_some(parsed.email)
}

#[derive(Debug)]
struct ParsedEmail {
    email: String,
    localpart: String,
    domain: String,
}

fn parse_email(email: &str) -> Option<ParsedEmail> {
    let email = email.trim().to_ascii_lowercase();
    let (localpart, domain) = email.split_once('@')?;
    if localpart.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || !valid_nip05_localpart(localpart)
    {
        return None;
    }
    let localpart = localpart.to_owned();
    let domain = domain.to_owned();
    Some(ParsedEmail {
        email,
        localpart,
        domain,
    })
}

fn valid_nip05_localpart(localpart: &str) -> bool {
    !localpart.is_empty()
        && localpart
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

#[derive(Debug, Deserialize)]
struct EmailChallengeRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct EmailChallengeResponse {
    email: String,
}

#[derive(Debug, Deserialize)]
struct VipEmailRedeemRequest {
    email: String,
    token: String,
}

#[derive(Debug, Serialize)]
struct VipEmailRedeemResponse {
    email: String,
    pubkey: String,
    nip05: String,
}

#[derive(Debug, Deserialize)]
struct SatisfiesGrantRequest {
    grant: String,
    actor_pubkey: String,
}

#[derive(Debug, Serialize)]
struct SatisfiesGrantResponse {
    satisfied: bool,
    principal: Option<PrincipalResponse>,
}

#[derive(Debug, Serialize)]
struct PrincipalResponse {
    kind: &'static str,
    pubkey: String,
}
