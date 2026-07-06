//! Identity Authority contract tests. These exercise the public HTTP seam
//! against temporary SQLite storage so product integrations can depend on the
//! behavior rather than the implementation layout.

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use finite_identity::authority::{
    AuthorityConfig, AuthorityState, FixedClock, IdentityStore, Mailer, router,
};
use finite_identity::{hex, nip98, npub};
use tower::ServiceExt as _;

const NOW: u64 = 1_788_000_000;
const BASE_URL: &str = "https://identity.test";
const ALICE_EMAIL: &str = "alice@finite.vip";
const ALICE_LOCALPART: &str = "alice";
const ALICE_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
const BOB_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
];
const ALICE_PUBKEY: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

#[derive(Default)]
struct RecordingMailer {
    deliveries: Mutex<Vec<(String, String)>>,
}

impl RecordingMailer {
    fn last_token_for(&self, email: &str) -> String {
        self.deliveries
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|(delivered_email, token)| (delivered_email == email).then(|| token.clone()))
            .expect("token delivered")
    }
}

impl Mailer for RecordingMailer {
    fn send_email_challenge(&self, email: &str, token: &str) -> Result<(), String> {
        self.deliveries
            .lock()
            .unwrap()
            .push((email.to_owned(), token.to_owned()));
        Ok(())
    }
}

fn fixture() -> (
    axum::Router,
    IdentityStore,
    Arc<RecordingMailer>,
    FixedClock,
) {
    let store = IdentityStore::open_memory().expect("open memory store");
    let mailer = Arc::new(RecordingMailer::default());
    let clock = FixedClock::new(NOW);
    let state = AuthorityState::new(
        store.clone(),
        Arc::clone(&mailer) as Arc<dyn Mailer>,
        clock.clone(),
        AuthorityConfig {
            external_base_url: BASE_URL.to_owned(),
            finite_vip_domain: "finite.vip".to_owned(),
            email_challenge_ttl_seconds: 600,
        },
    );
    (router(state), store, mailer, clock)
}

async fn json_request(
    app: axum::Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
    auth: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let bytes = serde_json::to_vec(&body).expect("json serializes");
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    let response = app
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).expect("response is json")
    };
    (status, value)
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&body).expect("response is json"),
    )
}

#[tokio::test]
async fn nip05_endpoint_serves_persisted_vip_name() {
    let (app, store, _mailer, _clock) = fixture();
    store
        .bind_vip_email(ALICE_EMAIL, ALICE_PUBKEY, NOW)
        .expect("persist binding");

    let (status, body) = get_json(app.clone(), "/.well-known/nostr.json?name=alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "names": {
                ALICE_LOCALPART: ALICE_PUBKEY,
            }
        })
    );

    let (status, body) = get_json(app, "/.well-known/nostr.json?name=unknown").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "names": {} }));
}

#[tokio::test]
async fn binding_vip_email_requires_email_challenge_and_nip98() {
    let (app, _store, mailer, _clock) = fixture();
    let (status, challenge) = json_request(
        app.clone(),
        "POST",
        "/api/v1/email-challenges",
        serde_json::json!({ "email": ALICE_EMAIL }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(challenge["email"], ALICE_EMAIL);
    let token = mailer.last_token_for(ALICE_EMAIL);

    let redeem_body = serde_json::json!({ "email": ALICE_EMAIL, "token": token });
    let redeem_bytes = serde_json::to_vec(&redeem_body).unwrap();
    let auth = nip98::build_auth_header(
        &ALICE_SECRET,
        &format!("{BASE_URL}/api/v1/vip-email-bindings/redeem"),
        "POST",
        Some(&redeem_bytes),
        NOW,
    )
    .expect("build auth");
    let (status, redeemed) = json_request(
        app.clone(),
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        redeem_body.clone(),
        Some(auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(redeemed["email"], ALICE_EMAIL);
    assert_eq!(redeemed["pubkey"], ALICE_PUBKEY);
    assert_eq!(redeemed["nip05"], ALICE_EMAIL);

    let (status, body) = get_json(app.clone(), "/.well-known/nostr.json?name=alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["names"][ALICE_LOCALPART], ALICE_PUBKEY);

    let replay_auth = nip98::build_auth_header(
        &ALICE_SECRET,
        &format!("{BASE_URL}/api/v1/vip-email-bindings/redeem"),
        "POST",
        Some(&redeem_bytes),
        NOW,
    )
    .unwrap();
    let (status, _body) = json_request(
        app,
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        redeem_body,
        Some(replay_auth),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn binding_vip_email_rejects_missing_auth_and_expired_challenge() {
    let (app, _store, mailer, clock) = fixture();
    let (status, _challenge) = json_request(
        app.clone(),
        "POST",
        "/api/v1/email-challenges",
        serde_json::json!({ "email": ALICE_EMAIL }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = mailer.last_token_for(ALICE_EMAIL);
    let body = serde_json::json!({ "email": ALICE_EMAIL, "token": token });

    let (status, missing_auth) = json_request(
        app.clone(),
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        body.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_auth["error"], "missing_authorization");

    let wrong_body = serde_json::json!({ "email": ALICE_EMAIL, "token": "wrong-token" });
    let wrong_body_bytes = serde_json::to_vec(&wrong_body).unwrap();
    let auth_for_wrong_body = nip98::build_auth_header(
        &ALICE_SECRET,
        &format!("{BASE_URL}/api/v1/vip-email-bindings/redeem"),
        "POST",
        Some(&wrong_body_bytes),
        NOW,
    )
    .unwrap();
    let (status, tampered_body) = json_request(
        app.clone(),
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        body.clone(),
        Some(auth_for_wrong_body),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(tampered_body["error"], "nip98_rejected");

    clock.set(NOW + 601);
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let auth = nip98::build_auth_header(
        &ALICE_SECRET,
        &format!("{BASE_URL}/api/v1/vip-email-bindings/redeem"),
        "POST",
        Some(&body_bytes),
        NOW + 601,
    )
    .unwrap();
    let (status, expired) = json_request(
        app,
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        body,
        Some(auth),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(expired["error"], "unknown_or_expired_email_challenge");
}

#[tokio::test]
async fn binding_same_vip_email_to_same_pubkey_is_idempotent() {
    let (app, _store, mailer, _clock) = fixture();
    request_and_redeem(app.clone(), &mailer, ALICE_EMAIL, &ALICE_SECRET).await;
    request_and_redeem(app.clone(), &mailer, ALICE_EMAIL, &ALICE_SECRET).await;

    let (status, body) = get_json(app, "/.well-known/nostr.json?name=alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["names"][ALICE_LOCALPART], ALICE_PUBKEY);
}

#[tokio::test]
async fn binding_vip_email_to_different_pubkey_is_rejected() {
    let (app, _store, mailer, _clock) = fixture();
    request_and_redeem(app.clone(), &mailer, ALICE_EMAIL, &ALICE_SECRET).await;

    let (status, _challenge) = json_request(
        app.clone(),
        "POST",
        "/api/v1/email-challenges",
        serde_json::json!({ "email": ALICE_EMAIL }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = mailer.last_token_for(ALICE_EMAIL);
    let body = serde_json::json!({ "email": ALICE_EMAIL, "token": token });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let auth = nip98::build_auth_header(
        &BOB_SECRET,
        &format!("{BASE_URL}/api/v1/vip-email-bindings/redeem"),
        "POST",
        Some(&body_bytes),
        NOW,
    )
    .unwrap();

    let (status, response) = json_request(
        app,
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        body,
        Some(auth),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(response["error"], "vip_email_already_bound");
}

#[tokio::test]
async fn disabled_vip_binding_is_not_served_as_nip05() {
    let (app, store, _mailer, _clock) = fixture();
    store
        .bind_vip_email(ALICE_EMAIL, ALICE_PUBKEY, NOW)
        .expect("persist binding");
    store.disable_vip_email(ALICE_EMAIL, NOW + 1).unwrap();

    let (status, body) = get_json(app, "/.well-known/nostr.json?name=alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "names": {} }));
}

#[tokio::test]
async fn product_grants_resolve_against_native_and_vip_principals() {
    let (app, store, _mailer, _clock) = fixture();
    store
        .bind_vip_email(ALICE_EMAIL, ALICE_PUBKEY, NOW)
        .expect("persist binding");
    let alice_npub = npub::encode(&hex::decode32(ALICE_PUBKEY).unwrap());

    let (status, by_email) = json_request(
        app.clone(),
        "POST",
        "/api/v1/principal-resolution/satisfies-grant",
        serde_json::json!({ "grant": ALICE_EMAIL, "actor_pubkey": ALICE_PUBKEY }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(by_email["satisfied"], true);
    assert_eq!(by_email["principal"]["kind"], "native");

    let (status, by_npub) = json_request(
        app.clone(),
        "POST",
        "/api/v1/principal-resolution/satisfies-grant",
        serde_json::json!({ "grant": alice_npub, "actor_pubkey": ALICE_PUBKEY }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(by_npub["satisfied"], true);

    let (status, third_party) = json_request(
        app.clone(),
        "POST",
        "/api/v1/principal-resolution/satisfies-grant",
        serde_json::json!({ "grant": "alice@example.com", "actor_pubkey": ALICE_PUBKEY }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(third_party["satisfied"], false);

    store.disable_vip_email(ALICE_EMAIL, NOW + 1).unwrap();
    let (status, disabled) = json_request(
        app,
        "POST",
        "/api/v1/principal-resolution/satisfies-grant",
        serde_json::json!({ "grant": ALICE_EMAIL, "actor_pubkey": ALICE_PUBKEY }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(disabled["satisfied"], false);
}

async fn request_and_redeem(
    app: axum::Router,
    mailer: &RecordingMailer,
    email: &str,
    secret: &[u8; 32],
) {
    let (status, _challenge) = json_request(
        app.clone(),
        "POST",
        "/api/v1/email-challenges",
        serde_json::json!({ "email": email }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = mailer.last_token_for(email);
    let body = serde_json::json!({ "email": email, "token": token });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let auth = nip98::build_auth_header(
        secret,
        &format!("{BASE_URL}/api/v1/vip-email-bindings/redeem"),
        "POST",
        Some(&body_bytes),
        NOW,
    )
    .unwrap();
    let (status, _redeemed) = json_request(
        app,
        "POST",
        "/api/v1/vip-email-bindings/redeem",
        body,
        Some(auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
