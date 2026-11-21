//! "Sign in with Kith": the whole browser flow against a mock OpenID provider.
//!
//! Needs a scratch Postgres: set `TEST_DATABASE_URL` (the test skips without it, as CI
//! has no database). The mock provider signs RS256 ID tokens and checks PKCE.
use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use opensourcepasswordmanager::{
    api::native::{native_router, router::NativeState},
    auth::{manager::AuthManager, OidcService, PasskeyService, SessionService},
    config::{AuthConfig, Config, OidcConfig},
    core::CryptoEngine,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use uuid::Uuid;

const CLIENT_ID: &str = "secretd";
const JWT_SECRET: &str = "test-jwt-secret-test-jwt-secret-0123";

// ── mock provider ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Idp {
    issuer: String,
    /// Set by the test once it has seen the authorization request.
    challenge: String,
    nonce: String,
    /// What the next ID token says.
    sub: String,
    email: Option<String>,
    email_verified: bool,
    /// Reject the token request (as if the code were bad).
    reject: bool,
    jwk: serde_json::Value,
    key: Option<jsonwebtoken::EncodingKey>,
}

type IdpState = Arc<Mutex<Idp>>;

async fn discovery(State(s): State<IdpState>) -> Json<serde_json::Value> {
    let i = s.lock().unwrap().issuer.clone();
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/oauth/authorize"),
        "token_endpoint": format!("{i}/oauth/token"),
        "jwks_uri": format!("{i}/.well-known/jwks.json"),
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks(State(s): State<IdpState>) -> Json<serde_json::Value> {
    Json(json!({ "keys": [s.lock().unwrap().jwk.clone()] }))
}

async fn token(
    State(s): State<IdpState>,
    Form(f): Form<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let i = s.lock().unwrap();
    let verifier = f.get("code_verifier").cloned().unwrap_or_default();
    let pkce_ok = B64.encode(Sha256::digest(verifier.as_bytes())) == i.challenge;
    if i.reject || !pkce_ok || f.get("code").map(String::as_str) != Some("good-code") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        );
    }
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": i.issuer, "aud": CLIENT_ID, "sub": i.sub, "iat": now, "exp": now + 300,
        "nonce": i.nonce, "email_verified": i.email_verified, "acr": "urn:kith:acr:aal2",
    });
    if let Some(e) = &i.email {
        claims["email"] = json!(e);
    }
    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    h.kid = Some("k1".into());
    let id_token = jsonwebtoken::encode(&h, &claims, i.key.as_ref().unwrap()).unwrap();
    (
        StatusCode::OK,
        Json(json!({"id_token": id_token, "access_token": "x", "token_type": "Bearer"})),
    )
}

async fn spawn_idp() -> (IdpState, String) {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(Idp {
        issuer: issuer.clone(),
        jwk: json!({
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
            "n": B64.encode(rsa.n().to_vec()), "e": B64.encode(rsa.e().to_vec()),
        }),
        key: Some(
            jsonwebtoken::EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap(),
        ),
        ..Default::default()
    }));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/token", post(token))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (state, issuer)
}

// ── the relying party under test ──────────────────────────────────────────────

struct App {
    router: Router,
    pool: sqlx::PgPool,
    sessions: Arc<SessionService>,
    org: Uuid,
}

async fn app(db_url: &str, issuer: &str, auto_provision: bool) -> App {
    std::env::set_var("SECRETD_KEK_ID", Uuid::new_v4().to_string());
    std::env::set_var(
        "SECRETD_KEK",
        base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
    );
    let pool = sqlx::PgPool::connect(db_url).await.unwrap();
    sqlx::migrate::Migrator::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
    )
    .await
    .unwrap()
    .run(&pool)
    .await
    .unwrap();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug) VALUES ('default', 'default')
         ON CONFLICT (slug) DO UPDATE SET name = 'default' RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let oidc_cfg = OidcConfig {
        id: "kith".into(),
        display_name: "Kith".into(),
        issuer: issuer.into(),
        client_id: CLIENT_ID.into(),
        client_secret: Some("s3cret".into()),
        redirect_uri: "http://localhost:8200/api/v1/auth/oidc/kith/callback".into(),
        scopes: vec![],
        auto_provision,
        acr_values: None,
    };
    let mut auth = AuthManager::new();
    let oidc = Arc::new(OidcService::new(vec![oidc_cfg.clone()]).unwrap());
    for p in oidc.all() {
        auth.register_boxed(p.clone());
    }
    let sessions = Arc::new(SessionService::from_secret(JWT_SECRET));
    let config = Config {
        listen_addr: "127.0.0.1:0".into(),
        database_url: db_url.into(),
        dev_root_token: None,
        jwt_secret: JWT_SECRET.into(),
        auth: AuthConfig {
            oidc: vec![oidc_cfg],
            ..Default::default()
        },
    };
    let router = native_router(NativeState {
        pool: pool.clone(),
        sessions: sessions.clone(),
        auth_manager: Arc::new(auth),
        config: Arc::new(config),
        crypto: Arc::new(CryptoEngine::from_env().unwrap()),
        passkey: Arc::new(PasskeyService::from_config(None, None)),
        oidc,
    });
    App {
        router,
        pool,
        sessions,
        org,
    }
}

struct Reply {
    status: StatusCode,
    location: String,
    cookies: Vec<String>,
    body: String,
}

async fn get_req(app: &App, uri: &str, cookie: Option<&str>) -> Reply {
    let mut req = Request::builder().uri(uri);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let resp = app
        .router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let h = resp.headers().clone();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    Reply {
        status,
        location: h
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().into())
            .unwrap_or_default(),
        cookies: h
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().into())
            .collect(),
        body: String::from_utf8_lossy(&body).into(),
    }
}

/// `start`, then play the browser and the provider's login page: remember what the
/// authorization request asked for, and return the callback URL + the flow cookie.
async fn begin(
    app: &App,
    idp: &IdpState,
    sub: &str,
    email: Option<&str>,
    verified: bool,
) -> (String, String) {
    let r = get_req(app, "/api/v1/auth/oidc/kith/start", None).await;
    assert_eq!(r.status, StatusCode::FOUND, "{}", r.body);
    let u = url::Url::parse(&r.location).unwrap();
    let q: HashMap<_, _> = u.query_pairs().into_owned().collect();
    assert_eq!(u.path(), "/oauth/authorize");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(
        q["redirect_uri"],
        "http://localhost:8200/api/v1/auth/oidc/kith/callback"
    );
    assert_eq!(q["scope"], "openid email profile");
    {
        let mut i = idp.lock().unwrap();
        i.challenge = q["code_challenge"].clone();
        i.nonce = q["nonce"].clone();
        i.sub = sub.into();
        i.email = email.map(Into::into);
        i.email_verified = verified;
        i.reject = false;
    }
    let cookie = r
        .cookies
        .iter()
        .find(|c| c.starts_with("secretd_oidc="))
        .unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"),
        "{cookie}"
    );
    let state = &q["state"];
    (
        format!("/api/v1/auth/oidc/kith/callback?code=good-code&state={state}"),
        format!("secretd_oidc={state}"),
    )
}

async fn user_count(app: &App, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

async fn add_user(app: &App, email: &str, active: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (org_id, email, is_active) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(app.org)
    .bind(email)
    .bind(active)
    .fetch_one(&app.pool)
    .await
    .unwrap()
}

fn session_of(app: &App, r: &Reply) -> opensourcepasswordmanager::auth::Claims {
    let c = r
        .cookies
        .iter()
        .find(|c| c.starts_with("secretd_token="))
        .expect("session cookie");
    assert!(
        c.contains("HttpOnly") && c.contains("SameSite=Strict"),
        "{c}"
    );
    let token = c
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("secretd_token=");
    app.sessions.validate(token).unwrap()
}

#[tokio::test]
async fn sign_in_with_kith() {
    let Ok(db) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping the OIDC flow test");
        return;
    };
    let (idp, issuer) = spawn_idp().await;
    let tag = Uuid::new_v4().simple().to_string();
    let app = app(&db, &issuer, false).await;

    // The login screen lists the provider as a redirect.
    let r = get_req(&app, "/api/v1/auth/providers", None).await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["providers"][0]["id"], "kith");
    assert_eq!(v["providers"][0]["kind"], "redirect");
    assert_eq!(v["providers"][0]["url"], "/api/v1/auth/oidc/kith/start");
    assert_eq!(
        get_req(&app, "/api/v1/auth/oidc/nope/start", None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // 1. A verified email that matches an existing user signs them in and binds the sub.
    let ada = format!("ada-{tag}@example.com");
    let ada_id = add_user(&app, &ada, true).await;
    let sub = format!("did:kith:{tag}");
    let (cb, cookie) = begin(&app, &idp, &sub, Some(&ada.to_uppercase()), true).await;
    let r = get_req(&app, &cb, Some(&cookie)).await;
    assert_eq!(r.location, "/ui/login?oidc=ok", "{r:?}", r = r.location);
    let claims = session_of(&app, &r);
    assert_eq!(claims.sub, ada_id.to_string());
    assert_eq!(claims.email, ada);
    assert!(r
        .cookies
        .iter()
        .any(|c| c.starts_with("secretd_oidc=;") && c.contains("Max-Age=0")));

    // 2. The same callback cannot be replayed.
    let r = get_req(&app, &cb, Some(&cookie)).await;
    assert_eq!(r.location, "/ui/login?oidc_error=expired");
    assert!(!r
        .cookies
        .iter()
        .any(|c| c.starts_with("secretd_token=") && !c.contains("Max-Age=0")));

    // 3. Now the sub is what counts: a different (even unverified) email still lands on Ada.
    let (cb, cookie) = begin(&app, &idp, &sub, Some("someone-else@example.com"), false).await;
    let r = get_req(&app, &cb, Some(&cookie)).await;
    assert_eq!(session_of(&app, &r).sub, ada_id.to_string());
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(&issuer)
    .bind(&sub)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);

    // 4. An unverified email must not link to an existing account.
    let bob = format!("bob-{tag}@example.com");
    add_user(&app, &bob, true).await;
    let (cb, cookie) = begin(&app, &idp, &format!("did:kith:bob{tag}"), Some(&bob), false).await;
    let r = get_req(&app, &cb, Some(&cookie)).await;
    assert_eq!(r.location, "/ui/login?oidc_error=unverified_email");
    assert!(!r.cookies.iter().any(|c| c.starts_with("secretd_token=")));

    // 5. A deactivated user stays out, by email or by sub.
    let eve = format!("eve-{tag}@example.com");
    add_user(&app, &eve, false).await;
    let (cb, cookie) = begin(&app, &idp, &format!("did:kith:eve{tag}"), Some(&eve), true).await;
    assert_eq!(
        get_req(&app, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=denied"
    );
    sqlx::query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind(ada_id)
        .execute(&app.pool)
        .await
        .unwrap();
    let (cb, cookie) = begin(&app, &idp, &sub, Some(&ada), true).await;
    assert_eq!(
        get_req(&app, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=denied"
    );
    sqlx::query("UPDATE users SET is_active = TRUE WHERE id = $1")
        .bind(ada_id)
        .execute(&app.pool)
        .await
        .unwrap();

    // 6. Unknown user: refused unless auto-provisioning is on.
    let zed = format!("zed-{tag}@example.com");
    let (cb, cookie) = begin(&app, &idp, &format!("did:kith:zed{tag}"), Some(&zed), true).await;
    assert_eq!(
        get_req(&app, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=no_account"
    );
    assert_eq!(user_count(&app, &zed).await, 0);
    let open = self::app(&db, &issuer, true).await;
    let (cb, cookie) = begin(&open, &idp, &format!("did:kith:zed{tag}"), Some(&zed), true).await;
    let r = get_req(&open, &cb, Some(&cookie)).await;
    assert_eq!(r.location, "/ui/login?oidc=ok");
    assert_eq!(session_of(&open, &r).email, zed);
    assert_eq!(user_count(&open, &zed).await, 1);
    // ...but never from an unverified email.
    let yan = format!("yan-{tag}@example.com");
    let (cb, cookie) = begin(
        &open,
        &idp,
        &format!("did:kith:yan{tag}"),
        Some(&yan),
        false,
    )
    .await;
    assert_eq!(
        get_req(&open, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=unverified_email"
    );
    assert_eq!(user_count(&open, &yan).await, 0);

    // 7. Login CSRF: the callback must come from the browser that started the flow.
    let (cb, _cookie) = begin(&app, &idp, &sub, Some(&ada), true).await;
    assert_eq!(
        get_req(&app, &cb, None).await.location,
        "/ui/login?oidc_error=expired"
    );
    let (cb, _cookie) = begin(&app, &idp, &sub, Some(&ada), true).await;
    assert_eq!(
        get_req(&app, &cb, Some("secretd_oidc=other"))
            .await
            .location,
        "/ui/login?oidc_error=expired"
    );
    // An invented state is no good either.
    let r = get_req(
        &app,
        "/api/v1/auth/oidc/kith/callback?code=good-code&state=forged",
        Some("secretd_oidc=forged"),
    )
    .await;
    assert_eq!(r.location, "/ui/login?oidc_error=expired");

    // 8. Provider-side failures never sign anyone in.
    let (cb, cookie) = begin(&app, &idp, &sub, Some(&ada), true).await;
    idp.lock().unwrap().nonce = "not-the-nonce".into(); // token replayed from another login
    assert_eq!(
        get_req(&app, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=failed"
    );
    let (cb, cookie) = begin(&app, &idp, &sub, Some(&ada), true).await;
    idp.lock().unwrap().reject = true;
    assert_eq!(
        get_req(&app, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=failed"
    );
    let (cb, cookie) = begin(&app, &idp, &sub, Some(&ada), true).await;
    let cb = cb.replace("code=good-code", "error=access_denied");
    assert_eq!(
        get_req(&app, &cb, Some(&cookie)).await.location,
        "/ui/login?oidc_error=denied"
    );
}
