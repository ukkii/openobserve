// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use config::{get_config, meta::user::UserRole};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration as CookieDuration, OffsetDateTime};
use url::Url;

const DISCOVERY_URL: &str = "https://accounts.google.com/.well-known/openid-configuration";
const STATE_COOKIE: &str = "o2_google_state";
const SESSION_COOKIE: &str = "o2_session";
const LOGIN_TTL_SECS: u64 = 600;
const PENDING_LOGIN_PREFIX: &str = "google_pending:";

static JWKS_CACHE: LazyLock<tokio::sync::RwLock<Option<CachedJwks>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(None));
static DISCOVERY_CACHE: LazyLock<tokio::sync::RwLock<Option<CachedDiscovery>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(None));

#[derive(Deserialize, Serialize)]
struct PendingLogin {
    nonce: String,
    verifier: String,
}

struct CachedJwks {
    body: String,
    expires_at: Instant,
}

struct CachedDiscovery {
    value: Discovery,
    expires_at: Instant,
}

#[derive(Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct Claims {
    nonce: String,
    email: String,
    email_verified: bool,
}

#[derive(Serialize)]
pub struct CommunitySession {
    email: String,
    first_name: String,
    last_name: String,
}

pub fn is_enabled() -> bool {
    valid_config().is_some()
}

pub async fn login(cookies: CookieJar) -> Response {
    let Some((client_id, _, redirect_url)) = valid_config() else {
        return (StatusCode::NOT_FOUND, "Google login is disabled").into_response();
    };
    let discovery = match fetch_discovery().await {
        Ok(discovery) => discovery,
        Err(error) => return auth_error(StatusCode::BAD_GATEWAY, error),
    };

    let state = config::utils::rand::random_hex(32);
    let nonce = config::utils::rand::random_hex(32);
    let verifier = URL_SAFE_NO_PAD.encode(config::utils::rand::random_bytes(48));
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let pending = PendingLogin {
        nonce: nonce.clone(),
        verifier,
    };
    if let Err(error) = store_pending(&state, &pending).await {
        return auth_error(StatusCode::INTERNAL_SERVER_ERROR, error);
    }

    let authorization_url = build_authorization_url(
        &discovery.authorization_endpoint,
        &client_id,
        &redirect_url,
        &state,
        &nonce,
        &challenge,
    );
    let cookie = state_cookie(state, redirect_is_secure(&redirect_url));
    (
        cookies.add(cookie),
        Redirect::temporary(authorization_url.as_str()),
    )
        .into_response()
}

pub async fn callback(cookies: CookieJar, Query(query): Query<CallbackQuery>) -> Response {
    let config = valid_config();
    let secure = config
        .as_ref()
        .is_none_or(|(_, _, redirect_url)| redirect_is_secure(redirect_url));
    let clear_state = expired_cookie(STATE_COOKIE, secure);
    if query.error.is_some() {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    }
    let Some(state) = query.state.as_deref() else {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    };
    if !state_matches(&cookies, state) {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    }
    let Some((client_id, client_secret, redirect_url)) = config else {
        return (cookies.add(clear_state), StatusCode::NOT_FOUND).into_response();
    };
    let Ok(pending) = consume_pending(state).await else {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    };
    let Some(code) = query.code.as_deref() else {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    };

    let discovery = match fetch_discovery().await {
        Ok(discovery) => discovery,
        Err(error) => return auth_error(StatusCode::BAD_GATEWAY, error),
    };
    let token = match exchange_code(
        &discovery,
        code,
        &pending.verifier,
        &client_id,
        &client_secret,
        &redirect_url,
    )
    .await
    {
        Ok(token) => token,
        Err(error) => return auth_error(StatusCode::UNAUTHORIZED, error),
    };
    let claims =
        match validate_id_token(&token.id_token, &discovery, &client_id, &pending.nonce).await {
            Ok(claims) => claims,
            Err(error) => return auth_error(StatusCode::UNAUTHORIZED, error),
        };
    let email = claims.email.trim().to_lowercase();
    if !claims.email_verified || !existing_login_user(&email).await {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    }

    let now = chrono::Utc::now().timestamp();
    let ttl_secs = get_config().auth.cookie_max_age.max(1);
    let expires_at = session_expiry(now, ttl_secs);
    let session_id = config::utils::rand::random_hex(32);
    if let Err(error) = db::session::set_with_expiry(
        &session_id,
        &format!("Community {email}"),
        expires_at.saturating_mul(1_000_000),
    )
    .await
    {
        return auth_error(StatusCode::INTERNAL_SERVER_ERROR, error);
    }

    let jar = cookies.add(clear_state).add(session_cookie(
        session_id,
        ttl_secs,
        redirect_is_secure(&redirect_url),
    ));
    (jar, Redirect::temporary(&console_url())).into_response()
}

pub async fn session(cookies: CookieJar) -> Response {
    let Some(session_id) = cookies.get(SESSION_COOKIE).map(Cookie::value) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(token) = db::session::get(session_id).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(email) = token.strip_prefix("Community ").map(str::trim) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(user) = db::user::get_user_by_email(email).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !login_user_allowed(&user) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(CommunitySession {
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
    })
    .into_response()
}

fn valid_config() -> Option<(String, String, String)> {
    let cfg = get_config();
    let client_id = cfg.auth.google_client_id.trim();
    let client_secret = cfg.auth.google_client_secret.trim();
    let redirect_url = cfg.auth.google_redirect_url.trim();
    if client_id.is_empty() || client_secret.is_empty() || !valid_redirect_url(redirect_url) {
        return None;
    }
    Some((
        client_id.to_string(),
        client_secret.to_string(),
        redirect_url.to_string(),
    ))
}

fn valid_redirect_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    matches!(
        (url.scheme(), url.host_str()),
        ("https", Some(_)) | ("http", Some("localhost" | "127.0.0.1" | "::1"))
    )
}

fn redirect_is_secure(redirect_url: &str) -> bool {
    Url::parse(redirect_url).is_ok_and(|url| url.scheme() == "https")
}

fn state_matches(cookies: &CookieJar, state: &str) -> bool {
    cookies.get(STATE_COOKIE).map(Cookie::value) == Some(state)
}

fn valid_google_endpoint(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && matches!(
                url.host_str(),
                Some("accounts.google.com" | "oauth2.googleapis.com" | "www.googleapis.com")
            )
    })
}

async fn fetch_discovery() -> Result<Discovery, anyhow::Error> {
    if let Some(cached) = DISCOVERY_CACHE.read().await.as_ref()
        && cached.expires_at > Instant::now()
    {
        return Ok(cached.value.clone());
    }
    let response = reqwest::Client::new()
        .get(DISCOVERY_URL)
        .send()
        .await?
        .error_for_status()?;
    let max_age = response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(cache_max_age);
    let discovery = response.json::<Discovery>().await?;
    if discovery.issuer != "https://accounts.google.com"
        || !valid_google_endpoint(&discovery.authorization_endpoint)
        || !valid_google_endpoint(&discovery.token_endpoint)
        || !valid_google_endpoint(&discovery.jwks_uri)
    {
        anyhow::bail!("Google discovery metadata is invalid");
    }
    *DISCOVERY_CACHE.write().await = max_age.map(|seconds| CachedDiscovery {
        value: discovery.clone(),
        expires_at: Instant::now() + Duration::from_secs(seconds),
    });
    Ok(discovery)
}

fn build_authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_url: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Url {
    let mut url = Url::parse(endpoint).expect("validated discovery authorization URL");
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_url)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    url
}

fn pending_key(state: &str) -> String {
    format!("{PENDING_LOGIN_PREFIX}{state}")
}

fn session_expiry(now: i64, ttl_secs: i64) -> i64 {
    now.saturating_add(ttl_secs.max(1))
}

async fn store_pending(state: &str, pending: &PendingLogin) -> Result<(), anyhow::Error> {
    let expires_at = chrono::Utc::now()
        .timestamp_micros()
        .saturating_add((LOGIN_TTL_SECS as i64).saturating_mul(1_000_000));
    // Pending OAuth state is not a user session, so it must not enter cluster session caches.
    infra::table::sessions::set_with_expiry(
        &pending_key(state),
        &serde_json::to_string(pending)?,
        expires_at,
    )
    .await
    .map_err(Into::into)
}

async fn consume_pending(state: &str) -> Result<PendingLogin, anyhow::Error> {
    let session = infra::table::sessions::take(&pending_key(state)).await?;
    let Some(session) = session else {
        anyhow::bail!("Pending login not found");
    };
    if session.expires_at < chrono::Utc::now().timestamp_micros() {
        anyhow::bail!("Pending login expired");
    }
    Ok(serde_json::from_str(&session.access_token)?)
}

async fn exchange_code(
    discovery: &Discovery,
    code: &str,
    verifier: &str,
    client_id: &str,
    client_secret: &str,
    redirect_url: &str,
) -> Result<TokenResponse, anyhow::Error> {
    Ok(reqwest::Client::new()
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_url),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn validate_id_token(
    token: &str,
    discovery: &Discovery,
    client_id: &str,
    nonce: &str,
) -> Result<Claims, anyhow::Error> {
    let jwks: jwk::JwkSet = serde_json::from_str(&fetch_jwks(&discovery.jwks_uri).await?)?;
    validate_id_token_with_jwks(token, discovery, client_id, nonce, &jwks)
}

fn validate_id_token_with_jwks(
    token: &str,
    discovery: &Discovery,
    client_id: &str,
    nonce: &str,
    jwks: &jwk::JwkSet,
) -> Result<Claims, anyhow::Error> {
    let header = decode_header(token)?;
    if header.alg != Algorithm::RS256 {
        anyhow::bail!("unsupported Google ID token algorithm");
    }
    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("missing ID token key id"))?;
    let key = jwks
        .find(&kid)
        .ok_or_else(|| anyhow::anyhow!("ID token signing key not found"))?;
    let jwk::AlgorithmParameters::RSA(rsa) = &key.algorithm else {
        anyhow::bail!("ID token signing key is not RSA");
    };
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[discovery.issuer.as_str()]);
    validation.validate_exp = true;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?,
        &validation,
    )?
    .claims;
    if claims.nonce != nonce {
        anyhow::bail!("ID token nonce does not match");
    }
    if !claims.email_verified {
        anyhow::bail!("Google email is not verified");
    }
    Ok(claims)
}

async fn fetch_jwks(uri: &str) -> Result<String, anyhow::Error> {
    if let Some(cached) = JWKS_CACHE.read().await.as_ref()
        && cached.expires_at > Instant::now()
    {
        return Ok(cached.body.clone());
    }
    let response = reqwest::Client::new()
        .get(uri)
        .send()
        .await?
        .error_for_status()?;
    let max_age = response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(cache_max_age);
    let body = response.text().await?;
    let _: jwk::JwkSet = serde_json::from_str(&body)?;
    *JWKS_CACHE.write().await = max_age.map(|seconds| CachedJwks {
        body: body.clone(),
        expires_at: Instant::now() + Duration::from_secs(seconds),
    });
    Ok(body)
}

fn cache_max_age(value: &str) -> Option<u64> {
    value.split(',').find_map(|directive| {
        directive
            .trim()
            .strip_prefix("max-age=")
            .and_then(|value| value.parse().ok())
    })
}

async fn existing_login_user(email: &str) -> bool {
    db::user::get_user_by_email(email)
        .await
        .is_some_and(|user| login_user_allowed(&user))
}

fn login_user_allowed(user: &config::meta::user::DBUser) -> bool {
    user.organizations.iter().any(|org| {
        !matches!(
            org.role,
            UserRole::ServiceAccount | UserRole::SreAgent | UserRole::User
        )
    })
}

fn state_cookie(value: String, secure: bool) -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, value))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(LOGIN_TTL_SECS as i64))
        .expires(OffsetDateTime::now_utc() + CookieDuration::seconds(LOGIN_TTL_SECS as i64))
        .build()
}

fn session_cookie(value: String, ttl_secs: i64, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, value))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(ttl_secs))
        .expires(OffsetDateTime::now_utc() + CookieDuration::seconds(ttl_secs))
        .build()
}

fn expired_cookie(name: &'static str, secure: bool) -> Cookie<'static> {
    Cookie::build((name, ""))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::ZERO)
        .build()
}

fn console_url() -> String {
    let cfg = get_config();
    format!(
        "{}{}/web/google/cb",
        cfg.common.web_url, cfg.common.base_uri
    )
}

fn auth_error(status: StatusCode, error: impl std::fmt::Display) -> Response {
    log::warn!("Google login failed: {error}");
    (status, "Google login failed").into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use common::infra::config::{USER_SESSIONS, USER_SESSIONS_EXPIRY};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;

    use super::*;

    const CLIENT_ID: &str = "community-client";
    const KID: &str = "test-key";
    const PRIVATE_KEY: &[u8] = include_bytes!("testdata/google_rsa_private.pem");
    const MODULUS: &str = "tsQsUV8QpqrygsY-2-JCQ6Fw8_omM71IM2N_R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04LHb2HJAYlz25-lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ_wcBOnyCgb3yLcvJrXyrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0NfFdfsZhTT8YbxBvA8FdODgEwx7u_vf3J9qbi4-Kv8cvqyJuleIRSjVXPsIMnoejIn04APPKIjpMyQdnWlby7rNyQtE4-CV-jcFjqJbE_Xilcvqxt6DirjFCvYeKYl1uHLw";

    #[derive(Clone, Serialize)]
    struct TestClaims {
        iss: String,
        aud: String,
        exp: i64,
        nonce: String,
        email: String,
        email_verified: bool,
    }

    fn discovery() -> Discovery {
        Discovery {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        }
    }

    fn jwks() -> jwk::JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": KID,
                "n": MODULUS,
                "e": "AQAB"
            }]
        }))
        .unwrap()
    }

    fn valid_claims() -> TestClaims {
        TestClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: CLIENT_ID.to_string(),
            exp: chrono::Utc::now().timestamp() + 300,
            nonce: "expected-nonce".to_string(),
            email: "viewer@example.com".to_string(),
            email_verified: true,
        }
    }

    fn signed(claims: &TestClaims, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(str::to_string);
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn validate(token: &str) -> Result<Claims, anyhow::Error> {
        validate_id_token_with_jwks(token, &discovery(), CLIENT_ID, "expected-nonce", &jwks())
    }

    async fn meta_store() {
        static ONCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        ONCE.get_or_init(|| async {
            infra::db::create_table().await.unwrap();
            infra::db_init().await.unwrap();
            infra::table::migrate().await.unwrap();
        })
        .await;
    }

    fn db_user(role: UserRole) -> config::meta::user::DBUser {
        config::meta::user::DBUser {
            email: "viewer@example.com".to_string(),
            first_name: "View".to_string(),
            last_name: "Er".to_string(),
            password: String::new(),
            salt: String::new(),
            organizations: vec![config::meta::user::UserOrg {
                name: "acme".to_string(),
                org_name: "Acme".to_string(),
                token: String::new(),
                rum_token: None,
                role,
            }],
            is_external: true,
            password_ext: None,
        }
    }

    #[test]
    fn redirect_urls_allow_https_and_local_http_only() {
        assert!(valid_redirect_url(
            "https://example.com/config/google_callback"
        ));
        assert!(valid_redirect_url(
            "http://localhost:5080/config/google_callback"
        ));
        assert!(valid_redirect_url(
            "http://127.0.0.1:5080/config/google_callback"
        ));
        assert!(!valid_redirect_url(
            "http://example.com/config/google_callback"
        ));
        assert!(!valid_redirect_url("https://user@example.com/callback"));
        assert!(!valid_redirect_url("https://example.com/callback#fragment"));
    }

    #[test]
    fn authorization_request_is_pkce_and_minimal_scope() {
        let url = build_authorization_url(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "client",
            "https://example.com/callback",
            "state",
            "nonce",
            "challenge",
        );
        let pairs = url.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(
            pairs.get("scope").map(|value| value.as_ref()),
            Some("openid email")
        );
        assert_eq!(
            pairs
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert!(!pairs.contains_key("access_type"));
        assert!(!pairs.contains_key("prompt"));
    }

    #[test]
    fn cache_honors_only_explicit_max_age() {
        assert_eq!(cache_max_age("public, max-age=3600"), Some(3600));
        assert_eq!(cache_max_age("no-cache"), None);
        assert_eq!(cache_max_age("public, s-maxage=60"), None);
    }

    #[test]
    fn pending_state_uses_the_shared_session_namespace() {
        assert_eq!(pending_key("one-use-state"), "google_pending:one-use-state");
        let pending = PendingLogin {
            nonce: "nonce".to_string(),
            verifier: "verifier".to_string(),
        };
        assert_eq!(
            serde_json::from_str::<PendingLogin>(&serde_json::to_string(&pending).unwrap())
                .unwrap()
                .nonce,
            "nonce"
        );
    }

    #[test]
    fn state_cookie_must_match_callback_state() {
        let cookies = CookieJar::new().add(state_cookie("expected".to_string(), true));
        assert!(state_matches(&cookies, "expected"));
        assert!(!state_matches(&cookies, "different"));
    }

    #[tokio::test]
    async fn callback_rejects_a_state_cookie_mismatch() {
        let response = callback(
            CookieJar::new().add(state_cookie("expected".to_string(), true)),
            Query(CallbackQuery {
                code: Some("code".to_string()),
                state: Some("different".to_string()),
                error: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn pending_state_is_one_use_and_never_enters_user_session_caches() {
        meta_store().await;
        let state = format!("test-{}", config::ider::uuid());
        let pending = PendingLogin {
            nonce: "nonce".to_string(),
            verifier: "verifier".to_string(),
        };

        store_pending(&state, &pending).await.unwrap();
        let key = pending_key(&state);
        assert!(!USER_SESSIONS.contains_key(&key));
        assert!(!USER_SESSIONS_EXPIRY.contains_key(&key));
        assert_eq!(consume_pending(&state).await.unwrap().nonce, "nonce");
        assert!(consume_pending(&state).await.is_err());
    }

    #[tokio::test]
    async fn nonexistent_local_user_cannot_complete_google_login() {
        meta_store().await;
        let email = format!("missing-{}@example.com", config::ider::uuid());
        assert!(!existing_login_user(&email).await);
    }

    #[test]
    fn google_cookies_are_http_only_lax_and_bounded() {
        for cookie in [
            state_cookie("state".to_string(), true),
            session_cookie("session".to_string(), 3600, true),
        ] {
            assert_eq!(cookie.http_only(), Some(true));
            assert_eq!(cookie.secure(), Some(true));
            assert_eq!(cookie.same_site(), Some(SameSite::Lax));
            assert_eq!(cookie.path(), Some("/"));
            assert!(cookie.max_age().is_some());
            assert!(cookie.expires().is_some());
        }
    }

    #[test]
    fn session_lifetime_uses_configured_cookie_ttl_not_id_token_expiry() {
        assert_eq!(session_expiry(1_000, 86_400), 87_400);
        assert_eq!(session_expiry(1_000, 0), 1_001);
    }

    #[test]
    fn existing_google_login_requires_an_allowed_membership() {
        assert!(login_user_allowed(&db_user(UserRole::Viewer)));
        assert!(login_user_allowed(&db_user(UserRole::Editor)));
        assert!(!login_user_allowed(&db_user(UserRole::User)));
        assert!(!login_user_allowed(&db_user(UserRole::ServiceAccount)));
        let mut missing = db_user(UserRole::Viewer);
        missing.organizations.clear();
        assert!(!login_user_allowed(&missing));
    }

    #[test]
    fn id_token_accepts_a_valid_google_rs256_token() {
        let claims = validate(&signed(&valid_claims(), Some(KID))).unwrap();
        assert_eq!(claims.email, "viewer@example.com");
    }

    #[test]
    fn id_token_rejects_signature_algorithm_and_key_id_failures() {
        let valid = signed(&valid_claims(), Some(KID));
        let (prefix, signature) = valid.rsplit_once('.').unwrap();
        let replacement = if signature.starts_with('A') { "B" } else { "A" };
        let bad_signature = format!("{prefix}.{replacement}{}", &signature[1..]);
        assert!(validate(&bad_signature).is_err());
        assert!(validate(&signed(&valid_claims(), None)).is_err());
        assert!(validate(&signed(&valid_claims(), Some("unknown"))).is_err());

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let hs256 = encode(
            &header,
            &valid_claims(),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        assert!(validate(&hs256).is_err());
    }

    #[test]
    fn id_token_rejects_invalid_standard_and_google_claims() {
        let cases = [
            TestClaims {
                iss: "https://issuer.example.com".to_string(),
                ..valid_claims()
            },
            TestClaims {
                aud: "other-client".to_string(),
                ..valid_claims()
            },
            TestClaims {
                exp: chrono::Utc::now().timestamp() - 300,
                ..valid_claims()
            },
            TestClaims {
                nonce: "different".to_string(),
                ..valid_claims()
            },
            TestClaims {
                email_verified: false,
                ..valid_claims()
            },
        ];
        for claims in cases {
            assert!(validate(&signed(&claims, Some(KID))).is_err());
        }
    }
}
