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
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use axum::{
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
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::{Duration as CookieDuration, OffsetDateTime};
use url::Url;

const DISCOVERY_URL: &str = "https://accounts.google.com/.well-known/openid-configuration";
const STATE_COOKIE: &str = "o2_google_state";
const SESSION_COOKIE: &str = "o2_session";
const LOGIN_TTL_SECS: u64 = 600;

static PENDING_LOGINS: LazyLock<Mutex<HashMap<String, PendingLogin>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static JWKS_CACHE: LazyLock<tokio::sync::RwLock<Option<CachedJwks>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(None));

struct PendingLogin {
    nonce: String,
    verifier: String,
    expires_at: Instant,
}

struct CachedJwks {
    body: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
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
    exp: i64,
    nonce: String,
    email: String,
    email_verified: bool,
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
    PENDING_LOGINS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(
            state.clone(),
            PendingLogin {
                nonce: nonce.clone(),
                verifier,
                expires_at: Instant::now() + Duration::from_secs(LOGIN_TTL_SECS),
            },
        );

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
    let Some((client_id, client_secret, redirect_url)) = valid_config() else {
        return (StatusCode::NOT_FOUND, "Google login is disabled").into_response();
    };
    let clear_state = expired_cookie(STATE_COOKIE, redirect_is_secure(&redirect_url));
    if query.error.is_some() {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    }
    let Some(state) = query.state.as_deref() else {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    };
    if cookies.get(STATE_COOKIE).map(Cookie::value) != Some(state) {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    }
    let Some(pending) = consume_pending(state) else {
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
    let expires_at = claims
        .exp
        .min(now + get_config().auth.cookie_max_age.max(1));
    if expires_at <= now {
        return (cookies.add(clear_state), StatusCode::UNAUTHORIZED).into_response();
    }
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
        expires_at - now,
        redirect_is_secure(&redirect_url),
    ));
    (jar, Redirect::temporary(&console_url(&email))).into_response()
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
    let discovery = reqwest::Client::new()
        .get(DISCOVERY_URL)
        .send()
        .await?
        .error_for_status()?
        .json::<Discovery>()
        .await?;
    if discovery.issuer != "https://accounts.google.com"
        || !valid_google_endpoint(&discovery.authorization_endpoint)
        || !valid_google_endpoint(&discovery.token_endpoint)
        || !valid_google_endpoint(&discovery.jwks_uri)
    {
        anyhow::bail!("Google discovery metadata is invalid");
    }
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

fn consume_pending(state: &str) -> Option<PendingLogin> {
    let mut pending = PENDING_LOGINS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    pending.retain(|_, login| login.expires_at > Instant::now());
    pending.remove(state)
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
    let header = decode_header(token)?;
    if header.alg != Algorithm::RS256 {
        anyhow::bail!("unsupported Google ID token algorithm");
    }
    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("missing ID token key id"))?;
    let jwks: jwk::JwkSet = serde_json::from_str(&fetch_jwks(&discovery.jwks_uri).await?)?;
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
        .is_some_and(|user| {
            !user.organizations.is_empty()
                && user.organizations.iter().any(|org| {
                    !matches!(
                        org.role,
                        UserRole::ServiceAccount | UserRole::SreAgent | UserRole::User
                    )
                })
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

fn console_url(email: &str) -> String {
    let cfg = get_config();
    let user = serde_json::json!({"email": email, "name": email});
    format!(
        "{}{}/web/cb#id_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        cfg.common.web_url,
        cfg.common.base_uri,
        config::utils::base64::encode(&user.to_string())
    )
}

fn auth_error(status: StatusCode, error: impl std::fmt::Display) -> Response {
    log::warn!("Google login failed: {error}");
    (status, "Google login failed").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn pending_state_is_consumed_once() {
        let state = "one-use-state".to_string();
        PENDING_LOGINS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                state.clone(),
                PendingLogin {
                    nonce: "nonce".to_string(),
                    verifier: "verifier".to_string(),
                    expires_at: Instant::now() + Duration::from_secs(10),
                },
            );
        assert!(consume_pending(&state).is_some());
        assert!(consume_pending(&state).is_none());
    }
}
