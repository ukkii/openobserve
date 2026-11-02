// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

use anyhow::{Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use config::meta::user::UserRole;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TOKEN_PREFIX: &str = "o2mcp.";
pub const SESSION_PREFIX: &str = "mcp:";
pub const LIFETIME_SECONDS: i64 = 86_400;

#[derive(Deserialize, Serialize)]
struct Identity {
    email: String,
    org: String,
}

#[derive(Deserialize, Serialize)]
struct Credential {
    digest: Vec<u8>,
    user_created_at: i64,
    membership_created_at: Option<i64>,
}

#[derive(Serialize)]
pub struct IssuedCredential {
    pub email: String,
    pub token: String,
    pub expires_at: i64,
    pub expires_in: i64,
}

pub async fn issue(email: &str, org: &str) -> Result<IssuedCredential> {
    let (role, user_created_at, membership_created_at) = live_identity(email, org).await?;
    if !role_allowed(&role) {
        bail!("MCP access denied");
    }
    let identity = Identity {
        email: email.to_owned(),
        org: org.to_owned(),
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&identity)?);
    let token = format!(
        "{TOKEN_PREFIX}{encoded}.{}",
        config::utils::rand::random_hex(32)
    );
    let expires_at = config::utils::time::now_micros() + LIFETIME_SECONDS * 1_000_000;
    let credential = Credential {
        digest: Sha256::digest(token.as_bytes()).to_vec(),
        user_created_at,
        membership_created_at,
    };
    infra::table::sessions::set_with_expiry(
        &session_key(&encoded),
        &serde_json::to_string(&credential)?,
        expires_at,
    )
    .await?;
    Ok(IssuedCredential {
        email: email.to_owned(),
        token,
        expires_at,
        expires_in: LIFETIME_SECONDS,
    })
}

pub async fn revoke(email: &str, org: &str) -> Result<()> {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Identity {
        email: email.to_owned(),
        org: org.to_owned(),
    })?);
    infra::table::sessions::delete(&session_key(&encoded)).await?;
    Ok(())
}

pub async fn validate(token: &str, org: &str) -> Result<(String, UserRole)> {
    if !config::get_config().common.mcp_enabled {
        bail!("MCP is disabled");
    }
    if token.len() > 4096 {
        bail!("Invalid MCP credential");
    }
    let encoded = token
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|value| value.split_once('.'))
        .map(|(identity, _)| identity)
        .ok_or_else(|| anyhow!("Invalid MCP credential"))?;
    let identity: Identity = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?;
    if identity.org != org {
        bail!("MCP organization mismatch");
    }
    let stored = infra::table::sessions::get_primary(&session_key(encoded))
        .await?
        .ok_or_else(|| anyhow!("Invalid MCP credential"))?;
    if stored.expires_at <= config::utils::time::now_micros() {
        bail!("MCP credential expired");
    }
    let credential: Credential = serde_json::from_str(&stored.access_token)?;
    if credential.digest != Sha256::digest(token.as_bytes()).as_slice() {
        bail!("Invalid MCP credential");
    }
    let (role, user_created_at, membership_created_at) =
        live_identity(&identity.email, org).await?;
    if !role_allowed(&role)
        || credential.user_created_at != user_created_at
        || credential.membership_created_at != membership_created_at
    {
        bail!("MCP access revoked");
    }
    Ok((identity.email, role))
}

pub fn role_allowed(role: &UserRole) -> bool {
    matches!(
        role,
        UserRole::Root | UserRole::Admin | UserRole::Editor | UserRole::Viewer
    )
}

pub fn self_service(method: &str, template: &str) -> bool {
    matches!(method, "POST" | "DELETE") && route_template(template) == "/{org_id}/mcp/credentials"
}

pub fn transport(method: &str, template: &str) -> bool {
    matches!(method, "GET" | "POST" | "DELETE") && route_template(template) == "/{org_id}/mcp"
}

fn session_key(encoded: &str) -> String {
    let mut key = format!("{SESSION_PREFIX}{:x}", Sha256::digest(encoded.as_bytes()));
    // Session IDs are VARCHAR(36); a 128-bit digest leaves room for the isolated namespace.
    key.truncate(36);
    key
}

async fn live_identity(email: &str, org: &str) -> Result<(UserRole, i64, Option<i64>)> {
    if infra::table::organizations::get_on_writer(org)
        .await?
        .status
        != "active"
    {
        bail!("Organization is inactive");
    }
    let user = infra::table::users::get_primary(email).await?;
    if user.must_reset_password {
        bail!("Password reset required");
    }
    if user.is_root {
        return Ok((UserRole::Root, user.created_at, None));
    }
    let membership = infra::table::org_users::get_optional_primary(org, email)
        .await?
        .ok_or_else(|| anyhow!("MCP membership not found"))?;
    Ok((
        membership.role,
        user.created_at,
        Some(membership.created_at),
    ))
}

fn route_template(template: &str) -> &str {
    let base = &config::get_config().common.base_uri;
    let template = template.strip_prefix(base).unwrap_or(template);
    template.strip_prefix("/api").unwrap_or(template)
}

#[cfg(test)]
mod tests {
    use config::meta::{
        organization::OrganizationType,
        user::{DBUser, UserOrg},
    };

    use super::*;

    async fn setup() -> (String, String) {
        static ONCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        ONCE.get_or_init(|| async {
            infra::db::create_table().await.unwrap();
            infra::table::create_user_tables().await.unwrap();
            infra::table::sessions::create_table().await.unwrap();
        })
        .await;
        let org = format!("mcp-{}", config::ider::uuid());
        let email = format!("{}@example.com", org);
        infra::table::organizations::add(&org, &org, OrganizationType::Custom)
            .await
            .unwrap();
        let user = DBUser {
            email: email.clone(),
            first_name: String::new(),
            last_name: String::new(),
            password: String::new(),
            salt: String::new(),
            password_ext: None,
            is_external: false,
            organizations: vec![UserOrg {
                name: org.clone(),
                org_name: org.clone(),
                token: String::new(),
                rum_token: None,
                role: UserRole::Viewer,
            }],
        };
        infra::table::users::add((&user).into()).await.unwrap();
        infra::table::org_users::add(&org, &email, UserRole::Viewer, "", None)
            .await
            .unwrap();
        (org, email)
    }

    #[tokio::test]
    async fn credential_lifecycle_is_bound_to_user_org_membership_and_expiry() {
        let (org, email) = setup().await;
        let first = issue(&email, &org).await.unwrap();
        assert_eq!(
            validate(&first.token, &org).await.unwrap(),
            (email.clone(), UserRole::Viewer)
        );
        assert!(validate(&first.token, "other-org").await.is_err());
        let second = issue(&email, &org).await.unwrap();
        assert!(validate(&first.token, &org).await.is_err());
        assert!(validate(&second.token, &org).await.is_ok());
        revoke(&email, &org).await.unwrap();
        assert!(validate(&second.token, &org).await.is_err());
        let third = issue(&email, &org).await.unwrap();
        let encoded = third
            .token
            .strip_prefix(TOKEN_PREFIX)
            .unwrap()
            .split_once('.')
            .unwrap()
            .0;
        let key = session_key(encoded);
        let stored = infra::table::sessions::get_primary(&key)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.access_token.contains(&third.token));
        infra::table::sessions::set_with_expiry(&key, &stored.access_token, 1)
            .await
            .unwrap();
        assert!(validate(&third.token, &org).await.is_err());
        let fourth = issue(&email, &org).await.unwrap();
        infra::table::org_users::update(&org, &email, UserRole::User, "", None)
            .await
            .unwrap();
        assert!(validate(&fourth.token, &org).await.is_err());
        assert!(issue(&email, &org).await.is_err());
        infra::table::org_users::remove(&org, &email).await.unwrap();
        assert!(validate(&fourth.token, &org).await.is_err());
    }

    #[test]
    fn credential_scope_does_not_grant_neighbouring_routes_or_account_kinds() {
        assert!(self_service("POST", "/api/{org_id}/mcp/credentials"));
        assert!(transport("POST", "/api/{org_id}/mcp"));
        assert!(!self_service("POST", "/{org_id}/users"));
        assert!(!self_service("GET", "/{org_id}/mcp/credentials"));
        assert!(!transport("POST", "/{org_id}/mcp/other"));
        for role in [UserRole::User, UserRole::ServiceAccount, UserRole::SreAgent] {
            assert!(!role_allowed(&role));
        }
    }
}
