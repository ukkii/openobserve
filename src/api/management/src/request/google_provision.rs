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

use config::{
    get_config,
    meta::user::{DBUser, UserOrg, UserRole},
};

use super::google_auth::login_user_allowed;

/// Which Google identities may sign in, and whether unknown ones get a local account.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProvisionPolicy {
    auto_create: bool,
    allowed_domains: Vec<String>,
    role: Option<UserRole>,
    orgs: Vec<String>,
}

impl ProvisionPolicy {
    pub(crate) fn from_config() -> Self {
        let cfg = get_config();
        Self::parse(
            cfg.auth.google_auto_create_users,
            &cfg.auth.google_allowed_domains,
            &cfg.auth.google_default_role,
            &cfg.auth.google_default_orgs,
        )
    }

    pub(crate) fn parse(auto_create: bool, domains: &str, role: &str, orgs: &str) -> Self {
        let role = match role.trim().to_lowercase().as_str() {
            "viewer" => Some(UserRole::Viewer),
            "editor" => Some(UserRole::Editor),
            "admin" => Some(UserRole::Admin),
            _ => None,
        };
        Self {
            auto_create,
            allowed_domains: split_list(domains, true),
            role,
            orgs: split_list(orgs, false),
        }
    }

    /// With no allowed domains configured every verified identity passes, as before.
    pub(crate) fn identity_allowed(&self, email: &str, hd: Option<&str>) -> bool {
        if self.allowed_domains.is_empty() {
            return true;
        }
        let Some(domain) = email_domain(email) else {
            return false;
        };
        // Google sets `hd` only for Workspace accounts; a consumer account can carry any address.
        let hosted = hd.map(|hd| hd.trim().to_lowercase());
        self.allowed_domains.contains(&domain) && hosted.as_deref() == Some(domain.as_str())
    }

    /// Role and orgs for a new account, or `None` when provisioning must not happen.
    fn grant(&self) -> Option<(UserRole, &[String])> {
        if !self.auto_create || self.allowed_domains.is_empty() || self.orgs.is_empty() {
            return None;
        }
        self.role.clone().map(|role| (role, self.orgs.as_slice()))
    }
}

/// Creates a local account for a first-time Google identity; returns whether it may now log in.
pub(crate) async fn provision_user(policy: &ProvisionPolicy, email: &str) -> bool {
    let Some((role, org_ids)) = policy.grant() else {
        return false;
    };
    // An existing account is never modified here; it logs in only if its own role allows it.
    if let Some(user) = db::user::get_user_by_email(email).await {
        return login_user_allowed(&user);
    }
    let organizations = resolve_orgs(org_ids, &role).await;
    if organizations.is_empty() {
        log::warn!("google auto-provisioning skipped for {email}: no configured org exists");
        return false;
    }
    let orgs = organizations
        .iter()
        .map(|org| org.name.clone())
        .collect::<Vec<_>>();
    let salt = config::ider::uuid();
    let db_user = DBUser {
        email: email.to_string(),
        first_name: String::new(),
        last_name: String::new(),
        password: openobserve_core::auth::get_hash(&config::utils::rand::random_hex(32), &salt),
        salt,
        organizations,
        is_external: false,
        password_ext: None,
    };
    match openobserve_core::users::create_new_user(db_user).await {
        Ok(()) => {
            log::info!(
                "google auto-provisioned {email} as {} in {orgs:?}",
                role_name(&role)
            );
            true
        }
        // A concurrent first login may have inserted the same account a moment earlier.
        Err(error) => match db::user::get_user_by_email(email).await {
            Some(user) => login_user_allowed(&user),
            None => {
                log::warn!("google auto-provisioning failed for {email}: {error}");
                false
            }
        },
    }
}

async fn resolve_orgs(org_ids: &[String], role: &UserRole) -> Vec<UserOrg> {
    let mut organizations = Vec::with_capacity(org_ids.len());
    for org_id in org_ids {
        match infra::table::organizations::get_on_writer(org_id).await {
            Ok(org) => organizations.push(UserOrg {
                name: org.identifier,
                org_name: org.org_name,
                token: String::new(),
                rum_token: None,
                role: role.clone(),
            }),
            Err(_) => log::warn!("google auto-provisioning: org {org_id} does not exist, skipped"),
        }
    }
    organizations
}

fn role_name(role: &UserRole) -> &'static str {
    match role {
        UserRole::Admin => "admin",
        UserRole::Editor => "editor",
        _ => "viewer",
    }
}

fn email_domain(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    (!local.is_empty() && !domain.is_empty()).then(|| domain.to_lowercase())
}

fn split_list(value: &str, lowercase: bool) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            if lowercase {
                item.to_lowercase()
            } else {
                item.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> ProvisionPolicy {
        ProvisionPolicy::parse(true, "HelloTickets.com", "viewer", "default")
    }

    #[test]
    fn domain_must_match_exactly_and_agree_with_hosted_domain() {
        let policy = enabled();
        assert!(policy.identity_allowed("a@hellotickets.com", Some("hellotickets.com")));
        assert!(policy.identity_allowed("A@HelloTickets.COM", Some("HELLOTICKETS.com")));
        assert!(!policy.identity_allowed("a@evilhellotickets.com", Some("evilhellotickets.com")));
        assert!(!policy.identity_allowed("a@sub.hellotickets.com", Some("hellotickets.com")));
        assert!(!policy.identity_allowed("a@gmail.com", Some("hellotickets.com")));
        assert!(!policy.identity_allowed("not-an-email", Some("hellotickets.com")));
    }

    #[test]
    fn missing_or_mismatched_hosted_domain_is_rejected() {
        let policy = enabled();
        assert!(!policy.identity_allowed("a@hellotickets.com", None));
        assert!(!policy.identity_allowed("a@hellotickets.com", Some("other.com")));
    }

    #[test]
    fn empty_domain_list_keeps_existing_behaviour() {
        let policy = ProvisionPolicy::parse(false, "", "viewer", "");
        assert!(policy.identity_allowed("a@gmail.com", None));
        assert!(policy.grant().is_none());
    }

    #[test]
    fn grant_requires_flag_domains_orgs_and_a_safe_role() {
        assert_eq!(
            enabled().grant(),
            Some((UserRole::Viewer, &["default".to_string()][..]))
        );
        assert!(
            ProvisionPolicy::parse(false, "hellotickets.com", "viewer", "default")
                .grant()
                .is_none()
        );
        assert!(
            ProvisionPolicy::parse(true, "", "viewer", "default")
                .grant()
                .is_none()
        );
        assert!(
            ProvisionPolicy::parse(true, "hellotickets.com", "viewer", " , ")
                .grant()
                .is_none()
        );
        for role in ["root", "service_account", "sre_agent", "user", "", "owner"] {
            let policy = ProvisionPolicy::parse(true, "hellotickets.com", role, "default");
            assert!(policy.grant().is_none(), "role {role} must not be granted");
        }
        for (role, expected) in [("Editor", UserRole::Editor), ("admin", UserRole::Admin)] {
            let policy = ProvisionPolicy::parse(true, "hellotickets.com", role, "default");
            assert_eq!(policy.grant().map(|(role, _)| role), Some(expected));
        }
    }

    #[test]
    fn org_list_is_trimmed_and_keeps_identifier_case() {
        let policy = ProvisionPolicy::parse(
            true,
            "hellotickets.com",
            "viewer",
            " default , 3LawW0tqeuCg7HKG3z82gal4yqL ,",
        );
        assert_eq!(
            policy.orgs,
            vec![
                "default".to_string(),
                "3LawW0tqeuCg7HKG3z82gal4yqL".to_string()
            ]
        );
    }
}
