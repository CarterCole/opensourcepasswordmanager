//! Role-based access control.
//!
//! Built-in roles, highest privilege first: `owner`, `admin`, `developer`, `reader`.
//! Organization administration (API-key and user management) requires an
//! admin-tier role; everything else is denied by default (fail closed).

pub struct RbacService;

/// Roles permitted to manage API keys, users, and role assignments.
pub const ADMIN_ROLES: &[&str] = &["owner", "admin"];

impl RbacService {
    /// True if any of the caller's roles grants organization-admin privileges.
    pub fn is_admin(roles: &[String]) -> bool {
        roles.iter().any(|r| ADMIN_ROLES.contains(&r.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_and_admin_are_admin() {
        assert!(RbacService::is_admin(&["owner".into()]));
        assert!(RbacService::is_admin(&["admin".into()]));
        assert!(RbacService::is_admin(&["reader".into(), "admin".into()]));
    }

    #[test]
    fn lower_roles_and_empty_are_not_admin() {
        assert!(!RbacService::is_admin(&["developer".into()]));
        assert!(!RbacService::is_admin(&["reader".into()]));
        assert!(!RbacService::is_admin(&[]));
        assert!(!RbacService::is_admin(&["owners".into(), "Admin".into()])); // exact match only
    }
}
