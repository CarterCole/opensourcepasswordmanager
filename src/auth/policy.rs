//! Minimal Vault-style path policies for the KV API.
//!
//! A token carries a list of policy strings. Each is either a built-in name or
//! an inline rule `"<caps> <path-glob>"`, e.g. `"read,list secret/app/*"`.
//!
//! Built-ins:
//! - `root` / `owner` / `admin` / `sudo` — every capability on every path
//! - `developer` — read, list, create, update, delete (no destroy)
//! - `reader` / `read-only` — read, list
//! - `default` — read, list (least privilege; the fallback for new child tokens)
//! - `deny` — nothing
//!
//! Globs support a trailing `*` (prefix match) or `*` alone (match anything).

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    Read,
    Create,
    Update,
    Delete,
    List,
    Destroy,
}

impl Capability {
    fn parse(s: &str) -> Option<Capability> {
        match s.trim() {
            "read" => Some(Capability::Read),
            "create" => Some(Capability::Create),
            "update" | "write" => Some(Capability::Update),
            "delete" => Some(Capability::Delete),
            "list" => Some(Capability::List),
            "destroy" => Some(Capability::Destroy),
            _ => None,
        }
    }
}

/// True if any of `policies` grants `cap` on `path`.
pub fn allows(policies: &[String], path: &str, cap: Capability) -> bool {
    policies.iter().any(|p| policy_allows(p, path, cap))
}

/// True if the policy set is root-equivalent (may delegate any policy).
pub fn is_root(policies: &[String]) -> bool {
    policies
        .iter()
        .any(|p| matches!(p.trim(), "root" | "owner" | "admin" | "sudo"))
}

fn policy_allows(policy: &str, path: &str, cap: Capability) -> bool {
    let p = policy.trim();
    match p {
        "root" | "owner" | "admin" | "sudo" => true,
        "developer" => !matches!(cap, Capability::Destroy),
        "reader" | "read-only" | "readonly" | "default" => {
            matches!(cap, Capability::Read | Capability::List)
        }
        "deny" | "" => false,
        _ => {
            // Inline rule: "caps glob", e.g. "read,list,update secret/app/*"
            let mut it = p.splitn(2, char::is_whitespace);
            let caps = it.next().unwrap_or("");
            let glob = it.next().unwrap_or("").trim();
            if glob.is_empty() {
                return false;
            }
            let cap_ok = caps
                .split(',')
                .filter_map(Capability::parse)
                .any(|c| c == cap);
            cap_ok && glob_match(glob, path)
        }
    }
}

fn glob_match(glob: &str, path: &str) -> bool {
    if glob == "*" {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    glob == path
}

#[cfg(test)]
mod tests {
    use super::Capability::*;
    use super::*;

    #[test]
    fn root_allows_everything() {
        let p = vec!["root".to_string()];
        assert!(allows(&p, "secret/app/db", Destroy));
        assert!(is_root(&p));
    }

    #[test]
    fn reader_is_read_only() {
        let p = vec!["reader".to_string()];
        assert!(allows(&p, "secret/x", Read));
        assert!(allows(&p, "secret/x", List));
        assert!(!allows(&p, "secret/x", Update));
        assert!(!allows(&p, "secret/x", Delete));
        assert!(!is_root(&p));
    }

    #[test]
    fn developer_cannot_destroy() {
        let p = vec!["developer".to_string()];
        assert!(allows(&p, "secret/x", Update));
        assert!(allows(&p, "secret/x", Delete));
        assert!(!allows(&p, "secret/x", Destroy));
    }

    #[test]
    fn inline_rule_scopes_by_path_and_cap() {
        let p = vec!["read,list,update secret/app/*".to_string()];
        assert!(allows(&p, "secret/app/db", Read));
        assert!(allows(&p, "secret/app/db", Update));
        assert!(!allows(&p, "secret/app/db", Destroy));
        assert!(!allows(&p, "secret/other/x", Read)); // outside the glob
    }

    #[test]
    fn deny_and_default() {
        assert!(!allows(&["deny".into()], "secret/x", Read));
        assert!(allows(&["default".into()], "secret/x", Read));
        assert!(!allows(&["default".into()], "secret/x", Update));
    }
}
