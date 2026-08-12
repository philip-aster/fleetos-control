use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Read,
    Write,
    Delete,
    List,
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Path pattern, e.g. "production/database/*" or "staging/api/key"
    pub path_pattern: String,
    pub allowed_actions: HashSet<Action>,
}

#[derive(Debug, Clone, Default)]
pub struct AclEvaluator {
    rules: Vec<PolicyRule>,
}

impl AclEvaluator {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, path_pattern: impl Into<String>, actions: &[Action]) {
        self.rules.push(PolicyRule {
            path_pattern: path_pattern.into(),
            allowed_actions: actions.iter().copied().collect(),
        });
    }

    /// Validates if an action is permitted for a given secret path.
    pub fn check_permission(&self, path: &str, action: Action) -> bool {
        for rule in &self.rules {
            if self.matches_pattern(&rule.path_pattern, path) {
                if rule.allowed_actions.contains(&action) {
                    return true;
                }
            }
        }
        false
    }

    fn matches_pattern(&self, pattern: &str, path: &str) -> bool {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            path.starts_with(prefix)
        } else {
            pattern == path
        }
    }
}
