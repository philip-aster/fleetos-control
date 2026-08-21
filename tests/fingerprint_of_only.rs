//! Hard invariant: of_with_ordinal NEVER appears in this crate's code.
//! Using it would silently break role-based load balancing.

use std::fs;
use walkdir::WalkDir;

/// Strip single-line comments from source code.
/// This removes `//` and `///` lines so we only match actual code usage,
/// not warning comments that mention the forbidden function.
fn strip_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            // Keep lines that don't start with // (after whitespace)
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn of_with_ordinal_is_never_used() {
    let src_dir = "src";
    let mut violations = Vec::new();

    for entry in WalkDir::new(src_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().extension().map_or(false, |ext| ext == "rs") {
            let content = fs::read_to_string(entry.path()).unwrap();

            // Strip comments before searching — we want to catch actual usage,
            // not warning comments that mention the forbidden function.
            let code_only = strip_comments(&content);

            if code_only.contains("of_with_ordinal") {
                violations.push(entry.path().to_path_buf());
            }
        }
    }

    assert!(
        violations.is_empty(),
        "of_with_ordinal found in code (not comments) in: {:?}. \
         This breaks role-based routing! Use IdentityFingerprint::of() instead.",
        violations
    );
}
