//! Captures the git revision the binary was built from, so `-V`, the
//! engine's /version endpoint, and the Android versionName can all answer
//! "which exact build is running" without guessing.

use std::process::Command;

fn main() {
    let hash = git_hash();
    println!("cargo:rustc-env=ANYWHERE_GIT_HASH={hash}");
    // Keep the hash current: rebuild when HEAD (or the branch ref it points
    // at) moves, in addition to the default any-package-file-changed rule.
    // Paths are relative to this crate, which sits inside the repo.
    println!("cargo:rerun-if-changed=.");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    if let Ok(head) = std::fs::read_to_string("../.git/HEAD") {
        if let Some(ref_path) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed=../.git/{ref_path}");
        }
    }
}

/// Short hash of the built revision, `-dirty`-suffixed when the tree has
/// uncommitted changes (those are exactly the builds you end up debugging
/// in the field). Falls back to `unknown` outside a git checkout.
fn git_hash() -> String {
    let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
    else {
        return "unknown".to_string();
    };
    if !output.status.success() {
        return "unknown".to_string();
    }
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.is_empty() {
        return "unknown".to_string();
    }
    // `git diff --quiet` exits 0 on a clean tree; untracked files don't
    // count as dirty (they aren't part of any build anyway).
    let clean = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !clean(&["diff", "--quiet"]) || !clean(&["diff", "--cached", "--quiet"]) {
        return format!("{hash}-dirty");
    }
    hash
}
