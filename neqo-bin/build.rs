use std::{env, process::Command};

use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Platforms
        apple: {
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos"
            )
        },
    }

    if env::var_os("CARGO_FEATURE_QCSD").is_some() {
        println!("cargo:rerun-if-env-changed=NEQO_QCSD_GIT_COMMIT");
        println!("cargo:rerun-if-changed=../.git/HEAD");
        println!("cargo:rerun-if-changed=../.git/index");
        let commit = env::var("NEQO_QCSD_GIT_COMMIT").unwrap_or_else(|_| {
            let revision = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir("..")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map_or_else(|| "unknown".into(), |revision| revision.trim().to_owned());
            let dirty = Command::new("git")
                .args(["status", "--porcelain", "--untracked-files=no"])
                .current_dir("..")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .is_some_and(|output| !output.stdout.is_empty());
            if dirty {
                format!("{revision}-dirty")
            } else {
                revision
            }
        });
        println!("cargo:rustc-env=NEQO_QCSD_GIT_COMMIT={commit}");
    }
}
