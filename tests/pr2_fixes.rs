//! PR #2 Fix Verification Tests

/// Test 3: No hardcoded secrets in source code
#[test]
fn no_hardcoded_secrets_in_source() {
    use std::process::Command;

    let output = Command::new("grep")
        .args([
            "-rn",
            "--include=*.rs",
            "-E",
            r#"/home/hera/|/root/\.openclaw|sk-proj-[a-zA-Z0-9]{20}|AKIA[A-Z0-9]{16}"#,
            "src/",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run grep");

    let matches = String::from_utf8_lossy(&output.stdout);

    // Filter out legitimate pattern-matching code (DLP detection patterns, emergency kit)
    let real_secrets: Vec<&str> = matches
        .lines()
        .filter(|line| {
            // Skip DLP regex definitions and test data
            !line.contains("Regex::new")
                && !line.contains("patterns.insert")
                && !line.contains("description:")
                && !line.contains("//")
                && !line.contains("r\"")
                && !line.contains("r#\"")
                && !line.contains("assert")
                && !line.contains("let input")
                && !line.contains("check_for_violations")
        })
        .collect();

    assert!(
        real_secrets.is_empty(),
        "Found hardcoded secrets in source:\n{}",
        real_secrets.join("\n")
    );
}

/// Test 3b: No hardcoded paths in tools/
#[test]
fn no_hardcoded_paths_in_tools() {
    use std::process::Command;

    let output = Command::new("grep")
        .args(["-rn", "--include=*.rs", "-E", r"/home/|/root/", "tools/"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run grep");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "Found hardcoded paths in tools/:\n{}",
        stdout
    );
}

/// Test 4: CLI accepts --skip-integrity flag
#[test]
fn cli_accepts_skip_integrity_flag() {
    use std::process::Command;

    let output = Command::new(env!("CARGO_BIN_EXE_open-guardian"))
        .args(["start", "--help"])
        .output()
        .expect("Failed to run binary");

    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        help_text.contains("skip-integrity") || help_text.contains("dev"),
        "CLI help should mention --skip-integrity or --dev flag.\nGot: {}",
        help_text
    );
}

/// Test 5: Version is 0.1.2
#[test]
fn version_is_0_1_2() {
    let cargo_toml = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    assert!(
        cargo_toml.contains("version = \"0.1.2\""),
        "Cargo.toml should have version 0.1.2"
    );
}

/// Test 5b: gen_manifest.rs duplicate is removed
#[test]
fn no_duplicate_gen_manifest() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/gen_manifest.rs");
    assert!(
        !path.exists(),
        "tools/gen_manifest.rs should be deleted (duplicate)"
    );
}
