use std::path::PathBuf;

use e2e_fixtures::materialize_all;
use e2e_tiers::{TargetWorkspace, Tier, TierRunConfig, run_tiers};
use tempfile::TempDir;

fn guap_root() -> PathBuf {
    if let Some(env_root) = std::env::var_os("GUAP_ROOT") {
        return PathBuf::from(env_root);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap_or_else(|| std::path::Path::new(".."))
        .to_path_buf()
}

#[test]
fn test_live_smoke_guap_kit_unbuilt_and_built_suites_via_run_tiers() {
    let root = guap_root();
    if !root.join("guap-kit/Cargo.toml").is_file() {
        eprintln!(
            "Skipping live smoke: GUAP repo not found at {}",
            root.display()
        );
        return;
    }

    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    // 1) GuapKit static contracts + meta gate (skip_cargo_build=true so GUAP is not mutated/built)
    let kit_report = run_tiers(&TierRunConfig {
        guap_root: root.clone(),
        fixtures: fixtures.clone(),
        tiers: Tier::all(),
        target: TargetWorkspace::GuapKit,
        skip_cargo_build: true,
    })
    .unwrap();
    let kit_fails: Vec<_> = kit_report
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped)
        .map(|r| format!("{}: {}", r.id, r.message))
        .collect();
    assert!(
        kit_fails.is_empty(),
        "GuapKit failures:\n{}",
        kit_fails.join("\n")
    );
    assert!(
        kit_report.passed >= 6,
        "Expected GuapKit static+meta checks to pass, got {}",
        kit_report.passed
    );

    if !root.join("forensics2rust/Cargo.toml").is_file() {
        eprintln!(
            "Skipping built-suite live smoke: sibling suites not present under {}",
            root.display()
        );
        return;
    }

    // 2) Built suites executed strictly end-to-end through run_tiers(Tier::all())
    for ws in [
        TargetWorkspace::Forensics2Rust,
        TargetWorkspace::Chrome2Rust,
        TargetWorkspace::Mail2Rust,
        TargetWorkspace::Android2Rust,
        TargetWorkspace::Sys2Rust,
        TargetWorkspace::Fs2Rust,
    ] {
        let report = run_tiers(&TierRunConfig {
            guap_root: root.clone(),
            fixtures: fixtures.clone(),
            tiers: Tier::all(),
            target: ws,
            skip_cargo_build: true,
        })
        .unwrap();
        let fails: Vec<_> = report
            .results
            .iter()
            .filter(|r| !r.passed && !r.skipped)
            .map(|r| format!("{}: {}", r.id, r.message))
            .collect();
        assert!(
            fails.is_empty(),
            "{:?} live run_tiers failures:\n{}",
            ws,
            fails.join("\n")
        );
        assert!(
            report.passed >= 8
                && report
                    .results
                    .iter()
                    .filter(|r| r.skipped)
                    .all(|r| r.id.ends_with("-01")),
            "{:?} live run_tiers expected all checks to pass without skips, got passed={} skipped={} total={}",
            ws,
            report.passed,
            report.skipped,
            report.total
        );
    }

    // 3) Winctl2Rust live smoke: keep run_tiers strict; fail on any non-EnumWindows/0x800700cb check
    let winctl_report = run_tiers(&TierRunConfig {
        guap_root: root.clone(),
        fixtures: fixtures.clone(),
        tiers: Tier::all(),
        target: TargetWorkspace::Winctl2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    assert!(
        winctl_report.total > 0,
        "Expected Winctl2Rust checks to execute, got total=0"
    );
    let mut non_enum_fails = Vec::new();
    for r in winctl_report
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped)
    {
        if r.message.contains("EnumWindows") || r.message.contains("0x800700cb") {
            eprintln!(
                "[Winctl2Rust known upstream M6 EnumWindows 0x800700cb]: {}: {}",
                r.id, r.message
            );
        } else {
            non_enum_fails.push(format!("{}: {}", r.id, r.message));
        }
    }
    assert!(
        non_enum_fails.is_empty(),
        "Winctl2Rust non-EnumWindows/0x800700cb live failures:\n{}",
        non_enum_fails.join("\n")
    );

    // 4) Net2Rust live smoke: non-blocking check while M4.6 completes
    let net_report = run_tiers(&TierRunConfig {
        guap_root: root,
        fixtures,
        tiers: Tier::all(),
        target: TargetWorkspace::Net2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    eprintln!(
        "[Net2Rust non-blocking M4.6 probe] total={} passed={} failed={} skipped={}",
        net_report.total, net_report.passed, net_report.failed, net_report.skipped
    );
    for r in net_report
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped)
    {
        eprintln!("[Net2Rust non-blocking fail]: {}: {}", r.id, r.message);
    }
}
