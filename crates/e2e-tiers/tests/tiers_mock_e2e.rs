use std::path::{Path, PathBuf};
use std::sync::Mutex;

use e2e_fixtures::materialize_all;
use e2e_tiers::export_verify::{
    parse_rfc4180_csv, verify_csv_formula_neutralization, verify_tsv_bytes,
};
use e2e_tiers::workspace::WorkspaceSession;
use e2e_tiers::{TargetWorkspace, Tier, TierRunConfig, run_tiers};
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn mock_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-guap-suite"))
}

fn write_file(path: &Path, content: &str) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn create_mock_guap_kit(guap_root: &Path) {
    let kit = guap_root.join("guap-kit");
    write_file(
        &kit.join("Cargo.toml"),
        "[workspace]\nresolver = \"2\"\nmembers = [\n  \"crates/guap-table\",\n  \"crates/guap-export\",\n  \"crates/guap-gui-win32\",\n  \"crates/guap-gui-iced\",\n  \"crates/guap-mcp\",\n]\n\n[workspace.package]\nedition = \"2024\"\nlicense = \"Apache-2.0\"\n",
    );

    // 1) guap-table
    write_file(
        &kit.join("crates/guap-table/Cargo.toml"),
        "[package]\nname = \"guap-table\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &kit.join("crates/guap-table/src/lib.rs"),
        "pub enum CellValue { Empty, Text(String) }\n\
         pub struct ColumnDef;\npub struct TableColumn;\npub struct GuapQuery;\n\
         pub struct TableRow;\n\
         pub struct TableData;\n\
         pub struct TableQuery;\n\
         pub trait TableProvider {}\n\
         pub trait ActionCommand {}\n\
         pub enum FilterExpr { Contains }\n\
         pub struct TableTextCompare;\n\
         pub struct TableTextDiff;\n",
    );
    write_file(
        &kit.join("crates/guap-table/tests/synthetic_10k.rs"),
        "#[test] fn cell_value_ord_consistency_and_nan() {}\n\
         #[test] fn query_10k_filter_regex_and_boolean() {}\n\
         #[test] fn query_10k_multi_sort_projection_and_pagination() {}\n\
         #[test] fn guap_query_10k_expressions() {}\n\
         #[test] fn table_text_compare_10k_diff() {}\n\
         #[test] fn guap_query_rejects_standalone_amp_pipe_and_excessive_nesting() {}\n\
         #[test] fn table_text_compare_rejects_duplicate_left_column_ids() {}\n\
         #[test] fn filter_numeric_comparison_preserves_precision_above_2_pow_53() {}\n",
    );

    // 2) guap-export
    write_file(
        &kit.join("crates/guap-export/Cargo.toml"),
        "[package]\nname = \"guap-export\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &kit.join("crates/guap-export/src/lib.rs"),
        "pub enum ExportFormat { Csv, Tsv, Json, Jsonl, Html, HtmlVertical, Markdown }\n\
         pub struct ExportOptions;\n\
         pub struct CustodyManifest;\n\
         pub struct CustodyLeaf;\n\
         pub fn neutralize_spreadsheet_cell(s: &str) -> String { s.to_string() }\npub fn neutralize_csv_cell(s: &str) -> String { s.to_string() }\n\
         pub fn write_export() {}\n\
         pub fn write_custody_manifest() {}\n\
         pub fn compute_merkle_root_sha256() {}\npub fn merkle_root_sha256() {}\n\
         pub fn merkle_root_sha512() {}\n",
    );
    write_file(
        &kit.join("crates/guap-export/tests/export_and_merkle.rs"),
        "#[test] fn csv_rfc4180_and_formula_neutralization() {}\n\
         #[test] fn tsv_sanitizes_embedded_tabs_and_newlines() {}\n\
         #[test] fn json_and_jsonl_roundtrip() {}\n\
         #[test] fn html_horizontal_and_vertical_csp_and_xss_escaping() {}\n\
         #[test] fn markdown_escapes_pipes_and_newlines() {}\n\
         #[test] fn merkle_sha256_and_sha512_vectors_and_write_export() {}\n",
    );

    // 3) guap-gui-win32
    write_file(
        &kit.join("crates/guap-gui-win32/Cargo.toml"),
        "[package]\nname = \"guap-gui-win32\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         [features]\ndefault = [\"native-host\"]\nnative-host = []\n",
    );
    write_file(
        &kit.join("crates/guap-gui-win32/src/lib.rs"),
        "pub struct Win32TableHostConfig;\n\
         pub struct Win32GridState;\n\
         pub fn run_win32_suite() {}\n\
         pub fn utf16_null_terminated(s: &str) -> Vec<u16> { s.encode_utf16().chain([0]).collect() }\n\
         #[cfg(test)]\nmod state {\n    #[cfg(test)]\n    mod tests {\n\
             #[test] fn win32_state_25k_no_cap_filter_sort_and_export() {}\n\
             #[test] fn utf16_buf_write_empty_exact_and_surrogate_safe() {}\n\
         }\n}\n",
    );

    // 4) guap-gui-iced
    write_file(
        &kit.join("crates/guap-gui-iced/Cargo.toml"),
        "[package]\nname = \"guap-gui-iced\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &kit.join("crates/guap-gui-iced/src/lib.rs"),
        "pub struct IcedSuiteConfig;\n\
         pub struct IcedDataGrid;\n\
         pub enum DataGridMessage { NextPage }\npub enum GridMessage { NextPage }\n\
         pub fn run_iced_suite() {}\n",
    );
    write_file(
        &kit.join("crates/guap-gui-iced/tests/grid_headless.rs"),
        "#[test] fn iced_grid_25k_paginated_and_all_messages_headless() {}\n",
    );

    // 5) guap-mcp
    write_file(
        &kit.join("crates/guap-mcp/Cargo.toml"),
        "[package]\nname = \"guap-mcp\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &kit.join("crates/guap-mcp/src/lib.rs"),
        "pub enum PolicyMode { ReadOnlyOnly, AllowMutating }\n\
         pub struct McpServerRegistry;\n\
         pub struct McpServer;\n\
         pub fn execute_tool_call() {}\n\
         pub const PROTOCOL_VERSION: &str = \"2024-11-05\";\npub trait ActionCommand {}\npub const ERR_SAFETY_REFUSAL: i32 = -32003;\n",
    );
    write_file(
        &kit.join("crates/guap-mcp/tests/mcp_contract.rs"),
        "#[test] fn protocol_initialize_ping_notifications_and_errors() {}\n\
         #[test] fn tools_list_annotations_and_table_provider_query() {}\n\
         #[test] fn policy_gates_enforce_32003_and_allow_confirmed_mutations() {}\n\
         #[test] fn stdio_frame_loop_processes_stream() {}\n\
         #[test] fn non_read_only_table_provider_exposes_confirm_destructive_and_enforces_32003() {}\n",
    );
}

fn setup_mock_guap_root(place_binaries: bool) -> TempDir {
    let root = TempDir::new().unwrap();
    create_mock_guap_kit(root.path());

    let suites = [
        "forensics2rust",
        "chrome2rust",
        "mail2rust",
        "android2rust",
        "winctl2rust",
        "net2rust",
        "sys2rust",
        "fs2rust",
    ];
    let mock_bin = mock_bin_path();
    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    for ws in suites {
        let ws_dir = root.path().join(ws);
        write_file(
            &ws_dir.join("Cargo.toml"),
            &format!("[workspace]\nresolver = \"2\"\nmembers = [\"crates/{ws}-win32\"]\n"),
        );
        let win32 = ws_dir.join("crates").join(format!("{ws}-win32"));
        write_file(
            &win32.join("Cargo.toml"),
            &format!("[package]\nname = \"{ws}-win32\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        );
        write_file(
            &win32.join("app.manifest"),
            "<assembly><dependency><dependentAssembly><assemblyIdentity name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" /></dependentAssembly></dependency></assembly>",
        );
        write_file(
            &win32.join("build.rs"),
            "fn main() { println!(\"cargo:rerun-if-changed=app.manifest\"); }",
        );
        write_file(&win32.join("src/lib.rs"), "pub fn init() {}\n");

        if place_binaries {
            let dst = ws_dir
                .join("target/debug")
                .join(format!("{ws}{exe_suffix}"));
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(&mock_bin, &dst).unwrap();
        }
    }
    root
}
struct ModeGuard;
impl ModeGuard {
    fn set(val: &str) -> Self {
        unsafe {
            std::env::set_var("MOCK_GUAP_MODE", val);
        }
        Self
    }
}
impl Drop for ModeGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("MOCK_GUAP_MODE");
        }
    }
}

#[test]
fn test_positive_full_4tier_run_against_mock_workspaces() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("ok");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let cfg = TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: Tier::all(),
        target: TargetWorkspace::All,
        skip_cargo_build: false,
    };

    let report = run_tiers(&cfg).unwrap();
    let fails: Vec<_> = report
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped)
        .map(|r| format!("{}: {}", r.id, r.message))
        .collect();
    assert!(
        fails.is_empty(),
        "Unexpected failures:\n{}",
        fails.join("\n")
    );
    let skips: Vec<_> = report
        .results
        .iter()
        .filter(|r| r.skipped)
        .map(|r| format!("{}: {}", r.id, r.message))
        .collect();
    assert!(skips.is_empty(), "Unexpected skips:\n{}", skips.join("\n"));
    assert_eq!(report.total, 360);
    assert_eq!(report.passed, 360);
    assert_eq!(report.failed, 0);
    assert_eq!(report.skipped, 0);
}

#[test]
fn test_tier_filtering_and_strict_workspace_filtering() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("ok");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    // Strict Chrome2Rust target must include ONLY FG-12 (10) + T3-16 (1) + T4-S06 (1) = 12 checks
    let cfg = TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: Tier::all(),
        target: TargetWorkspace::Chrome2Rust,
        skip_cargo_build: true,
    };
    let report = run_tiers(&cfg).unwrap();
    assert_eq!(
        report.total, 13,
        "Chrome2Rust strict target should run 13 checks"
    );
    assert_eq!(
        report.failed,
        0,
        "Failures: {:?}",
        report
            .results
            .iter()
            .filter(|r| !r.passed && !r.skipped)
            .collect::<Vec<_>>()
    );
    assert_eq!(report.passed, 12);
    assert_eq!(report.skipped, 1);
    assert!(
        !report.results.iter().any(|r| r.id == "T4-S16"),
        "T4-S16 must NOT leak into Chrome2Rust target"
    );
}

#[test]
fn test_skip_behavior_when_binary_and_cargo_skipped() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("ok");

    let guap_root = setup_mock_guap_root(false);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let cfg = TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: Tier::all(),
        target: TargetWorkspace::All,
        skip_cargo_build: true,
    };
    let report = run_tiers(&cfg).unwrap();
    assert_eq!(
        report.failed, 0,
        "Unexpected failures when binaries missing & cargo skipped"
    );
    assert!(
        report.skipped > 250,
        "Expected missing-binary & guap-kit runtime checks to skip cleanly, got skipped={}",
        report.skipped
    );
    // GuapKit runtime checks (e.g. T3-01..08) must SKIP when skip_cargo_build=true
    for r in report.results.iter().filter(|r| r.id.starts_with("T3-0")) {
        assert!(
            r.skipped,
            "{} should be Skipped when skip_cargo_build=true, got {:?}",
            r.id, r
        );
    }
}

#[test]
fn test_negative_silent_empty_json_fails_tier1() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("silent_empty");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let cfg = TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier1],
        target: TargetWorkspace::Forensics2Rust,
        skip_cargo_build: true,
    };
    let report = run_tiers(&cfg).unwrap();
    let mcp_fails = report
        .results
        .iter()
        .filter(|r| r.id.ends_with("-04") && !r.passed)
        .count();
    let cli_fails = report
        .results
        .iter()
        .filter(|r| r.id.ends_with("-05") && !r.passed)
        .count();
    assert_eq!(
        mcp_fails, 6,
        "All 6 forensics2rust Tier1 MCP checks must reject silent '{{}}'"
    );
    assert_eq!(
        cli_fails, 6,
        "All 6 forensics2rust Tier1 CLI checks must reject silent '{{}}'"
    );
}

#[test]
fn test_negative_clap_exit2_fails_tier2() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("clap_exit2_on_negative");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let cfg = TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier2],
        target: TargetWorkspace::Mail2Rust,
        skip_cargo_build: true,
    };
    let report = run_tiers(&cfg).unwrap();
    let t2_01 = report
        .results
        .iter()
        .find(|r| r.id == "T2-FG-13-01")
        .unwrap();
    let t2_02 = report
        .results
        .iter()
        .find(|r| r.id == "T2-FG-13-02")
        .unwrap();
    let t2_03 = report
        .results
        .iter()
        .find(|r| r.id == "T2-FG-13-03")
        .unwrap();
    assert!(
        !t2_01.passed,
        "T2-FG13-01 must fail when CLI gives clap exit-2 unknown-arg error"
    );
    assert!(
        !t2_02.passed,
        "T2-FG13-02 must fail when CLI gives clap exit-2 unknown-arg error"
    );
    assert!(
        !t2_03.passed,
        "T2-FG13-03 must fail when CLI gives clap exit-2 unknown-arg error"
    );
}

#[test]
fn test_negative_comment_only_guap_kit_fails_contract_scan() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("ok");

    let guap_root = setup_mock_guap_root(false);
    // Replace guap-table/src/lib.rs with comment-only declarations!
    write_file(
        &guap_root
            .path()
            .join("guap-kit/crates/guap-table/src/lib.rs"),
        "// pub enum CellValue {} pub struct TableColumn; pub struct TableRow;\n\
         /* pub struct TableData; pub struct TableQuery; pub trait TableProvider {}\n\
            pub trait ActionCommand {} pub enum FilterExpr {} pub struct TableTextCompare;\n\
            pub struct TableTextDiff; */\n",
    );
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let cfg = TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier1],
        target: TargetWorkspace::GuapKit,
        skip_cargo_build: true,
    };
    let report = run_tiers(&cfg).unwrap();
    let c = report
        .results
        .iter()
        .find(|r| r.id == "T1-FG-01-03")
        .unwrap();
    assert!(
        !c.passed && !c.skipped,
        "T1-FG-01-03 must FAIL on comment-only declarations, got {:?}",
        c
    );
}

#[test]
fn test_negative_r4_secret_leak_fails_t3_27_and_t4_s12() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    for leak_mode in [
        "leak_r4_secret",
        "leak_r4_keymaterial_mcp",
        "leak_r4_keymaterial_cli",
        "leak_r4_keymaterial_csv",
        "leak_r4_plaintext_flag_mcp",
        "leak_r4_plaintext_flag_cli",
        "leak_r4_plaintext_flag_csv",
    ] {
        let _m = ModeGuard::set(leak_mode);
        let cfg = TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures: fixtures.clone(),
            tiers: vec![Tier::Tier3, Tier::Tier4],
            target: TargetWorkspace::Net2Rust,
            skip_cargo_build: true,
        };
        let report = run_tiers(&cfg).unwrap();
        let t3_27 = report.results.iter().find(|r| r.id == "T3-27").unwrap();
        let t4_s12 = report.results.iter().find(|r| r.id == "T4-S12").unwrap();
        assert!(
            !t3_27.passed,
            "T3-27 must FAIL under {leak_mode}, got {t3_27:?}"
        );
        assert!(
            !t4_s12.passed,
            "T4-S12 must FAIL under {leak_mode}, got {t4_s12:?}"
        );
    }
}

#[test]
fn test_negative_unneutralized_csv_and_bad_merkle_fail_tier4() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    {
        let _m = ModeGuard::set("unneutralized_csv");
        let cfg = TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures: fixtures.clone(),
            tiers: vec![Tier::Tier4],
            target: TargetWorkspace::Chrome2Rust,
            skip_cargo_build: true,
        };
        let report = run_tiers(&cfg).unwrap();
        let s06 = report.results.iter().find(|r| r.id == "T4-S05").unwrap();
        assert!(!s06.passed, "T4-S05 must FAIL on unneutralized CSV");
    }
    {
        let _m = ModeGuard::set("bad_merkle");
        let cfg = TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures,
            tiers: vec![Tier::Tier4],
            target: TargetWorkspace::Chrome2Rust,
            skip_cargo_build: true,
        };
        let report = run_tiers(&cfg).unwrap();
        let s06 = report.results.iter().find(|r| r.id == "T4-S05").unwrap();
        assert!(!s06.passed, "T4-S05 must FAIL on bad Merkle root");
    }
}

#[test]
fn test_negative_mutating_bypass_fails_tier3() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("allow_mutating_readonly");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let sys_report = run_tiers(&TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures: fixtures.clone(),
        tiers: vec![Tier::Tier3],
        target: TargetWorkspace::Sys2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    let t3_28 = sys_report.results.iter().find(|r| r.id == "T3-28").unwrap();
    assert!(
        !t3_28.passed,
        "T3-28 must FAIL when mutating tool executes under ReadOnlyOnly"
    );

    let net_report = run_tiers(&TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier3],
        target: TargetWorkspace::Net2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    for tid in ["T3-23", "T3-25", "T3-26", "T3-27"] {
        let r = net_report.results.iter().find(|r| r.id == tid).unwrap();
        assert!(
            !r.passed,
            "{tid} must FAIL when mutating tool executes under ReadOnlyOnly, got {r:?}"
        );
    }
}

#[test]
fn test_negative_malformed_mcp_missing_32700_fails_tier2() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("bad_parse_error");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let report = run_tiers(&TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier2],
        target: TargetWorkspace::Mail2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    let t2_05 = report
        .results
        .iter()
        .find(|r| r.id == "T2-FG-13-05")
        .unwrap();
    assert!(
        !t2_05.passed,
        "T2-FG-13-05 must FAIL when MCP server does not return -32700 on malformed JSON"
    );
}

#[test]
fn test_resolve_binary_prefers_debug_over_newer_release_when_building() {
    let root = TempDir::new().unwrap();
    let net_dir = root.path().join("net2rust");
    write_file(
        &net_dir.join("Cargo.toml"),
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/net2rust-cli\"]\n",
    );
    write_file(
        &net_dir.join("crates/net2rust-cli/Cargo.toml"),
        "[package]\nname = \"net2rust-cli\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[[bin]]\nname = \"net2rust\"\npath = \"src/main.rs\"\n",
    );
    write_file(
        &net_dir.join("crates/net2rust-cli/src/main.rs"),
        "fn main() {}\n",
    );

    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let rel_bin = net_dir
        .join("target/release")
        .join(format!("net2rust{exe_suffix}"));
    write_file(&rel_bin, "STALE_RELEASE_BINARY");
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&rel_bin)
        .unwrap();
    file.set_modified(future).unwrap();

    let mut session = WorkspaceSession::new(root.path().to_path_buf(), false);
    let resolved = session
        .resolve_binary(TargetWorkspace::Net2Rust)
        .unwrap()
        .unwrap();
    let expected_debug = net_dir
        .join("target/debug")
        .join(format!("net2rust{exe_suffix}"));
    assert_eq!(resolved, expected_debug);
    assert!(resolved.is_file());
}

#[test]
fn test_export_verify_bom_and_post_quote_trailing_chars() {
    assert!(
        parse_rfc4180_csv(b"\"a\"trailing,b\r\n").is_err(),
        "trailing chars after closing quote must fail"
    );
    let bom_quoted = "\u{FEFF}\"abc\",def\r\n".as_bytes();
    assert_eq!(
        parse_rfc4180_csv(bom_quoted).unwrap(),
        vec![vec!["abc".to_string(), "def".to_string()]]
    );
    let bom_evil = "\u{FEFF}=HYPERLINK(\"http://bad\",\"click\")\r\n".as_bytes();
    assert!(
        verify_csv_formula_neutralization(bom_evil, &[]).is_err(),
        "UTF-8 BOM prefixed formula cell must be rejected"
    );
    let bom_quoted_evil = "\u{FEFF}\"=1+1\",ok\r\n".as_bytes();
    assert!(
        verify_csv_formula_neutralization(bom_quoted_evil, &[]).is_err(),
        "UTF-8 BOM prefixed quoted formula cell must be rejected"
    );
    let tsv_bom_evil = "\u{FEFF}=1+1\tok\n1\t2\n".as_bytes();
    assert!(
        verify_tsv_bytes(tsv_bom_evil, &[]).is_err(),
        "UTF-8 BOM prefixed TSV formula cell must be rejected"
    );
    let tsv_bom_ok = "\u{FEFF}'=1+1\tok\n1\t2\n".as_bytes();
    assert_eq!(verify_tsv_bytes(tsv_bom_ok, &["=1+1"]).unwrap(), 2);
}

#[test]
fn test_negative_unknown_tool_iserror_rejected_except_android2rust() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("bad_32601_iserror");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    for ws in [
        TargetWorkspace::Mail2Rust,
        TargetWorkspace::Sys2Rust,
        TargetWorkspace::Net2Rust,
    ] {
        let report = run_tiers(&TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures: fixtures.clone(),
            tiers: vec![Tier::Tier2],
            target: ws,
            skip_cargo_build: true,
        })
        .unwrap();
        let t2_05: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.id.ends_with("-05"))
            .collect();
        assert!(!t2_05.is_empty(), "{ws:?} missing T2-*-05 checks");
        for r in t2_05 {
            assert!(
                !r.passed && !r.skipped,
                "{ws:?} {} must FAIL when returning result.isError=true instead of -32601, got {r:?}",
                r.id
            );
        }
    }

    let android_report = run_tiers(&TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier2],
        target: TargetWorkspace::Android2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    let android_05 = android_report
        .results
        .iter()
        .find(|r| r.id == "T2-FG-14-05")
        .unwrap();
    assert!(
        android_05.passed,
        "Android2Rust T2-FG-14-05 must still PASS with legacy result.isError=true fallback, got {android_05:?}"
    );
}

#[test]
fn test_negative_header_only_csv_and_zero_leaf_custody_rejected() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    for mode in ["csv_header_only", "custody_0leaves"] {
        let _m = ModeGuard::set(mode);
        let report = run_tiers(&TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures: fixtures.clone(),
            tiers: vec![Tier::Tier3, Tier::Tier4],
            target: TargetWorkspace::Chrome2Rust,
            skip_cargo_build: true,
        })
        .unwrap();
        let t3_15 = report.results.iter().find(|r| r.id == "T3-15").unwrap();
        let t4_s05 = report.results.iter().find(|r| r.id == "T4-S05").unwrap();
        assert!(
            !t3_15.passed && !t3_15.skipped,
            "T3-15 must FAIL under {mode}, got {t3_15:?}"
        );
        assert!(
            !t4_s05.passed && !t4_s05.skipped,
            "T4-S05 must FAIL under {mode}, got {t4_s05:?}"
        );
    }
}

#[test]
fn test_single_workspace_isolation_ignores_broken_foreign_binaries() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    {
        let _m = ModeGuard::set("broken_chrome");
        let mail_report = run_tiers(&TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures: fixtures.clone(),
            tiers: vec![Tier::Tier4],
            target: TargetWorkspace::Mail2Rust,
            skip_cargo_build: true,
        })
        .unwrap();
        let s06 = mail_report
            .results
            .iter()
            .find(|r| r.id == "T4-S06")
            .unwrap();
        assert!(
            s06.passed,
            "Single-workspace Mail2Rust T4-S06 must PASS even when chrome2rust fails, got {s06:?}"
        );
    }

    {
        let _m = ModeGuard::set("broken_fs");
        let sys_report = run_tiers(&TierRunConfig {
            guap_root: guap_root.path().to_path_buf(),
            fixtures,
            tiers: vec![Tier::Tier4],
            target: TargetWorkspace::Sys2Rust,
            skip_cargo_build: true,
        })
        .unwrap();
        let s14 = sys_report
            .results
            .iter()
            .find(|r| r.id == "T4-S14")
            .unwrap();
        assert!(
            s14.passed,
            "Single-workspace Sys2Rust T4-S14 must PASS even when fs2rust fails, got {s14:?}"
        );
    }
}

#[test]
fn test_negative_non_json_mcp_radio_fails_t3_27_and_t4_s12() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("non_json_mcp_radio");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let report = run_tiers(&TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier3, Tier::Tier4],
        target: TargetWorkspace::Net2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    let t3_27 = report.results.iter().find(|r| r.id == "T3-27").unwrap();
    let t4_s12 = report.results.iter().find(|r| r.id == "T4-S12").unwrap();
    assert!(
        !t3_27.passed && !t3_27.skipped,
        "T3-27 must FAIL on plain 'ok' MCP response, got {t3_27:?}"
    );
    assert!(
        !t4_s12.passed && !t4_s12.skipped,
        "T4-S12 must FAIL on plain 'ok' MCP response, got {t4_s12:?}"
    );
}

#[test]
fn test_negative_nonpriv_empty_stdout_fails_t2_04() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _m = ModeGuard::set("nonpriv_empty");

    let guap_root = setup_mock_guap_root(true);
    let fix_tmp = TempDir::new().unwrap();
    let fixtures = materialize_all(fix_tmp.path()).unwrap();

    let report = run_tiers(&TierRunConfig {
        guap_root: guap_root.path().to_path_buf(),
        fixtures,
        tiers: vec![Tier::Tier2],
        target: TargetWorkspace::Sys2Rust,
        skip_cargo_build: true,
    })
    .unwrap();
    let t2_04: Vec<_> = report
        .results
        .iter()
        .filter(|r| r.id.ends_with("-04"))
        .collect();
    assert_eq!(t2_04.len(), 4);
    for r in t2_04 {
        assert!(
            !r.passed && !r.skipped,
            "Sys2Rust {} must FAIL on exit-0 0-byte stdout, got {r:?}",
            r.id
        );
    }
}

#[test]
fn test_resolve_binary_repropagates_cached_build_error() {
    let root = TempDir::new().unwrap();
    let net_dir = root.path().join("net2rust");
    write_file(
        &net_dir.join("Cargo.toml"),
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/net2rust-cli\"]\n",
    );
    write_file(
        &net_dir.join("crates/net2rust-cli/Cargo.toml"),
        "[package]\nname = \"net2rust-cli\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[[bin]]\nname = \"net2rust\"\npath = \"src/main.rs\"\n",
    );
    write_file(
        &net_dir.join("crates/net2rust-cli/src/main.rs"),
        "compile_error!(\"intentional broken build\");\n",
    );

    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let stale_bin = net_dir
        .join("target/debug")
        .join(format!("net2rust{exe_suffix}"));
    write_file(&stale_bin, "STALE_BINARY_SHOULD_NOT_BE_RETURNED");

    let mut session = WorkspaceSession::new(root.path().to_path_buf(), false);
    let first = session.resolve_binary(TargetWorkspace::Net2Rust);
    assert!(
        first.is_err(),
        "first resolve_binary must propagate build failure"
    );
    let second = session.resolve_binary(TargetWorkspace::Net2Rust);
    assert!(
        second.is_err(),
        "second resolve_binary must re-propagate cached build error rather than falling through to stale binary, got {second:?}"
    );
}

#[test]
fn test_net2rust_sockets_and_wol_mutating_schemas() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guap_root = setup_mock_guap_root(true);
    let mut session = WorkspaceSession::new(guap_root.path().to_path_buf(), true);
    let tools = session
        .cached_mcp_tools(TargetWorkspace::Net2Rust)
        .unwrap()
        .unwrap();

    let close = tools
        .iter()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some("sockets.ports.close"))
        .expect("sockets.ports.close must be listed");
    assert_eq!(close["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        close["inputSchema"]["required"],
        serde_json::json!(["local_addr", "local_port", "remote_addr", "remote_port"])
    );

    let wol = tools
        .iter()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some("lan.wol.send"))
        .expect("lan.wol.send must be listed");
    assert_eq!(wol["inputSchema"]["additionalProperties"], false);
    assert_eq!(wol["inputSchema"]["required"], serde_json::json!(["mac"]));
}
