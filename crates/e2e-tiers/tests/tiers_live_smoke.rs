use std::path::{Path, PathBuf};
use std::process::Command;

use e2e_fixtures::materialize_all;
use e2e_tiers::export_verify::{
    verify_csv_formula_neutralization_min_rows, verify_custody_manifest,
};
use e2e_tiers::mcp_client::McpSession;
use e2e_tiers::{TargetWorkspace, Tier, TierRunConfig, run_tiers};
use serde_json::{Value, json};
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

fn find_or_build_binary(ws_dir: &Path, bin_name: &str, pkg: &str) -> PathBuf {
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let debug = ws_dir
        .join("target")
        .join("debug")
        .join(format!("{bin_name}{suffix}"));
    if debug.is_file() {
        return debug;
    }
    let release = ws_dir
        .join("target")
        .join("release")
        .join(format!("{bin_name}{suffix}"));
    if release.is_file() {
        return release;
    }
    let out = Command::new("cargo")
        .current_dir(ws_dir)
        .args(["build", "--offline", "-p", pkg])
        .output()
        .expect("spawn cargo build");
    assert!(
        out.status.success(),
        "cargo build --offline -p {pkg} in {} failed: {}",
        ws_dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(debug.is_file(), "expected binary at {}", debug.display());
    debug
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
        TargetWorkspace::Winctl2Rust,
        TargetWorkspace::Net2Rust,
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
}

#[test]
fn appliance_and_robocopy_live_smoke() {
    let root = guap_root();
    let guap_dir = root.join("guap");
    let robo_dir = root.join("robocopy2rust");
    if !guap_dir.join("Cargo.toml").is_file() || !robo_dir.join("Cargo.toml").is_file() {
        eprintln!(
            "Skipping appliance_and_robocopy_live_smoke: sibling workspaces not present under {}",
            root.display()
        );
        return;
    }

    // 1) robocopy2rust CLI mcp --tools + live MCP JSON-RPC contract
    let robo_bin = find_or_build_binary(&robo_dir, "robocopy2rust", "robocopy2rust-cli");
    let robo_tools_out = Command::new(&robo_bin)
        .args(["mcp", "--tools"])
        .output()
        .unwrap();
    assert!(
        robo_tools_out.status.success(),
        "robocopy2rust mcp --tools failed: {}",
        String::from_utf8_lossy(&robo_tools_out.stderr)
    );
    let robo_tools: Vec<Value> = serde_json::from_slice(&robo_tools_out.stdout).unwrap();
    assert_eq!(robo_tools.len(), 9);
    for t in &robo_tools {
        let ann = t.get("annotations").and_then(Value::as_object).unwrap();
        assert!(ann.get("readOnlyHint").and_then(Value::as_bool).is_some());
        assert!(
            ann.get("destructiveHint")
                .and_then(Value::as_bool)
                .is_some()
        );
    }

    let mut robo_mcp = McpSession::spawn(&robo_bin, &["mcp"], &[]).unwrap();
    robo_mcp.initialize().unwrap();
    let robo_listed = robo_mcp.tools_list().unwrap();
    assert_eq!(robo_listed.len(), 9);
    let presets_resp = robo_mcp
        .tools_call("robocopy2rust_presets", json!({}))
        .unwrap();
    assert_eq!(presets_resp["result"]["isError"], json!(false));
    let bad_json = robo_mcp.send_raw_line_and_read("{bad json").unwrap();
    assert_eq!(bad_json.pointer("/error/code"), Some(&json!(-32700)));
    let bad_args = robo_mcp
        .tools_call("robocopy2rust_presets", json!("not_object"))
        .unwrap();
    assert_eq!(bad_args.pointer("/error/code"), Some(&json!(-32602)));
    let unknown_tool = robo_mcp
        .tools_call("__nonexistent_robo_tool", json!({}))
        .unwrap();
    assert_eq!(unknown_tool.pointer("/error/code"), Some(&json!(-32601)));
    let safety_resp = robo_mcp
        .tools_call(
            "robocopy2rust_run",
            json!({
                "preset": "exact-mirror",
                "source": "C:\\Src",
                "destination": "D:\\Dst"
            }),
        )
        .unwrap();
    assert_eq!(safety_resp["result"]["isError"], json!(true));
    let safety_msg = safety_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        safety_msg.contains("SAFETY REFUSAL"),
        "expected SAFETY REFUSAL, got {safety_msg}"
    );
    robo_mcp.close().unwrap();

    // 2) guap appliance CLI + CSV/Merkle + compact 6-meta-tool MCP + portable bundle round-trip
    let guap_bin = find_or_build_binary(&guap_dir, "guap", "guap-cli");
    let state_tmp = TempDir::new().unwrap();
    let state_dir = state_tmp.path().join("state");
    let state_str = state_dir.display().to_string();

    let st_out = Command::new(&guap_bin)
        .args(["--offline", "--state-dir", &state_str, "status", "--json"])
        .output()
        .unwrap();
    assert!(
        st_out.status.success(),
        "guap status --json failed: {}",
        String::from_utf8_lossy(&st_out.stderr)
    );
    let st_val: Value = serde_json::from_slice(&st_out.stdout).unwrap();
    assert!(st_val.get("appliance").is_some());
    assert!(st_val.get("suites").is_some());

    let suites_csv = Command::new(&guap_bin)
        .args([
            "--offline",
            "--state-dir",
            &state_str,
            "suites",
            "--format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(
        suites_csv.status.success(),
        "guap suites --format csv failed: {}",
        String::from_utf8_lossy(&suites_csv.stderr)
    );
    verify_csv_formula_neutralization_min_rows(&suites_csv.stdout, &[], 10).unwrap();

    let guap_tools_out = Command::new(&guap_bin)
        .args(["--offline", "--state-dir", &state_str, "mcp", "--tools"])
        .output()
        .unwrap();
    assert!(guap_tools_out.status.success());
    let guap_tools: Vec<Value> = serde_json::from_slice(&guap_tools_out.stdout).unwrap();
    let compact_len = serde_json::to_string(&guap_tools).unwrap().len();
    assert!(
        compact_len < 4800,
        "guap 6 meta-tools exceeded prompt budget: {compact_len} compact bytes"
    );
    assert_eq!(guap_tools.len(), 6);
    for t in &guap_tools {
        assert!(t.get("annotations").and_then(Value::as_object).is_some());
    }

    let mut guap_mcp = McpSession::spawn(
        &guap_bin,
        &["--offline", "--state-dir", &state_str, "mcp"],
        &[],
    )
    .unwrap();
    guap_mcp.initialize().unwrap();
    assert_eq!(guap_mcp.tools_list().unwrap().len(), 6);
    let host_summary = guap_mcp.tools_call("guap_host_summary", json!({})).unwrap();
    assert_eq!(host_summary["result"]["isError"], json!(false));
    let find_tools = guap_mcp
        .tools_call("guap_find_tools", json!({ "query": "process" }))
        .unwrap();
    assert_eq!(find_tools["result"]["isError"], json!(false));
    let mut_blocked = guap_mcp
        .tools_call(
            "guap_call_readonly",
            json!({ "tool": "sys2rust/service_set_start_mode" }),
        )
        .unwrap();
    assert_eq!(mut_blocked.pointer("/error/code"), Some(&json!(-32003)));
    let staged = guap_mcp
        .tools_call(
            "guap_stage_fix",
            json!({
                "tool": "sys2rust/service_set_start_mode",
                "arguments": { "target": "Fax" },
                "rationale": "test",
                "rollback_hint": "undo"
            }),
        )
        .unwrap();
    assert_eq!(staged["result"]["isError"], json!(false));
    let staged_text = staged["result"]["content"][0]["text"].as_str().unwrap();
    let staged_val: Value = serde_json::from_str(staged_text).unwrap();
    assert_eq!(staged_val["staged"], json!(true));
    assert_eq!(
        guap_mcp
            .send_raw_line_and_read("{bad json")
            .unwrap()
            .pointer("/error/code"),
        Some(&json!(-32700))
    );
    assert_eq!(
        guap_mcp
            .tools_call("guap_find_tools", json!("not_object"))
            .unwrap()
            .pointer("/error/code"),
        Some(&json!(-32602))
    );
    assert_eq!(
        guap_mcp
            .tools_call("__nonexistent_guap_tool", json!({}))
            .unwrap()
            .pointer("/error/code"),
        Some(&json!(-32601))
    );
    guap_mcp.close().unwrap();

    let bundle_dir = state_tmp.path().join("bundle");
    let bundle_str = bundle_dir.display().to_string();
    let create_out = Command::new(&guap_bin)
        .args([
            "--offline",
            "--state-dir",
            &state_str,
            "bundle",
            "create",
            "--out",
            &bundle_str,
        ])
        .output()
        .unwrap();
    assert!(
        create_out.status.success(),
        "guap bundle create failed: {}",
        String::from_utf8_lossy(&create_out.stderr)
    );
    let verify_out = Command::new(&guap_bin)
        .args([
            "--offline",
            "--state-dir",
            &state_str,
            "bundle",
            "verify",
            "--dir",
            &bundle_str,
        ])
        .output()
        .unwrap();
    assert!(
        verify_out.status.success(),
        "guap bundle verify failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let manifest_bytes = std::fs::read(bundle_dir.join("portable-manifest.custody.json")).unwrap();
    verify_custody_manifest(&manifest_bytes, false).unwrap();
}

#[test]
fn all_suites_mcp_annotations_and_jsonrpc_contract() {
    let root = guap_root();
    let specs: &[(&str, &str, &str, &[&str], usize, usize, usize)] = &[
        (
            "chrome2rust",
            "chrome2rust-mcp",
            "chrome2rust-mcp",
            &[],
            29,
            29,
            0,
        ),
        (
            "android2rust",
            "android2rust-mcp",
            "android2rust-mcp",
            &[],
            13,
            11,
            2,
        ),
        (
            "mail2rust",
            "mail2rust-mcp",
            "mail2rust-mcp",
            &["--allow-mutating"],
            15,
            9,
            6,
        ),
        (
            "robocopy2rust",
            "robocopy2rust-mcp",
            "robocopy2rust-mcp",
            &[],
            9,
            6,
            3,
        ),
    ];

    for &(dir_name, bin_name, pkg_name, _, _, _, _) in specs {
        if !root.join(dir_name).join("Cargo.toml").is_file() {
            eprintln!(
                "Skipping all_suites_mcp_annotations_and_jsonrpc_contract: missing {dir_name}"
            );
            return;
        }
        let _ = (bin_name, pkg_name);
    }

    for &(dir_name, bin_name, pkg_name, extra_args, expected_total, expected_ro, expected_mut) in
        specs
    {
        let ws_dir = root.join(dir_name);
        let bin = find_or_build_binary(&ws_dir, bin_name, pkg_name);
        let mut sess = McpSession::spawn(&bin, extra_args, &[]).unwrap();
        sess.initialize().unwrap();

        let tools = sess.tools_list().unwrap();
        assert_eq!(
            tools.len(),
            expected_total,
            "{dir_name} tool count mismatch"
        );
        let mut ro_count = 0usize;
        let mut mut_count = 0usize;
        for t in &tools {
            let ann = t
                .get("annotations")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{dir_name} tool '{}' missing annotations", t["name"]));
            let ro = ann
                .get("readOnlyHint")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| {
                    panic!("{dir_name} tool '{}' missing bool readOnlyHint", t["name"])
                });
            assert!(
                ann.get("destructiveHint")
                    .and_then(Value::as_bool)
                    .is_some(),
                "{dir_name} tool '{}' missing bool destructiveHint",
                t["name"]
            );
            if ro {
                ro_count += 1;
            } else {
                mut_count += 1;
            }
        }
        assert_eq!(
            ro_count, expected_ro,
            "{dir_name} RO annotation count mismatch"
        );
        assert_eq!(
            mut_count, expected_mut,
            "{dir_name} Mut annotation count mismatch"
        );

        let bad_json = sess.send_raw_line_and_read("{bad json").unwrap();
        assert_eq!(
            bad_json.pointer("/error/code"),
            Some(&json!(-32700)),
            "{dir_name} parse error"
        );

        let first_tool = tools[0]["name"].as_str().unwrap();
        let bad_args = sess.tools_call(first_tool, json!("not_object")).unwrap();
        assert_eq!(
            bad_args.pointer("/error/code"),
            Some(&json!(-32602)),
            "{dir_name} -32602 check"
        );

        let unknown = sess
            .tools_call("__nonexistent_contract_tool", json!({}))
            .unwrap();
        assert_eq!(
            unknown.pointer("/error/code"),
            Some(&json!(-32601)),
            "{dir_name} -32601 check"
        );

        sess.close().unwrap();
    }
}
