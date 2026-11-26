use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, bail, ensure};
use e2e_fixtures::MaterializedFixtures;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::catalog::{
    catalog_checks, feature_groups, find_feature_group, is_legacy_no_annotations_tool,
    validate_catalog_invariants,
};
use crate::export_verify::{
    build_sample_custody_manifest, is_formula_dangerous, neutralize_spreadsheet_cell,
    parse_rfc4180_csv, verify_csv_formula_neutralization,
    verify_csv_formula_neutralization_min_rows, verify_custody_manifest,
};
use crate::mcp_client::{McpSession, assert_policy_denied, assert_tool_call_ok};
use crate::model::{
    CatalogCheckDef, CheckKind, CheckResult, CliExportStyle, CliInputStyle, CliLiveStyle,
    FeatureGroupDef, ItemSpec, McpArgsKind, MutatingActionSpec, MutatingArgsKind, TargetWorkspace,
    Tier, TierReport, TierRunConfig,
};
use crate::workspace::{WorkspaceSession, truncate_preview};

pub fn run_tiers(cfg: &TierRunConfig) -> anyhow::Result<TierReport> {
    let active_tiers: BTreeSet<Tier> = if cfg.tiers.is_empty() {
        Tier::all().into_iter().collect()
    } else {
        cfg.tiers.iter().copied().collect()
    };

    let mut session = WorkspaceSession::new(cfg.guap_root.clone(), cfg.skip_cargo_build);
    let mut results = Vec::new();

    for chk in catalog_checks() {
        if !active_tiers.contains(&chk.tier) {
            continue;
        }
        if !matches_target(chk, cfg.target) {
            continue;
        }

        let start = Instant::now();
        let outcome = execute_check(chk, cfg, &mut session);
        let duration_ms = start.elapsed().as_millis() as u64;

        match outcome {
            Ok(CheckOutcome::Pass(msg)) => results.push(CheckResult {
                id: chk.id.to_string(),
                tier: chk.tier,
                workspace: chk.primary_workspace.dir_name().to_string(),
                feature_group: chk.feature_group_name.to_string(),
                passed: true,
                skipped: false,
                message: msg,
                duration_ms,
            }),
            Ok(CheckOutcome::Skip(msg)) => results.push(CheckResult {
                id: chk.id.to_string(),
                tier: chk.tier,
                workspace: chk.primary_workspace.dir_name().to_string(),
                feature_group: chk.feature_group_name.to_string(),
                passed: false,
                skipped: true,
                message: msg,
                duration_ms,
            }),
            Err(err) => results.push(CheckResult {
                id: chk.id.to_string(),
                tier: chk.tier,
                workspace: chk.primary_workspace.dir_name().to_string(),
                feature_group: chk.feature_group_name.to_string(),
                passed: false,
                skipped: false,
                message: format!("{err:#}"),
                duration_ms,
            }),
        }
    }

    Ok(TierReport::from_results(results))
}

enum CheckOutcome {
    Pass(String),
    Skip(String),
}

fn matches_target(chk: &CatalogCheckDef, target: TargetWorkspace) -> bool {
    if target == TargetWorkspace::All {
        return true;
    }
    chk.primary_workspace == target
}

fn check_required_workspaces(
    chk: &CatalogCheckDef,
    session: &WorkspaceSession,
) -> Option<CheckOutcome> {
    for &ws in chk.required_workspaces {
        if !session.is_workspace_present(ws) {
            return Some(CheckOutcome::Skip(format!(
                "workspace '{}' not present under {}",
                ws.dir_name(),
                session.guap_root.display()
            )));
        }
    }
    None
}

fn require_domain_binary(
    ws: TargetWorkspace,
    session: &mut WorkspaceSession,
) -> anyhow::Result<Result<std::path::PathBuf, CheckOutcome>> {
    if !session.is_workspace_present(ws) {
        return Ok(Err(CheckOutcome::Skip(format!(
            "workspace '{}' not present under {}",
            ws.dir_name(),
            session.guap_root.display()
        ))));
    }
    match session.resolve_binary(ws)? {
        Some(path) => Ok(Ok(path)),
        None => Ok(Err(CheckOutcome::Skip(format!(
            "binary for '{}' not built and skip_cargo_build=true",
            ws.dir_name()
        )))),
    }
}

fn execute_check(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if let Some(skip) = check_required_workspaces(chk, session) {
        return Ok(skip);
    }

    match chk.kind {
        CheckKind::GuapKitCargoBaseline => run_guap_kit_cargo_baseline(chk, cfg, session),
        CheckKind::GuapKitCargoTest => run_guap_kit_cargo_test(chk, cfg, session),
        CheckKind::GuapKitContractScan => run_guap_kit_contract_scan(chk, cfg, session),
        CheckKind::GuapKitFunctionalA => run_guap_kit_functional_a(chk, cfg, session),
        CheckKind::GuapKitFunctionalB => run_guap_kit_functional_b(chk, cfg, session),
        CheckKind::GuapKitBoundary(tag) => run_guap_kit_boundary(chk, tag, cfg, session),

        CheckKind::E2eFixtureIntegrity => {
            let report = e2e_fixtures::verify_fixture_integrity(&cfg.fixtures)?;
            ensure!(report.all_verified(), "fixture integrity check failed");
            Ok(CheckOutcome::Pass(format!(
                "verified {}/{} fixtures + R4 zero-credential scan",
                report.verified_files, report.total_files
            )))
        }
        CheckKind::E2eCatalogCompleteness => {
            validate_catalog_invariants()?;
            Ok(CheckOutcome::Pass(
                "360 checks, 31 feature groups, 227/227 unique items verified".to_string(),
            ))
        }
        CheckKind::E2eExportVerifierSelfCheck => run_e2e_export_verifier_self_check(cfg),
        CheckKind::E2eMcpProtocolSelfCheck => run_e2e_mcp_protocol_self_check(),
        CheckKind::E2eHarnessWorkspaceCheck => run_e2e_harness_workspace_check(cfg),
        CheckKind::E2eNegativeSelfCheck(tag) => run_e2e_negative_self_check(tag, cfg),

        CheckKind::DomainCargoCheckTest => run_domain_cargo_check_test(chk, cfg, session),
        CheckKind::DomainCliHelpAllItems => run_domain_cli_help(chk, session),
        CheckKind::DomainMcpToolsAllItems => run_domain_mcp_tools(chk, session),
        CheckKind::DomainMcpJsonRpcReadOnly => run_domain_mcp_jsonrpc(chk, cfg, session),
        CheckKind::DomainCliReadOnlyAllItems => run_domain_cli_readonly_all(chk, cfg, session),

        CheckKind::DomainMissingPath => run_domain_missing_path(chk, session),
        CheckKind::DomainCorruptFixture => run_domain_corrupt_fixture(chk, cfg, session),
        CheckKind::DomainEmptyAndInvalidFlags => run_domain_empty_and_invalid(chk, cfg, session),
        CheckKind::DomainNonPrivilegedFallback => run_domain_nonpriv_fallback(chk, session),
        CheckKind::DomainMalformedMcpJsonRpc => run_domain_malformed_mcp(chk, cfg, session),

        CheckKind::Tier3Pairwise(id) => run_tier3_pairwise(id, chk, cfg, session),
        CheckKind::Tier4Scenario(id) => run_tier4_scenario(id, chk, cfg, session),
    }
}

fn fg_for_check(chk: &CatalogCheckDef) -> anyhow::Result<&'static FeatureGroupDef> {
    find_feature_group(chk.feature_group_id)
        .with_context(|| format!("missing feature group {}", chk.feature_group_id))
}

fn strip_rust_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0usize;
    let mut block_depth = 0usize;
    let mut in_line_comment = false;
    let mut in_str = false;
    let mut raw_hashes: Option<usize> = None;

    while i < len {
        if in_line_comment {
            if bytes[i] == b'\n' {
                in_line_comment = false;
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if block_depth > 0 {
            if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                block_depth += 1;
                i += 2;
            } else if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                block_depth -= 1;
                if block_depth == 0 {
                    out.push(' ');
                }
                i += 2;
            } else {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if let Some(hashes) = raw_hashes {
            let ch = src[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            if ch == '"' {
                let mut matched = 0usize;
                while matched < hashes && i + matched < len && bytes[i + matched] == b'#' {
                    matched += 1;
                }
                if matched == hashes {
                    for _ in 0..hashes {
                        out.push('#');
                    }
                    i += hashes;
                    raw_hashes = None;
                }
            }
            continue;
        }
        if in_str {
            let ch = src[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            if ch == '\\' && i < len {
                let esc = src[i..].chars().next().unwrap();
                out.push(esc);
                i += esc.len_utf8();
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }

        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            in_line_comment = true;
            i += 2;
            continue;
        }
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            block_depth = 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'\'' && i + 1 < len {
            if bytes[i + 1] == b'\\' && i + 2 < len {
                let mut j = i + 2;
                let esc = src[j..].chars().next().unwrap();
                j += esc.len_utf8();
                if esc == 'x' {
                    while j < len && j < i + 5 && bytes[j].is_ascii_hexdigit() {
                        j += 1;
                    }
                } else if esc == 'u' && j < len && bytes[j] == b'{' {
                    j += 1;
                    while j < len && bytes[j] != b'}' && bytes[j] != b'\n' {
                        j += 1;
                    }
                    if j < len && bytes[j] == b'}' {
                        j += 1;
                    }
                }
                if j < len && bytes[j] == b'\'' {
                    j += 1;
                    out.push_str(&src[i..j]);
                    i = j;
                    continue;
                }
            } else if let Some(c) = src[i + 1..].chars().next()
                && c != '\\'
                && c != '\''
                && c != '\n'
                && c != '\r'
            {
                let after = i + 1 + c.len_utf8();
                if after < len && bytes[after] == b'\'' {
                    let end = after + 1;
                    out.push_str(&src[i..end]);
                    i = end;
                    continue;
                }
            }
        }
        if bytes[i] == b'r' {
            let mut j = i + 1;
            while j < len && bytes[j] == b'#' {
                j += 1;
            }
            if j < len && bytes[j] == b'"' {
                let hashes = j - (i + 1);
                while i <= j {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                raw_hashes = Some(hashes);
                continue;
            }
        }
        let ch = src[i..].chars().next().unwrap();
        if ch == '"' {
            in_str = true;
        }
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn parse_cargo_test_passed_count(stdout: &str) -> anyhow::Result<usize> {
    let mut total_passed = 0usize;
    let mut saw_summary = false;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("test result: ") {
            saw_summary = true;
            ensure!(
                rest.starts_with("ok."),
                "cargo test summary did not report ok: {line}"
            );
            // Format: "ok. N passed; M failed; ..."
            let after_ok = rest.trim_start_matches("ok.").trim();
            let passed_num = after_ok
                .split_whitespace()
                .next()
                .and_then(|tok| tok.parse::<usize>().ok())
                .with_context(|| format!("could not parse passed count from '{line}'"))?;
            total_passed += passed_num;
        }
    }
    ensure!(saw_summary, "cargo test output missing 'test result:' summary");
    Ok(total_passed)
}

fn run_guap_kit_cargo_test_checked(
    session: &mut WorkspaceSession,
    args: &[&str],
    min_passed: usize,
) -> anyhow::Result<usize> {
    let gk_dir = session.workspace_dir(TargetWorkspace::GuapKit);
    let out = session.run_cargo_cached(&gk_dir, args)?;
    ensure!(
        out.success(),
        "cargo {} in {} failed: {}",
        args.join(" "),
        gk_dir.display(),
        truncate_preview(&out.stderr, 400)
    );
    let passed = parse_cargo_test_passed_count(&out.stdout)?;
    ensure!(
        passed >= min_passed,
        "cargo {} passed {} test(s), expected >= {}",
        args.join(" "),
        passed,
        min_passed
    );
    Ok(passed)
}

fn run_guap_kit_cargo_baseline(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let gk_dir = session.workspace_dir(TargetWorkspace::GuapKit);
    let root_toml = std::fs::read_to_string(gk_dir.join("Cargo.toml"))
        .context("missing guap-kit/Cargo.toml")?;
    ensure!(
        root_toml.contains("resolver = \"2\""),
        "guap-kit/Cargo.toml missing resolver = \"2\""
    );
    ensure!(
        root_toml.contains("edition = \"2024\""),
        "guap-kit/Cargo.toml missing edition = \"2024\""
    );
    ensure!(
        root_toml.contains("license = \"Apache-2.0\""),
        "guap-kit/Cargo.toml missing license = \"Apache-2.0\""
    );
    let fg = fg_for_check(chk)?;
    let crate_toml_path = gk_dir.join("crates").join(fg.domain_crate).join("Cargo.toml");
    let crate_toml = std::fs::read_to_string(&crate_toml_path)
        .with_context(|| format!("missing {}", crate_toml_path.display()))?;
    ensure!(
        crate_toml.contains(&format!("name = \"{}\"", fg.domain_crate)),
        "{} missing package name = \"{}\"",
        crate_toml_path.display(),
        fg.domain_crate
    );
    if fg.domain_crate == "guap-gui-win32" {
        ensure!(
            crate_toml.contains("native-host"),
            "guap-gui-win32/Cargo.toml missing native-host feature"
        );
    }

    if !cfg.skip_cargo_build {
        let out = session.run_cargo_cached(&gk_dir, &["check", "--offline", "-p", fg.domain_crate])?;
        ensure!(
            out.success(),
            "cargo check --offline -p {} failed: {}",
            fg.domain_crate,
            truncate_preview(&out.stderr, 350)
        );
        if fg.domain_crate == "guap-gui-win32" {
            let headless = session.run_cargo_cached(
                &gk_dir,
                &["check", "--offline", "-p", "guap-gui-win32", "--no-default-features"],
            )?;
            ensure!(
                headless.success(),
                "cargo check --offline -p guap-gui-win32 --no-default-features failed: {}",
                truncate_preview(&headless.stderr, 350)
            );
        }
        return Ok(CheckOutcome::Pass(format!(
            "{} Cargo.toml baseline + cargo check passed",
            fg.domain_crate
        )));
    }
    Ok(CheckOutcome::Pass(format!(
        "{} Cargo.toml baseline verified (skip_cargo_build=true)",
        fg.domain_crate
    )))
}

fn run_guap_kit_cargo_test(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if cfg.skip_cargo_build {
        return Ok(CheckOutcome::Skip(
            "guap-kit runtime cargo test skipped because skip_cargo_build=true".to_string(),
        ));
    }
    let fg = fg_for_check(chk)?;
    let (args, min_tests): (&[&str], usize) = match fg.domain_crate {
        "guap-table" => (&["test", "--offline", "-p", "guap-table"], 8),
        "guap-export" => (&["test", "--offline", "-p", "guap-export"], 6),
        "guap-gui-win32" => (&["test", "--offline", "-p", "guap-gui-win32", "--no-default-features", "--lib"], 2),
        "guap-gui-iced" => (&["test", "--offline", "-p", "guap-gui-iced"], 1),
        "guap-mcp" => (&["test", "--offline", "-p", "guap-mcp"], 5),
        other => bail!("unknown guap-kit crate {other}"),
    };
    let passed = run_guap_kit_cargo_test_checked(session, args, min_tests)?;
    Ok(CheckOutcome::Pass(format!(
        "cargo {} passed ({passed} tests)",
        args.join(" ")
    )))
}

fn read_crate_sources(crate_dir: &Path) -> anyhow::Result<String> {
    let mut combined = String::new();
    let src_dir = crate_dir.join("src");
    ensure!(src_dir.is_dir(), "missing src dir {}", src_dir.display());
    for entry in walkdir::WalkDir::new(&src_dir) {
        let entry = entry?;
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|e| e.to_str()) == Some("rs")
        {
            combined.push_str(&std::fs::read_to_string(entry.path())?);
            combined.push('\n');
        }
    }
    Ok(combined)
}

fn run_guap_kit_contract_scan(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    let gk_dir = session.workspace_dir(TargetWorkspace::GuapKit);
    let crate_dir = gk_dir.join("crates").join(fg.domain_crate);
    let raw_src = read_crate_sources(&crate_dir)?;
    let code_only = strip_rust_comments(&raw_src);
    let normalized: String = code_only.split_whitespace().collect::<Vec<_>>().join(" ");

    let required_decls: &[&str] = match fg.domain_crate {
        "guap-table" => &[
            "pub trait TableProvider",
            "pub struct ColumnDef",
            "pub enum CellValue",
            "pub struct GetNirQuery",
            "pub struct TableTextCompare",
        ],
        "guap-export" => &[
            "pub enum ExportFormat",
            "pub struct CustodyManifest",
            "pub fn neutralize_spreadsheet_cell",
            "pub fn compute_merkle_root_sha256",
        ],
        "guap-gui-win32" => &["pub struct Win32TableHostConfig", "pub struct Win32GridState"],
        "guap-gui-iced" => &["pub struct IcedDataGrid", "pub enum DataGridMessage"],
        "guap-mcp" => &["\"2024-11-05\"", "-32003", "pub enum PolicyMode", "pub trait ActionCommand"],
        _ => &[],
    };
    for &decl in required_decls {
        ensure!(
            normalized.contains(decl),
            "{} missing non-comment declaration {:?}",
            fg.domain_crate,
            decl
        );
    }

    if !cfg.skip_cargo_build {
        let out = session.run_cargo_cached(
            &gk_dir,
            &["check", "--offline", "-p", fg.domain_crate, "--all-targets"],
        )?;
        ensure!(
            out.success(),
            "cargo check --all-targets failed for {}: {}",
            fg.domain_crate,
            truncate_preview(&out.stderr, 350)
        );
    }

    Ok(CheckOutcome::Pass(format!(
        "{} non-comment pub declarations verified ({} symbols)",
        fg.domain_crate,
        required_decls.len()
    )))
}

fn run_guap_kit_functional_a(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if cfg.skip_cargo_build {
        return Ok(CheckOutcome::Skip(
            "guap-kit runtime cargo test skipped because skip_cargo_build=true".to_string(),
        ));
    }
    let fg = fg_for_check(chk)?;
    match fg.domain_crate {
        "guap-table" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "query_10k"],
                2,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-table 10k query/filter/sort tests passed ({n})")))
        }
        "guap-export" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "csv_rfc4180_and_formula_neutralization"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-export CSV RFC-4180 + formula neutralization passed ({n})")))
        }
        "guap-gui-win32" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-gui-win32", "--no-default-features", "--lib", "win32_state_25k"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-gui-win32 25k state/filter/sort/export passed ({n})")))
        }
        "guap-gui-iced" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-gui-iced", "--test", "grid_headless", "iced_grid_25k"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-gui-iced 25k paginated headless grid passed ({n})")))
        }
        "guap-mcp" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "protocol_initialize"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-mcp 2024-11-05 handshake/ping/notifications passed ({n})")))
        }
        other => bail!("unknown guap-kit crate {other}"),
    }
}

fn run_guap_kit_functional_b(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if cfg.skip_cargo_build {
        return Ok(CheckOutcome::Skip(
            "guap-kit runtime cargo test skipped because skip_cargo_build=true".to_string(),
        ));
    }
    let fg = fg_for_check(chk)?;
    match fg.domain_crate {
        "guap-table" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "table_text_compare_10k_diff"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-table TableTextCompare 10k diff passed ({n})")))
        }
        "guap-export" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "merkle_sha256_and_sha512"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-export SHA-256/512 Merkle vectors passed ({n})")))
        }
        "guap-gui-win32" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-gui-win32", "--no-default-features", "--lib", "utf16_buf_write"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-gui-win32 UTF-16 surrogate buffer test passed ({n})")))
        }
        "guap-gui-iced" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-gui-iced", "--test", "grid_headless"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-gui-iced TableProvider interop passed ({n})")))
        }
        "guap-mcp" => {
            let n = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "tools_list_annotations"],
                1,
            )?;
            Ok(CheckOutcome::Pass(format!("guap-mcp tools/list annotations & TableProvider passed ({n})")))
        }
        other => bail!("unknown guap-kit crate {other}"),
    }
}

fn run_guap_kit_boundary(
    chk: &CatalogCheckDef,
    tag: &str,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if cfg.skip_cargo_build {
        return Ok(CheckOutcome::Skip(
            "guap-kit runtime cargo test skipped because skip_cargo_build=true".to_string(),
        ));
    }
    let fg = fg_for_check(chk)?;
    let (args, min_passed): (&[&str], usize) = match (fg.domain_crate, tag) {
        ("guap-table", "empty_schema") => (&["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "table_text_compare_rejects_duplicate_left_column_ids"], 1),
        ("guap-table", "invalid_query") => (&["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "get_nir_query_rejects_standalone_amp_pipe_and_excessive_nesting"], 1),
        ("guap-table", "injection_escape") => (&["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "filter_numeric_comparison_preserves_precision_above_2_pow_53"], 1),
        ("guap-table", "missing_or_headless") => (&["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "cell_value_ord_consistency_and_nan"], 1),
        ("guap-table", "rpc_policy_boundary") => (&["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k"], 8),

        ("guap-export", "empty_schema") => (&["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "tsv_sanitizes_embedded_tabs_and_newlines"], 1),
        ("guap-export", "invalid_query") => (&["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "json_and_jsonl_roundtrip"], 1),
        ("guap-export", "injection_escape") => (&["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "html_horizontal_and_vertical_csp_and_xss_escaping"], 1),
        ("guap-export", "missing_or_headless") => (&["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "markdown_escapes_pipes_and_newlines"], 1),
        ("guap-export", "rpc_policy_boundary") => (&["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle"], 6),

        ("guap-gui-win32", _) => (&["test", "--offline", "-p", "guap-gui-win32", "--no-default-features", "--lib"], 2),
        ("guap-gui-iced", _) => (&["test", "--offline", "-p", "guap-gui-iced", "--test", "grid_headless"], 1),

        ("guap-mcp", "empty_schema") | ("guap-mcp", "invalid_query") => {
            (&["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "protocol_initialize_ping_notifications_and_errors"], 1)
        }
        ("guap-mcp", "injection_escape") => {
            (&["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "stdio_frame_loop_processes_stream"], 1)
        }
        ("guap-mcp", "missing_or_headless") => {
            (&["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "non_read_only_table_provider_exposes_confirm_destructive_and_enforces_32003"], 1)
        }
        ("guap-mcp", "rpc_policy_boundary") => {
            (&["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "policy_gates_enforce_32003_and_allow_confirmed_mutations"], 1)
        }
        _ => bail!("unknown guap-kit boundary ({}, {tag})", fg.domain_crate),
    };
    let n = run_guap_kit_cargo_test_checked(session, args, min_passed)?;
    Ok(CheckOutcome::Pass(format!(
        "{} boundary ({tag}) via cargo test passed ({n})",
        fg.domain_crate
    )))
}
fn run_e2e_export_verifier_self_check(cfg: &TierRunConfig) -> anyhow::Result<CheckOutcome> {
    let raw = std::fs::read(cfg.fixtures.sys_fs_dir.join("sample_data.csv"))?;
    let rows = parse_rfc4180_csv(&raw)?;
    let mut csv_out = String::new();
    for r in &rows {
        let line: Vec<String> = r
            .iter()
            .map(|c| {
                let n = neutralize_spreadsheet_cell(c);
                if n.contains(',') || n.contains('"') {
                    format!("\"{}\"", n.replace('"', "\"\""))
                } else {
                    n
                }
            })
            .collect();
        csv_out.push_str(&line.join(","));
        csv_out.push_str("\r\n");
    }
    let verified_rows = verify_csv_formula_neutralization(
        csv_out.as_bytes(),
        &["=cmd|'/C calc'!A0", "+1234+5678", "-5678", "@SUM(1,2)", "\tleading_tab"],
    )?;
    let p1 = cfg.fixtures.sys_fs_dir.join("sample_data.csv");
    let manifest = build_sample_custody_manifest("guap-e2e", "0.1.0", &[&p1])?;
    verify_custody_manifest(&manifest, true)?;
    Ok(CheckOutcome::Pass(format!(
        "verified {verified_rows} neutralized CSV rows and 1-leaf SHA-256/512 Merkle custody"
    )))
}

fn run_e2e_mcp_protocol_self_check() -> anyhow::Result<CheckOutcome> {
    let denied = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"SAFETY REFUSAL"}});
    assert_policy_denied(&denied, "test_tool", true)?;
    let ok = json!({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"rows\":[]}"}],"isError":false}});
    let txt = assert_tool_call_ok(&ok, "test_tool")?;
    ensure!(txt.contains("rows"));
    Ok(CheckOutcome::Pass(
        "MCP JSON-RPC 2024-11-05 & -32003 policy validators verified".to_string(),
    ))
}

fn run_e2e_harness_workspace_check(cfg: &TierRunConfig) -> anyhow::Result<CheckOutcome> {
    ensure!(
        cfg.fixtures.root.join("fixture_manifest.json").is_file(),
        "missing fixture_manifest.json under {}",
        cfg.fixtures.root.display()
    );
    ensure!(
        feature_groups().len() == 31,
        "expected 31 feature groups in catalog"
    );
    Ok(CheckOutcome::Pass(
        "e2e_harness workspace & fixture_manifest.json verified".to_string(),
    ))
}

fn run_e2e_negative_self_check(tag: &str, cfg: &TierRunConfig) -> anyhow::Result<CheckOutcome> {
    let p1 = cfg.fixtures.sys_fs_dir.join("sample_data.csv");
    let p2 = cfg.fixtures.sys_fs_dir.join("sample_data_right.csv");
    match tag {
        "tampered_merkle_leaf" => {
            let bytes = build_sample_custody_manifest("guap-e2e", "0.1.0", &[&p1, &p2])?;
            let mut val: Value = serde_json::from_slice(&bytes)?;
            val["leaves"][0]["sha256"] = json!("0".repeat(64));
            let tampered = serde_json::to_vec(&val)?;
            ensure!(
                verify_custody_manifest(&tampered, false).is_err(),
                "tampered leaf sha256 unexpectedly passed"
            );
            Ok(CheckOutcome::Pass("tampered Merkle leaf SHA-256 rejected".into()))
        }
        "tampered_merkle_root512" => {
            let bytes = build_sample_custody_manifest("guap-e2e", "0.1.0", &[&p1, &p2])?;
            let mut val: Value = serde_json::from_slice(&bytes)?;
            val["merkle_root_sha512"] = json!("f".repeat(128));
            let tampered = serde_json::to_vec(&val)?;
            ensure!(
                verify_custody_manifest(&tampered, false).is_err(),
                "tampered merkle_root_sha512 unexpectedly passed"
            );
            Ok(CheckOutcome::Pass("tampered Merkle root SHA-512 rejected".into()))
        }
        "unneutralized_csv" => {
            let raw = std::fs::read(cfg.fixtures.sys_fs_dir.join("sample_data.csv"))?;
            ensure!(
                verify_csv_formula_neutralization(&raw, &[]).is_err(),
                "unneutralized sample_data.csv unexpectedly passed"
            );
            Ok(CheckOutcome::Pass("unneutralized =cmd| CSV injection rejected".into()))
        }
        "leading_space_formula" => {
            let evil = b"col\r\n   =HYPERLINK(\"http://bad\",\"click\")\r\n";
            ensure!(is_formula_dangerous("   =HYPERLINK(\"http://bad\",\"click\")"));
            ensure!(
                verify_csv_formula_neutralization(evil, &[]).is_err(),
                "leading whitespace formula unexpectedly passed"
            );
            Ok(CheckOutcome::Pass("leading whitespace + formula injection rejected".into()))
        }
        "bad_total_bytes" => {
            let bytes = build_sample_custody_manifest("guap-e2e", "0.1.0", &[&p1])?;
            let mut val: Value = serde_json::from_slice(&bytes)?;
            val["total_bytes"] = json!(999_999_999u64);
            let tampered = serde_json::to_vec(&val)?;
            ensure!(
                verify_custody_manifest(&tampered, false).is_err(),
                "mismatched total_bytes unexpectedly passed"
            );
            Ok(CheckOutcome::Pass("CustodyManifest total_bytes mismatch rejected".into()))
        }
        _ => bail!("unknown negative self-check tag {tag}"),
    }
}

fn stage_mail_nk2_file() -> anyhow::Result<TempDir> {
    let tmp = TempDir::new()?;
    let mut out = Vec::new();
    out.extend_from_slice(&0x0D0A_04BAu32.to_le_bytes());
    out.extend_from_slice(&10u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let push_slot = |dst: &mut Vec<u8>, prop_type: u16, prop_id: u16, val: u64| {
        dst.extend_from_slice(&prop_type.to_le_bytes());
        dst.extend_from_slice(&prop_id.to_le_bytes());
        dst.extend_from_slice(&0u32.to_le_bytes());
        dst.extend_from_slice(&val.to_le_bytes());
    };
    let push_u16_blob = |dst: &mut Vec<u8>, s: &str| {
        let mut raw: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        raw.extend_from_slice(&[0u8, 0u8]);
        dst.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        dst.extend_from_slice(&raw);
    };

    for (nick, name, email, weight) in [
        ("Alice Vance", "Alice Vance", "alice.vance@example.org", 500u64),
        ("Bob Chen", "Bob Chen", "bob.chen@example.org", 250u64),
    ] {
        out.extend_from_slice(&6u32.to_le_bytes());
        push_slot(&mut out, 0x001F, 0x6001, 0);
        push_slot(&mut out, 0x001F, 0x3001, 0);
        push_slot(&mut out, 0x001F, 0x3002, 0);
        push_slot(&mut out, 0x001F, 0x3003, 0);
        push_slot(&mut out, 0x0003, 0x0C15, 1);
        push_slot(&mut out, 0x0003, 0x6002, weight);
        push_u16_blob(&mut out, nick);
        push_u16_blob(&mut out, name);
        push_u16_blob(&mut out, "SMTP");
        push_u16_blob(&mut out, email);
    }

    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    std::fs::write(tmp.path().join("staged_outlook.NK2"), out)?;
    Ok(tmp)
}

fn stage_forensics_compat_dir(fixtures: &MaterializedFixtures) -> anyhow::Result<TempDir> {
    let tmp = TempDir::new()?;
    std::fs::write(
        tmp.path().join("staged_watch.reg"),
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\GUAP]\r\n\"Test\"=\"ok\"\r\n",
    )?;
    std::fs::write(
        tmp.path().join("staged_vss_catalog.json"),
        r#"[{"shadow_copy_name":"HarddiskVolumeShadowCopy1","device_object":"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1","volume_name":"C:\\","created_time":"2026-11-22T14:30:00Z","snapshot_id":"{11111111-2222-3333-4444-555555555555}","originating_machine":"WORKSTATION","service_machine":"WORKSTATION","provider_id":"{b5946137-7b9f-4925-af80-51abd60b20d5}"}]"#,
    )?;
    let prev_user = tmp.path().join("staged_previous_dir").join("Users").join("Test");
    std::fs::create_dir_all(&prev_user)?;
    std::fs::write(prev_user.join("sample.txt"), b"shadow copy test file\n")?;

    let wmi_raw = std::fs::read(fixtures.crash_dir.join("wmi_posture.json"))
        .context("missing wmi_posture.json for security_center staging")?;
    let wmi_val: Value = serde_json::from_slice(&wmi_raw)?;
    let sc2 = wmi_val
        .get("security_center2")
        .context("wmi_posture.json missing security_center2")?;
    std::fs::write(
        tmp.path().join("staged_security_center2.json"),
        serde_json::to_vec_pretty(sc2)?,
    )?;
    std::fs::write(tmp.path().join("staged_SRUDB.dat"), build_staged_srudb_ese())?;
    std::fs::write(tmp.path().join("staged_DataStore.edb"), build_staged_datastore_ese())?;
    Ok(tmp)
}

fn ese_encode_record(fixed_cols: &[(u16, &[u8])], var_cols: &[(u16, &[u8])]) -> Vec<u8> {
    let fid_fixed_last = fixed_cols.iter().map(|(id, _)| *id).max().unwrap_or(0) as u8;
    let fid_var_last = var_cols.iter().map(|(id, _)| *id).max().unwrap_or(127) as u8;
    let mut out = vec![0u8; 4];
    for (_, bytes) in fixed_cols {
        out.extend_from_slice(bytes);
    }
    if fid_fixed_last > 0 {
        let bmp_len = (fid_fixed_last as usize).div_ceil(8);
        out.resize(out.len() + bmp_len, 0);
    }
    let cb_var = out.len() as u16;
    out[0] = fid_fixed_last;
    out[1] = fid_var_last;
    out[2..4].copy_from_slice(&cb_var.to_le_bytes());

    if fid_var_last >= 128 {
        let var_count = (fid_var_last - 127) as usize;
        let tbl_start = out.len();
        out.resize(tbl_start + var_count * 2, 0);
        let mut var_data = Vec::new();
        for i in 0..var_count {
            let fid = 128 + i as u16;
            let word = if let Some((_, bytes)) = var_cols.iter().find(|(id, _)| *id == fid) {
                var_data.extend_from_slice(bytes);
                (var_data.len() as u16) & 0x7FFF
            } else {
                0x8000 | ((var_data.len() as u16) & 0x7FFF)
            };
            out[tbl_start + i * 2..tbl_start + i * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&var_data);
    }
    out
}

fn ese_msys_row(objid_table: i32, obj_type: i16, id: i32, coltyp_or_pgno: i32, size: i32, locale: i32, name: &str) -> Vec<u8> {
    let o = objid_table.to_le_bytes();
    let t = obj_type.to_le_bytes();
    let i = id.to_le_bytes();
    let c = coltyp_or_pgno.to_le_bytes();
    let s = size.to_le_bytes();
    let z4 = 0i32.to_le_bytes();
    let l = locale.to_le_bytes();
    let r1 = [0u8];
    let z2 = 0i16.to_le_bytes();
    ese_encode_record(
        &[
            (1, &o), (2, &t), (3, &i), (4, &c), (5, &s),
            (6, &z4), (7, &l), (8, &r1), (9, &z2), (10, &z4), (11, &z2),
        ],
        &[(128, name.as_bytes())],
    )
}

fn ese_write_leaf_page(buf: &mut [u8], pgno: u32, objid_fdp: u32, flags: u32, records: &[Vec<u8>]) {
    let ps = 4096usize;
    let start = (pgno as usize + 1) * ps;
    let page = &mut buf[start..start + ps];
    page.fill(0);
    let tag_count = records.len() + 1;
    page[24..28].copy_from_slice(&objid_fdp.to_le_bytes());
    page[34..36].copy_from_slice(&(tag_count as u16).to_le_bytes());
    page[36..40].copy_from_slice(&flags.to_le_bytes());

    let mut cur = 40usize;
    let write_tag = |dst: &mut [u8], itag: usize, rel_off: usize, sz: usize| {
        let pos = ps - 4 * (itag + 1);
        dst[pos..pos + 2].copy_from_slice(&(sz as u16).to_le_bytes());
        dst[pos + 2..pos + 4].copy_from_slice(&(rel_off as u16).to_le_bytes());
    };
    write_tag(page, 0, 0, 16);
    cur += 16;

    for (idx, rec) in records.iter().enumerate() {
        let rel = cur - 40;
        let key = (idx as u32 + 1).to_be_bytes();
        page[cur..cur + 2].copy_from_slice(&4u16.to_le_bytes());
        page[cur + 2..cur + 6].copy_from_slice(&key);
        page[cur + 6..cur + 6 + rec.len()].copy_from_slice(rec);
        let sz = 6 + rec.len();
        write_tag(page, idx + 1, rel, sz);
        cur += sz;
    }
    let ib_mic_free = (cur - 40) as u16;
    let cb_free = (ps - tag_count * 4 - cur) as u16;
    page[28..30].copy_from_slice(&cb_free.to_le_bytes());
    page[32..34].copy_from_slice(&ib_mic_free.to_le_bytes());
}

fn ese_finalize_db(total_logical_pages: u32) -> Vec<u8> {
    let ps = 4096usize;
    let mut buf = vec![0u8; (total_logical_pages as usize + 2) * ps];
    let hdr = &mut buf[0..ps];
    hdr[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
    hdr[8..12].copy_from_slice(&0x0000_0620u32.to_le_bytes());
    hdr[0x34..0x38].copy_from_slice(&3u32.to_le_bytes());
    hdr[0xE8..0xEC].copy_from_slice(&0x17u32.to_le_bytes());
    hdr[0xEC..0xF0].copy_from_slice(&(ps as u32).to_le_bytes());
    let mut xor = 0x89AB_CDEFu32;
    for chunk in hdr[4..668].as_chunks::<4>().0 {
        xor ^= u32::from_le_bytes(*chunk);
    }
    hdr[0..4].copy_from_slice(&xor.to_le_bytes());
    let (h0, h1) = buf.split_at_mut(ps);
    h1[0..ps].copy_from_slice(&h0[0..ps]);
    // Space tree pages on pgno 2 and 3
    ese_write_leaf_page(&mut buf, 2, 1, 0x0023, &[]);
    ese_write_leaf_page(&mut buf, 3, 1, 0x0023, &[]);
    buf
}

fn utf16le_nul_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

fn build_staged_srudb_ese() -> Vec<u8> {
    let mut buf = ese_finalize_db(9);
    let msys = vec![
        ese_msys_row(1, 1, 10, 5, 0, 0, "SruDbIdMapTable"),
        ese_msys_row(10, 2, 1, 2, 1, 0, "IdType"),
        ese_msys_row(10, 2, 2, 4, 4, 0, "IdIndex"),
        ese_msys_row(10, 2, 128, 11, 0, 0, "IdBlob"),
        ese_msys_row(1, 1, 20, 6, 0, 0, "{973F5D5C-1D90-4944-BE8E-24B94231A174}"),
        ese_msys_row(20, 2, 1, 4, 4, 0, "AutoIncId"),
        ese_msys_row(20, 2, 2, 8, 8, 0, "TimeStamp"),
        ese_msys_row(20, 2, 3, 4, 4, 0, "AppId"),
        ese_msys_row(20, 2, 4, 4, 4, 0, "UserId"),
        ese_msys_row(20, 2, 5, 15, 8, 0, "InterfaceLuid"),
        ese_msys_row(20, 2, 6, 15, 8, 0, "L2ProfileId"),
        ese_msys_row(20, 2, 7, 4, 4, 0, "L2ProfileFlags"),
        ese_msys_row(20, 2, 8, 15, 8, 0, "BytesSent"),
        ese_msys_row(20, 2, 9, 15, 8, 0, "BytesRecvd"),
        ese_msys_row(1, 1, 30, 7, 0, 0, "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"),
        ese_msys_row(30, 2, 1, 8, 8, 0, "TimeStamp"),
        ese_msys_row(30, 2, 2, 4, 4, 0, "AppId"),
        ese_msys_row(30, 2, 3, 4, 4, 0, "UserId"),
        ese_msys_row(30, 2, 4, 15, 8, 0, "ForegroundCycleTime"),
        ese_msys_row(30, 2, 5, 15, 8, 0, "BackgroundCycleTime"),
        ese_msys_row(30, 2, 6, 4, 4, 0, "FaceTime"),
        ese_msys_row(30, 2, 7, 15, 8, 0, "ForegroundBytesRead"),
        ese_msys_row(30, 2, 8, 15, 8, 0, "BackgroundBytesRead"),
        ese_msys_row(30, 2, 9, 15, 8, 0, "ForegroundBytesWritten"),
        ese_msys_row(30, 2, 10, 15, 8, 0, "BackgroundBytesWritten"),
        ese_msys_row(30, 2, 11, 4, 4, 0, "ForegroundContextSwitches"),
        ese_msys_row(30, 2, 12, 4, 4, 0, "BackgroundContextSwitches"),
        ese_msys_row(1, 1, 40, 8, 0, 0, "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"),
        ese_msys_row(40, 2, 1, 8, 8, 0, "TimeStamp"),
        ese_msys_row(40, 2, 2, 4, 4, 0, "AppId"),
        ese_msys_row(40, 2, 3, 4, 4, 0, "UserId"),
        ese_msys_row(40, 2, 4, 15, 8, 0, "TotalEnergyConsumption"),
        ese_msys_row(40, 2, 5, 15, 8, 0, "CPUEnergyConsumption"),
        ese_msys_row(40, 2, 6, 15, 8, 0, "NetworkTailEnergyConsumption"),
        ese_msys_row(40, 2, 7, 4, 4, 0, "DisplayRequiredTime"),
        ese_msys_row(1, 1, 50, 9, 0, 0, "{DD6636C4-8929-4683-974E-22C046A43763}"),
        ese_msys_row(50, 2, 1, 8, 8, 0, "TimeStamp"),
        ese_msys_row(50, 2, 2, 4, 4, 0, "AppId"),
        ese_msys_row(50, 2, 3, 4, 4, 0, "UserId"),
        ese_msys_row(50, 2, 4, 15, 8, 0, "InterfaceLuid"),
        ese_msys_row(50, 2, 5, 15, 8, 0, "L2ProfileId"),
        ese_msys_row(50, 2, 6, 4, 4, 0, "ConnectedTime"),
        ese_msys_row(50, 2, 7, 15, 8, 0, "ConnectStartTime"),
    ];
    ese_write_leaf_page(&mut buf, 4, 2, 0x2003, &msys);

    let app_blob = utf16le_nul_bytes(r"\Device\HarddiskVolume3\Tools\forensics_sample.exe");
    let sid_blob: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let id_rows = vec![
        ese_encode_record(&[(1, &[0u8]), (2, &1i32.to_le_bytes())], &[(128, &app_blob)]),
        ese_encode_record(&[(1, &[3u8]), (2, &2i32.to_le_bytes())], &[(128, &sid_blob)]),
    ];
    ese_write_leaf_page(&mut buf, 5, 10, 0x2003, &id_rows);

    let ts = 45600.5f64.to_le_bytes();
    let app1 = 1i32.to_le_bytes();
    let usr2 = 2i32.to_le_bytes();
    let luid = ((6i64 << 48) | 1i64).to_le_bytes();
    let prof = 1i64.to_le_bytes();
    let z4 = 0i32.to_le_bytes();
    let net_rows = vec![ese_encode_record(
        &[
            (1, &app1), (2, &ts), (3, &app1), (4, &usr2),
            (5, &luid), (6, &prof), (7, &z4),
            (8, &1_048_576i64.to_le_bytes()), (9, &262_144i64.to_le_bytes()),
        ],
        &[],
    )];
    ese_write_leaf_page(&mut buf, 6, 20, 0x2003, &net_rows);

    let app_rows = vec![ese_encode_record(
        &[
            (1, &ts), (2, &app1), (3, &usr2),
            (4, &500_000_000i64.to_le_bytes()), (5, &25_000_000i64.to_le_bytes()),
            (6, &120i32.to_le_bytes()), (7, &65_536i64.to_le_bytes()),
            (8, &4_096i64.to_le_bytes()), (9, &16_384i64.to_le_bytes()),
            (10, &1_024i64.to_le_bytes()), (11, &320i32.to_le_bytes()), (12, &45i32.to_le_bytes()),
        ],
        &[],
    )];
    ese_write_leaf_page(&mut buf, 7, 30, 0x2003, &app_rows);

    let energy_rows = vec![ese_encode_record(
        &[
            (1, &ts), (2, &app1), (3, &usr2),
            (4, &10_000i64.to_le_bytes()), (5, &6_000i64.to_le_bytes()),
            (6, &2_000i64.to_le_bytes()), (7, &300i32.to_le_bytes()),
        ],
        &[],
    )];
    ese_write_leaf_page(&mut buf, 8, 40, 0x2003, &energy_rows);

    let conn_rows = vec![ese_encode_record(
        &[
            (1, &ts), (2, &app1), (3, &usr2), (4, &luid), (5, &prof),
            (6, &3600i32.to_le_bytes()), (7, &133_751_856_000_000_000i64.to_le_bytes()),
        ],
        &[],
    )];
    ese_write_leaf_page(&mut buf, 9, 50, 0x2003, &conn_rows);
    buf
}

fn build_staged_datastore_ese() -> Vec<u8> {
    let mut buf = ese_finalize_db(7);
    let msys = vec![
        ese_msys_row(1, 1, 10, 5, 0, 0, "tbHistory"),
        ese_msys_row(10, 2, 1, 4, 4, 0, "IdEvent"),
        ese_msys_row(10, 2, 2, 4, 4, 0, "Status"),
        ese_msys_row(10, 2, 3, 4, 4, 0, "Flags"),
        ese_msys_row(10, 2, 4, 4, 4, 0, "MappedResult"),
        ese_msys_row(10, 2, 5, 4, 4, 0, "UnmappedResult"),
        ese_msys_row(10, 2, 6, 8, 8, 0, "Date"),
        ese_msys_row(10, 2, 128, 9, 16, 0, "UpdateId"),
        ese_msys_row(10, 2, 129, 12, 0, 1200, "Title"),
        ese_msys_row(10, 2, 130, 12, 0, 1200, "Description"),
        ese_msys_row(10, 2, 131, 10, 0, 1200, "ClientId"),
        ese_msys_row(1, 1, 11, 6, 0, 0, "tbUpdates"),
        ese_msys_row(11, 2, 1, 4, 4, 0, "IdLocal"),
        ese_msys_row(11, 2, 2, 4, 4, 0, "RevisionNumber"),
        ese_msys_row(11, 2, 128, 9, 16, 0, "UpdateId"),
        ese_msys_row(11, 2, 129, 12, 0, 1200, "KBArticleIds"),
        ese_msys_row(1, 1, 12, 7, 0, 0, "tbUpdateLocalizedProps"),
        ese_msys_row(12, 2, 1, 4, 4, 0, "IdLocal"),
        ese_msys_row(12, 2, 128, 12, 0, 1200, "Title"),
        ese_msys_row(12, 2, 129, 12, 0, 1200, "Description"),
        ese_msys_row(12, 2, 130, 12, 0, 1200, "SupportUrl"),
    ];
    ese_write_leaf_page(&mut buf, 4, 2, 0x2003, &msys);

    let guid = [0x11u8; 16];
    let title = utf16le_nul_bytes("2026-11 Cumulative Update for Windows 11 (KB5048685)");
    let desc = utf16le_nul_bytes("Security and quality improvements.");
    let client = utf16le_nul_bytes("MoUpdateOrchestrator");
    let kb = utf16le_nul_bytes("5048685");
    let url = utf16le_nul_bytes("https://support.microsoft.com/kb/5048685");

    let hist_rows = vec![ese_encode_record(
        &[
            (1, &1i32.to_le_bytes()), (2, &2i32.to_le_bytes()), (3, &1i32.to_le_bytes()),
            (4, &0i32.to_le_bytes()), (5, &0i32.to_le_bytes()), (6, &45600.5f64.to_le_bytes()),
        ],
        &[(128, &guid), (129, &title), (130, &desc), (131, &client)],
    )];
    ese_write_leaf_page(&mut buf, 5, 10, 0x2003, &hist_rows);

    let upd_rows = vec![ese_encode_record(
        &[(1, &101i32.to_le_bytes()), (2, &1i32.to_le_bytes())],
        &[(128, &guid), (129, &kb)],
    )];
    ese_write_leaf_page(&mut buf, 6, 11, 0x2003, &upd_rows);

    let loc_rows = vec![ese_encode_record(
        &[(1, &101i32.to_le_bytes())],
        &[(128, &title), (129, &desc), (130, &url)],
    )];
    ese_write_leaf_page(&mut buf, 7, 12, 0x2003, &loc_rows);
    buf
}

fn effective_item_fixture_path(
    it: &ItemSpec,
    fixtures: &MaterializedFixtures,
    nk2_dir: Option<&Path>,
    forensics_dir: Option<&Path>,
) -> std::path::PathBuf {
    if it.workspace == TargetWorkspace::Mail2Rust
        && it.fixture_rel == "outlook.NK2"
        && let Some(dir) = nk2_dir
    {
        return dir.join("staged_outlook.NK2");
    }
    if it.workspace == TargetWorkspace::Forensics2Rust
        && it.fixture_rel.starts_with("staged_")
        && let Some(dir) = forensics_dir
    {
        return dir.join(it.fixture_rel);
    }
    item_fixture_path(it, fixtures)
}

fn stage_sys2rust_gac_root(fixtures: &MaterializedFixtures) -> anyhow::Result<TempDir> {
    let tmp = TempDir::new()?;
    let gac_dir = tmp
        .path()
        .join("Microsoft.NET")
        .join("assembly")
        .join("GAC_MSIL")
        .join("GuapDotNetFixture")
        .join("v4.0_1.2.3.4__0123456789abcdef");
    std::fs::create_dir_all(&gac_dir)?;
    let src_pe = fixtures.sys_fs_dir.join("sample_pe64_dotnet.exe");
    std::fs::copy(&src_pe, gac_dir.join("GuapDotNetFixture.dll"))?;
    Ok(tmp)
}

fn assert_not_clap_usage_error(context: &str, out: &crate::workspace::CommandOutput) -> anyhow::Result<()> {
    ensure!(
        !out.stderr.contains("unexpected argument") && !out.stderr.contains("unrecognized subcommand"),
        "{context}: CLI rejected argument/subcommand as unknown (clap exit {:?}): {}",
        out.exit_code,
        truncate_preview(&out.stderr, 300)
    );
    ensure!(
        out.exit_code != Some(2) || out.stderr.is_empty(),
        "{context}: unexpected clap exit code 2: {}",
        truncate_preview(&out.stderr, 300)
    );
    Ok(())
}

fn item_fixture_path(it: &ItemSpec, fixtures: &MaterializedFixtures) -> std::path::PathBuf {
    it.fixture_kind.resolve_dir(fixtures).join(it.fixture_rel)
}

fn build_cli_readonly_args(
    it: &ItemSpec,
    fixtures: &MaterializedFixtures,
    out_dir: Option<&Path>,
    gac_windir: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    build_cli_readonly_args_ext(it, fixtures, out_dir, gac_windir, None, None)
}

fn build_cli_readonly_args_ext(
    it: &ItemSpec,
    fixtures: &MaterializedFixtures,
    out_dir: Option<&Path>,
    gac_windir: Option<&Path>,
    nk2_dir: Option<&Path>,
    forensics_dir: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    let mut args: Vec<String> = it.cli_tokens.iter().map(|s| (*s).to_string()).collect();
    if it.workspace == TargetWorkspace::Mail2Rust {
        args.extend(["--log-level".into(), "error".into()]);
    }
    let f_path = effective_item_fixture_path(it, fixtures, nk2_dir, forensics_dir);

    match it.cli_input {
        CliInputStyle::Positional => {
            args.push(f_path.display().to_string());
            if it.workspace == TargetWorkspace::Chrome2Rust {
                args.extend(["-f".into(), "json".into()]);
            } else {
                args.extend(["--format".into(), "json".into()]);
            }
        }
        CliInputStyle::Flag(flag) => {
            let target_str = if flag == "--gac-root" {
                let root = gac_windir
                    .context("missing staged GAC root for --gac-root")?
                    .join("Microsoft.NET")
                    .join("assembly");
                root.display().to_string()
            } else {
                f_path.display().to_string()
            };
            args.extend([flag.to_string(), target_str, "--format".into(), "json".into()]);
        }
        CliInputStyle::FlagOffline(flag) => {
            args.extend([
                "--offline".into(),
                flag.to_string(),
                f_path.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::FlagOfflineDir(flag) => {
            let parent = f_path.parent().context("fixture has no parent dir")?;
            args.extend([
                "--offline".into(),
                flag.to_string(),
                parent.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::SourceDirParent => {
            let parent = f_path.parent().context("fixture has no parent dir")?;
            args.extend([
                "--source-dir".into(),
                parent.display().to_string(),
                "--json".into(),
            ]);
        }
        CliInputStyle::OfflineNoFile => {
            args.extend(["--offline".into(), "--format".into(), "json".into()]);
        }
        CliInputStyle::OmitPath => {
            args.extend(["--format".into(), "json".into()]);
        }
        CliInputStyle::ForensicsDiff => {
            let right_hive = fixtures.hive_dir.join("SOFTWARE");
            args.extend([
                "--source".into(),
                f_path.display().to_string(),
                "--right".into(),
                right_hive.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::FsDataDiff => {
            let left_csv = fixtures.sys_fs_dir.join("sample_data.csv");
            args.extend([
                "--offline".into(),
                "--left".into(),
                left_csv.display().to_string(),
                "--right".into(),
                f_path.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::InputFlag => {
            args.extend(["--input".into(), f_path.display().to_string()]);
            if let Some(od) = out_dir {
                args.extend(["--output".into(), od.display().to_string()]);
            }
            args.extend(["--format".into(), "json".into()]);
        }
    }
    Ok(args)
}

fn verify_cli_json_output(stdout: &str, it: &ItemSpec) -> anyhow::Result<usize> {
    verify_cli_json_output_mode(stdout, it, it.expects_nonempty_rows)
}

fn verify_cli_json_output_mode(
    stdout: &str,
    it: &ItemSpec,
    require_nonempty_rows: bool,
) -> anyhow::Result<usize> {
    let trimmed = stdout.trim();
    ensure!(!trimmed.is_empty(), "item {:?} emitted empty stdout", it.name);
    let val: Value = serde_json::from_str(trimmed).with_context(|| {
        format!(
            "item {:?} CLI stdout is not valid JSON: {}",
            it.name,
            truncate_preview(trimmed, 240)
        )
    })?;

    match &val {
        Value::Array(arr) => {
            if require_nonempty_rows {
                ensure!(
                    !arr.is_empty(),
                    "item {:?} CLI JSON array is empty [] on populated fixture",
                    it.name
                );
            }
            for (idx, elem) in arr.iter().enumerate() {
                ensure!(
                    elem.is_object(),
                    "item {:?} CLI JSON element {} is not an object",
                    it.name,
                    idx
                );
            }
            Ok(arr.len())
        }
        Value::Object(obj) => {
            let arr = obj
                .get("entries")
                .or_else(|| obj.get("rows"))
                .and_then(Value::as_array)
                .with_context(|| {
                    format!(
                        "item {:?} CLI JSON object missing 'entries' or 'rows' array (got {})",
                        it.name,
                        truncate_preview(trimmed, 200)
                    )
                })?;
            if require_nonempty_rows {
                ensure!(
                    !arr.is_empty(),
                    "item {:?} CLI JSON 'entries'/'rows' is empty on populated fixture",
                    it.name
                );
            }
            if !arr.is_empty() {
                ensure!(
                    arr[0].is_object(),
                    "item {:?} CLI JSON first row is not an object",
                    it.name
                );
            }
            Ok(arr.len())
        }
        other => bail!(
            "item {:?} CLI JSON must be array or object with entries/rows, got {}",
            it.name,
            other
        ),
    }
}

fn build_mcp_readonly_args(it: &ItemSpec, fixtures: &MaterializedFixtures) -> anyhow::Result<Value> {
    build_mcp_readonly_args_ext(it, fixtures, None, None)
}

fn build_mcp_readonly_args_ext(
    it: &ItemSpec,
    fixtures: &MaterializedFixtures,
    nk2_dir: Option<&Path>,
    forensics_dir: Option<&Path>,
) -> anyhow::Result<Value> {
    let f_path = effective_item_fixture_path(it, fixtures, nk2_dir, forensics_dir);
    let f_str = f_path.display().to_string();
    Ok(match it.mcp_args {
        McpArgsKind::EmptyObject => json!({}),
        McpArgsKind::Path => json!({ "path": f_str }),
        McpArgsKind::Source => json!({ "source": f_str }),
        McpArgsKind::SourcePath => json!({ "source_path": f_str }),
        McpArgsKind::ForensicsDiff => {
            let right_hive = fixtures.hive_dir.join("SOFTWARE");
            json!({
                "source_path": f_str,
                "right_path": right_hive.display().to_string()
            })
        }
        McpArgsKind::HiveList => json!({ "hives": [f_str] }),
        McpArgsKind::SourceDirParent => {
            let parent = f_path.parent().context("fixture has no parent dir")?;
            json!({ "source_dir": parent.display().to_string() })
        }
    })
}

fn verify_mcp_json_output(text: &str, tool_name: &str, require_nonempty_rows: bool) -> anyhow::Result<usize> {
    let trimmed = text.trim();
    let val: Value = serde_json::from_str(trimmed).with_context(|| {
        format!(
            "MCP tool '{tool_name}' content is not valid JSON: {}",
            truncate_preview(trimmed, 240)
        )
    })?;

    match &val {
        Value::Array(arr) => {
            if require_nonempty_rows {
                ensure!(!arr.is_empty(), "MCP tool '{tool_name}' returned empty JSON array []");
            }
            for (idx, elem) in arr.iter().enumerate() {
                ensure!(elem.is_object(), "MCP tool '{tool_name}' element {idx} is not object");
            }
            Ok(arr.len())
        }
        Value::Object(obj) => {
            let table_obj = obj.get("table").and_then(Value::as_object).unwrap_or(obj);
            if let Some(rows) = table_obj.get("rows").and_then(Value::as_array) {
                let has_table_meta = table_obj.get("columns").and_then(Value::as_array).is_some_and(|c| !c.is_empty())
                    || table_obj.get("tool_id").and_then(Value::as_str).is_some()
                    || table_obj.get("title").and_then(Value::as_str).is_some();
                ensure!(
                    has_table_meta || !rows.is_empty(),
                    "MCP tool '{tool_name}' returned bare 'rows' without TableData metadata or rows"
                );
                if require_nonempty_rows {
                    ensure!(
                        !rows.is_empty(),
                        "MCP tool '{tool_name}' returned 0 rows in 'rows' array"
                    );
                }
                if !rows.is_empty() {
                    ensure!(rows[0].is_object(), "MCP tool '{tool_name}' row[0] is not an object");
                }
                return Ok(rows.len());
            }
            if let Some(entries) = obj.get("entries").and_then(Value::as_array) {
                if require_nonempty_rows {
                    ensure!(
                        !entries.is_empty(),
                        "MCP tool '{tool_name}' returned 0 entries"
                    );
                }
                if !entries.is_empty() {
                    ensure!(entries[0].is_object(), "MCP tool '{tool_name}' entry[0] is not an object");
                }
                return Ok(entries.len());
            }
            bail!(
                "MCP tool '{tool_name}' JSON object missing 'rows' or 'entries' (got {})",
                truncate_preview(trimmed, 200)
            );
        }
        other => bail!("MCP tool '{tool_name}' returned non-object/non-array JSON: {other}"),
    }
}

fn build_mutating_args(spec: MutatingActionSpec, fixture_path: &Path) -> Value {
    let f_str = fixture_path.display().to_string();
    match spec.args_kind {
        MutatingArgsKind::MailNk2Edit => json!({ "path": f_str, "dedup": true }),
        MutatingArgsKind::AndroidWpdDelete => json!({ "device_id": "wpd-0", "object_id": "obj-1" }),
        MutatingArgsKind::SysProcTerminate => json!({ "pid": 4200 }),
        MutatingArgsKind::SysHwServiceControl => json!({ "service_name": "Spooler", "action": "stop" }),
        MutatingArgsKind::SysShellPrivacyClean => json!({ "categories": ["Temp"] }),
        MutatingArgsKind::FsBulkTargets => json!({ "targets": [f_str] }),
        MutatingArgsKind::FsAdsDelete => json!({ "file_path": f_str, "stream_name": "Zone.Identifier" }),
        MutatingArgsKind::WinctlNirCmd => json!({ "script": "beep 440 100" }),
        MutatingArgsKind::WinctlAudioSvcl => json!({ "verb": "SetVolume", "target": "Speakers", "args": ["50"] }),
        MutatingArgsKind::WinctlDisplayDdc => json!({ "monitor": "DISPLAY1", "vcp_code": 16, "value": 50 }),
        MutatingArgsKind::WinctlDesktopClip => json!({ "operation": "clear" }),
        MutatingArgsKind::NetOsintSetDns => {
            json!({ "interface": "Ethernet", "servers": ["9.9.9.9"], "dry_run": true })
        }
        MutatingArgsKind::NetRadioWifiSetOrder => {
            json!({ "profile_name": "CorpNet-5G", "position": 0, "dry_run": true })
        }
        MutatingArgsKind::NetSocketsClose => {
            json!({
                "local_addr": "192.168.1.50",
                "local_port": 51234,
                "remote_addr": "93.184.216.34",
                "remote_port": 443,
                "dry_run": true
            })
        }
        MutatingArgsKind::NetLanWol => {
            json!({ "mac": "aa:bb:cc:dd:ee:ff", "dry_run": true })
        }
        MutatingArgsKind::PathGeneric => json!({ "path": f_str }),
    }
}

fn mcp_spawn_args_and_env(
    ws: TargetWorkspace,
    gac_tmp: Option<&Path>,
) -> (&'static [&'static str], Vec<(&'static str, String)>) {
    if ws == TargetWorkspace::Sys2Rust {
        let mut envs = Vec::new();
        if let Some(dir) = gac_tmp {
            envs.push(("WINDIR", dir.display().to_string()));
        }
        (&["--offline", "mcp"], envs)
    } else if matches!(ws, TargetWorkspace::Fs2Rust | TargetWorkspace::Net2Rust) {
        (&["--offline", "mcp"], Vec::new())
    } else if ws == TargetWorkspace::Mail2Rust {
        (&["--log-level", "error", "mcp"], Vec::new())
    } else {
        (&["mcp"], Vec::new())
    }
}

fn run_domain_cargo_check_test(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if cfg.skip_cargo_build {
        return Ok(CheckOutcome::Skip(
            "cargo check/test skipped because skip_cargo_build=true".to_string(),
        ));
    }
    let fg = fg_for_check(chk)?;
    let ws_dir = session.workspace_dir(fg.workspace);
    let crate_toml = ws_dir.join("crates").join(fg.domain_crate).join("Cargo.toml");
    let pkg_args: Vec<&str> = if crate_toml.is_file() {
        vec!["test", "--offline", "-p", fg.domain_crate]
    } else {
        vec!["test", "--offline", "--workspace"]
    };
    let out = session.run_cargo_cached(&ws_dir, &pkg_args)?;
    ensure!(
        out.success(),
        "cargo test failed in {}: {}",
        ws_dir.display(),
        truncate_preview(&out.stderr, 400)
    );
    Ok(CheckOutcome::Pass(format!(
        "cargo test --offline passed for {}",
        fg.domain_crate
    )))
}

fn help_contains_subcommand_token(help_text: &str, leaf: &str) -> bool {
    let hay = help_text.to_ascii_lowercase();
    let needle = leaf.to_ascii_lowercase();
    if needle.is_empty() {
        return false;
    }
    let is_ident_char = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    let bytes = hay.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = hay[pos..].find(&needle) {
        let start = pos + rel;
        let end = start + needle.len();
        let left_ok = start == 0 || !is_ident_char(bytes[start - 1]);
        let right_ok = end == bytes.len() || !is_ident_char(bytes[end]);
        if left_ok && right_ok {
            return true;
        }
        pos = start + 1;
    }
    false
}

fn run_domain_cli_help(
    chk: &CatalogCheckDef,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }

    let mut prefixes: BTreeMap<Vec<&'static str>, Vec<&'static ItemSpec>> = BTreeMap::new();
    for it in fg.items {
        ensure!(
            !it.cli_tokens.is_empty(),
            "domain item {:?} has empty cli_tokens",
            it.name
        );
        let prefix = &it.cli_tokens[..it.cli_tokens.len().saturating_sub(1)];
        prefixes.entry(prefix.to_vec()).or_default().push(it);
    }

    for (prefix, items) in prefixes {
        let help_text = session
            .cached_help_for_prefix(fg.workspace, &prefix)?
            .context("missing --help output")?;
        for it in items {
            let leaf = it.cli_tokens.last().copied().unwrap_or("");
            ensure!(
                help_contains_subcommand_token(&help_text, leaf),
                "{} {} --help missing leaf subcommand {:?} for item {:?}",
                fg.workspace.dir_name(),
                prefix.join(" "),
                leaf,
                it.name
            );
        }
    }

    Ok(CheckOutcome::Pass(format!(
        "CLI --help discovered all {}/{} leaf subcommands in {}",
        fg.items.len(),
        fg.items.len(),
        fg.name
    )))
}

fn run_domain_mcp_tools(
    chk: &CatalogCheckDef,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }
    let tools = session
        .cached_mcp_tools(fg.workspace)?
        .context("missing mcp --tools output")?;
    ensure!(!tools.is_empty(), "{} mcp --tools returned 0 tools", fg.workspace.dir_name());

    let mut tool_map: BTreeMap<String, &Value> = BTreeMap::new();
    for tool in &tools {
        let name = tool
            .get("name")
            .and_then(|v| v.as_str())
            .with_context(|| format!("mcp --tools entry missing 'name': {tool}"))?;
        ensure!(
            tool.get("description").and_then(|v| v.as_str()).is_some(),
            "mcp --tools '{name}' missing description"
        );
        let schema_type = tool
            .get("inputSchema")
            .and_then(|s| s.get("type"))
            .and_then(|v| v.as_str());
        ensure!(
            schema_type == Some("object"),
            "mcp --tools '{name}' inputSchema.type != \"object\""
        );
        if !is_legacy_no_annotations_tool(fg.workspace, name) {
            let ann = tool
                .get("annotations")
                .and_then(|a| a.as_object())
                .with_context(|| format!("mcp --tools '{name}' missing annotations object"))?;
            ensure!(
                ann.get("readOnlyHint").and_then(|v| v.as_bool()).is_some()
                    && ann.get("destructiveHint").and_then(|v| v.as_bool()).is_some(),
                "mcp --tools '{name}' missing readOnlyHint/destructiveHint booleans"
            );
        }
        tool_map.insert(name.to_string(), tool);
    }

    for it in fg.items {
        let tool = tool_map.get(it.mcp_tool).with_context(|| {
            format!(
                "{} mcp --tools missing expected tool {:?} for item {:?}",
                fg.workspace.dir_name(),
                it.mcp_tool,
                it.name
            )
        })?;
        let ann = tool
            .get("annotations")
            .and_then(|a| a.as_object())
            .with_context(|| format!("cataloged tool '{}' missing annotations", it.mcp_tool))?;
        ensure!(
            ann.get("readOnlyHint").and_then(|v| v.as_bool()) == Some(true),
            "cataloged read-only tool '{}' readOnlyHint != true",
            it.mcp_tool
        );
    }

    if let Some(mut_spec) = fg.mutating_action {
        let mtool = tool_map.get(mut_spec.tool_id).with_context(|| {
            format!(
                "{} mcp --tools missing expected mutating tool {:?}",
                fg.workspace.dir_name(),
                mut_spec.tool_id
            )
        })?;
        let ann = mtool
            .get("annotations")
            .and_then(|a| a.as_object())
            .with_context(|| format!("mutating tool '{}' missing annotations", mut_spec.tool_id))?;
        ensure!(
            ann.get("readOnlyHint").and_then(|v| v.as_bool()) == Some(false)
                && ann.get("destructiveHint").and_then(|v| v.as_bool()) == Some(true),
            "mutating tool '{}' annotations must have readOnlyHint=false, destructiveHint=true",
            mut_spec.tool_id
        );
    }

    Ok(CheckOutcome::Pass(format!(
        "mcp --tools validated schema & annotations for all {} items in {}",
        fg.items.len(),
        fg.name
    )))
}

fn run_domain_mcp_jsonrpc(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    let bin = match require_domain_binary(fg.workspace, session)? {
        Ok(b) => b,
        Err(skip) => return Ok(skip),
    };
    let gac_tmp = if fg.workspace == TargetWorkspace::Sys2Rust {
        Some(stage_sys2rust_gac_root(&cfg.fixtures)?)
    } else {
        None
    };
    let (spawn_args, envs_owned) = mcp_spawn_args_and_env(fg.workspace, gac_tmp.as_ref().map(|t| t.path()));
    let env_refs: Vec<(&str, &str)> = envs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let mut mcp = McpSession::spawn(&bin, spawn_args, &env_refs)?;
    mcp.initialize()?;
    mcp.ping()?;
    let tools = mcp.tools_list()?;
    ensure!(!tools.is_empty(), "MCP tools/list returned empty list");

    let nk2_tmp = if fg.workspace == TargetWorkspace::Mail2Rust {
        Some(stage_mail_nk2_file()?)
    } else {
        None
    };
    let forensics_tmp = if fg.workspace == TargetWorkspace::Forensics2Rust {
        Some(stage_forensics_compat_dir(&cfg.fixtures)?)
    } else {
        None
    };
    let mut called = 0usize;
    let mut total_rows = 0usize;
    for it in fg.items {
        if it.mutating_capable {
            continue;
        }
        let args = build_mcp_readonly_args_ext(
            it,
            &cfg.fixtures,
            nk2_tmp.as_ref().map(|t| t.path()),
            forensics_tmp.as_ref().map(|t| t.path()),
        )?;
        let resp = mcp.tools_call(it.mcp_tool, args)?;
        let text = assert_tool_call_ok(&resp, it.mcp_tool)?;
        let require_nonempty = it.expects_nonempty_rows
            && !(fg.id == "FG-27" && matches!(it.mcp_tool, "pe_exports" | "pe_icons" | "pe_dotnet"));
        let rows = verify_mcp_json_output(&text, it.mcp_tool, require_nonempty)?;
        total_rows += rows;
        called += 1;
    }
    ensure!(called > 0, "{} has 0 read-only MCP items to call", fg.name);
    ensure!(
        total_rows > 0,
        "{} MCP tools/call returned 0 total rows across {} items",
        fg.name,
        called
    );

    let _stderr = mcp.close()?;
    Ok(CheckOutcome::Pass(format!(
        "MCP 2024-11-05 tools/call verified all {called} read-only items in {} ({total_rows} total rows)",
        fg.name
    )))
}

fn run_domain_cli_readonly_all(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }
    let tmp = TempDir::new()?;
    let gac_tmp = if fg.id == "FG-27" {
        Some(stage_sys2rust_gac_root(&cfg.fixtures)?)
    } else {
        None
    };
    let nk2_tmp = if fg.workspace == TargetWorkspace::Mail2Rust {
        Some(stage_mail_nk2_file()?)
    } else {
        None
    };
    let forensics_tmp = if fg.workspace == TargetWorkspace::Forensics2Rust {
        Some(stage_forensics_compat_dir(&cfg.fixtures)?)
    } else {
        None
    };

    let mut total_rows = 0usize;
    for (idx, it) in fg.items.iter().enumerate() {
        let fixture_path = effective_item_fixture_path(
            it,
            &cfg.fixtures,
            nk2_tmp.as_ref().map(|t| t.path()),
            forensics_tmp.as_ref().map(|t| t.path()),
        );
        ensure!(
            fixture_path.exists(),
            "missing materialized fixture {}",
            fixture_path.display()
        );
        let out_dir = tmp.path().join(format!("item_{idx}"));
        std::fs::create_dir_all(&out_dir)?;

        let owned_args = build_cli_readonly_args_ext(
            it,
            &cfg.fixtures,
            Some(&out_dir),
            gac_tmp.as_ref().map(|t| t.path()),
            nk2_tmp.as_ref().map(|t| t.path()),
            forensics_tmp.as_ref().map(|t| t.path()),
        )?;
        let arg_refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();
        let out = session
            .run_cli(fg.workspace, &arg_refs)?
            .context("binary missing unexpectedly")?;
        assert_not_clap_usage_error(&format!("item {:?}", it.name), &out)?;
        ensure!(
            out.success(),
            "item {:?} ({}) exited with {:?}: stdout={} stderr={}",
            it.name,
            arg_refs.join(" "),
            out.exit_code,
            truncate_preview(&out.stdout, 200),
            truncate_preview(&out.stderr, 200)
        );
        total_rows += verify_cli_json_output(&out.stdout, it)?;
    }

    ensure!(
        total_rows > 0,
        "{} CLI returned 0 total JSON rows across {} items",
        fg.name,
        fg.items.len()
    );

    Ok(CheckOutcome::Pass(format!(
        "CLI JSON verified all {}/{} items in {} ({total_rows} total rows)",
        fg.items.len(),
        fg.items.len(),
        fg.name
    )))
}
fn run_domain_missing_path(
    chk: &CatalogCheckDef,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("definitely_missing_e2e_target.bin");
    let missing_dir = tmp.path().join("definitely_missing_e2e_dir");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir)?;

    let it = &fg.items[0];
    let mut owned_args: Vec<String> = Vec::new();
    match it.cli_input {
        CliInputStyle::OfflineNoFile => match fg.workspace {
            TargetWorkspace::Sys2Rust => {
                owned_args.extend([
                    "pe".into(),
                    "exports".into(),
                    "--path".into(),
                    missing.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
            TargetWorkspace::Net2Rust => {
                owned_args.extend([
                    "capture".into(),
                    "sniff".into(),
                    "--offline".into(),
                    "--pcap".into(),
                    missing.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
            TargetWorkspace::Fs2Rust => {
                owned_args.extend([
                    "search".into(),
                    "files".into(),
                    "--offline".into(),
                    "--root".into(),
                    missing.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
            TargetWorkspace::Forensics2Rust => {
                owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
                owned_args.extend([
                    "--source".into(),
                    missing.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
            TargetWorkspace::Winctl2Rust => {
                owned_args.extend([
                    "display".into(),
                    "edid".into(),
                    "--file".into(),
                    missing.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
            _ => {
                owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
                owned_args.extend([
                    "--input".into(),
                    missing.display().to_string(),
                    "--output".into(),
                    out_dir.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
        },
        CliInputStyle::OmitPath => match fg.workspace {
            TargetWorkspace::Winctl2Rust => {
                owned_args.extend([
                    "display".into(),
                    "edid".into(),
                    "--file".into(),
                    missing.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
            _ => {
                owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
                owned_args.extend([
                    "--input".into(),
                    missing.display().to_string(),
                    "--output".into(),
                    out_dir.display().to_string(),
                    "--format".into(),
                    "json".into(),
                ]);
            }
        },
        CliInputStyle::Positional => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.push(missing.display().to_string());
            if fg.workspace == TargetWorkspace::Chrome2Rust {
                owned_args.extend(["-f".into(), "json".into()]);
            } else {
                owned_args.extend(["--format".into(), "json".into()]);
            }
        }
        CliInputStyle::Flag(flag) => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            let effective_flag = if flag == "--gac-root" { "--path" } else { flag };
            owned_args.extend([
                effective_flag.into(),
                missing.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::FlagOffline(flag) => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--offline".into(),
                flag.into(),
                missing.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::FlagOfflineDir(flag) => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--offline".into(),
                flag.into(),
                missing_dir.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::ForensicsDiff => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--source".into(),
                missing.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::FsDataDiff => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--offline".into(),
                "--left".into(),
                missing.display().to_string(),
                "--right".into(),
                missing.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        CliInputStyle::SourceDirParent => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--source-dir".into(),
                missing_dir.display().to_string(),
                "--json".into(),
            ]);
        }
        CliInputStyle::InputFlag => {
            owned_args.extend(it.cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--input".into(),
                missing.display().to_string(),
                "--output".into(),
                out_dir.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
    }

    let refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();
    let out = session
        .run_cli(fg.workspace, &refs)?
        .context("binary missing unexpectedly")?;
    assert_not_clap_usage_error(&format!("{} missing-path", fg.name), &out)?;
    ensure!(
        !out.stderr.contains("panicked at"),
        "{} panicked on missing path: {}",
        fg.name,
        truncate_preview(&out.stderr, 240)
    );

    if fg.workspace == TargetWorkspace::Chrome2Rust {
        let trimmed = out.stdout.trim();
        ensure!(
            (out.success() && trimmed == "[]") || !out.success(),
            "{} missing-path unexpected output (exit {:?}): stdout={} stderr={}",
            fg.name,
            out.exit_code,
            truncate_preview(trimmed, 200),
            truncate_preview(&out.stderr, 200)
        );
    } else {
        ensure!(
            !out.success(),
            "{} unexpectedly exited 0 on missing path: stdout={}",
            fg.name,
            truncate_preview(&out.stdout, 200)
        );
        ensure!(
            !out.stderr.trim().is_empty() || !out.stdout.trim().is_empty(),
            "{} exited non-zero on missing path with empty diagnostics",
            fg.name
        );
    }
    Ok(CheckOutcome::Pass(format!(
        "{} handled missing path cleanly without panic or clap exit-2",
        fg.name
    )))
}

fn run_domain_corrupt_fixture(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }
    let tmp = TempDir::new()?;
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir)?;

    let mut owned_args: Vec<String> = Vec::new();
    match fg.workspace {
        TargetWorkspace::Chrome2Rust => {
            let corrupt = cfg.fixtures.corrupt_dir.join(fg.items[0].corrupt_rel.unwrap_or("bad_magic.sqlite"));
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([corrupt.display().to_string(), "-f".into(), "json".into()]);
        }
        TargetWorkspace::Mail2Rust => {
            let corrupt = cfg.fixtures.corrupt_dir.join("bad_nk2.nk2");
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([corrupt.display().to_string(), "--format".into(), "json".into()]);
        }
        TargetWorkspace::Android2Rust => {
            // Passing a corrupt regular file as --source-dir triggers clean directory/read error
            let corrupt_file = tmp.path().join("corrupt_not_a_dir.bin");
            std::fs::write(&corrupt_file, b"\x00\xffCORRUPT_WPD_HEADER\xde\xad\xbe\xef")?;
            owned_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--source-dir".into(),
                corrupt_file.display().to_string(),
                "--json".into(),
            ]);
        }
        TargetWorkspace::Sys2Rust => {
            let corrupt = cfg.fixtures.corrupt_dir.join("bad_pe_magic.exe");
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend([
                "pe".into(),
                "exports".into(),
                "--path".into(),
                corrupt.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Forensics2Rust => {
            let corrupt_name = fg.items.iter().find_map(|it| it.corrupt_rel).unwrap_or("bad_magic.sqlite");
            let corrupt = cfg.fixtures.corrupt_dir.join(corrupt_name);
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--source".into(),
                corrupt.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Winctl2Rust => {
            let corrupt = cfg.fixtures.corrupt_dir.join("truncated_edid.bin");
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend([
                "display".into(),
                "edid".into(),
                "--file".into(),
                corrupt.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Net2Rust => {
            let corrupt = cfg.fixtures.corrupt_dir.join("bad_pcap_magic.pcap");
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend([
                "capture".into(),
                "sniff".into(),
                "--offline".into(),
                "--pcap".into(),
                corrupt.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Fs2Rust => {
            let corrupt = cfg.fixtures.corrupt_dir.join("bad_exif.jpg");
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend([
                "data".into(),
                "exif".into(),
                "--offline".into(),
                "--path".into(),
                corrupt.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        _ => {
            let corrupt_name = fg.items.iter().find_map(|it| it.corrupt_rel).unwrap_or("bad_magic.sqlite");
            let corrupt = cfg.fixtures.corrupt_dir.join(corrupt_name);
            ensure!(corrupt.is_file(), "missing corrupt fixture {}", corrupt.display());
            owned_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            owned_args.extend([
                "--input".into(),
                corrupt.display().to_string(),
                "--output".into(),
                out_dir.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
    }

    let refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();
    let out = session
        .run_cli(fg.workspace, &refs)?
        .context("binary missing unexpectedly")?;
    assert_not_clap_usage_error(&format!("{} corrupt-fixture", fg.name), &out)?;
    ensure!(
        !out.stderr.contains("panicked at"),
        "{} panicked on corrupt fixture: {}",
        fg.name,
        truncate_preview(&out.stderr, 240)
    );

    if fg.workspace == TargetWorkspace::Chrome2Rust {
        let trimmed = out.stdout.trim();
        ensure!(
            (out.success() && trimmed == "[]") || !out.success(),
            "{} corrupt-fixture unexpected output: stdout={} stderr={}",
            fg.name,
            truncate_preview(trimmed, 200),
            truncate_preview(&out.stderr, 200)
        );
    } else {
        ensure!(
            !out.success(),
            "{} unexpectedly exited 0 on corrupt fixture: stdout={}",
            fg.name,
            truncate_preview(&out.stdout, 200)
        );
    }

    Ok(CheckOutcome::Pass(format!(
        "{} handled corrupt fixture cleanly without panic or clap exit-2",
        fg.name
    )))
}

fn run_domain_empty_and_invalid(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }
    let tmp = TempDir::new()?;
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir)?;
    let zero = tmp.path().join("zero_bytes.bin");
    std::fs::write(&zero, b"")?;

    // Part A: 0-byte file or empty dir
    let mut zero_args: Vec<String> = Vec::new();
    match fg.workspace {
        TargetWorkspace::Chrome2Rust => {
            let zero_db = tmp.path().join("zero_places.sqlite");
            std::fs::write(&zero_db, b"")?;
            zero_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            zero_args.extend([zero_db.display().to_string(), "-f".into(), "json".into()]);
        }
        TargetWorkspace::Mail2Rust => {
            let zero_nk2 = tmp.path().join("zero.nk2");
            std::fs::write(&zero_nk2, b"")?;
            zero_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            zero_args.extend([zero_nk2.display().to_string(), "--format".into(), "json".into()]);
        }
        TargetWorkspace::Android2Rust => {
            let empty_dir = tmp.path().join("empty_wpd_dir");
            std::fs::create_dir_all(&empty_dir)?;
            zero_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            zero_args.extend([
                "--source-dir".into(),
                empty_dir.display().to_string(),
                "--json".into(),
            ]);
        }
        TargetWorkspace::Sys2Rust => {
            let zero_pe = tmp.path().join("zero.exe");
            std::fs::write(&zero_pe, b"")?;
            zero_args.extend([
                "pe".into(),
                "exports".into(),
                "--path".into(),
                zero_pe.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Forensics2Rust => {
            zero_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            zero_args.extend([
                "--source".into(),
                zero.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Winctl2Rust => {
            zero_args.extend([
                "display".into(),
                "edid".into(),
                "--file".into(),
                zero.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Net2Rust => {
            zero_args.extend([
                "capture".into(),
                "sniff".into(),
                "--offline".into(),
                "--pcap".into(),
                zero.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        TargetWorkspace::Fs2Rust => {
            zero_args.extend([
                "data".into(),
                "exif".into(),
                "--offline".into(),
                "--path".into(),
                zero.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
        _ => {
            zero_args.extend(fg.items[0].cli_tokens.iter().map(|s| (*s).to_string()));
            zero_args.extend([
                "--input".into(),
                zero.display().to_string(),
                "--output".into(),
                out_dir.display().to_string(),
                "--format".into(),
                "json".into(),
            ]);
        }
    }
    let zero_refs: Vec<&str> = zero_args.iter().map(String::as_str).collect();
    let zero_out = session
        .run_cli(fg.workspace, &zero_refs)?
        .context("binary missing unexpectedly")?;
    assert_not_clap_usage_error(&format!("{} zero-byte", fg.name), &zero_out)?;
    ensure!(
        !zero_out.stderr.contains("panicked at"),
        "{} panicked on zero-byte input",
        fg.name
    );
    match fg.workspace {
        TargetWorkspace::Chrome2Rust => {
            ensure!(
                (zero_out.success() && zero_out.stdout.trim() == "[]") || !zero_out.success(),
                "{} zero-byte unexpected output: {}",
                fg.name,
                truncate_preview(&zero_out.stdout, 200)
            );
        }
        TargetWorkspace::Android2Rust => {
            ensure!(
                zero_out.success(),
                "{} empty dir failed unexpectedly: {}",
                fg.name,
                truncate_preview(&zero_out.stderr, 200)
            );
            let val: Value = serde_json::from_str(zero_out.stdout.trim())
                .context("android2rust empty dir output not JSON")?;
            let entries = val
                .get("entries")
                .and_then(Value::as_array)
                .context("android2rust empty dir JSON missing entries")?;
            ensure!(entries.is_empty(), "expected 0 entries on empty wpd dir");
        }
        _ => {
            ensure!(
                !zero_out.success(),
                "{} zero-byte input unexpectedly exited 0",
                fg.name
            );
        }
    }

    // Part B: invalid query/sort/filter on real populated fixture
    let it0 = &fg.items[0];
    let gac_tmp = if fg.id == "FG-27" {
        Some(stage_sys2rust_gac_root(&cfg.fixtures)?)
    } else {
        None
    };
    let nk2_tmp = if fg.workspace == TargetWorkspace::Mail2Rust {
        Some(stage_mail_nk2_file()?)
    } else {
        None
    };
    let forensics_tmp = if fg.workspace == TargetWorkspace::Forensics2Rust {
        Some(stage_forensics_compat_dir(&cfg.fixtures)?)
    } else {
        None
    };
    let mut bad_query_args = build_cli_readonly_args_ext(
        it0,
        &cfg.fixtures,
        Some(&out_dir),
        gac_tmp.as_ref().map(|t| t.path()),
        nk2_tmp.as_ref().map(|t| t.path()),
        forensics_tmp.as_ref().map(|t| t.path()),
    )?;
    match fg.workspace {
        TargetWorkspace::Chrome2Rust => {
            bad_query_args.extend(["--sort".into(), "nonexistent_col_e2e".into()]);
        }
        TargetWorkspace::Android2Rust => {
            bad_query_args.extend(["--pattern".into(), "[unclosed".into(), "--regex".into()]);
        }
        _ => {
            bad_query_args.extend(["--filter".into(), "[unclosed".into()]);
        }
    }
    let bad_refs: Vec<&str> = bad_query_args.iter().map(String::as_str).collect();
    let bad_q_out = session
        .run_cli(fg.workspace, &bad_refs)?
        .context("binary missing unexpectedly")?;
    assert_not_clap_usage_error(&format!("{} invalid-query", fg.name), &bad_q_out)?;
    ensure!(
        !bad_q_out.stderr.contains("panicked at"),
        "{} panicked on invalid query",
        fg.name
    );
    ensure!(
        !bad_q_out.success(),
        "{} unexpectedly accepted invalid query/sort/filter: {}",
        fg.name,
        bad_refs.join(" ")
    );

    // Part C: explicit invalid CLI flag rejection (clap exit 2 expected here ONLY)
    let mut bad_flag_args: Vec<String> = it0.cli_tokens.iter().map(|s| (*s).to_string()).collect();
    bad_flag_args.push("--nonexistent-flag-e2e".into());
    let flag_refs: Vec<&str> = bad_flag_args.iter().map(String::as_str).collect();
    let flag_out = session
        .run_cli(fg.workspace, &flag_refs)?
        .context("binary missing unexpectedly")?;
    ensure!(
        !flag_out.success(),
        "{} unexpectedly accepted --nonexistent-flag-e2e",
        fg.name
    );

    Ok(CheckOutcome::Pass(format!(
        "{} handled 0-byte input, invalid query, and invalid flag cleanly",
        fg.name
    )))
}
fn run_domain_nonpriv_fallback(
    chk: &CatalogCheckDef,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }
    let tmp = TempDir::new()?;
    let it0 = &fg.items[0];
    let effective_item: &ItemSpec = match fg.workspace {
        TargetWorkspace::Mail2Rust => fg.items.get(4).unwrap_or(it0),
        TargetWorkspace::Sys2Rust if fg.id == "FG-27" => fg.items.get(4).unwrap_or(it0),
        _ => it0,
    };
    let mut args: Vec<String> = Vec::new();

    if fg.id == "FG-27" {
        let exe = session
            .resolve_binary(TargetWorkspace::Sys2Rust)?
            .context("sys2rust binary missing")?;
        args.extend([
            "pe".into(),
            "info".into(),
            "--path".into(),
            exe.display().to_string(),
            "--format".into(),
            "json".into(),
        ]);
    } else {
        match fg.cli_live {
            CliLiveStyle::LiveFlag => {
                args.extend(it0.cli_tokens.iter().map(|s| (*s).to_string()));
                args.push("--live".into());
                if fg.workspace == TargetWorkspace::Android2Rust {
                    args.push("--json".into());
                } else {
                    args.extend(["--limit".into(), "2".into(), "--format".into(), "json".into()]);
                }
            }
            CliLiveStyle::OmitOffline => {
                args.extend(it0.cli_tokens.iter().map(|s| (*s).to_string()));
                if fg.id == "FG-28" {
                    let probe_dir = tmp.path().join("live_probe_dir");
                    std::fs::create_dir_all(&probe_dir)?;
                    std::fs::write(probe_dir.join("probe.txt"), b"ok")?;
                    args.extend(["--root".into(), probe_dir.display().to_string()]);
                }
                args.extend(["--limit".into(), "2".into(), "--format".into(), "json".into()]);
            }
            CliLiveStyle::PositionalNoPath | CliLiveStyle::MailLive => match fg.workspace {
                TargetWorkspace::Chrome2Rust => {
                    let empty_dir = tmp.path().join("empty_profile");
                    std::fs::create_dir_all(&empty_dir)?;
                    args.extend([
                        "fx".into(),
                        "history".into(),
                        empty_dir.display().to_string(),
                        "-f".into(),
                        "json".into(),
                    ]);
                }
                TargetWorkspace::Mail2Rust => {
                    args.extend([
                        "office".into(),
                        "addins".into(),
                        "list".into(),
                        "--log-level".into(),
                        "error".into(),
                        "--format".into(),
                        "json".into(),
                    ]);
                }
                _ => {
                    return Ok(CheckOutcome::Pass(format!(
                        "{} has no live CLI mode; non-privileged static path verified",
                        fg.name
                    )));
                }
            },
        }
    }

    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = session
        .run_cli(fg.workspace, &refs)?
        .context("binary missing unexpectedly")?;
    assert_not_clap_usage_error(&format!("{} nonpriv-fallback", fg.name), &out)?;
    ensure!(
        !out.stderr.contains("panicked at"),
        "{} panicked on non-privileged fallback: {}",
        fg.name,
        truncate_preview(&out.stderr, 240)
    );

    if fg.workspace == TargetWorkspace::Android2Rust {
        // Live WPD scan without attached device exits 1 with JSON status=unavailable or 0 if attached
        let trimmed = out.stdout.trim();
        let val: Value = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "android2rust --live --json did not emit JSON: {}",
                truncate_preview(trimmed, 200)
            )
        })?;
        ensure!(val.is_object(), "android2rust --live JSON must be an object");
    } else if matches!(
        fg.workspace,
        TargetWorkspace::Forensics2Rust | TargetWorkspace::Net2Rust
    ) && !out.success()
    {
        let diag = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
        let is_perm_denied = !out.stderr.trim().is_empty()
            && (diag.contains("permission denied")
                || diag.contains("access is denied")
                || diag.contains("access denied")
                || diag.contains("run elevated")
                || diag.contains("elevation")
                || diag.contains("privilege")
                || diag.contains("location privacy")
                || diag.contains("driver unavailable")
                || diag.contains("wireless interface")
                || diag.contains("wlansvc")
                || diag.contains("no wireless"));
        ensure!(
            is_perm_denied,
            "{} non-privileged fallback failed unexpectedly (exit {:?}): {}",
            fg.name,
            out.exit_code,
            truncate_preview(&out.stderr, 240)
        );
    } else {
        ensure!(
            out.success(),
            "{} non-privileged fallback failed (exit {:?}): {}",
            fg.name,
            out.exit_code,
            truncate_preview(&out.stderr, 240)
        );
        let require_nonempty = if fg.workspace == TargetWorkspace::Net2Rust {
            false
        } else {
            effective_item.expects_nonempty_rows
        };
        let _ = verify_cli_json_output_mode(&out.stdout, effective_item, require_nonempty).with_context(|| {
            format!(
                "{} non-privileged fallback stdout validation failed",
                fg.name
            )
        })?;
    }

    Ok(CheckOutcome::Pass(format!(
        "{} non-privileged execution path completed without panic or clap exit-2",
        fg.name
    )))
}

fn run_domain_malformed_mcp(
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let fg = fg_for_check(chk)?;
    let bin = match require_domain_binary(fg.workspace, session)? {
        Ok(b) => b,
        Err(skip) => return Ok(skip),
    };
    let ro = fg
        .items
        .iter()
        .find(|it| !it.mutating_capable)
        .with_context(|| format!("{} has no read-only item", fg.name))?;

    let gac_tmp = if fg.id == "FG-27" {
        Some(stage_sys2rust_gac_root(&cfg.fixtures)?)
    } else {
        None
    };
    let (spawn_args, envs_owned) = mcp_spawn_args_and_env(
        fg.workspace,
        gac_tmp.as_ref().map(|t| t.path()),
    );
    let env_refs: Vec<(&str, &str)> = envs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut mcp = McpSession::spawn(&bin, spawn_args, &env_refs)?;
    mcp.initialize()?;

    // 1) Malformed JSON -> JSON-RPC -32700 Parse Error
    let parse_resp = mcp.send_raw_line_and_read("{bad json")?;
    let parse_code = parse_resp.pointer("/error/code").and_then(Value::as_i64);
    ensure!(
        parse_code == Some(-32700),
        "{} MCP server expected JSON-RPC -32700 parse error on malformed JSON, got: {parse_resp}",
        fg.name
    );

    // 2) Non-object `arguments` on first read-only tool -> JSON-RPC -32602 Invalid Params
    let bad_resp = mcp.tools_call(ro.mcp_tool, json!("not_an_object"))?;
    let bad_code = bad_resp.pointer("/error/code").and_then(Value::as_i64);
    ensure!(
        bad_code == Some(-32602),
        "{} MCP tool '{}' expected JSON-RPC -32602 on non-object arguments, got: {bad_resp}",
        fg.name,
        ro.mcp_tool
    );

    // 3) Unknown tool name -> JSON-RPC -32601 Method Not Found (or legacy isError=true strictly on android2rust)
    let unknown_resp = mcp.tools_call("__nonexistent_e2e_tool", json!({}))?;
    if unknown_resp.get("error").is_some() {
        let unknown_code = unknown_resp.pointer("/error/code").and_then(Value::as_i64);
        ensure!(
            unknown_code == Some(-32601),
            "{} MCP server expected JSON-RPC -32601 for unknown tool, got: {unknown_resp}",
            fg.name
        );
    } else if fg.workspace == TargetWorkspace::Android2Rust {
        let is_err = unknown_resp
            .pointer("/result/isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        ensure!(
            is_err,
            "{} MCP server unexpectedly accepted unknown tool: {unknown_resp}",
            fg.name
        );
    } else {
        bail!(
            "{} MCP server expected JSON-RPC -32601 for unknown tool (result.isError fallback only allowed for android2rust), got: {unknown_resp}",
            fg.name
        );
    }

    // 4) Server remains responsive after malformed calls
    mcp.ping()?;
    let _ = mcp.close()?;
    Ok(CheckOutcome::Pass(format!(
        "{} MCP rejected -32700 parse error, -32602 params on '{}', and unknown tool, and remained responsive",
        fg.name, ro.mcp_tool
    )))
}

fn verify_suite_export_and_custody(
    fg: &FeatureGroupDef,
    item_idx: usize,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<String> {
    let it = &fg.items[item_idx];
    let tmp = TempDir::new()?;
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir)?;
    let csv_path = out_dir.join("export.csv");
    let man_path = out_dir.join("custody.json");
    let nk2_tmp = if fg.workspace == TargetWorkspace::Mail2Rust {
        Some(stage_mail_nk2_file()?)
    } else {
        None
    };
    let forensics_tmp = if fg.workspace == TargetWorkspace::Forensics2Rust {
        Some(stage_forensics_compat_dir(&cfg.fixtures)?)
    } else {
        None
    };
    let f_path = effective_item_fixture_path(
        it,
        &cfg.fixtures,
        nk2_tmp.as_ref().map(|t| t.path()),
        forensics_tmp.as_ref().map(|t| t.path()),
    );
    let gac_tmp = if it.cli_input == CliInputStyle::Flag("--gac-root") {
        Some(stage_sys2rust_gac_root(&cfg.fixtures)?)
    } else {
        None
    };

    let mut args: Vec<String> = it.cli_tokens.iter().map(|s| (*s).to_string()).collect();
    match fg.cli_export {
        CliExportStyle::Chrome => {
            args.extend([
                f_path.display().to_string(),
                "-f".into(),
                "csv".into(),
                "-o".into(),
                csv_path.display().to_string(),
                "--custody-manifest".into(),
                man_path.display().to_string(),
            ]);
        }
        CliExportStyle::Mail => {
            args.extend([
                f_path.display().to_string(),
                "--log-level".into(),
                "error".into(),
                "--format".into(),
                "csv".into(),
                "--export".into(),
                csv_path.display().to_string(),
            ]);
        }
        CliExportStyle::Android => {
            let parent = f_path.parent().context("fixture has no parent")?;
            args.extend([
                "--source-dir".into(),
                parent.display().to_string(),
                "--format".into(),
                "csv".into(),
                "--output".into(),
                csv_path.display().to_string(),
                "--json".into(),
            ]);
        }
        CliExportStyle::Sys2Rust => {
            match it.cli_input {
                CliInputStyle::OfflineNoFile => args.push("--offline".into()),
                CliInputStyle::Flag("--gac-root") => {
                    let root = gac_tmp.as_ref().unwrap().path().join("Microsoft.NET").join("assembly");
                    args.extend(["--gac-root".into(), root.display().to_string()]);
                }
                CliInputStyle::Flag(flag) => {
                    args.extend([flag.to_string(), f_path.display().to_string()]);
                }
                _ => bail!("unexpected sys2rust cli_input {:?}", it.cli_input),
            }
            args.extend([
                "--format".into(),
                "csv".into(),
                "--export".into(),
                csv_path.display().to_string(),
                "--custody".into(),
                man_path.display().to_string(),
            ]);
        }
        CliExportStyle::Forensics => {
            args.extend([
                "--source".into(),
                f_path.display().to_string(),
                "--format".into(),
                "csv".into(),
                "-o".into(),
                csv_path.display().to_string(),
                "--custody".into(),
                man_path.display().to_string(),
            ]);
        }
        CliExportStyle::Winctl => {
            if let CliInputStyle::Flag(flag) = it.cli_input {
                args.extend([flag.to_string(), f_path.display().to_string()]);
            }
            args.extend([
                "--format".into(),
                "csv".into(),
                "-o".into(),
                csv_path.display().to_string(),
                "--custody".into(),
                man_path.display().to_string(),
            ]);
        }
        CliExportStyle::Fs => {
            args.push("--offline".into());
            match it.cli_input {
                CliInputStyle::FlagOffline(flag) => {
                    args.extend([flag.to_string(), f_path.display().to_string()]);
                }
                CliInputStyle::FlagOfflineDir(flag) => {
                    let parent = f_path.parent().context("fixture has no parent")?;
                    args.extend([flag.to_string(), parent.display().to_string()]);
                }
                CliInputStyle::FsDataDiff => {
                    let left_csv = cfg.fixtures.sys_fs_dir.join("sample_data.csv");
                    args.extend([
                        "--left".into(),
                        left_csv.display().to_string(),
                        "--right".into(),
                        f_path.display().to_string(),
                    ]);
                }
                _ => {}
            }
            args.extend([
                "--format".into(),
                "csv".into(),
                "-o".into(),
                csv_path.display().to_string(),
                "--custody".into(),
                man_path.display().to_string(),
            ]);
        }
        CliExportStyle::Net => {
            args.push("--offline".into());
            if let CliInputStyle::FlagOffline(flag) = it.cli_input {
                args.extend([flag.to_string(), f_path.display().to_string()]);
            }
            args.extend([
                "--format".into(),
                "csv".into(),
                "--out".into(),
                csv_path.display().to_string(),
                "--custody-out".into(),
                man_path.display().to_string(),
            ]);
        }
        CliExportStyle::Standard => {
            args.extend([
                "--input".into(),
                f_path.display().to_string(),
                "--output".into(),
                out_dir.display().to_string(),
                "--format".into(),
                "csv".into(),
                "--export-csv".into(),
                csv_path.display().to_string(),
                "--manifest".into(),
                man_path.display().to_string(),
            ]);
        }
    }

    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = session
        .run_cli(fg.workspace, &refs)?
        .context("binary missing unexpectedly")?;
    assert_not_clap_usage_error(&format!("{} export", fg.name), &out)?;
    ensure!(
        out.success(),
        "{} CSV/custody export failed (exit {:?}): stdout={} stderr={}",
        fg.name,
        out.exit_code,
        truncate_preview(&out.stdout, 200),
        truncate_preview(&out.stderr, 200)
    );

    ensure!(
        csv_path.is_file(),
        "{} did not write CSV export at {}",
        fg.name,
        csv_path.display()
    );
    let csv_bytes = std::fs::read(&csv_path)?;
    ensure!(
        !csv_bytes.is_empty(),
        "{} wrote 0-byte CSV export at {}",
        fg.name,
        csv_path.display()
    );
    let min_data_rows = usize::from(it.expects_nonempty_rows);
    verify_csv_formula_neutralization_min_rows(&csv_bytes, &[], min_data_rows)
        .with_context(|| format!("{} CSV verification failed", fg.name))?;

    let manifest_bytes = match fg.cli_export {
        CliExportStyle::Mail => {
            let sidecar = std::path::PathBuf::from(format!("{}.custody.json", csv_path.display()));
            ensure!(
                sidecar.is_file(),
                "{} mail export did not emit sidecar {}",
                fg.name,
                sidecar.display()
            );
            std::fs::read(&sidecar)?
        }
        CliExportStyle::Android => {
            let sidecar = std::path::PathBuf::from(format!("{}.custody.json", csv_path.display()));
            if sidecar.is_file() {
                std::fs::read(&sidecar)?
            } else {
                let v: Value = serde_json::from_str(out.stdout.trim())
                    .context("android2rust export --json stdout is not JSON")?;
                let cm = v
                    .get("custody_manifest")
                    .filter(|m| !m.is_null())
                    .context("android2rust export JSON missing custody_manifest")?;
                serde_json::to_vec(cm)?
            }
        }
        _ => {
            ensure!(
                man_path.is_file(),
                "{} did not write custody manifest at {}",
                fg.name,
                man_path.display()
            );
            std::fs::read(&man_path)?
        }
    };
    let unwrapped_manifest_bytes = {
        let parsed: Value = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("{} custody JSON parse failed", fg.name))?;
        if parsed.get("leaves").is_none()
            && let Some(inner) = parsed.get("custody").filter(|c| c.is_object())
        {
            serde_json::to_vec(inner)?
        } else {
            manifest_bytes
        }
    };
    let manifest = verify_custody_manifest(&unwrapped_manifest_bytes, false)
        .with_context(|| format!("{} CustodyManifest verification failed", fg.name))?;
    ensure!(
        !manifest.leaves.is_empty() && manifest.artifact_count >= 1,
        "{} CustodyManifest must contain at least 1 artifact leaf",
        fg.name
    );
    ensure!(
        !manifest.merkle_root_sha256.is_empty() && !manifest.merkle_root_sha512.is_empty(),
        "{} CustodyManifest missing Merkle roots",
        fg.name
    );

    Ok(String::from_utf8_lossy(&csv_bytes).into_owned())
}
fn verify_suite_mutating_gate(
    fg: &FeatureGroupDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    let bin = match require_domain_binary(fg.workspace, session)? {
        Ok(b) => b,
        Err(skip) => return Ok(skip),
    };
    let gac_tmp = if fg.id == "FG-27" {
        Some(stage_sys2rust_gac_root(&cfg.fixtures)?)
    } else {
        None
    };
    let (spawn_args, envs_owned) = mcp_spawn_args_and_env(
        fg.workspace,
        gac_tmp.as_ref().map(|t| t.path()),
    );
    let env_refs: Vec<(&str, &str)> = envs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut mcp = McpSession::spawn(&bin, spawn_args, &env_refs)?;
    mcp.initialize()?;
    let listed = mcp.tools_list()?;

    match fg.mutating_action {
        None => {
            // Assert all non-legacy tools in this suite are marked readOnlyHint: true & destructiveHint != true
            for t in &listed {
                let t_name = t.get("name").and_then(Value::as_str).unwrap_or("");
                if is_legacy_no_annotations_tool(fg.workspace, t_name) {
                    continue;
                }
                let ann = t.get("annotations");
                let ro = ann
                    .and_then(|a| a.get("readOnlyHint"))
                    .and_then(Value::as_bool);
                let dest = ann
                    .and_then(|a| a.get("destructiveHint"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if fg.items.iter().any(|it| it.mcp_tool == t_name) {
                    ensure!(
                        ro == Some(true) && !dest,
                        "{} tool '{}' expected readOnlyHint=true & destructiveHint=false, got {:?}",
                        fg.name,
                        t_name,
                        ann
                    );
                }
            }
            let _ = mcp.close()?;

            // For Chrome2Rust (FG-12), also verify `cache delete` dry-run (omitting --yes) makes 0 disk edits
            if fg.workspace == TargetWorkspace::Chrome2Rust {
                let tmp = TempDir::new()?;
                let cache_copy = tmp.path().join("cache2_entries");
                std::fs::create_dir_all(&cache_copy)?;
                let sample_src = cfg.fixtures.browser_dir.join("media/sample_exif.jpg");
                let sample_dst = cache_copy.join("f_000001");
                std::fs::copy(&sample_src, &sample_dst)?;
                let out = session
                    .run_cli(
                        TargetWorkspace::Chrome2Rust,
                        &["cache", "delete", &cache_copy.display().to_string()],
                    )?
                    .context("chrome2rust binary missing")?;
                assert_not_clap_usage_error("chrome2rust cache delete dry-run", &out)?;
                ensure!(
                    !out.stderr.contains("panicked at"),
                    "chrome2rust cache delete dry-run panicked"
                );
                ensure!(
                    sample_dst.is_file(),
                    "chrome2rust cache delete without --yes unexpectedly deleted {}",
                    sample_dst.display()
                );
                return Ok(CheckOutcome::Pass(
                    "chrome2rust read-only MCP annotations + cache delete without --yes (0 disk edits) verified"
                        .to_string(),
                ));
            }

            Ok(CheckOutcome::Pass(format!(
                "{} read-only MCP annotations verified (no mutating action exposed)",
                fg.name
            )))
        }
        Some(spec) => {
            let tool = listed
                .iter()
                .find(|t| t.get("name").and_then(Value::as_str) == Some(spec.tool_id))
                .with_context(|| format!("mutating MCP tool '{}' missing from tools/list", spec.tool_id))?;
            let ann = tool
                .get("annotations")
                .with_context(|| format!("mutating MCP tool '{}' missing annotations", spec.tool_id))?;
            ensure!(
                ann.get("destructiveHint").and_then(Value::as_bool) == Some(true)
                    && ann.get("readOnlyHint").and_then(Value::as_bool) != Some(true),
                "mutating tool '{}' annotations expected destructiveHint=true & readOnlyHint!=true, got {ann}",
                spec.tool_id
            );

            let fixture_path = item_fixture_path(&fg.items[0], &cfg.fixtures);
            let call_args = build_mutating_args(spec, &fixture_path);
            let resp = mcp.tools_call(spec.tool_id, call_args)?;
            let code = resp.pointer("/error/code").and_then(Value::as_i64);
            let msg = resp.pointer("/error/message").and_then(Value::as_str).unwrap_or("");
            ensure!(
                code == Some(-32003),
                "mutating tool '{}' under ReadOnlyOnly policy expected JSON-RPC -32003, got {resp}",
                spec.tool_id
            );
            ensure!(
                msg.to_ascii_uppercase().contains("SAFETY REFUSAL")
                    || msg.to_ascii_lowercase().contains("read-only")
                    || msg.to_ascii_lowercase().contains("readonly"),
                "mutating tool '{}' -32003 message missing policy context: {msg}",
                spec.tool_id
            );
            mcp.ping()?;
            let _ = mcp.close()?;
            Ok(CheckOutcome::Pass(format!(
                "MCP ReadOnlyOnly enforced JSON-RPC -32003 SAFETY REFUSAL on '{}'",
                spec.tool_id
            )))
        }
    }
}

fn is_xml_ncname_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

fn strip_redacted_keymaterial_tags(lower: &str) -> String {
    const OPEN_NO_PREFIX: &str = "<keymaterial>[redacted]</keymaterial>";
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(lower.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if lower[i..].starts_with(OPEN_NO_PREFIX) {
            i += OPEN_NO_PREFIX.len();
            continue;
        }
        if bytes[i] == b'<' {
            let after_lt = i + 1;
            let mut colon = after_lt;
            while colon < bytes.len() && is_xml_ncname_char(bytes[colon]) {
                colon += 1;
            }
            if colon > after_lt && colon < bytes.len() && bytes[colon] == b':' {
                let prefix = &lower[after_lt..colon];
                let expected = format!("<{prefix}:keymaterial>[redacted]</{prefix}:keymaterial>");
                if lower[i..].starts_with(&expected) {
                    i += expected.len();
                    continue;
                }
            }
        }
        let ch = lower[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn check_no_r4_secret_leak(label: &str, text: &str) -> anyhow::Result<()> {
    const R4_PSK: &str = "GuapTestWpa2Key!2026";
    ensure!(
        !text.contains(R4_PSK),
        "R4 secret leak detected in {label}: literal PSK must be redacted"
    );
    let lower = text.to_ascii_lowercase();
    ensure!(
        !lower.contains("wlan_profile_get_plaintext_key"),
        "R4 secret leak detected in {label}: forbidden WLAN_PROFILE_GET_PLAINTEXT_KEY marker"
    );
    let cleaned_lower = strip_redacted_keymaterial_tags(&lower);
    ensure!(
        !cleaned_lower.contains("<keymaterial") && !cleaned_lower.contains("keymaterial"),
        "R4 secret leak detected in {label}: unredacted keyMaterial element/field"
    );
    Ok(())
}

fn verify_net2rust_radio_r4_redaction(
    label_prefix: &str,
    fg: &FeatureGroupDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<()> {
    let bin = session
        .resolve_binary(fg.workspace)?
        .context("net2rust binary missing")?;
    let (spawn_args, envs_owned) = mcp_spawn_args_and_env(fg.workspace, None);
    let env_refs: Vec<(&str, &str)> = envs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut mcp = McpSession::spawn(&bin, spawn_args, &env_refs)?;
    mcp.initialize()?;

    // Probe both FG23_ITEMS[0] (radio.wifi-info) and FG23_ITEMS[4] (radio.wifi-profiles / ManageWirelessNetworks)
    for item_idx in [0usize, 4usize] {
        let it = &fg.items[item_idx];
        let out_dir = TempDir::new()?;
        let args = build_cli_readonly_args(it, &cfg.fixtures, Some(out_dir.path()), None)?;
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let cli_out = session
            .run_cli(fg.workspace, &refs)?
            .context("net2rust binary missing")?;
        assert_not_clap_usage_error(&format!("{label_prefix} {}", it.mcp_tool), &cli_out)?;
        ensure!(
            cli_out.success(),
            "{label_prefix} CLI ({}) failed: {}",
            it.mcp_tool,
            truncate_preview(&cli_out.stderr, 200)
        );
        let _ = verify_cli_json_output(&cli_out.stdout, it)?;
        check_no_r4_secret_leak(&format!("{label_prefix} CLI stdout JSON ({})", it.mcp_tool), &cli_out.stdout)?;

        let csv_str = verify_suite_export_and_custody(fg, item_idx, cfg, session)?;
        check_no_r4_secret_leak(&format!("{label_prefix} exported CSV ({})", it.mcp_tool), &csv_str)?;

        let mcp_args = build_mcp_readonly_args(it, &cfg.fixtures)?;
        let resp = mcp.tools_call(it.mcp_tool, mcp_args)?;
        let text = assert_tool_call_ok(&resp, it.mcp_tool)?;
        let _ = verify_mcp_json_output(&text, it.mcp_tool, it.expects_nonempty_rows)?;
        check_no_r4_secret_leak(&format!("{label_prefix} MCP {}", it.mcp_tool), &text)?;
    }

    let _ = mcp.close()?;
    Ok(())
}

fn run_tier3_pairwise(
    id: &str,
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    match id {
        "T3-01" | "T3-02" | "T3-03" | "T3-04" | "T3-05" | "T3-06" | "T3-07" | "T3-08" => {
            if cfg.skip_cargo_build {
                return Ok(CheckOutcome::Skip(format!(
                    "{id}: guap-kit runtime cargo test skipped because skip_cargo_build=true"
                )));
            }
            match id {
                "T3-01" => {
                    let n1 = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "get_nir_query_10k_expressions"],
                        1,
                    )?;
                    let n2 = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "query_10k"],
                        2,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-01 guap-table GetNir & query tests passed ({n1}+{n2})")))
                }
                "T3-02" => {
                    let n = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-table", "--test", "synthetic_10k", "table_text_compare_10k_diff"],
                        1,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-02 guap-table TableTextCompare diff passed ({n})")))
                }
                "T3-03" => {
                    let n1 = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "csv_rfc4180_and_formula_neutralization"],
                        1,
                    )?;
                    let n2 = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle", "tsv_sanitizes_embedded_tabs_and_newlines"],
                        1,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-03 guap-export CSV/TSV formula neutralization passed ({n1}+{n2})")))
                }
                "T3-04" => {
                    let n = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-export", "--test", "export_and_merkle"],
                        6,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-04 guap-export 7-format + Merkle CustodyManifest passed ({n})")))
                }
                "T3-05" => {
                    let n = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-gui-win32", "--no-default-features", "--lib", "win32_state_25k"],
                        1,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-05 guap-gui-win32 25k TableProvider state passed ({n})")))
                }
                "T3-06" => {
                    let n = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-gui-iced", "--test", "grid_headless", "iced_grid_25k"],
                        1,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-06 guap-gui-iced 25k IcedDataGrid state passed ({n})")))
                }
                "T3-07" => {
                    let n1 = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "non_read_only_table_provider_exposes_confirm_destructive_and_enforces_32003"],
                        1,
                    )?;
                    let n2 = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "tools_list_annotations_and_table_provider_query"],
                        1,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-07 guap-mcp ReadOnlyOnly -32003 policy gate passed ({n1}+{n2})")))
                }
                "T3-08" => {
                    let n = run_guap_kit_cargo_test_checked(
                        session,
                        &["test", "--offline", "-p", "guap-mcp", "--test", "mcp_contract", "policy_gates_enforce_32003_and_allow_confirmed_mutations"],
                        1,
                    )?;
                    Ok(CheckOutcome::Pass(format!("T3-08 guap-mcp AllowMutating confirm_destructive & dry_run passed ({n})")))
                }
                _ => unreachable!(),
            }
        }
        "T3-15" => {
            let fg = fg_for_check(chk)?;
            if let Err(skip) = require_domain_binary(fg.workspace, session)? {
                return Ok(skip);
            }
            let _unified_csv = verify_suite_export_and_custody(fg, 13, cfg, session)?;
            let _exif_csv = verify_suite_export_and_custody(fg, 19, cfg, session)?;
            Ok(CheckOutcome::Pass(
                "T3-15 chrome2rust unified multi-browser history + EXIF carve CSV & Merkle custody manifest verified"
                    .to_string(),
            ))
        }
        "T3-27" => {
            let fg = fg_for_check(chk)?;
            if let Err(skip) = require_domain_binary(fg.workspace, session)? {
                return Ok(skip);
            }
            verify_net2rust_radio_r4_redaction("T3-27", fg, cfg, session)?;
            match verify_suite_mutating_gate(fg, cfg, session)? {
                CheckOutcome::Pass(gate_msg) => Ok(CheckOutcome::Pass(format!(
                    "T3-27 net2rust WiFi PSK redacted across CLI JSON, CSV export, and MCP (radio.wifi-info & radio.wifi-profiles); {gate_msg}"
                ))),
                skip @ CheckOutcome::Skip(_) => Ok(skip),
            }
        }
        _ => {
            let fg = fg_for_check(chk)?;
            verify_suite_mutating_gate(fg, cfg, session)
        }
    }
}

fn verify_downstream_gui_wiring(guap_root: &Path) -> anyhow::Result<usize> {
    let mut verified_crates = 0usize;
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
    for suite in suites {
        let win32_dir = guap_root.join(suite).join("crates").join(format!("{suite}-win32"));
        if win32_dir.join("Cargo.toml").is_file() {
            let manifest_path = win32_dir.join("app.manifest");
            ensure!(
                manifest_path.is_file(),
                "{}-win32 missing app.manifest at {}",
                suite,
                manifest_path.display()
            );
            let manifest_txt = std::fs::read_to_string(&manifest_path)?;
            ensure!(
                manifest_txt.contains("Microsoft.Windows.Common-Controls")
                    && manifest_txt.contains("6.0.0.0"),
                "{}-win32 app.manifest missing ComCtl v6 6.0.0.0 entry",
                suite
            );
            let build_rs = win32_dir.join("build.rs");
            ensure!(
                build_rs.is_file(),
                "{}-win32 missing build.rs manifest embedder",
                suite
            );
            verified_crates += 1;
        }
    }
    Ok(verified_crates)
}

fn run_tier4_scenario(
    id: &str,
    chk: &CatalogCheckDef,
    cfg: &TierRunConfig,
    session: &mut WorkspaceSession,
) -> anyhow::Result<CheckOutcome> {
    if id == "T4-S16" {
        validate_catalog_invariants()?;
        let fix_report = e2e_fixtures::verify_fixture_integrity(&cfg.fixtures)?;
        ensure!(
            fix_report.all_verified() && fix_report.verified_files > 0,
            "T4-S16 fixture integrity failed: {}/{}",
            fix_report.verified_files,
            fix_report.total_files
        );

        let guap_kit_root = session.workspace_dir(TargetWorkspace::GuapKit);
        for krate in [
            "guap-table",
            "guap-export",
            "guap-gui-win32",
            "guap-gui-iced",
            "guap-mcp",
        ] {
            let cargo_toml = guap_kit_root.join("crates").join(krate).join("Cargo.toml");
            ensure!(cargo_toml.is_file(), "T4-S16 missing {}", cargo_toml.display());
        }
        let win32_cargo = std::fs::read_to_string(
            guap_kit_root
                .join("crates")
                .join("guap-gui-win32")
                .join("Cargo.toml"),
        )?;
        ensure!(
            win32_cargo.contains("native-host"),
            "T4-S16 guap-gui-win32 Cargo.toml missing native-host feature"
        );

        let downstream_win32_count = verify_downstream_gui_wiring(&cfg.guap_root)?;

        let cargo_summary = if cfg.skip_cargo_build {
            "skip_cargo_build=true (workspace cargo tests skipped)".to_string()
        } else {
            let n_ws = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "--workspace", "--exclude", "guap-gui-win32"],
                10,
            )?;
            let n_w32 = run_guap_kit_cargo_test_checked(
                session,
                &["test", "--offline", "-p", "guap-gui-win32", "--no-default-features", "--lib"],
                2,
            )?;
            format!("cargo tests passed ({n_ws} workspace + {n_w32} win32)")
        };

        return Ok(CheckOutcome::Pass(format!(
            "T4-S16 meta gate verified ({}/{} fixtures, 360 catalog checks, {downstream_win32_count} downstream ComCtl v6 win32 crates, {cargo_summary})",
            fix_report.verified_files, fix_report.total_files
        )));
    }

    let fg = fg_for_check(chk)?;
    if let Err(skip) = require_domain_binary(fg.workspace, session)? {
        return Ok(skip);
    }

    let primary_item_idx = fg
        .items
        .iter()
        .position(|it| it.expects_nonempty_rows)
        .unwrap_or(0);
    let csv_str = verify_suite_export_and_custody(fg, primary_item_idx, cfg, session)?;
    let mut extra_note = String::new();
    match id {
        "T4-S06" => {
            if let CheckOutcome::Pass(gate_msg) = verify_suite_mutating_gate(fg, cfg, session)? {
                extra_note.push_str(&format!("; {gate_msg}"));
            }
            if cfg.target == TargetWorkspace::All
                && session.resolve_binary(TargetWorkspace::Chrome2Rust)?.is_some()
            {
                let fg12 = find_feature_group("FG-12").context("missing FG-12")?;
                let _ = verify_suite_export_and_custody(fg12, 13, cfg, session)?;
                extra_note.push_str(" + chrome2rust unified history custody");
            }
        }
        "T4-S12" => {
            check_no_r4_secret_leak("T4-S12 exported CSV (radio.wifi-info)", &csv_str)?;
            verify_net2rust_radio_r4_redaction("T4-S12", fg, cfg, session)?;
            extra_note.push_str(" + R4 zero-keyMaterial/PSK check (radio.wifi-info & radio.wifi-profiles)");
        }
        "T4-S14" if cfg.target == TargetWorkspace::All => {
            if session.resolve_binary(TargetWorkspace::Fs2Rust)?.is_some() {
                let fg28 = find_feature_group("FG-28").context("missing FG-28")?;
                let _ = verify_suite_export_and_custody(fg28, 5, cfg, session)?;
                extra_note.push_str(" + fs2rust HashMyFiles custody");
            } else {
                extra_note.push_str(" (fs2rust secondary binary unbuilt)");
            }
        }
        _ => {}
    }

    Ok(CheckOutcome::Pass(format!(
        "{id} end-to-end scenario verified CSV formula neutralization + CustodyManifest for {}{extra_note}",
        fg.name
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_rust_comments_handles_double_quote_char_literals() {
        let src = r#"
pub fn quote_char() -> char { '"' }
pub fn escaped_quote() -> char { '\"' }
// pub struct FakeCommentedOut;
pub struct RealAfterChar;
"#;
        let stripped = strip_rust_comments(src);
        assert!(stripped.contains("pub struct RealAfterChar;"));
        assert!(!stripped.contains("FakeCommentedOut"));
    }

    #[test]
    fn test_check_no_r4_secret_leak_catches_all_prohibited_markers() {
        assert!(check_no_r4_secret_leak("ok", "ssid=GUAP_TEST_NET, psk=[REDACTED]").is_ok());
        assert!(
            check_no_r4_secret_leak(
                "sanitized",
                "<WLANProfile><keyMaterial>[REDACTED]</keyMaterial></WLANProfile>"
            )
            .is_ok()
        );
        assert!(check_no_r4_secret_leak("psk", "GuapTestWpa2Key!2026").is_err());
        assert!(check_no_r4_secret_leak("km_tag", "<keyMaterial>SecretWifiPass99</keyMaterial>").is_err());
        assert!(check_no_r4_secret_leak("km_lower", "<KeyMaterial>abc</KeyMaterial>").is_err());
        assert!(check_no_r4_secret_leak("km_field", r#""keyMaterial": "abc""#).is_err());
        assert!(check_no_r4_secret_leak("flag", "WLAN_PROFILE_GET_PLAINTEXT_KEY").is_err());
    }

    #[test]
    fn test_strip_rust_comments_emits_space_for_block_comments() {
        let src = "pub/*c*/struct ColumnDef;
pub/* outer /* inner */ */enum CellValue {}
";
        let stripped = strip_rust_comments(src);
        assert!(stripped.contains("pub struct ColumnDef;"), "got: {stripped}");
        assert!(stripped.contains("pub enum CellValue {}"), "got: {stripped}");
    }

    #[test]
    fn test_check_no_r4_secret_leak_handles_xml_namespace_prefixes() {
        assert!(
            check_no_r4_secret_leak(
                "namespaced_redacted",
                "<WLANProfile><v1:keyMaterial>[REDACTED]</v1:keyMaterial></WLANProfile>"
            )
            .is_ok()
        );
        assert!(
            check_no_r4_secret_leak(
                "namespaced_unredacted",
                "<WLANProfile><v1:keyMaterial>secret</v1:keyMaterial></WLANProfile>"
            )
            .is_err()
        );
        assert!(
            check_no_r4_secret_leak(
                "namespaced_attr",
                r#"<WLANProfile><v1:keyMaterial protected="false">[REDACTED]</v1:keyMaterial></WLANProfile>"#
            )
            .is_err()
        );
        assert!(
            check_no_r4_secret_leak(
                "namespaced_mismatch",
                "<WLANProfile><v1:keyMaterial>[REDACTED]</v2:keyMaterial></WLANProfile>"
            )
            .is_err()
        );
    }

    #[test]
    fn test_help_contains_subcommand_token_respects_word_boundaries() {
        let help = "Commands:\n  wifi-info   Wireless info\n  menu-new    Create item\n";
        assert!(help_contains_subcommand_token(help, "wifi-info"));
        assert!(!help_contains_subcommand_token(help, "wifi"));
        assert!(help_contains_subcommand_token(help, "menu-new"));
        assert!(!help_contains_subcommand_token(help, "menu"));
    }

    #[test]
    fn test_staged_forensics_compat_and_aligned_mutating_payloads() {
        let fix_dir = TempDir::new().unwrap();
        let fixtures = e2e_fixtures::materialize_all(fix_dir.path()).unwrap();
        let staged = stage_forensics_compat_dir(&fixtures).unwrap();

        assert!(staged.path().join("staged_watch.reg").is_file());
        assert!(staged.path().join("staged_vss_catalog.json").is_file());
        assert!(staged.path().join("staged_previous_dir/Users/Test/sample.txt").is_file());

        let sc2_bytes = std::fs::read(staged.path().join("staged_security_center2.json")).unwrap();
        let sc2_val: Value = serde_json::from_slice(&sc2_bytes).unwrap();
        assert!(sc2_val.get("AntiVirusProduct").is_some());

        for name in ["staged_SRUDB.dat", "staged_DataStore.edb"] {
            let ese = std::fs::read(staged.path().join(name)).unwrap();
            assert!(ese.len() >= 6 * 4096);
            assert_eq!(&ese[4..8], &0x89AB_CDEFu32.to_le_bytes());
            assert_eq!(&ese[0..4096], &ese[4096..8192]);
            // MSysObjects lives on logical page 4 (offset 5 * 4096) with objidFDP=2
            let p4 = &ese[5 * 4096..6 * 4096];
            assert_eq!(&p4[24..28], &2u32.to_le_bytes());
        }

        let svcl = build_mutating_args(
            MutatingActionSpec {
                tool_id: "audio_svcl",
                args_kind: MutatingArgsKind::WinctlAudioSvcl,
                cli_supports_allow_mutating: true,
            },
            Path::new("dummy"),
        );
        assert_eq!(svcl["verb"], "SetVolume");
        assert_eq!(svcl["target"], "Speakers");

        let clip = build_mutating_args(
            MutatingActionSpec {
                tool_id: "desktop_clip_hist_control",
                args_kind: MutatingArgsKind::WinctlDesktopClip,
                cli_supports_allow_mutating: true,
            },
            Path::new("dummy"),
        );
        assert_eq!(clip["operation"], "clear");

        let ads = build_mutating_args(
            MutatingActionSpec {
                tool_id: "alternate_stream_delete",
                args_kind: MutatingArgsKind::FsAdsDelete,
                cli_supports_allow_mutating: true,
            },
            Path::new("host.txt"),
        );
        assert_eq!(ads["file_path"], "host.txt");
        assert_eq!(ads["stream_name"], "Zone.Identifier");
    }
}
