use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use e2e_fixtures::{FixtureVerificationReport, MaterializedFixtures, materialize_all, verify_fixture_integrity};
use e2e_r4::{R4Report, R4ScanConfig, run_r4_scan};
use e2e_tiers::{TargetWorkspace, Tier, TierReport, TierRunConfig, catalog, run_tiers};
use serde::Serialize;
use tempfile::TempDir;

fn default_guap_root() -> PathBuf {
    if let Some(root) = std::env::var_os("GUAP_ROOT") {
        return PathBuf::from(root);
    }
    if Path::new("..").join("guap-kit").join("Cargo.toml").is_file() {
        return PathBuf::from("..");
    }
    let manifest_parent = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent);
    if let Some(parent) = manifest_parent
        && parent.join("guap-kit").join("Cargo.toml").is_file()
    {
        return parent.to_path_buf();
    }
    PathBuf::from(".")
}

#[derive(Debug, Parser)]
#[command(
    name = "guap-e2e",
    version,
    about = "Opaque-box E2E and R4 compliance runner for GUAP Rust production suites"
)]
struct CliArgs {
    /// Tier(s) to run (1, 2, 3, or 4). May be repeated.
    #[arg(long = "tier", value_name = "1|2|3|4")]
    tiers: Vec<String>,

    /// Run automated R4 exclusion and prohibition scanner across guap-root.
    #[arg(long = "r4-check")]
    r4_check: bool,

    /// Run all 4 E2E tiers (combine with --r4-check to run full M6 gate).
    #[arg(long = "all")]
    all: bool,

    /// Target workspace filter (all|guap-kit|forensics2rust|chrome2rust|mail2rust|android2rust|winctl2rust|net2rust|sys2rust|fs2rust).
    #[arg(long = "target", default_value = "all")]
    target: String,

    /// Root GUAP directory containing the 9 Cargo workspaces (defaults to $GUAP_ROOT or sibling workspace root).
    #[arg(long = "guap-root")]
    guap_root: Option<PathBuf>,

    /// Optional directory to materialize deterministic fixtures into (uses TempDir when omitted).
    #[arg(long = "fixtures-dir")]
    fixtures_dir: Option<PathBuf>,

    /// Reuse existing target/debug binaries without invoking `cargo build`.
    #[arg(long = "skip-cargo-build")]
    skip_cargo_build: bool,

    /// Emit machine-readable JSON output.
    #[arg(long = "json")]
    json: bool,

    /// Optional path to write a formatted TEST_READY.md report.
    #[arg(long = "write-test-ready")]
    write_test_ready: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPlan {
    run_tiers: bool,
    tiers: Vec<Tier>,
    run_r4: bool,
    target: TargetWorkspace,
    guap_root: PathBuf,
    fixtures_dir: Option<PathBuf>,
    skip_cargo_build: bool,
    json: bool,
    write_test_ready: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct UnifiedE2eReport {
    schema_version: u32,
    generated_at: String,
    guap_root: String,
    target: String,
    overall_passed: bool,
    catalog_feature_groups: usize,
    catalog_items: usize,
    fixture_verification: Option<FixtureVerificationReport>,
    tier_report: Option<TierReport>,
    r4_report: Option<R4Report>,
}

fn resolve_plan(args: CliArgs) -> Result<ResolvedPlan> {
    let target = TargetWorkspace::parse(&args.target)?;
    let mut parsed_tiers = Vec::new();
    let mut seen = BTreeSet::new();

    for raw in &args.tiers {
        let tier = Tier::parse(raw)?;
        if seen.insert(tier) {
            parsed_tiers.push(tier);
        }
    }

    let explicit_mode = args.all || !args.tiers.is_empty() || args.r4_check;
    let run_tiers_flag = args.all || !args.tiers.is_empty() || !explicit_mode;
    let run_r4_flag = args.r4_check || !explicit_mode;

    let tiers = if args.all || !explicit_mode || parsed_tiers.is_empty() {
        Tier::all()
    } else {
        parsed_tiers
    };

    Ok(ResolvedPlan {
        run_tiers: run_tiers_flag,
        tiers,
        run_r4: run_r4_flag,
        target,
        guap_root: args.guap_root.unwrap_or_else(default_guap_root),
        fixtures_dir: args.fixtures_dir,
        skip_cargo_build: args.skip_cargo_build,
        json: args.json,
        write_test_ready: args.write_test_ready,
    })
}

fn prepare_fixtures(fixtures_dir: Option<&Path>) -> Result<(Option<TempDir>, MaterializedFixtures, FixtureVerificationReport)> {
    let (temp_guard, root_dir) = if let Some(dir) = fixtures_dir {
        (None, dir.to_path_buf())
    } else {
        let td = TempDir::new().context("creating temporary fixtures directory")?;
        let p = td.path().to_path_buf();
        (Some(td), p)
    };

    let fixtures = materialize_all(&root_dir)
        .with_context(|| format!("materializing synthetic fixtures under {}", root_dir.display()))?;
    let verification = verify_fixture_integrity(&fixtures)
        .context("verifying materialized synthetic fixtures")?;
    if !verification.all_verified() {
        bail!(
            "fixture integrity verification incomplete ({}/{})",
            verification.verified_files,
            verification.total_files
        );
    }

    Ok((temp_guard, fixtures, verification))
}

fn is_overall_passed(
    target: TargetWorkspace,
    fixture_verif: Option<&FixtureVerificationReport>,
    tier_report: Option<&TierReport>,
    r4_report: Option<&R4Report>,
) -> bool {
    let fixtures_ok = fixture_verif.is_none_or(FixtureVerificationReport::all_verified);
    let tiers_ok = tier_report.is_none_or(|tr| {
        tr.all_passed() && (target != TargetWorkspace::All || tr.skipped == 0)
    });
    let r4_ok = r4_report.is_none_or(|r4| r4.passed);
    fixtures_ok && tiers_ok && r4_ok
}

fn format_human_summary(report: &UnifiedE2eReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "guap-e2e report (target={}, guap_root={}, overall_passed={})\n",
        report.target, report.guap_root, report.overall_passed
    ));

    if let Some(fv) = &report.fixture_verification {
        out.push_str(&format!(
            "  Fixtures: {}/{} verified\n",
            fv.verified_files, fv.total_files
        ));
    }

    if let Some(tr) = &report.tier_report {
        out.push_str(&format!(
            "  Tiers: total={}, passed={}, failed={}, skipped={}\n",
            tr.total, tr.passed, tr.failed, tr.skipped
        ));
        for tier in Tier::all() {
            let subset = tr.by_tier(tier);
            if subset.is_empty() {
                continue;
            }
            let p = subset.iter().filter(|r| !r.skipped && r.passed).count();
            let f = subset.iter().filter(|r| !r.skipped && !r.passed).count();
            let s = subset.iter().filter(|r| r.skipped).count();
            out.push_str(&format!(
                "    {tier}: {p}/{} passed (failed={f}, skipped={s})\n",
                subset.len()
            ));
        }
        for res in tr.results.iter().filter(|r| !r.passed && !r.skipped) {
            out.push_str(&format!(
                "    [FAIL] {} ({}/{}): {}\n",
                res.id, res.workspace, res.feature_group, res.message
            ));
        }
        for res in tr.results.iter().filter(|r| r.skipped) {
            out.push_str(&format!(
                "    [SKIP] {} ({}/{}): {}\n",
                res.id, res.workspace, res.feature_group, res.message
            ));
        }
    }

    if let Some(r4) = &report.r4_report {
        out.push_str(&format!(
            "  R4 Scan: passed={}, files_scanned={}, crates_scanned={}, violations={}\n",
            r4.passed,
            r4.files_scanned,
            r4.crates_scanned,
            r4.violations.len()
        ));
        for v in &r4.violations {
            out.push_str(&format!(
                "    [R4 {}] {}:{:?} ({}): {}\n",
                v.rule_id,
                v.path.display(),
                v.line,
                v.matched_symbol,
                v.detail
            ));
        }
    }

    out
}

fn format_test_ready_markdown(report: &UnifiedE2eReport) -> String {
    let mut md = String::new();
    let status = if report.overall_passed { "PASS (M6 GATE GREEN)" } else { "FAIL" };
    md.push_str("# TEST_READY — GUAP Rust Production Suites (Phases 0–4)\n\n");
    md.push_str(&format!("- **Status**: {status}\n"));
    md.push_str(&format!("- **Generated At**: `{}`\n", report.generated_at));
    md.push_str(&format!("- **Target Workspace Filter**: `{}`\n", report.target));
    md.push_str(&format!("- **GUAP Root**: `{}`\n", report.guap_root));
    md.push_str(&format!(
        "- **Catalog Coverage Target**: `{}` feature groups, `{}` discrete items\n\n",
        report.catalog_feature_groups, report.catalog_items
    ));

    if let Some(fv) = &report.fixture_verification {
        md.push_str("## Synthetic Fixtures\n\n");
        md.push_str(&format!(
            "- Materialized & SHA-256 verified files: **`{} / {}`**\n",
            fv.verified_files, fv.total_files
        ));
        for detail in &fv.details {
            md.push_str(&format!("- {detail}\n"));
        }
        md.push('\n');
    }

    if let Some(tr) = &report.tier_report {
        md.push_str("## 4-Tier Opaque-Box E2E Verification\n\n");
        md.push_str(&format!(
            "- **Totals**: `{}` passed / `{}` total (`{}` failed, `{}` skipped)\n\n",
            tr.passed, tr.total, tr.failed, tr.skipped
        ));
        md.push_str("| Tier | Total | Passed | Failed | Skipped |\n");
        md.push_str("|---|---:|---:|---:|---:|\n");
        for tier in Tier::all() {
            let subset = tr.by_tier(tier);
            if subset.is_empty() {
                continue;
            }
            let p = subset.iter().filter(|r| !r.skipped && r.passed).count();
            let f = subset.iter().filter(|r| !r.skipped && !r.passed).count();
            let s = subset.iter().filter(|r| r.skipped).count();
            md.push_str(&format!("| {tier} | {} | {p} | {f} | {s} |\n", subset.len()));
        }
        md.push('\n');

        let mut by_ws: BTreeMap<&str, (usize, usize, usize, usize)> = BTreeMap::new();
        for res in &tr.results {
            let entry = by_ws.entry(res.workspace.as_str()).or_insert((0, 0, 0, 0));
            entry.0 += 1;
            if res.skipped {
                entry.3 += 1;
            } else if res.passed {
                entry.1 += 1;
            } else {
                entry.2 += 1;
            }
        }
        md.push_str("### Breakdown by Workspace\n\n");
        md.push_str("| Workspace | Checks | Passed | Failed | Skipped |\n");
        md.push_str("|---|---:|---:|---:|---:|\n");
        for (ws, (tot, p, f, s)) in by_ws {
            md.push_str(&format!("| `{ws}` | {tot} | {p} | {f} | {s} |\n"));
        }
        md.push('\n');
    }

    if let Some(r4) = &report.r4_report {
        md.push_str("## Automated R4 Exclusion & Prohibition Compliance\n\n");
        md.push_str(&format!("- **Result**: `{}`\n", if r4.passed { "PASS (0 violations)" } else { "FAIL" }));
        md.push_str(&format!("- **Files Scanned** (source + binaries): `{}`\n", r4.files_scanned));
        md.push_str(&format!("- **Crates Scanned**: `{}`\n", r4.crates_scanned));
        md.push_str(&format!("- **Violations**: `{}`\n", r4.violations.len()));
        if !r4.baseline_notes.is_empty() {
            md.push_str("- **Baseline Notes**:\n");
            for note in &r4.baseline_notes {
                md.push_str(&format!("  - {note}\n"));
            }
        }
        md.push('\n');
    }

    md
}

fn execute_plan(plan: &ResolvedPlan) -> Result<UnifiedE2eReport> {
    let mut _temp_guard: Option<TempDir> = None;
    let (fixture_verification, tier_report) = if plan.run_tiers {
        let (guard, fixtures, verification) = prepare_fixtures(plan.fixtures_dir.as_deref())?;
        _temp_guard = guard;
        let report = run_tiers(&TierRunConfig {
            guap_root: plan.guap_root.clone(),
            fixtures,
            target: plan.target,
            tiers: plan.tiers.clone(),
            skip_cargo_build: plan.skip_cargo_build,
        })?;
        (Some(verification), Some(report))
    } else {
        (None, None)
    };

    let r4_report = if plan.run_r4 {
        Some(run_r4_scan(&R4ScanConfig {
            guap_root: plan.guap_root.clone(),
            scan_binaries: true,
            scan_cli_mcp: true,
        })?)
    } else {
        None
    };

    let overall_passed = is_overall_passed(
        plan.target,
        fixture_verification.as_ref(),
        tier_report.as_ref(),
        r4_report.as_ref(),
    );
    let groups = catalog::feature_groups();
    let total_items: usize = groups.iter().map(|g| g.items.len()).sum();

    Ok(UnifiedE2eReport {
        schema_version: 1,
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        guap_root: plan.guap_root.display().to_string(),
        target: plan.target.to_string(),
        overall_passed,
        catalog_feature_groups: groups.len(),
        catalog_items: total_items,
        fixture_verification,
        tier_report,
        r4_report,
    })
}

fn main() -> ExitCode {
    let args = CliArgs::parse();
    let plan = match resolve_plan(args) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("error: {err:#}");
            return ExitCode::from(2);
        }
    };

    let report = match execute_plan(&plan) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("error: {err:#}");
            return ExitCode::from(1);
        }
    };

    if let Some(md_path) = &plan.write_test_ready {
        if let Some(parent) = md_path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(err) = std::fs::create_dir_all(parent)
        {
            eprintln!("error creating parent dir for {}: {err}", md_path.display());
            return ExitCode::from(1);
        }
        let md = format_test_ready_markdown(&report);
        if let Err(err) = std::fs::write(md_path, md) {
            eprintln!("error writing {}: {err}", md_path.display());
            return ExitCode::from(1);
        }
    }

    if plan.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing report: {err}");
                return ExitCode::from(1);
            }
        }
    } else {
        print!("{}", format_human_summary(&report));
    }

    if report.overall_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2e_tiers::CheckResult;

    #[test]
    fn cli_parses_all_flags_and_target_net2rust() {
        let args = CliArgs::try_parse_from([
            "guap-e2e",
            "--all",
            "--r4-check",
            "--target",
            "net2rust",
            "--skip-cargo-build",
            "--json",
        ])
        .unwrap();
        let plan = resolve_plan(args).unwrap();
        assert!(plan.run_tiers);
        assert!(plan.run_r4);
        assert_eq!(plan.tiers, Tier::all());
        assert_eq!(plan.target, TargetWorkspace::Net2Rust);
        assert!(plan.skip_cargo_build);
        assert!(plan.json);
    }

    #[test]
    fn cli_parses_specific_tiers_without_r4() {
        let args = CliArgs::try_parse_from(["guap-e2e", "--tier", "1", "--tier", "3"]).unwrap();
        let plan = resolve_plan(args).unwrap();
        assert!(plan.run_tiers);
        assert!(!plan.run_r4);
        assert_eq!(plan.tiers, vec![Tier::Tier1, Tier::Tier3]);
        assert_eq!(plan.target, TargetWorkspace::All);
    }

    #[test]
    fn cli_parses_r4_only_without_tiers() {
        let args = CliArgs::try_parse_from(["guap-e2e", "--r4-check", "--json"]).unwrap();
        let plan = resolve_plan(args).unwrap();
        assert!(!plan.run_tiers);
        assert!(plan.run_r4);
        assert!(plan.json);
    }

    #[test]
    fn cli_default_runs_all_tiers_and_r4() {
        let args = CliArgs::try_parse_from(["guap-e2e"]).unwrap();
        let plan = resolve_plan(args).unwrap();
        assert!(plan.run_tiers);
        assert!(plan.run_r4);
        assert_eq!(plan.tiers, Tier::all());
    }

    #[test]
    fn cli_rejects_invalid_tier() {
        let args = CliArgs::try_parse_from(["guap-e2e", "--tier", "9"]).unwrap();
        assert!(resolve_plan(args).is_err());
    }

    #[test]
    fn report_gate_requires_zero_skips_for_all_target() {
        let skipped = TierReport::from_results(vec![CheckResult {
            id: "T1-NET-01".into(),
            tier: Tier::Tier1,
            workspace: "net2rust".into(),
            feature_group: "net2rust -sockets".into(),
            passed: false,
            skipped: true,
            message: "missing bin".into(),
            duration_ms: 1,
        }]);
        assert!(!is_overall_passed(TargetWorkspace::All, None, Some(&skipped), None));

        let passed = TierReport::from_results(vec![CheckResult {
            id: "T1-NET-01".into(),
            tier: Tier::Tier1,
            workspace: "net2rust".into(),
            feature_group: "net2rust -sockets".into(),
            passed: true,
            skipped: false,
            message: "ok".into(),
            duration_ms: 2,
        }]);
        let r4_ok = R4Report {
            passed: true,
            files_scanned: 100,
            crates_scanned: 10,
            violations: vec![],
            baseline_notes: vec!["note".into()],
        };
        let report = UnifiedE2eReport {
            schema_version: 1,
            generated_at: "2026-11-26T00:00:00Z".into(),
            guap_root: default_guap_root().display().to_string(),
            target: "all".into(),
            overall_passed: is_overall_passed(TargetWorkspace::All, None, Some(&passed), Some(&r4_ok)),
            catalog_feature_groups: 31,
            catalog_items: 227,
            fixture_verification: None,
            tier_report: Some(passed),
            r4_report: Some(r4_ok),
        };
        assert!(report.overall_passed);
        let summary = format_human_summary(&report);
        assert!(summary.contains("overall_passed=true"));
        let md = format_test_ready_markdown(&report);
        assert!(md.contains("PASS (M6 GATE GREEN)"));
        assert!(md.contains("`net2rust`"));
    }
}
