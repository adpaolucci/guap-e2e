use std::fmt;
use std::path::PathBuf;

use e2e_fixtures::MaterializedFixtures;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    Tier1,
    Tier2,
    Tier3,
    Tier4,
}

impl Tier {
    pub fn all() -> Vec<Tier> {
        vec![Tier::Tier1, Tier::Tier2, Tier::Tier3, Tier::Tier4]
    }

    pub fn number(self) -> u8 {
        match self {
            Tier::Tier1 => 1,
            Tier::Tier2 => 2,
            Tier::Tier3 => 3,
            Tier::Tier4 => 4,
        }
    }

    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "t1" | "tier1" | "tier-1" => Ok(Tier::Tier1),
            "2" | "t2" | "tier2" | "tier-2" => Ok(Tier::Tier2),
            "3" | "t3" | "tier3" | "tier-3" => Ok(Tier::Tier3),
            "4" | "t4" | "tier4" | "tier-4" => Ok(Tier::Tier4),
            other => anyhow::bail!("invalid tier '{other}' (expected 1|2|3|4 or Tier1..Tier4)"),
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Tier1 => f.write_str("Tier1"),
            Tier::Tier2 => f.write_str("Tier2"),
            Tier::Tier3 => f.write_str("Tier3"),
            Tier::Tier4 => f.write_str("Tier4"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TargetWorkspace {
    All,
    GuapKit,
    Forensics2Rust,
    Chrome2Rust,
    Mail2Rust,
    Android2Rust,
    Winctl2Rust,
    Net2Rust,
    Sys2Rust,
    Fs2Rust,
}

impl TargetWorkspace {
    pub fn all_variants() -> &'static [TargetWorkspace] {
        &[
            TargetWorkspace::All,
            TargetWorkspace::GuapKit,
            TargetWorkspace::Forensics2Rust,
            TargetWorkspace::Chrome2Rust,
            TargetWorkspace::Mail2Rust,
            TargetWorkspace::Android2Rust,
            TargetWorkspace::Winctl2Rust,
            TargetWorkspace::Net2Rust,
            TargetWorkspace::Sys2Rust,
            TargetWorkspace::Fs2Rust,
        ]
    }

    pub fn concrete_workspaces() -> &'static [TargetWorkspace] {
        &[
            TargetWorkspace::GuapKit,
            TargetWorkspace::Forensics2Rust,
            TargetWorkspace::Chrome2Rust,
            TargetWorkspace::Mail2Rust,
            TargetWorkspace::Android2Rust,
            TargetWorkspace::Winctl2Rust,
            TargetWorkspace::Net2Rust,
            TargetWorkspace::Sys2Rust,
            TargetWorkspace::Fs2Rust,
        ]
    }

    pub fn domain_suites() -> &'static [TargetWorkspace] {
        &[
            TargetWorkspace::Forensics2Rust,
            TargetWorkspace::Chrome2Rust,
            TargetWorkspace::Mail2Rust,
            TargetWorkspace::Android2Rust,
            TargetWorkspace::Winctl2Rust,
            TargetWorkspace::Net2Rust,
            TargetWorkspace::Sys2Rust,
            TargetWorkspace::Fs2Rust,
        ]
    }

    pub fn dir_name(self) -> &'static str {
        match self {
            TargetWorkspace::All => "all",
            TargetWorkspace::GuapKit => "guap-kit",
            TargetWorkspace::Forensics2Rust => "forensics2rust",
            TargetWorkspace::Chrome2Rust => "chrome2rust",
            TargetWorkspace::Mail2Rust => "mail2rust",
            TargetWorkspace::Android2Rust => "android2rust",
            TargetWorkspace::Winctl2Rust => "winctl2rust",
            TargetWorkspace::Net2Rust => "net2rust",
            TargetWorkspace::Sys2Rust => "sys2rust",
            TargetWorkspace::Fs2Rust => "fs2rust",
        }
    }

    pub fn binary_name(self) -> Option<&'static str> {
        match self {
            TargetWorkspace::All | TargetWorkspace::GuapKit => None,
            TargetWorkspace::Forensics2Rust => Some("forensics2rust"),
            TargetWorkspace::Chrome2Rust => Some("chrome2rust"),
            TargetWorkspace::Mail2Rust => Some("mail2rust"),
            TargetWorkspace::Android2Rust => Some("android2rust"),
            TargetWorkspace::Winctl2Rust => Some("winctl2rust"),
            TargetWorkspace::Net2Rust => Some("net2rust"),
            TargetWorkspace::Sys2Rust => Some("sys2rust"),
            TargetWorkspace::Fs2Rust => Some("fs2rust"),
        }
    }

    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(TargetWorkspace::All),
            "guap-kit" | "guap_kit" | "guapkit" => Ok(TargetWorkspace::GuapKit),
            "forensics2rust" => Ok(TargetWorkspace::Forensics2Rust),
            "chrome2rust" => Ok(TargetWorkspace::Chrome2Rust),
            "mail2rust" => Ok(TargetWorkspace::Mail2Rust),
            "android2rust" => Ok(TargetWorkspace::Android2Rust),
            "winctl2rust" => Ok(TargetWorkspace::Winctl2Rust),
            "net2rust" => Ok(TargetWorkspace::Net2Rust),
            "sys2rust" => Ok(TargetWorkspace::Sys2Rust),
            "fs2rust" => Ok(TargetWorkspace::Fs2Rust),
            other => anyhow::bail!("unknown target workspace '{other}'"),
        }
    }
}

impl fmt::Display for TargetWorkspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.dir_name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierRunConfig {
    pub guap_root: PathBuf,
    pub fixtures: MaterializedFixtures,
    pub target: TargetWorkspace,
    pub tiers: Vec<Tier>,
    pub skip_cargo_build: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub tier: Tier,
    pub workspace: String,
    pub feature_group: String,
    pub passed: bool,
    pub skipped: bool,
    pub message: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<CheckResult>,
}

impl TierReport {
    pub fn from_results(results: Vec<CheckResult>) -> Self {
        let total = results.len();
        let skipped = results.iter().filter(|r| r.skipped).count();
        let passed = results.iter().filter(|r| !r.skipped && r.passed).count();
        let failed = results.iter().filter(|r| !r.skipped && !r.passed).count();
        Self {
            total,
            passed,
            failed,
            skipped,
            results,
        }
    }

    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    pub fn by_tier(&self, tier: Tier) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| r.tier == tier).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureKind {
    Evtx,
    Hive,
    Srum,
    Artifacts,
    Crash,
    Browser,
    Mail,
    Wpd,
    Winctl,
    Net,
    SysFs,
    Corrupt,
}

impl FixtureKind {
    pub fn resolve_dir(self, fixtures: &MaterializedFixtures) -> &std::path::Path {
        match self {
            FixtureKind::Evtx => &fixtures.evtx_dir,
            FixtureKind::Hive => &fixtures.hive_dir,
            FixtureKind::Srum => &fixtures.srum_dir,
            FixtureKind::Artifacts => &fixtures.artifacts_dir,
            FixtureKind::Crash => &fixtures.crash_dir,
            FixtureKind::Browser => &fixtures.browser_dir,
            FixtureKind::Mail => &fixtures.mail_dir,
            FixtureKind::Wpd => &fixtures.wpd_dir,
            FixtureKind::Winctl => &fixtures.winctl_dir,
            FixtureKind::Net => &fixtures.net_dir,
            FixtureKind::SysFs => &fixtures.sys_fs_dir,
            FixtureKind::Corrupt => &fixtures.corrupt_dir,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliInputStyle {
    Positional,
    Flag(&'static str),
    FlagOffline(&'static str),
    FlagOfflineDir(&'static str),
    SourceDirParent,
    OfflineNoFile,
    OmitPath,
    ForensicsDiff,
    FsDataDiff,
    InputFlag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliExportStyle {
    Chrome,
    Mail,
    Android,
    Sys2Rust,
    Forensics,
    Winctl,
    Fs,
    Net,
    Standard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliLiveStyle {
    OmitOffline,
    LiveFlag,
    PositionalNoPath,
    MailLive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpArgsKind {
    EmptyObject,
    Path,
    Source,
    SourcePath,
    ForensicsDiff,
    HiveList,
    SourceDirParent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutatingArgsKind {
    MailNk2Edit,
    AndroidWpdDelete,
    SysProcTerminate,
    SysHwServiceControl,
    SysShellPrivacyClean,
    FsBulkTargets,
    FsAdsDelete,
    WinctlCmdScript,
    WinctlAudioCtl,
    WinctlDisplayDdc,
    WinctlDesktopClip,
    NetOsintSetDns,
    NetRadioWifiSetOrder,
    NetSocketsClose,
    NetLanWol,
    PathGeneric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutatingActionSpec {
    pub tool_id: &'static str,
    pub args_kind: MutatingArgsKind,
    pub cli_supports_allow_mutating: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ItemSpec {
    pub name: &'static str,
    pub group_id: &'static str,
    pub workspace: TargetWorkspace,
    pub cli_tokens: &'static [&'static str],
    pub mcp_tool: &'static str,
    pub fixture_kind: FixtureKind,
    pub fixture_rel: &'static str,
    pub corrupt_rel: Option<&'static str>,
    pub mutating_capable: bool,
    pub cli_input: CliInputStyle,
    pub mcp_args: McpArgsKind,
    pub expects_nonempty_rows: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct FeatureGroupDef {
    pub id: &'static str,
    pub name: &'static str,
    pub workspace: TargetWorkspace,
    pub domain_crate: &'static str,
    pub cli_group: &'static str,
    pub fixture_kind: FixtureKind,
    pub items: &'static [ItemSpec],
    pub mutating_tool_hint: Option<&'static str>,
    pub cli_export: CliExportStyle,
    pub cli_live: CliLiveStyle,
    pub mutating_action: Option<MutatingActionSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    // Tier 1 - GuapKit
    GuapKitCargoBaseline,
    GuapKitCargoTest,
    GuapKitContractScan,
    GuapKitFunctionalA,
    GuapKitFunctionalB,
    // Tier 1 - Domain
    DomainCargoCheckTest,
    DomainCliHelpAllItems,
    DomainMcpToolsAllItems,
    DomainMcpJsonRpcReadOnly,
    DomainCliReadOnlyAllItems,
    // Tier 1 - E2E self-checks (FG-31)
    E2eFixtureIntegrity,
    E2eCatalogCompleteness,
    E2eExportVerifierSelfCheck,
    E2eMcpProtocolSelfCheck,
    E2eHarnessWorkspaceCheck,
    // Tier 2 - GuapKit
    GuapKitBoundary(&'static str),
    // Tier 2 - Domain
    DomainMissingPath,
    DomainCorruptFixture,
    DomainEmptyAndInvalidFlags,
    DomainNonPrivilegedFallback,
    DomainMalformedMcpJsonRpc,
    // Tier 2 - E2E self-checks (FG-31)
    E2eNegativeSelfCheck(&'static str),
    // Tier 3 - Pairwise integrations (T3-01..T3-34)
    Tier3Pairwise(&'static str),
    // Tier 4 - Scenarios (S1..S16)
    Tier4Scenario(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct CatalogCheckDef {
    pub id: &'static str,
    pub tier: Tier,
    pub feature_group_id: &'static str,
    pub feature_group_name: &'static str,
    pub primary_workspace: TargetWorkspace,
    pub required_workspaces: &'static [TargetWorkspace],
    pub summary: &'static str,
    pub kind: CheckKind,
}