pub mod catalog;
pub mod export_verify;
pub mod mcp_client;
pub mod model;
pub mod runner;
pub mod workspace;

pub use model::{
    CatalogCheckDef, CheckKind, CheckResult, CliExportStyle, CliInputStyle, CliLiveStyle,
    FeatureGroupDef, FixtureKind, ItemSpec, McpArgsKind, MutatingActionSpec, MutatingArgsKind,
    TargetWorkspace, Tier, TierReport, TierRunConfig,
};
pub use runner::run_tiers;
