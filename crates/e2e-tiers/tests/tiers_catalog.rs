use std::collections::BTreeSet;

use e2e_tiers::catalog::{all_items, catalog_checks, feature_groups, validate_catalog_invariants};
use e2e_tiers::{TargetWorkspace, Tier};

#[test]
fn test_catalog_counts_and_floor() {
    validate_catalog_invariants().expect("catalog invariants must hold");
    let checks = catalog_checks();
    assert!(
        checks.len() >= 356,
        "coverage floor is 356, got {}",
        checks.len()
    );
    assert_eq!(checks.len(), 360);
    assert_eq!(feature_groups().len(), 31);
    assert_eq!(all_items().len(), 227);
}

#[test]
fn test_catalog_tier_distribution_and_workspace_coverage() {
    let checks = catalog_checks();
    let t1 = checks.iter().filter(|c| c.tier == Tier::Tier1).count();
    let t2 = checks.iter().filter(|c| c.tier == Tier::Tier2).count();
    let t3 = checks.iter().filter(|c| c.tier == Tier::Tier3).count();
    let t4 = checks.iter().filter(|c| c.tier == Tier::Tier4).count();

    assert_eq!(t1, 155);
    assert_eq!(t2, 155);
    assert_eq!(t3, 34);
    assert_eq!(t4, 16);

    let workspaces: BTreeSet<TargetWorkspace> =
        checks.iter().map(|c| c.primary_workspace).collect();
    for ws in TargetWorkspace::concrete_workspaces() {
        assert!(
            workspaces.contains(ws),
            "workspace {:?} has no primary checks in catalog",
            ws
        );
    }
}
