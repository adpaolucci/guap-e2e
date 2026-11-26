# guap-e2e

Unified 4-tier opaque-box E2E test harness, deterministic synthetic fixture generator, and automated R4 exclusion/compliance scanner for the GUAP NirSoft-to-Rust production suites.

## Workspace Crates

- `e2e-fixtures`: Materializes and SHA-256/structure-verifies 79 deterministic valid and corrupt binary fixtures (EVTX, Registry hives, ESE SRUDB/DataStore, Prefetch, LNK, JumpLists, MDMP, WER, browser caches/SQLite/plists, NK2/MSG/EML, EDID, PCAP/PCAPNG, PE32/PE32+/.NET, `$UsnJrnl`, ATA SMART) with zero plaintext credentials.
- `e2e-tiers`: Runs 360 cataloged checks across 31 feature groups and 227 items spanning Tier 1 (build, `--help`, `mcp --tools`, JSON-RPC `2024-11-05`, CLI JSON), Tier 2 (negative paths, corrupt fixtures, non-privileged fallback, malformed MCP), Tier 3 (pairwise export/Merkle custody & `-32003` safety gates), and Tier 4 (cross-suite E2E scenarios).
- `e2e-r4`: AST, source, filesystem, binary (`ASCII` + `UTF-16LE`), CLI, and MCP compliance scanner enforcing zero credential recovery, zero DLL/API injection, and zero overlap with retired legacy tools.
- `e2e-runner`: Provides the `guap-e2e` CLI binary and `TEST_READY.md` gate writer.

## Usage

Run from inside `guap-e2e` (auto-detecting `GUAP_ROOT` or `..` when checked out alongside the sibling GUAP repositories):

```sh
cargo run --offline --bin guap-e2e -- --all --r4-check --write-test-ready TEST_READY.md
```

Override the workspace root explicitly with `--guap-root <PATH>` or `GUAP_ROOT`.
