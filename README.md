# `guap-e2e` — Unified 4-Tier E2E Test Harness, Synthetic Fixtures & R4 Compliance Scanner

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Ecosystem Hub: https://guap.ca**](https://guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/guap-e2e/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Workspace: 4 Crates](https://img.shields.io/badge/Workspace-4%20Crates-emerald.svg)](Cargo.toml)
[![Verification Gate: 360/360 Checks](https://img.shields.io/badge/M6%20Gate-360%2F360%20Passed-brightgreen.svg)](crates/e2e-tiers/src/catalog.rs)

**`guap-e2e`** is the standalone cross-workspace verification harness for the GUAP NirSoft-to-Rust production suites (`guap-kit`, `forensics2rust`, `chrome2rust`, `mail2rust`, `android2rust`, `winctl2rust`, `net2rust`, `sys2rust`, and `fs2rust`). It deterministically materializes **79 valid and corrupt binary fixtures**, executes **360 opaque-box checks across Tiers 1–4** spanning **31 feature groups** and **227 cataloged items**, runs a **52-rule automated R4 exclusion/security scanner** across source trees, Rust ASTs, compiled PE binaries, CLIs, and MCP servers, and emits signed verification artifacts (`TEST_READY.md` & JSON reports).

---

## Workspace Architecture (4 Crates)

```text
guap-e2e/
├── Cargo.toml                  # 4-crate workspace (`e2e-fixtures`, `e2e-tiers`, `e2e-r4`, `e2e-runner`)
├── .cargo/config.toml          # 16 MiB stack link args for Windows builds
├── LICENSE                     # Apache-2.0 License
└── crates/
    ├── e2e-fixtures/           # Materializes & SHA-256/structurally verifies 79 deterministic fixtures
    ├── e2e-tiers/              # 360-check 4-tier runner, MCP JSON-RPC client, RFC-4180/Merkle verifiers & mock-guap-suite
    ├── e2e-r4/                 # 52-rule R4 compliance scanner (FS, AST, ASCII/UTF-16LE binaries, CLI & MCP probes)
    └── e2e-runner/             # Unified `guap-e2e` CLI binary & TEST_READY.md gate generator
```

---

## 79 Synthetic Fixtures (`e2e-fixtures`)

Every fixture is generated deterministically in code with valid checksums, magic headers, and **zero real credentials** (`65` positive + `14` negative/corrupt fixtures):

- **EVTX (`evtx/`)**: 9 `.evtx` files (`Security.evtx`, `System.evtx`, WLAN-AutoConfig, Windows Defender, TerminalServices LSM & RCM, PowerShell, TaskScheduler, Kernel-PnP)
- **Registry Hives (`hive/`)**: 4 valid `regf`/`hbin` hives (`NTUSER.DAT`, `UsrClass.dat`, `SYSTEM`, `SOFTWARE`)
- **ESE Databases (`srum/`)**: 2 valid `0x89ABCDEF` ESE databases (`SRUDB.dat` with ECC+XOR pages, `DataStore.edb`)
- **Windows Artifacts (`artifacts/`)**: Uncompressed `SCCA v30` Prefetch, compressed `MAM\x04` Prefetch, `[MS-SHLLINK]` `.lnk`, `CFBF` + `DestList v4` `.automaticDestinations-ms`, `setupapi.dev.log`
- **Crash & Posture (`crash/`)**: `MDMP` 4-stream `memory.dmp`, UTF-16LE `Report.wer`, `CBS.log`, `wmi_posture.json`
- **Browser & Media (`browser/`)**: EXIF `II*\0` JPEG, `fMP4`/`m4s` segments, Firefox `cache2`/`places.sqlite`/`cookies.sqlite`/`formhistory.sqlite`/`.jsonlz4`, Safari `Cache.db`/`History.db`/`Bookmarks.plist`, Opera `dcache4.url`/SimpleCache
- **Mail, WPD, Winctl & Net (`mail/`, `wpd/`, `winctl/`, `net/`)**: `outlook.NK2`, MS-CFB `sample_attachment.msg`, EML, `wpd_device_tree.json`, 256B VESA EDID 1.4 + CEA-861, NirCmd/AdvancedRun/Audio mocks, 13-packet IPv4+L4 checksummed PCAP, 802.11 RadioTap beacon PCAP, WLAN/BLE mock JSON
- **PE/.NET & Filesystem (`sys_fs/`)**: PE32 DLL with exports & 3-level `.rsrc`, PE32+ `.NET` EXE (`BSJB` `#~`), `usnjrnl_j.bin` (`USN_RECORD_V2`), mod-256 checksummed ATA SMART `.bin`, CSV/TSV/HTML/VCF/JSONL vectors (including formula-injection probes)
- **Negative / Corrupt (`corrupt_dir/`)**: 14 malformed/truncated SQLite, NK2, `.jsonlz4`, `.plist`, PE, EDID, PCAP, EXIF, ATA SMART, and `$UsnJrnl` binaries

---

## 4-Tier 360-Check Matrix (`e2e-tiers`)

| Tier | Checks | Scope Across 31 Feature Groups (227 Items) |
|---|---:|---|
| **Tier 1** | 155 | `cargo check`/`test` per domain crate, CLI `--help` discovery for all items, `mcp --tools` JSON Schema & annotations, live MCP `2024-11-05` `tools/call`, CLI JSON fixtures |
| **Tier 2** | 155 | Missing paths without panic or clap exit-2, corrupt/truncated fixtures, 0-byte input + invalid `--filter`/`--sort` + invalid flags, non-privileged/missing-hw fallbacks, malformed MCP (`-32700`, `-32602`, `-32601`) |
| **Tier 3** | 34 | Pairwise CSV RFC-4180 formula neutralization, SHA-256/512 Merkle `CustodyManifest` verification, MCP `ReadOnlyOnly` `-32003` gates, R4 Wi-Fi `<keyMaterial>` redaction checks |
| **Tier 4** | 16 | End-to-end scenarios `T4-S01`..`T4-S16`, including multi-workspace correlations (`Mail2Rust`+`Chrome2Rust`, `Sys2Rust`+`Fs2Rust`) and `ComCtl v6` manifest validation across all 8 `-win32` crates |

---

## Automated 52-Rule R4 Compliance Scanner (`e2e-r4`)

Scans all GUAP repositories across 5 surfaces and fails closed on any prohibited pattern:
- **Credentials & Plaintext Keys (`R4-CRED-01..02`, `R4-API-CRED-01..06`)**: Blocks `cred2rust`, password/secret dumping, `CryptUnprotectData`, `VaultEnumerateItems`, `CredEnumerateW`, `LsaRetrievePrivateData`, `WLAN_PROFILE_GET_PLAINTEXT_KEY` (`0x0000_0004`), and unredacted `<keyMaterial>`.
- **Injection & Hooking (`R4-INJ-01..04`)**: Blocks `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, external-DLL `SetWindowsHookExW`, Detours/minhook/IAT patching, and `RunAsDate`.
- **Retired Legacy Tools (`R4-LEGACY-01..39`)**: Verifies zero overlap with the 39 retired legacy NirSoft utilities.
- **5 Inspection Surfaces**: Filesystem & Cargo dependencies (`surface_fs`), `syn` Rust AST taint analysis (`rust_ast`), compiled PE/DLL `ASCII` + `UTF-16LE` string scans (`surface_bin`), CLI subcommand probing, and MCP tool schema/callout probing (`surface_cli_mcp`), while documenting pre-existing classification-only `R4-BASELINE-CHROME` files.

---

## `guap-e2e` CLI Usage

When checked out alongside the sibling GUAP repositories (`../guap-kit`, `../forensics2rust`, etc.), `guap-e2e` auto-detects the workspace root (override anytime via `--guap-root <PATH>` or `GUAP_ROOT`):

```powershell
# Run the full 360-check Tier 1-4 gate + 52-rule R4 compliance scan & write TEST_READY.md
cargo run --offline --bin guap-e2e -- --all --r4-check --write-test-ready TEST_READY.md

# Scope tiers and R4 check to a single workspace, emitting machine-readable JSON
cargo run --offline --bin guap-e2e -- --tier 1 --tier 3 --target net2rust --json

# Run only R4 compliance across the sibling workspace root
cargo run --offline --bin guap-e2e -- --r4-check --guap-root .. --json
```

---

## Building & Testing `guap-e2e`

```powershell
# Fast harness unit & mock tests (deterministic, offline)
cargo check --offline --workspace --tests
cargo test --offline -p e2e-fixtures -p e2e-runner
cargo test --offline -p e2e-tiers --test tiers_catalog --test tiers_mock_e2e
cargo test --offline -p e2e-r4 -- --skip live_guap_workspace_compliance_scan

# Live cross-workspace E2E & compliance tests (when all 9 sibling workspaces exist)
cargo test --offline --workspace
```

---

## Wiki Documentation

Explore the full [`guap-e2e` Project Wiki](https://github.com/adpaolucci/guap-e2e/wiki):
- [Architecture](https://github.com/adpaolucci/guap-e2e/wiki/Architecture)
- [Synthetic Fixtures (79 Catalog)](https://github.com/adpaolucci/guap-e2e/wiki/Synthetic-Fixtures-79-Catalog)
- [Four-Tier 360-Check Matrix](https://github.com/adpaolucci/guap-e2e/wiki/Four-Tier-360-Check-Matrix)
- [R4 Compliance Scanner (52 Rules)](https://github.com/adpaolucci/guap-e2e/wiki/R4-Compliance-Scanner-52-Rules)
- [CLI Reference & `TEST_READY.md` Gate](https://github.com/adpaolucci/guap-e2e/wiki/CLI-Reference-and-TEST-READY-Gate)
- [Building, Testing & CI/CD](https://github.com/adpaolucci/guap-e2e/wiki/Building-Testing-and-CI-CD)

## License

Licensed under the [**Apache License, Version 2.0**](LICENSE).
