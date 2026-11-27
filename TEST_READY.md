# TEST_READY — GUAP Rust Production Suites (Phases 0–4)

- **Status**: PASS (M6 GATE GREEN)
- **Generated At**: `2026-11-27T15:45:21Z`
- **Target Workspace Filter**: `all`
- **GUAP Root**: `..`
- **Catalog Coverage Target**: `31` feature groups, `227` discrete items

## Synthetic Fixtures

- Materialized & SHA-256 verified files: **`79 / 79`**
- evtx/Security.evtx: 3 events verified
- evtx/System.evtx: 3 events verified
- evtx/Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx: 1 events verified
- evtx/Microsoft-Windows-Windows Defender%4Operational.evtx: 1 events verified
- evtx/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx: 1 events verified
- evtx/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx: 1 events verified
- evtx/Microsoft-Windows-PowerShell%4Operational.evtx: 1 events verified
- evtx/Microsoft-Windows-TaskScheduler%4Operational.evtx: 1 events verified
- evtx/Microsoft-Windows-Kernel-PnP%4Configuration.evtx: 1 events verified
- hive/NTUSER.DAT: 45 cells verified
- hive/UsrClass.dat: 33 cells verified
- hive/SYSTEM: 19 cells verified
- hive/SOFTWARE: 21 cells verified
- srum/SRUDB.dat: 6 data pages verified (ECC+XOR OK)
- srum/DataStore.edb: 4 data pages verified (ECC+XOR OK)
- artifacts/DEMO_UNCOMPRESSED-1234ABCD.pf: SCCA v30 verified
- artifacts/DEMO_COMPRESSED-5678EF01.pf: MAM\x04 -> 978B SCCA verified
- artifacts/ForensicsSample.lnk: MS-SHLLINK verified
- artifacts/1b4dd67f29cb1962.automaticDestinations-ms: CFBF + DestList v4 + LNK verified
- artifacts/setupapi.dev.log: verified
- crash/memory.dmp: MDMP 4 streams verified
- crash/Report.wer: UTF-16LE APPCRASH verified
- crash/CBS.log: verified
- crash/wmi_posture.json: verified
- browser/media/sample_exif.jpg: EXIF APP1 + II*\0 verified
- browser/media/sample_fmp4.mp4: boxes ["ftyp", "moof", "mdat"] verified
- browser/media/sample_segment.m4s: boxes ["styp", "moof", "mdat"] verified
- browser/firefox/cache2: 2 entries verified
- browser/firefox/*.sqlite: integrity + rows verified
- browser/firefox/jsonlz4+addons: verified
- browser/safari: plists + Cache.db + History.db verified
- browser/opera: dcache4.url + opr00001.tmp + SimpleCache verified
- mail/outlook.NK2: 0x0D0A04BA 2 rows verified
- mail/sample_attachment.msg: MS-CFB + MiniStream + RB-tree verified
- mail/sample_attachment.eml: MIME verified
- wpd/wpd_device_tree.json: 2 objects verified
- winctl/monitor_edid.bin: 256B EDID 1.4 + CEA-861 checksums verified
- winctl/cmd_script.gcl: verified
- winctl/advanced_run_profile.json: verified
- winctl/audio_mccs_mock.json: verified
- net/capture_ethernet.pcap: 13 packets (IPv4+L4 checksums OK)
- net/capture_wifi_80211.pcap: LINKTYPE_IEEE802_11 beacon verified
- net/wlan_ble_mock.json: verified
- sys_fs/sample_pe32.dll: PE32 + 3 exports + 3-level .rsrc verified
- sys_fs/sample_pe64_dotnet.exe: PE32+ + CLR + BSJB + #~ verified
- sys_fs/usnjrnl_j.bin: 3 USN_RECORD_V2 verified
- sys_fs/ata_smart*.bin: 512B mod-256 checksums verified
- sys_fs/* (csv/tsv/html/vcf/jsonl): 6 data files verified
- corrupt_dir: all 14 negative fixtures verified
- R4 zero-credential scan: 65 valid fixture files clean

## 4-Tier Opaque-Box E2E Verification

- **Totals**: `360` passed / `360` total (`0` failed, `0` skipped)

| Tier | Total | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| Tier1 | 155 | 155 | 0 | 0 |
| Tier2 | 155 | 155 | 0 | 0 |
| Tier3 | 34 | 34 | 0 | 0 |
| Tier4 | 16 | 16 | 0 | 0 |

### Breakdown by Workspace

| Workspace | Checks | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| `all` | 10 | 10 | 0 | 0 |
| `android2rust` | 12 | 12 | 0 | 0 |
| `chrome2rust` | 13 | 13 | 0 | 0 |
| `forensics2rust` | 70 | 70 | 0 | 0 |
| `fs2rust` | 34 | 34 | 0 | 0 |
| `guap-kit` | 59 | 59 | 0 | 0 |
| `mail2rust` | 12 | 12 | 0 | 0 |
| `net2rust` | 58 | 58 | 0 | 0 |
| `sys2rust` | 46 | 46 | 0 | 0 |
| `winctl2rust` | 46 | 46 | 0 | 0 |

## Automated R4 Exclusion & Prohibition Compliance

- **Result**: `PASS (0 violations)`
- **Files Scanned** (source + binaries): `1665`
- **Crates Scanned**: `200`
- **Violations**: `0`
- **Baseline Notes**:
  - R4-BASELINE-CHROME: pre-existing baseline file present: ..\chrome2rust\crates/chrome2rust-forensics/src/logins.rs
  - R4-BASELINE-CHROME: pre-existing baseline file verified DPAPI classification-only (CryptUnprotectData=false, dpapi_decrypted=false): ..\chrome2rust\crates/chrome2rust-core/src/crypto.rs

