pub mod rules;
pub mod rust_ast;
pub mod surface_bin;
pub mod surface_cli_mcp;
pub mod surface_fs;

use std::collections::HashSet;
use std::path::PathBuf;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::rules::RuleRegistry;
use crate::surface_bin::scan_binaries;
use crate::surface_cli_mcp::scan_cli_and_mcp;
use crate::surface_fs::scan_fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R4ScanConfig {
    pub guap_root: PathBuf,
    pub scan_binaries: bool,
    pub scan_cli_mcp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R4Violation {
    pub category: String,
    pub rule_id: String,
    pub path: PathBuf,
    pub line: Option<usize>,
    pub matched_symbol: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R4Report {
    pub passed: bool,
    pub files_scanned: usize,
    pub crates_scanned: usize,
    pub violations: Vec<R4Violation>,
    pub baseline_notes: Vec<String>,
}

pub fn run_r4_scan(cfg: &R4ScanConfig) -> Result<R4Report> {
    ensure!(
        cfg.guap_root.is_dir(),
        "guap_root does not exist or is not a directory: {}",
        cfg.guap_root.display()
    );

    let registry = RuleRegistry::compile()?;
    let fs_stats = scan_fs(&cfg.guap_root, &registry)?;

    let mut files_scanned = fs_stats.files_scanned;
    let crates_scanned = fs_stats.crates_scanned;
    let mut violations = fs_stats.violations;
    let baseline_notes = fs_stats.baseline_notes;

    if cfg.scan_binaries {
        scan_binaries(&cfg.guap_root, &registry, &mut files_scanned, &mut violations)?;
    }

    if cfg.scan_cli_mcp {
        scan_cli_and_mcp(&cfg.guap_root, &registry, &mut violations)?;
    }

    // Deduplicate identical violations while preserving deterministic order
    let mut seen = HashSet::new();
    violations.retain(|v| {
        seen.insert((
            v.rule_id.clone(),
            v.path.clone(),
            v.line,
            v.matched_symbol.clone(),
        ))
    });
    violations.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.matched_symbol.cmp(&b.matched_symbol))
    });

    let passed = violations.is_empty();
    Ok(R4Report {
        passed,
        files_scanned,
        crates_scanned,
        violations,
        baseline_notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    fn write_file(base: &Path, rel: &str, content: &str) {
        let p = base.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    fn write_bytes(base: &Path, rel: &str, bytes: &[u8]) {
        let p = base.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, bytes).unwrap();
    }

    fn scan_dir(dir: &Path) -> R4Report {
        run_r4_scan(&R4ScanConfig {
            guap_root: dir.to_path_buf(),
            scan_binaries: false,
            scan_cli_mcp: false,
        })
        .unwrap()
    }

    #[test]
    fn fail_closed_on_missing_guap_root() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist");
        let res = run_r4_scan(&R4ScanConfig {
            guap_root: missing,
            scan_binaries: true,
            scan_cli_mcp: true,
        });
        assert!(res.is_err());
    }

    #[test]
    fn rule_registry_contains_all_52_rules() {
        let reg = RuleRegistry::compile().unwrap();
        // 51 compiled regex rules + R4-BASELINE-CHROME = 52 total R4 rules
        assert_eq!(reg.rules.len(), 51);
        let ids: Vec<&str> = reg.rules.iter().map(|r| r.def.rule_id).collect();
        assert!(ids.contains(&"R4-CRED-01"));
        assert!(ids.contains(&"R4-CRED-02"));
        for i in 1..=6 {
            assert!(ids.contains(&format!("R4-API-CRED-{i:02}").as_str()));
        }
        for i in 1..=4 {
            assert!(ids.contains(&format!("R4-INJ-{i:02}").as_str()));
        }
        for i in 1..=39 {
            assert!(ids.contains(&format!("R4-LEGACY-{i:02}").as_str()));
        }
    }

    #[test]
    fn positive_r4_cred_01_dir_cargo_and_source() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "cred2rust/Cargo.toml",
            "[package]\nname = \"cred2rust-core\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        write_file(dir.path(), "cred2rust/src/lib.rs", "pub fn run() {}\n");
        let report = scan_dir(dir.path());
        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.rule_id == "R4-CRED-01"));
    }

    #[test]
    fn positive_r4_cred_02_all_27_tools() {
        let tools = [
            "WebBrowserPassView",
            "ChromePass",
            "PasswordFox",
            "IEPassView",
            "OperaPassView",
            "Mail PassView",
            "mailpv",
            "OutlookPassView",
            "WirelessKeyView",
            "WifiKeyView",
            "Network Password Recovery",
            "netpass",
            "CredentialsFileView",
            "VaultPasswordView",
            "LSASecretsView",
            "LSASecretsDump",
            "SecurityQuestionsView",
            "Dialupass",
            "Asterisk Logger",
            "BulletsPassView",
            "Protected Storage PassView",
            "pspv",
            "Remote Desktop PassView",
            "rdpv",
            "VNCPassView",
            "RouterPassView",
            "ProduKey",
            "ProductKey",
            "SniffPass",
            "ChromeCookiesView",
            "EdgeCookiesView",
            "CustomPassView",
        ];

        for tool in tools {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                &format!("pub fn launch() -> &'static str {{ \"{tool}\" }}\n"),
            );
            let report = scan_dir(dir.path());
            assert!(
                !report.passed && report.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "expected R4-CRED-02 for {tool}, got: {:?}",
                report.violations
            );
        }
    }

    #[test]
    fn positive_r4_api_cred_01_through_06() {
        let cases = [
            ("R4-API-CRED-01", "unsafe { CredEnumerateW(ptr, 0, &mut count, &mut creds); }"),
            ("R4-API-CRED-02", "unsafe { VaultEnumerateItems(vault, 0, &mut count, &mut items); }"),
            ("R4-API-CRED-03", "unsafe { LsaRetrievePrivateData(policy, &key, &mut data); }"),
            ("R4-API-CRED-04", "unsafe { CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out); }"),
            ("R4-API-CRED-05", "let flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;\nlet xml = \"<keyMaterial>secret</keyMaterial>\";"),
            ("R4-API-CRED-05", "unsafe { WlanGetProfile(h, &guid, name, None, &mut xml, Some(&mut 0x00000004), None); }"),
            ("R4-API-CRED-06", "pub fn extract_boot_key(sam: &[u8]) { let _ = lsa_secret_decrypt(sam); }"),
            ("R4-API-CRED-06", "pub fn dump_sam(hive: &[u8]) { /* SAM RC4 */ let _ = PEK; }"),
        ];

        for (expected_rule, snippet) in cases {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "suite/src/lib.rs", snippet);
            let report = scan_dir(dir.path());
            assert!(
                !report.passed && report.violations.iter().any(|v| v.rule_id == expected_rule),
                "expected {expected_rule} for `{snippet}`, got: {:?}",
                report.violations
            );
        }
    }

    #[test]
    fn positive_r4_baseline_chrome_guards() {
        // 1. Cross-workspace import of chrome2rust baseline
        let dir1 = TempDir::new().unwrap();
        write_file(
            dir1.path(),
            "forensics2rust/src/lib.rs",
            "use chrome2rust_core::crypto::try_decrypt_chrome_blob;\n",
        );
        let r1 = scan_dir(dir1.path());
        assert!(r1.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"));

        // 2. Expansion inside new chrome2rust module
        let dir2 = TempDir::new().unwrap();
        write_file(
            dir2.path(),
            "chrome2rust/crates/chrome2rust-forensics/src/firefox_passwords.rs",
            "pub fn dump() { let db = \"key4.db\"; let _ = db; }\n",
        );
        let r2 = scan_dir(dir2.path());
        assert!(r2.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"));

        // 3. Decrypting EncryptionScheme::Dpapi in crypto.rs
        let dir3 = TempDir::new().unwrap();
        write_file(
            dir3.path(),
            "chrome2rust/crates/chrome2rust-core/src/crypto.rs",
            "pub fn try_decrypt_chrome_blob(s: EncryptionScheme) -> (EncryptionScheme, Option<String>) {\n    match s {\n        EncryptionScheme::Dpapi => (s, Some(\"leaked\".into())),\n        _ => (s, None),\n    }\n}\n",
        );
        let r3 = scan_dir(dir3.path());
        assert!(r3.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"));

        // 4. Adding windows DPAPI dependency to chrome2rust Cargo.toml
        let dir4 = TempDir::new().unwrap();
        write_file(
            dir4.path(),
            "chrome2rust/crates/chrome2rust-core/Cargo.toml",
            "[package]\nname = \"chrome2rust-core\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nwindows = { version = \"0.62\", features = [\"Win32_Security_Cryptography\"] }\n",
        );
        let r4 = scan_dir(dir4.path());
        assert!(r4.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"));
    }

    #[test]
    fn positive_r4_inj_01_through_04() {
        let cases = [
            ("R4-INJ-01", "suite/src/lib.rs", "pub fn tool() -> &'static str { \"RunAsDate\" }\n"),
            ("R4-INJ-01", "suite/src/lib.rs", "pub fn tool() -> &'static str { \"SocketSniff\" }\n"),
            ("R4-INJ-01", "suite/src/lib.rs", "pub fn tool() -> &'static str { \"InjectedDLL\" }\n"),
            ("R4-INJ-02", "suite/src/lib.rs", "unsafe { CreateRemoteThread(h, None, 0, None, None, 0, None); }\n"),
            ("R4-INJ-02", "suite/src/lib.rs", "unsafe { NtCreateThreadEx(&mut th, 0, None, h, addr, arg, 0, 0, 0, 0, None); }\n"),
            ("R4-INJ-02", "suite/src/lib.rs", "unsafe { DetourAttach(&mut target, hook); }\n"),
            ("R4-INJ-02", "suite/src/lib.rs", "unsafe { MH_CreateHook(target, detour, &mut orig); }\n"),
            ("R4-INJ-02", "suite/Cargo.toml", "[package]\nname = \"bad\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nretour = \"0.3\"\n"),
            ("R4-INJ-03", "suite/src/lib.rs", "unsafe { SetWindowsHookExW(WH_CBT, Some(proc), dll_mod, tid); }\n"),
            ("R4-INJ-03", "winctl2rust/crates/winctl2rust-audio/src/lib.rs", "unsafe { SetWindowsHookExW(WH_GETMESSAGE, Some(proc), dll_mod, tid); }\n"),
            ("R4-INJ-04", "sys2rust/src/lib.rs", "unsafe { WriteProcessMemory(h, addr, buf, len, None); }\n"),
            ("R4-INJ-04", "winctl2rust/crates/winctl2rust-desktop/src/sysexporter.rs", "let fl = PAGE_EXECUTE_READWRITE;\nunsafe { WriteProcessMemory(h, addr, buf, len, None); }\n"),
        ];

        for (expected_rule, rel, content) in cases {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), rel, content);
            let report = scan_dir(dir.path());
            assert!(
                !report.passed && report.violations.iter().any(|v| v.rule_id == expected_rule),
                "expected {expected_rule} for {rel}, got: {:?}",
                report.violations
            );
        }
    }

    #[test]
    fn positive_all_39_retired_legacy_tools() {
        let cases = [
            ("R4-LEGACY-01", "IECacheView"),
            ("R4-LEGACY-02", "IEHistoryView"),
            ("R4-LEGACY-03", "IECookiesView"),
            ("R4-LEGACY-04", "iehv"),
            ("R4-LEGACY-04", "IESessionView"),
            ("R4-LEGACY-05", "IEDownloadView"),
            ("R4-LEGACY-06", "IEPassView"),
            ("R4-LEGACY-07", "URLStringGrabber"),
            ("R4-LEGACY-08", "FavoritesView"),
            ("R4-LEGACY-09", "WebVideoCap"),
            ("R4-LEGACY-10", "FlashCookiesView"),
            ("R4-LEGACY-11", "RTMPDumpHelper"),
            ("R4-LEGACY-12", "ActiveXHelper"),
            ("R4-LEGACY-13", "ActiveX Compatibility Manager"),
            ("R4-LEGACY-13", "acm"),
            ("R4-LEGACY-14", "win9xpv"),
            ("R4-LEGACY-15", "9xProtect"),
            ("R4-LEGACY-15", "win9x_tool"),
            ("R4-LEGACY-16", "MessenPass"),
            ("R4-LEGACY-17", "SkypeLogView"),
            ("R4-LEGACY-18", "SkypeContactsView"),
            ("R4-LEGACY-19", "pcANYWHERECIF"),
            ("R4-LEGACY-20", "accesspv"),
            ("R4-LEGACY-21", "OEView"),
            ("R4-LEGACY-21", "DBXtract"),
            ("R4-LEGACY-22", "wlmpv"),
            ("R4-LEGACY-23", "NetscapeCacheView"),
            ("R4-LEGACY-23", "NSHistoryView"),
            ("R4-LEGACY-24", "PaltalkPass"),
            ("R4-LEGACY-24", "MirandaPass"),
            ("R4-LEGACY-25", "TrillianPass"),
            ("R4-LEGACY-25", "PidginPass"),
            ("R4-LEGACY-26", "GoogleTalkPass"),
            ("R4-LEGACY-26", "GizmoPass"),
            ("R4-LEGACY-27", "ICQPass"),
            ("R4-LEGACY-27", "AIMPass"),
            ("R4-LEGACY-28", "WinUpdatesList"),
            ("R4-LEGACY-28", "wul"),
            ("R4-LEGACY-29", "DrWatsonLogView"),
            ("R4-LEGACY-29", "UserDump"),
            ("R4-LEGACY-30", "NetPass"),
            ("R4-LEGACY-31", "LiveContactsView"),
            ("R4-LEGACY-32", "WindowsMail"),
            ("R4-LEGACY-32", "WinMailPass"),
            ("R4-LEGACY-33", "SilverlightCache"),
            ("R4-LEGACY-33", "JavaCacheView"),
            ("R4-LEGACY-34", "SiteShoter"),
            ("R4-LEGACY-35", "HtmlDocEdit"),
            ("R4-LEGACY-36", "WebBrowserPassView"),
            ("R4-LEGACY-37", "SysTrayRefresh"),
            ("R4-LEGACY-37", "TaskbarHide"),
            ("R4-LEGACY-38", "FastCache"),
            ("R4-LEGACY-38", "IndexDatView"),
            ("R4-LEGACY-39", "SmartFTP PassView"),
            ("R4-LEGACY-39", "CuteFTP PassView"),
            ("R4-LEGACY-39", "FileZilla PassView"),
            ("R4-LEGACY-39", "WS_FTP PassView"),
            ("R4-LEGACY-39", "FlashFXP PassView"),
        ];

        for (rule_id, token) in cases {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                &format!("#[command(name = \"{token}\")]\npub struct Cmd;\n"),
            );
            let report = scan_dir(dir.path());
            assert!(
                !report.passed && report.violations.iter().any(|v| v.rule_id == rule_id),
                "expected {rule_id} for token `{token}`, got: {:?}",
                report.violations
            );
        }
    }

    #[test]
    fn negative_false_positive_resistance() {
        let dir = TempDir::new().unwrap();

        // Negated comments, docstrings, strings, assertions
        write_file(
            dir.path(),
            "forensics2rust/src/lib.rs",
            r#"
// NO RunAsDate
// excluded: IECacheView
/// Never implements CredEnumerateW or CryptUnprotectData.
/* prohibited: BootKey and SysKey */
pub fn describe() -> &'static str {
    "This tool replaces and does not include WinUpdatesList"
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_clean() {
        let out = "clean";
        assert!(!out.contains("RunAsDate"));
        assert_eq!(out.contains("IECacheView"), false);
    }
}
"#,
        );

        // Negated Python docstring
        write_file(
            dir.path(),
            "all2pst/clean.py",
            "\"\"\"Never calls CredEnumerateW or LsaRetrievePrivateData.\"\"\"\ndef ok():\n    return 'pacman schedule module wulf svcl'\n",
        );

        // SysExporter (LVITEMW + WriteProcessMemory without PAGE_EXECUTE)
        write_file(
            dir.path(),
            "winctl2rust/crates/winctl2rust-desktop/src/sysexporter.rs",
            r#"
pub fn marshal_lvitem() {
    let item = LVITEMW::default();
    unsafe {
        WriteProcessMemory(proc_handle, remote_buf, &item as *const _ as _, size, None);
    }
}
"#,
        );

        // Volumouse (WH_MOUSE_LL with None HINSTANCE)
        write_file(
            dir.path(),
            "winctl2rust/crates/winctl2rust-audio/src/volumouse.rs",
            r#"
pub fn install_mouse_hook() {
    unsafe {
        let _ = SetWindowsHookExW(
            WH_MOUSE_LL,
            Some(mouse_proc),
            None,
            0,
        );
    }
}
"#,
        );

        // InstalledCodec (acmDriverEnum / msacm32) + svcl + short tokens + PEK without SAM context
        write_file(
            dir.path(),
            "sys2rust/crates/sys2rust-hw/src/codecs.rs",
            r#"
pub fn list_codecs() {
    let _ = acmDriverEnum(None, 0, 0);
    let _ = "msacm32 Audio Compression Manager";
    let _ = "pacman schedule module wulf svcl SoundVolumeCommandLine pek";
}
"#,
        );

        // Ignored directories must never cause violations
        write_file(
            dir.path(),
            "all2pst/.venv/Lib/site-packages/win32crypt.py",
            "CredEnumerateW()\nCryptUnprotectData()\nLsaRetrievePrivateData()\n",
        );
        write_file(
            dir.path(),
            "sys2rust/target/debug/build/tmp.rs",
            "CreateRemoteThread();\n",
        );
        write_file(
            dir.path(),
            ".git/hooks/pre-commit.rs",
            "RunAsDate();\n",
        );
        write_file(
            dir.path(),
            ".agents/notes.rs",
            "WebBrowserPassView();\n",
        );

        let report = scan_dir(dir.path());
        assert!(
            report.passed && report.violations.is_empty(),
            "expected zero false positives, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn same_line_code_plus_trailing_negation_comment_must_fail() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "suite/src/lib.rs",
            "pub fn bad() { unsafe { CredEnumerateW(ptr, 0, &mut c, &mut out); } // NO CredEnumerateW\n}\n",
        );
        let report = scan_dir(dir.path());
        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.rule_id == "R4-API-CRED-01"));
    }

    #[test]
    fn surface_c_binary_ascii_utf16le_and_exclusions() {
        let dir = TempDir::new().unwrap();

        // 1. ASCII prohibited symbol
        write_bytes(
            dir.path(),
            "suite/target/release/ascii_bad.exe",
            b"MZ\x90\x00padding\0CredEnumerateW\0tail",
        );

        // 2. UTF-16LE prohibited symbol
        let mut utf16_bytes = b"MZ\x90\x00\x01".to_vec();
        for ch in "RunAsDate".encode_utf16() {
            utf16_bytes.extend_from_slice(&ch.to_le_bytes());
        }
        utf16_bytes.extend_from_slice(&[0, 0]);
        write_bytes(dir.path(), "suite/target/release/utf16_bad.exe", &utf16_bytes);

        // 3. winctl2rust SysExporter binary with WriteProcessMemory + LVITEMW -> allowed
        write_bytes(
            dir.path(),
            "winctl2rust/target/release/winctl2rust.exe",
            b"MZ\x90\x00WriteProcessMemory\0LVITEMW\0",
        );

        // 4. deps/proc.dll must be skipped, whereas release/bad.dll must be flagged
        write_bytes(
            dir.path(),
            "suite/target/debug/deps/proc.dll",
            b"MZ\x90\x00CredEnumerateW\0",
        );
        write_bytes(
            dir.path(),
            "suite/target/release/bad.dll",
            b"MZ\x90\x00CredEnumerateW\0",
        );

        let report = run_r4_scan(&R4ScanConfig {
            guap_root: dir.path().to_path_buf(),
            scan_binaries: true,
            scan_cli_mcp: false,
        })
        .unwrap();

        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| {
            v.rule_id == "R4-API-CRED-01" && v.path.ends_with("ascii_bad.exe")
        }));
        assert!(report.violations.iter().any(|v| {
            v.rule_id == "R4-INJ-01" && v.path.ends_with("utf16_bad.exe")
        }));
        assert!(report.violations.iter().any(|v| {
            v.rule_id == "R4-API-CRED-01" && v.path.ends_with("bad.dll")
        }));
        assert!(!report.violations.iter().any(|v| v.path.ends_with("winctl2rust.exe")));
        assert!(!report.violations.iter().any(|v| v.path.ends_with("proc.dll")));
    }

    fn compile_mock_exe(src: &str, out_exe: &Path) {
        if let Some(parent) = out_exe.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let src_path = out_exe.with_extension("rs");
        fs::write(&src_path, src).unwrap();
        let status = Command::new("rustc")
            .arg("--edition")
            .arg("2024")
            .arg(&src_path)
            .arg("-o")
            .arg(out_exe)
            .status()
            .expect("invoke rustc for mock CLI/MCP binary");
        assert!(status.success(), "mock rustc compilation failed");
    }

    #[test]
    fn surfaces_d_and_e_cli_and_mcp_checks() {
        let dir = TempDir::new().unwrap();

        // 1. Clean CLI + MCP binary (uses negation in --help, clean MCP tools)
        let clean_src = r#"
use std::io::{self, BufRead};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("guap-mock 0.1.0\nUsage: guap-mock <CMD>\nCommands:\n  scan   Run safe scan (excludes RunAsDate)\n");
        return;
    }
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"mock_scan\",\"description\":\"Read-only scan excluding IECacheView\"}}]");
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("mcp") {
        let stdin = io::stdin();
        for line in stdin.lock().lines().map_while(Result::ok) {
            if line.contains("\"initialize\"") {
                println!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocolVersion\":\"2024-11-05\",\"serverInfo\":{{\"name\":\"mock-mcp\"}}}}}}");
            } else if line.contains("\"tools/list\"") {
                println!("{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{{\"name\":\"mock_scan\",\"description\":\"Safe scan\"}}]}}}}");
            }
        }
    }
}
"#;
        let clean_exe = dir.path().join("clean_suite/target/release/clean_suite.exe");
        compile_mock_exe(clean_src, &clean_exe);
        let clean_report = run_r4_scan(&R4ScanConfig {
            guap_root: dir.path().to_path_buf(),
            scan_binaries: false,
            scan_cli_mcp: true,
        })
        .unwrap();
        assert!(
            clean_report.passed,
            "expected clean CLI/MCP binary to pass, got: {:?}",
            clean_report.violations
        );

        // 2. Prohibited subcommand in --help + prohibited MCP tool in tools/list
        let bad_src = r#"
use std::io::{self, BufRead};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("bad-mock 0.1.0\nCommands:\n  runasdate   Spoof date via injection\n");
        return;
    }
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"ie_cache_view\",\"description\":\"Dump IE cache\"}}]");
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("mcp") {
        let stdin = io::stdin();
        for line in stdin.lock().lines().map_while(Result::ok) {
            if line.contains("\"tools/list\"") {
                println!("{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{{\"name\":\"ie_cache_view\",\"description\":\"Dump IE cache\"}}]}}}}");
            }
        }
    }
}
"#;
        let bad_exe = dir.path().join("bad_suite/target/release/bad_suite.exe");
        compile_mock_exe(bad_src, &bad_exe);

        // 3. chrome2rust-mcp exposing a new login tool beyond the 8-tool baseline
        let chrome_bad_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"chrome2rust_firefox_logins\",\"description\":\"Read Firefox saved logins\"}}]");
    }
}
"#;
        let chrome_bad_exe = dir.path().join("chrome2rust/target/release/chrome2rust-mcp.exe");
        compile_mock_exe(chrome_bad_src, &chrome_bad_exe);

        let bad_report = run_r4_scan(&R4ScanConfig {
            guap_root: dir.path().to_path_buf(),
            scan_binaries: false,
            scan_cli_mcp: true,
        })
        .unwrap();

        assert!(!bad_report.passed);
        assert!(bad_report.violations.iter().any(|v| v.rule_id == "R4-INJ-01"));
        assert!(bad_report.violations.iter().any(|v| v.rule_id == "R4-LEGACY-01"));
        assert!(bad_report.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"));
    }

    #[test]
    fn live_guap_workspace_compliance_scan() {
        let workspace_parent = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        let guap_root = std::env::var_os("GUAP_ROOT")
            .map(std::path::PathBuf::from)
            .or(workspace_parent)
            .unwrap_or_else(|| std::path::PathBuf::from(".."));
        if !guap_root.join("guap-kit").is_dir() {
            return;
        }
        let report = run_r4_scan(&R4ScanConfig {
            guap_root,
            scan_binaries: true,
            scan_cli_mcp: true,
        })
        .unwrap();

        assert!(
            report.passed && report.violations.is_empty(),
            "live GUAP R4 scan failed with {} violations: {:#?}",
            report.violations.len(),
            report.violations
        );
        assert!(
            report.crates_scanned >= 30,
            "expected >= 30 crates scanned in GUAP, got {}",
            report.crates_scanned
        );
        assert!(
            report.baseline_notes.iter().any(|n| n.contains("logins.rs")),
            "expected logins.rs in baseline_notes: {:?}",
            report.baseline_notes
        );
        assert!(
            report.baseline_notes.iter().any(|n| n.contains("crypto.rs")),
            "expected crypto.rs in baseline_notes: {:?}",
            report.baseline_notes
        );
    }

    #[test]
    fn enforcement_blocklists_sanitizers_and_sdk_flags_do_not_false_positive() {
        let dir = TempDir::new().unwrap();

        // 1. R4 denylist constant + PolicyDenied rejection tests
        write_file(
            dir.path(),
            "winctl2rust/crates/winctl2rust-core/src/policy.rs",
            r#"
pub const R4_FORBIDDEN_IDENTIFIERS: &[&str] = &[
    "runasdate",
    "cred2rust",
    "createremotethread",
    "setwindowshookex",
];
pub fn check(val: &str) -> Result<(), &'static str> {
    if R4_FORBIDDEN_IDENTIFIERS.iter().any(|b| val.contains(b)) {
        return Err("PolicyDenied");
    }
    Ok(())
}
"#,
        );
        write_file(
            dir.path(),
            "winctl2rust/crates/winctl2rust-core/tests/core_tests.rs",
            r#"
#[test]
fn rejects_r4() {
    for bad in [
        "RunAsDate.exe",
        "CreateRemoteThread",
    ] {
        assert!(matches!(check(bad), Err("PolicyDenied")));
    }
    let arg_err = check("--inject=CreateRemoteThread").unwrap_err();
    assert_eq!(arg_err, "PolicyDenied");
}
"#,
        );

        // 2. WLAN <keyMaterial> redaction function + sanitizer test
        write_file(
            dir.path(),
            "net2rust/crates/net2rust-core/src/r4.rs",
            r#"
fn find_opening_keymaterial_tag(lower: &str) -> Option<usize> {
    const TAG_NAME: &str = "keymaterial";
    lower.find(TAG_NAME)
}
fn find_closing_keymaterial_tag(lower: &str) -> Option<usize> {
    const TAG_NAME: &str = "keymaterial";
    lower.rfind(TAG_NAME)
}
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let lower = xml.to_ascii_lowercase();
    if let (Some(_), Some(_)) = (find_opening_keymaterial_tag(&lower), find_closing_keymaterial_tag(&lower)) {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    xml.to_string()
}
"#,
        );
        write_file(
            dir.path(),
            "net2rust/crates/net2rust-core/src/lib.rs",
            r#"
#[cfg(test)]
mod tests {
    #[test]
    fn test_r4_sanitizers() {
        let wlan_xml = "<WLANProfile><keyMaterial>secret</keyMaterial></WLANProfile>";
        let out = sanitize_wlan_profile_xml(wlan_xml);
        assert!(out.contains("<keyMaterial>[REDACTED]</keyMaterial>"));
    }
}
"#,
        );

        // 3. Windows SDK QUEUE_USER_APC_FLAGS enum name
        write_file(
            dir.path(),
            "sys2rust/src/lib.rs",
            "pub fn check_flags() { let _ = windows::Win32::System::Threading::QUEUE_USER_APC_FLAGS(0); }\n",
        );

        // 4. Debug binaries with winsafe unused FFI symbols + QUEUE_USER_APC_FLAGS + net2rust redacted keyMaterial
        write_bytes(
            dir.path(),
            "forensics2rust/target/debug/forensics2rust-win32.exe",
            b"MZ\x90\x00\x007winsafe4user7handles5hhook\0SetWindowsHookExW\x007winsafe6kernel7handles8hprocess\0WriteProcessMemory\0QUEUE_USER_APC_FLAGS\0",
        );
        write_bytes(
            dir.path(),
            "net2rust/target/debug/net2rust-win32.exe",
            b"MZ\x90\x00\x00sanitize_wlan_profile_xml\0<keyMaterial>[REDACTED]</keyMaterial>\0",
        );

        let report = run_r4_scan(&R4ScanConfig {
            guap_root: dir.path().to_path_buf(),
            scan_binaries: true,
            scan_cli_mcp: false,
        })
        .unwrap();
        assert!(
            report.passed && report.violations.is_empty(),
            "expected zero false positives, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn winsafe_debug_binary_still_fails_with_dangerous_hook_or_apc() {
        let dir = TempDir::new().unwrap();
        write_bytes(
            dir.path(),
            "bad/target/debug/bad-win32.exe",
            b"MZ\x90\x00\x007winsafe4user7handles5hhook\0SetWindowsHookExW\0WH_CBT\0QueueUserAPC\0",
        );
        let report = run_r4_scan(&R4ScanConfig {
            guap_root: dir.path().to_path_buf(),
            scan_binaries: true,
            scan_cli_mcp: false,
        })
        .unwrap();
        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.rule_id == "R4-INJ-03"));
        assert!(report.violations.iter().any(|v| v.rule_id == "R4-INJ-02"));
    }

    #[test]
    fn regression_exemption_abuse_bypasses_all_fail() {
        // A4: sanitize_wlan_profile_xml + [REDACTED] alongside extract_plaintext_wifi_secret
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-core/src/r4.rs",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let _ = "<keyMaterial>[REDACTED]</keyMaterial>";
    xml.to_string()
}
pub fn extract_plaintext_wifi_secret(xml: &str) -> Option<&str> {
    let start = xml.find("<keyMaterial>")?;
    let end = xml.find("</keyMaterial>")?;
    Some(&xml[start + 13..end])
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "A4 must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // A4b: decoy comment sanitize_wlan_profile_xml [REDACTED]
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-core/src/steal.rs",
                "// Decoy: sanitize_wlan_profile_xml [REDACTED]\npub fn tag() -> &'static str { \"<keyMaterial>\" }\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "A4b must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // A4d: binary with sanitize_wlan_profile_xml\0[REDACTED]\0<keyMaterial\0</keyMaterial\0
        {
            let dir = TempDir::new().unwrap();
            write_bytes(
                dir.path(),
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0<keyMaterial\0</keyMaterial\0",
            );
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "A4d must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // A5b & Reviewer 2 Finding 2: denylist passed to Command::new or paired only with .contains(
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "winctl2rust/src/evil_exec.rs",
                r#"
pub const R4_FORBIDDEN_IDENTIFIERS: &[&str] = &["RunAsDate", "WebBrowserPassView"];
pub fn decoy() -> Result<(), &'static str> { Err("PolicyDenied") }
pub fn run_all() {
    for tool in R4_FORBIDDEN_IDENTIFIERS {
        let _ = std::process::Command::new(tool).spawn();
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01")
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "A5b must fail R4-INJ-01 and R4-CRED-02, got {:?}",
                r.violations
            );

            let dir2 = TempDir::new().unwrap();
            write_file(
                dir2.path(),
                "suite/src/lib.rs",
                r#"
pub const R4_FORBIDDEN_IDENTIFIERS: &[&str] = &["CreateRemoteThread", "RunAsDate"];
pub fn check_only(s: &str) -> bool {
    R4_FORBIDDEN_IDENTIFIERS.iter().any(|x| s.contains(x))
}
"#,
            );
            let r2 = scan_dir(dir2.path());
            assert!(
                !r2.passed
                    && r2.violations.iter().any(|v| v.rule_id == "R4-INJ-02")
                    && r2.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "Reviewer 2 Finding 2 must fail, got {:?}",
                r2.violations
            );
        }

        // A5c: let bad_cmd = "WebBrowserPassView.exe"; Command::new(bad_cmd).output(); let _ = Err::<(), ()>(()).is_err();
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/sneaky.rs",
                r#"
#[test]
fn sneaky_exec() {
    let bad_cmd = "WebBrowserPassView.exe";
    let _ = std::process::Command::new(bad_cmd).output();
    let _ = Err::<(), ()>(()).is_err();
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                    && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
                "A5c must fail R4-CRED-02 & R4-LEGACY-36, got {:?}",
                r.violations
            );
        }

        // A6b, A6c, A6d: WriteProcessMemory numeric 0x40, non-sysexporter comment LVITEMW, and winctl2rust-cmd.exe
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "winctl2rust/crates/winctl2rust-desktop/src/sysexporter.rs",
                r#"
pub fn bad_alloc() {
    let _ = LVITEMW::default();
    unsafe {
        let p = VirtualAllocEx(h, None, 0x1000, 0x3000, 0x40);
        WriteProcessMemory(h, p, buf, len, None);
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "A6b must fail R4-INJ-04, got {:?}",
                r.violations
            );

            let dir_c = TempDir::new().unwrap();
            write_file(
                dir_c.path(),
                "winctl2rust/crates/winctl2rust-desktop/src/wallpaper.rs",
                "// decoy LVITEMW\npub fn bad() { unsafe { WriteProcessMemory(h, p, b, l, None); } }\n",
            );
            let r_c = scan_dir(dir_c.path());
            assert!(
                !r_c.passed && r_c.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "A6c must fail R4-INJ-04, got {:?}",
                r_c.violations
            );

            let dir_d = TempDir::new().unwrap();
            write_bytes(
                dir_d.path(),
                "winctl2rust/target/release/winctl2rust-cmd.exe",
                b"MZ\x90\x00WriteProcessMemory\0LVITEMW\0",
            );
            let r_d = run_r4_scan(&R4ScanConfig {
                guap_root: dir_d.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r_d.passed && r_d.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "A6d must fail R4-INJ-04, got {:?}",
                r_d.violations
            );
        }

        // A7b & A7c: SetWindowsHookExW numeric 5 + next-line decoy; winsafe debug binary with evil.dll
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "winctl2rust/crates/winctl2rust-audio/src/volumouse.rs",
                r#"
pub fn hook() {
    unsafe {
        let _ = SetWindowsHookExW(5, Some(cbt_proc), dll_hmod, tid);
        let _decoy = (WH_MOUSE_LL, None::<HINSTANCE>);
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-03"),
                "A7b must fail R4-INJ-03, got {:?}",
                r.violations
            );

            let dir_c = TempDir::new().unwrap();
            write_bytes(
                dir_c.path(),
                "sys2rust/target/debug/sys2rust-win32.exe",
                b"MZ\x90\x007winsafe4user7handles5hhook\0SetWindowsHookExW\0evil.dll\0",
            );
            let r_c = run_r4_scan(&R4ScanConfig {
                guap_root: dir_c.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r_c.passed && r_c.violations.iter().any(|v| v.rule_id == "R4-INJ-03"),
                "A7c must fail R4-INJ-03, got {:?}",
                r_c.violations
            );
        }

        // A8b: multiline #[command(name = "acm")] and pub fn acm() in audio codec file
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "sys2rust/crates/sys2rust-hw/src/codecs.rs",
                "pub fn ok() { let _ = acmDriverEnum(None, 0, 0); }\n#[command(\n    name = \"acm\"\n)]\npub fn acm() {}\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-13"),
                "A8b must fail R4-LEGACY-13, got {:?}",
                r.violations
            );
        }

        // Reviewer 2 Finding 3: CreateRemoteThread_flags must fail R4-INJ-02
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                "pub fn bad() { let _ = CreateRemoteThread_flags; }\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-02"),
                "CreateRemoteThread_flags must fail R4-INJ-02, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_separators_camelcase_cargo_multiline_and_chrome_baseline() {
        // B1a-camel, B1b-*, B1c-*, B1d-*, B1e, B3c, B3d, B4d, B4f, Reviewer 2 Finding 5 & 6
        let cases: &[(&str, &str, &str)] = &[
            ("R4-CRED-01", "suite/src/lib.rs", "pub struct Cred2RustCli;\n"),
            ("R4-INJ-01", "suite/Cargo.toml", "[package]\nname = \"run-as-date\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
            ("R4-INJ-01", "suite/src/lib.rs", "#[command(name = \"socket-sniff\")]\npub struct S;\n"),
            ("R4-INJ-01", "suite/src/lib.rs", "#[command(name = \"injected-dll\")]\npub struct I;\n"),
            ("R4-CRED-02", "suite/src/lib.rs", "#[command(name = \"custom-pass-view\")]\npub struct C;\n"),
            ("R4-LEGACY-29", "suite/src/lib.rs", "#[command(name = \"user-dump\")]\npub struct U;\n"),
            ("R4-INJ-01", "suite/src/lib.rs", "pub fn invokeRunAsDateTool() {}\n"),
            ("R4-API-CRED-01", "suite/src/lib.rs", "pub fn callCredEnumerateWWrapper() {}\n"),
            ("R4-INJ-02", "suite/src/lib.rs", "pub fn doCreateRemoteThreadInject() {}\n"),
            ("R4-LEGACY-01", "suite/src/lib.rs", "pub fn openIeCacheView() {}\n"),
            ("R4-LEGACY-01", "suite/src/lib.rs", "#[command(name = \"IE Cache View\")]\npub struct A;\n"),
            ("R4-LEGACY-28", "suite/src/lib.rs", "#[command(name = \"Win Updates List\")]\npub struct B;\n"),
            ("R4-CRED-02", "suite/src/lib.rs", "#[command(name = \"Chrome Pass\")]\npub struct C;\n"),
            ("R4-CRED-02", "suite/src/lib.rs", "#[command(name = \"Sniff Pass\")]\npub struct D;\n"),
            ("R4-CRED-02", "suite/src/lib.rs", "#[command(name = \"Product Key\")]\npub struct E;\n"),
            ("R4-INJ-01", "suite/src/lib.rs", "#[command(name = \"Run As Date\")]\npub struct F;\n"),
            ("R4-INJ-02", "suite/Cargo.toml", "[package]\nname = \"ok\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nmy_hook = { package = \"retour\", version = \"0.3\" }\n"),
            ("R4-BASELINE-CHROME", "chrome2rust/crates/chrome2rust-core/Cargo.toml", "[package]\nname = \"chrome2rust-core\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nwin = { package = \"windows-sys\", version = \"0.59\", features = [\"Win32_Security_Cryptography\"] }\n"),
            ("R4-API-CRED-05", "suite/src/lib.rs", "pub fn f() {\n    unsafe {\n        WlanGetProfile(\n            h,\n            &g,\n            n,\n            None,\n            &mut x,\n            Some(&mut 0x00000004),\n            None,\n        );\n    }\n}\n"),
            ("R4-API-CRED-05", "suite/src/lib.rs", "pub fn f() { unsafe { WlanGetProfile(h, &g, n, None, &mut x, Some(&mut 0x00000004u32), None); } }\n"),
            ("R4-BASELINE-CHROME", "chrome2rust/crates/chrome2rust-core/src/crypto.rs", "pub fn try_decrypt_chrome_blob(scheme: EncryptionScheme) -> (EncryptionScheme, Option<String>) {\n    match scheme {\n        EncryptionScheme::Dpapi\n            => (scheme, Some(\"leaked\".into())),\n        _ => (scheme, None),\n    }\n}\n"),
            ("R4-BASELINE-CHROME", "suite/src/lib.rs", "pub fn mix() { /* NO CryptProtectData */ PK11SDR_Decrypt(); }\n"),
        ];

        for (expected_rule, rel, content) in cases {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), rel, content);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == *expected_rule),
                "expected {expected_rule} for {rel} (`{content}`), got {:?}",
                r.violations
            );
        }

        // B4f: chrome2rust-mcp exposing chrome2rust_creds
        {
            let dir = TempDir::new().unwrap();
            let src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"chrome2rust_creds\",\"description\":\"Dump saved auth secrets\"}}]");
    }
}
"#;
            let exe = dir.path().join("chrome2rust/target/release/chrome2rust-mcp.exe");
            compile_mock_exe(src, &exe);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: false,
                scan_cli_mcp: true,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"),
                "B4f must fail R4-BASELINE-CHROME, got {:?}",
                r.violations
            );
        }

        // Challenger 2 Bug 2: run-as-date in CLI --help
        {
            let dir = TempDir::new().unwrap();
            let src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        eprintln!("mock 0.1.0\nCommands:\n  run-as-date   Spoof date\n");
    }
}
"#;
            let exe = dir.path().join("suite/target/release/mock_cli.exe");
            compile_mock_exe(src, &exe);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: false,
                scan_cli_mcp: true,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "run-as-date --help must fail R4-INJ-01, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_surface_c_chunk_boundaries_and_cross_chunk_redaction() {
        const FOUR_MIB: usize = 4 * 1024 * 1024;

        // 1. Benign "foobaracm.exe" straddling 4 MiB in (4 MiB + 4096) binary -> PASS
        {
            let dir = TempDir::new().unwrap();
            let mut data = vec![0u8; FOUR_MIB + 4096];
            data[0..4].copy_from_slice(b"MZ\x90\x00");
            data[FOUR_MIB - 6..FOUR_MIB - 6 + 13].copy_from_slice(b"foobaracm.exe");
            write_bytes(dir.path(), "suite/target/release/benign_straddle.exe", &data);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "benign foobaracm.exe straddling 4 MiB must pass, got {:?}",
                r.violations
            );
        }

        // 2. Benign "foobaracm.exe" straddling (4 MiB - 4096) in (4 MiB + 8192) binary -> PASS
        {
            let dir = TempDir::new().unwrap();
            let mut data = vec![0u8; FOUR_MIB + 8192];
            data[0..4].copy_from_slice(b"MZ\x90\x00");
            let off = FOUR_MIB - 4096 - 6;
            data[off..off + 13].copy_from_slice(b"foobaracm.exe");
            write_bytes(dir.path(), "suite/target/release/benign_straddle2.exe", &data);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "benign foobaracm.exe straddling 4 MiB - 4096 must pass, got {:?}",
                r.violations
            );
        }

        // 3. Split "WebBrowserPassView" at 4 MiB - 8 in (4 MiB + 4096) binary -> exactly 1 R4-CRED-02 (no phantom "erPassView")
        {
            let dir = TempDir::new().unwrap();
            let mut data = vec![0u8; FOUR_MIB + 4096];
            data[0..4].copy_from_slice(b"MZ\x90\x00");
            let tok = b"WebBrowserPassView";
            data[FOUR_MIB - 8..FOUR_MIB - 8 + tok.len()].copy_from_slice(tok);
            write_bytes(dir.path(), "suite/target/release/split_wbpv.exe", &data);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            let cred_02: Vec<_> = r.violations.iter().filter(|v| v.rule_id == "R4-CRED-02").collect();
            assert_eq!(cred_02.len(), 1, "expected exactly 1 R4-CRED-02, got {:?}", cred_02);
            assert_eq!(cred_02[0].matched_symbol, "WebBrowserPassView");
        }

        // 4. Cross-chunk redacted <keyMaterial>[REDACTED]</keyMaterial> -> PASS
        {
            let dir = TempDir::new().unwrap();
            let mut data = vec![0u8; FOUR_MIB + 16384];
            data[0..4].copy_from_slice(b"MZ\x90\x00");
            let s1 = b"sanitize_wlan_profile_xml\0[REDACTED]\0";
            data[128..128 + s1.len()].copy_from_slice(s1);
            let s2 = b"<keyMaterial>[REDACTED]</keyMaterial>";
            data[FOUR_MIB + 10000..FOUR_MIB + 10000 + s2.len()].copy_from_slice(s2);
            write_bytes(dir.path(), "net2rust/target/release/net2rust.exe", &data);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "cross-chunk redacted keyMaterial in net2rust must pass, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_false_positive_edge_cases_and_char_raw_cstr() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "suite/src/lib.rs",
            r####"
/* This crate explicitly excludes
   RunAsDate and CredEnumerateW */
pub struct CompassView;
pub struct BypassView;
pub fn net_pass_through() {}
pub fn handle_sys_key() {}
pub fn parse_windows_mail_header() {}
pub fn raw_c_str_and_char() {
    let _c = cr#"excludes RunAsDate"#;
    let _q = '"'
    ;
}
"####,
        );
        let r = scan_dir(dir.path());
        assert!(
            r.passed && r.violations.is_empty(),
            "expected zero false positives on 6 edge cases + cr#/char, got {:?}",
            r.violations
        );

        // Ensure genuine NetPass, SysKey (in SAM context), WindowsMail, and WinMailPass still fail
        for (rule, snippet) in [
            ("R4-CRED-02", "pub fn run_netpass() {}\n"),
            ("R4-CRED-02", "pub fn net_pass_tool() {}\n"),
            ("R4-API-CRED-06", "pub fn dump_sam(hive: &[u8]) { let _ = SysKey; }\n"),
            ("R4-LEGACY-32", "#[command(name = \"WindowsMail\")]\npub struct W;\n"),
            ("R4-LEGACY-32", "#[command(name = \"WinMailPass\")]\npub struct P;\n"),
        ] {
            let d = TempDir::new().unwrap();
            write_file(d.path(), "suite/src/lib.rs", snippet);
            let rep = scan_dir(d.path());
            assert!(
                !rep.passed && rep.violations.iter().any(|v| v.rule_id == rule),
                "expected {rule} for `{snippet}`, got {:?}",
                rep.violations
            );
        }
    }

    #[test]
    fn regression_partial_tools_output_on_timeout_is_still_scanned() {
        let dir = TempDir::new().unwrap();
        let src = r#"
use std::io::Write;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"web_browser_pass_view\",\"description\":\"Dump saved browser passwords\"}}]");
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
}
"#;
        let exe = dir.path().join("hang_suite/target/release/hang_suite-mcp.exe");
        compile_mock_exe(src, &exe);
        let r = run_r4_scan(&R4ScanConfig {
            guap_root: dir.path().to_path_buf(),
            scan_binaries: false,
            scan_cli_mcp: true,
        })
        .unwrap();
        assert!(
            !r.passed
                && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
            "partial --tools stdout before timeout must be scanned and fail, got {:?}",
            r.violations
        );
    }

    #[test]
    fn regression_comment_redacted_decoy_fails_and_legit_guap_patterns_pass() {
        // 1. Comment-only [REDACTED] decoy on <keyMaterial> line MUST fail R4-API-CRED-05
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-core/src/leak.rs",
                "pub fn tag() -> &'static str { \"<keyMaterial>\" } // [REDACTED]\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "comment-only [REDACTED] decoy must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 2. Legitimate GUAP patterns: security_center has_single_product_key, winctl2rust-desktop win32_backend SysExporter,
        //    multi-line POLICY_DENIED test, tests/r4_compliance.rs FORBIDDEN_PATTERNS, net2rust-report validator + tests,
        //    and net2rust binary with WlanGetProfile(flags=0) + sanitizer + SYNTHETIC-PROTECTED-BLOB.
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "forensics2rust/crates/forensics2rust-posture/src/security_center.rs",
                "pub fn check_json(keys: &[&str]) -> bool {\n    let has_single_product_key = keys.contains(&\"displayName\");\n    has_single_product_key\n}\n",
            );
            write_file(
                dir.path(),
                "winctl2rust/crates/winctl2rust-desktop/src/win32_backend.rs",
                r#"
use crate::sysexport::LvItemW32;
pub fn read_lv() {
    let _p = VirtualAllocEx(h, None, 128, MEM_COMMIT, PAGE_READWRITE);
    let item = LVITEMW::default();
    unsafe {
        WriteProcessMemory(h, _p, &item as *const _ as _, 64, None);
        SendMessageTimeoutW(hwnd, LVM_GETITEMW, 0, 0, 0, 250, None);
    }
}
"#,
            );
            write_file(
                dir.path(),
                "winctl2rust/crates/winctl2rust-desktop/src/lib.rs",
                r#"
#[cfg(test)]
mod tests {
    #[test]
    fn rejects_r4_payload() {
        let r4_err = clip_action
            .execute(&serde_json::json!({ "operation": "set_text", "text": "runasdate /hook" }), true)
            .unwrap_err();
        assert_eq!(JsonRpcError::from(r4_err).code, JsonRpcError::POLICY_DENIED);
    }
}
"#,
            );
            let mut long_r4_test = String::from("const FORBIDDEN_PATTERNS: &[(&str, &str)] = &[\n");
            for i in 0..45 {
                long_r4_test.push_str(&format!("    (\"harmless_pad_{i}\", \"pad\"),\n"));
            }
            long_r4_test.push_str("    (\"cred2rust\", \"excluded\"),\n    (\"runasdate\", \"excluded\"),\n];\n");
            long_r4_test.push_str(
                r#"
fn scan_text(label: &str, text: &str, violations: &mut Vec<String>) {
    let lower = text.to_ascii_lowercase();
    for (pat, reason) in FORBIDDEN_PATTERNS {
        if lower.contains(pat) {
            violations.push(format!("{label}: {pat} ({reason})"));
        }
    }
}
#[test]
fn r4_workspace_check() {
    let mut violations = Vec::new();
    scan_text("ok", "clean", &mut violations);
    assert!(violations.is_empty());
}
"#,
            );
            write_file(dir.path(), "fs2rust/crates/fs2rust-cli/tests/r4_compliance.rs", &long_r4_test);

            write_file(
                dir.path(),
                "net2rust/crates/net2rust-report/src/lib.rs",
                r#"
fn contains_keymaterial_tag(s: &str) -> bool {
    s.to_ascii_lowercase().contains("<keymaterial")
}
pub fn sanitize_escaped_keymaterial_in_str(s: &str) -> String {
    if contains_keymaterial_tag(s) {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    s.to_string()
}
pub fn assert_r4_clean_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("<keyMaterial>") && !text.contains("[REDACTED]") {
        return Err("R4 violation: unredacted <keyMaterial> value detected");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_r4_self_closing_and_leak() {
        assert!(assert_r4_clean_bytes(b"<keyMaterial/>ok").is_ok());
        assert!(assert_r4_clean_bytes(b"<keyMaterial>Secret</keyMaterial>").is_err());
    }
}
"#,
            );

            write_bytes(
                dir.path(),
                "winctl2rust/target/debug/winctl2rust.exe",
                b"MZ\x90\x00WriteProcessMemory\0LVITEMW\0__imp_LoadLibraryA\0",
            );
            write_bytes(
                dir.path(),
                "net2rust/target/debug/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0WlanGetProfile\0:keyMaterial>\0:keyMaterial&gt;\0<keyMaterial>SYNTHETIC-PROTECTED-BLOB</keyMaterial>\0R4 violation: unredacted <keyMaterial> value detected\0",
            );

            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "legitimate GUAP patterns must pass cleanly, got {:?}",
                r.violations
            );
        }

        // 3. Genuine extract_product_key still fails R4-CRED-02
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                "pub fn extract_product_key() -> &'static str { \"key\" }\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "extract_product_key must still fail R4-CRED-02, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_iter3_all_9_evasion_bypasses_fail() {
        // 1. I2-EVADE-NET-decoy-redacted-in-sanitizer
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-core/src/r4.rs",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let _decoy = "[REDACTED]";
    let s = xml.find("<keyMaterial>").unwrap();
    let e = xml.find("</keyMaterial>").unwrap();
    xml[s + 13..e].to_string()
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "I2-EVADE-NET-decoy-redacted-in-sanitizer must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 2. I2-EVADE-NET-report-helper-steal
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-report/src/lib.rs",
                r#"
pub fn assert_r4_clean_bytes(bytes: &[u8]) -> bool {
    !String::from_utf8_lossy(bytes).contains("[REDACTED]")
}
pub fn sanitize_table_for_report(xml: &str) -> String {
    let s = xml.find("<keyMaterial>").unwrap();
    let e = xml.find("</keyMaterial>").unwrap();
    xml[s + 13..e].to_string()
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "I2-EVADE-NET-report-helper-steal must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 3. I2-EVADE-NET-wlan-decimal-4
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-radio/src/wlan.rs",
                "pub fn f() { unsafe { WlanGetProfile(h, g, n, None, x, Some(&mut 4), None); } }\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "I2-EVADE-NET-wlan-decimal-4 must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 4. I2-EVADE-WPM-wallpaper-decoy-var-0x40
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "winctl2rust/crates/winctl2rust-desktop/src/wallpaper.rs",
                r#"
pub fn inject(h: HANDLE, payload_buf: &[u8]) {
    let _decoy_str = "LVM_GETITEM";
    let _decoy_item = LVITEMW::default();
    let prot_rwx: u32 = 0x40;
    unsafe {
        let p = VirtualAllocEx(h, None, payload_buf.len(), 0x3000, prot_rwx);
        WriteProcessMemory(h, p, payload_buf.as_ptr() as _, payload_buf.len(), None);
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "I2-EVADE-WPM-wallpaper-decoy-var-0x40 must fail R4-INJ-04, got {:?}",
                r.violations
            );
        }

        // 5. I2-EVADE-WPM-wallpaper-sysexport-str
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "winctl2rust/crates/winctl2rust-desktop/src/wallpaper.rs",
                r#"
pub fn inject(h: HANDLE, remote_exec_ptr: *mut core::ffi::c_void, payload_buf: &[u8]) {
    let _decoy = "sysexport";
    let _item = LVITEMW::default();
    unsafe {
        WriteProcessMemory(h, remote_exec_ptr, payload_buf.as_ptr() as _, payload_buf.len(), None);
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "I2-EVADE-WPM-wallpaper-sysexport-str must fail R4-INJ-04, got {:?}",
                r.violations
            );
        }

        // 6. I2-EVADE-BIN-debug-win32-inject
        {
            let dir = TempDir::new().unwrap();
            write_bytes(
                dir.path(),
                "evil/target/debug/evil-win32.exe",
                b"MZ\x90\x00\x007winsafe6kernel7handles8hprocess\0WriteProcessMemory\0VirtualAllocEx\0LoadLibraryA\0evil.dll\0",
            );
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "I2-EVADE-BIN-debug-win32-inject must fail R4-INJ-04, got {:?}",
                r.violations
            );
        }

        // 7. I2-EVADE-FORBIDDEN-alias-in-tests
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/sneaky_alias.rs",
                r#"
const FORBIDDEN_PATTERNS: &[&str] = &["RunAsDate", "WebBrowserPassView"];
const EXEC_LIST: &[&str] = FORBIDDEN_PATTERNS;

#[test]
fn decoy_assert() {
    let _ = FORBIDDEN_PATTERNS;
    assert!(true);
}

#[test]
fn real_evil_spawn() {
    for t in EXEC_LIST {
        let _ = std::process::Command::new(t).spawn();
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01")
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                    && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
                "I2-EVADE-FORBIDDEN-alias-in-tests must fail R4-INJ-01/R4-CRED-02/R4-LEGACY-36, got {:?}",
                r.violations
            );
        }

        // 8. I2-EVADE-LET-BAD-var-alias
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/sneaky_var_alias.rs",
                r#"
#[test]
fn sneaky_var_alias() {
    let bad_tool = "WebBrowserPassView";
    assert!(Err::<(), &str>(bad_tool).is_err());
    let cmd_name = bad_tool;
    let _ = std::process::Command::new(cmd_name).spawn();
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                    && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
                "I2-EVADE-LET-BAD-var-alias must fail R4-CRED-02/R4-LEGACY-36, got {:?}",
                r.violations
            );
        }

        // 9. I2-EVADE-PK-cmd-spoof (command attr, Cargo.toml, CLI --help, MCP tools, while Rust var still passes)
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                "#[command(name = \"has_single_product_key\")]\npub fn steal() {}\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "I2-EVADE-PK-cmd-spoof must fail R4-CRED-02, got {:?}",
                r.violations
            );

            let dir_cargo = TempDir::new().unwrap();
            write_file(
                dir_cargo.path(),
                "suite/Cargo.toml",
                "[package]\nname = \"has_single_product_key\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            );
            let r_cargo = scan_dir(dir_cargo.path());
            assert!(
                !r_cargo.passed && r_cargo.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "Cargo.toml has_single_product_key must fail R4-CRED-02, got {:?}",
                r_cargo.violations
            );

            let dir_cli = TempDir::new().unwrap();
            let cli_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("mock 0.1.0\nCommands:\n  has_single_product_key   Extract keys\n");
    }
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"is_single_product_key\",\"description\":\"Extract\"}}]");
    }
}
"#;
            let exe = dir_cli.path().join("suite/target/release/pk_cli.exe");
            compile_mock_exe(cli_src, &exe);
            let r_cli = run_r4_scan(&R4ScanConfig {
                guap_root: dir_cli.path().to_path_buf(),
                scan_binaries: false,
                scan_cli_mcp: true,
            })
            .unwrap();
            assert!(
                !r_cli.passed && r_cli.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "CLI/MCP spoof has_single_product_key/is_single_product_key must fail R4-CRED-02, got {:?}",
                r_cli.violations
            );

            // Clean Rust code variable lookalikes must still pass
            let dir_clean = TempDir::new().unwrap();
            write_file(
                dir_clean.path(),
                "suite/src/lib.rs",
                "pub fn check(a: bool) -> bool {\n    let has_single_product_key = a;\n    let is_single_product_key = !a;\n    has_single_product_key || is_single_product_key\n}\n",
            );
            let r_clean = scan_dir(dir_clean.path());
            assert!(
                r_clean.passed && r_clean.violations.is_empty(),
                "clean Rust identifiers has_single_product_key/is_single_product_key must pass, got {:?}",
                r_clean.violations
            );
        }
    }

    #[test]
    fn regression_iter4_adversarial_bypasses_and_net2rust_report_generalization() {
        // 1. ADV-1-keymaterial-helper-steal-into (String/.into() and Option<&str> co-located with valid sanitizer)
        for helper_src in [
            r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn find_opening_keymaterial_tag(xml: &str) -> String {
    let s = xml.find("keyMaterial").unwrap();
    let e = xml.rfind("keyMaterial").unwrap();
    xml[s..e].into()
}
"#,
            r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn find_opening_keymaterial_tag(xml: &str) -> Option<&str> {
    let s = xml.find("keyMaterial")?;
    let e = xml.rfind("keyMaterial")?;
    Some(&xml[s..e])
}
"#,
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-core/src/r4.rs", helper_src);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "ADV-1 helper secret extraction must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 2. ADV-3-same-line-assert-next-line-spawn
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/adv3.rs",
                r#"
#[test]
fn adv3() {
    let tool = "WebBrowserPassView"; assert!(Err::<(), ()>(()).is_err());
    let _ = std::process::Command::new(tool).spawn();
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                    && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
                "ADV-3 must fail R4-CRED-02 & R4-LEGACY-36, got {:?}",
                r.violations
            );
        }

        // 3. ADV-4-block-expr-assert-then-spawn
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/adv4.rs",
                r#"
#[test]
fn adv4() {
    let cmd = { assert!(Err::<(), ()>(()).is_err()); "WebBrowserPassView" };
    let _ = std::process::Command::new(cmd).spawn();
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                    && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
                "ADV-4 must fail R4-CRED-02 & R4-LEGACY-36, got {:?}",
                r.violations
            );
        }

        // 4. ADV-11-helper-fn-before-let-bad (single-line and multi-line inner fn helper)
        for adv11_src in [
            r#"
#[test]
fn adv11_single_line() {
    fn helper() {}
    let bad_tool = "WebBrowserPassView";
    assert!(Err::<(), &str>(bad_tool).is_err());
    let cmd_name = bad_tool;
    let _ = std::process::Command::new(cmd_name).spawn();
}
"#,
            r#"
#[test]
fn adv11_multi_line() {
    fn helper() {
        let _x = 1;
    }
    let bad_tool = "WebBrowserPassView";
    assert!(Err::<(), &str>(bad_tool).is_err());
    let cmd_name = bad_tool;
    let _ = std::process::Command::new(cmd_name).spawn();
}
"#,
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "suite/tests/adv11.rs", adv11_src);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02")
                    && r.violations.iter().any(|v| v.rule_id == "R4-LEGACY-36"),
                "ADV-11 must fail R4-CRED-02 & R4-LEGACY-36, got {:?}",
                r.violations
            );
        }

        // 5. Generalized net2rust-report R4 validators/helpers + md_clean_br_note raw JSON test payload + binary symbols
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-report/src/lib.rs",
                r####"
pub fn assert_r4_clean_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("<keyMaterial>") && !text.contains("[REDACTED]") {
        return Err("R4 violation: unredacted <keyMaterial> value detected");
    }
    Ok(())
}
fn slice_contains_closing_keymaterial_tag(lower: &[u8]) -> Option<(usize, usize)> {
    let pos = lower.windows(b"keymaterial".len()).position(|w| w == b"keymaterial")?;
    Some((pos, pos + "keymaterial".len()))
}
fn has_unredacted_inner_keymaterial_in_span(lower: &[u8]) -> bool {
    slice_contains_closing_keymaterial_tag(lower).is_some()
}
fn raw_string_has_unredacted_closing_keymaterial_tag(bytes: &[u8]) -> bool {
    has_unredacted_inner_keymaterial_in_span(bytes)
}
fn has_unredacted_closing_keymaterial_tag_json(s: &str) -> bool {
    raw_string_has_unredacted_closing_keymaterial_tag(s.as_bytes())
}
fn has_unredacted_closing_keymaterial_tag_with_depth(bytes: &[u8], _depth: usize) -> bool {
    has_unredacted_closing_keymaterial_tag_json(&String::from_utf8_lossy(bytes))
}
fn verify_markdown_table_cell(cell: &[u8]) -> Result<(), &'static str> {
    if has_unredacted_closing_keymaterial_tag_with_depth(cell, 0) {
        return Err("R4 violation");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_r4_iter11_remediation_all_seven_defects() {
        // 2. Markdown <br> + literal </keyMaterial> field
        let md_clean_br_note = r#"{"xml":"<keyMaterial attr=\"a<br>b\"/>ok","note":"</keyMaterial>"}"#;
        assert!(assert_r4_clean_bytes(md_clean_br_note.as_bytes()).is_ok());
        assert!(verify_markdown_table_cell(b"ok").is_ok());
    }
}
"####,
            );
            write_bytes(
                dir.path(),
                "net2rust/target/debug/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0slice_contains_closing_keymaterial_tag\0raw_string_has_unredacted_closing_keymaterial_tag\0has_unredacted_closing_keymaterial_tag_json\0has_unredacted_closing_keymaterial_tag_with_depth\0has_unredacted_inner_keymaterial_in_span\0field_has_html_encoded_json_or_keymaterial\0or_else<usize, net2rust_report::slice_contains_closing_keymaterial_tag::{closure_env#0}>\0",
            );
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "generalized net2rust-report helpers, md_clean_br_note, and net2rust.exe symbols must pass, got {:?}",
                r.violations
            );
        }

        // 6. Rogue keymaterial symbol in net2rust.exe must still fail R4-API-CRED-05
        {
            let dir = TempDir::new().unwrap();
            write_bytes(
                dir.path(),
                "net2rust/target/debug/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0steal_wifi_keymaterial\0",
            );
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "rogue steal_wifi_keymaterial symbol in binary must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_iter5_all_iter4_verifier_findings() {
        let scan_bins = |dir: &Path| {
            run_r4_scan(&R4ScanConfig {
                guap_root: dir.to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap()
        };
        #[allow(unused_variables)]
        let scan_cli = |dir: &Path| {
            run_r4_scan(&R4ScanConfig {
                guap_root: dir.to_path_buf(),
                scan_binaries: false,
                scan_cli_mcp: true,
            })
            .unwrap()
        };

        // 1. ADV-4A, ADV-4B, ADV-4C, ADV-4H, ADV-13 (.split_once & .split)
        for (label, src) in [
            (
                "ADV-4A-mask-format-decoy",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn find_keymaterial_bounds(xml: &str) -> Option<(usize, usize)> {
    Some((xml.find("keyMaterial")?, xml.rfind("keyMaterial")?))
}
pub fn mask_and_steal_wifi(xml: &str) -> String {
    let mut scratch = vec![b'x'; 4];
    scratch.fill(b'_');
    let decoy = "[REDACTED]";
    let _ = decoy;
    let (s, e) = find_keymaterial_bounds(xml).unwrap();
    format!("{}", &xml[s..e])
}
"#,
            ),
            (
                "ADV-4B-void-out-param-steal",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn find_keymaterial_bounds(xml: &str) -> Option<(usize, usize)> {
    Some((xml.find("keyMaterial")?, xml.rfind("keyMaterial")?))
}
pub fn steal_to_out(xml: &str, out: &mut String) {
    if let Some((s, e)) = find_keymaterial_bounds(xml) {
        out.push_str(&xml[s..e]);
        let _ = std::fs::write("loot.txt", &xml[s..e]);
    }
}
"#,
            ),
            (
                "ADV-4C-sanitize-wrapper-format",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn find_keymaterial_bounds(xml: &str) -> Option<(usize, usize)> {
    Some((xml.find("keyMaterial")?, xml.rfind("keyMaterial")?))
}
pub fn sanitize_keymaterial_r4(xml: &str) -> String {
    let _ = sanitize_wlan_profile_xml("");
    let (s, e) = find_keymaterial_bounds(xml).unwrap();
    format!("{}", &xml[s..e])
}
"#,
            ),
            (
                "ADV-4H-opening-struct-secret",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub struct OpeningSecret(pub String);
fn get_keymaterial_opening(xml: &str) -> Option<OpeningSecret> {
    let pos = xml.find("keyMaterial")?;
    Some(OpeningSecret(xml[pos..].chars().take(32).collect()))
}
"#,
            ),
            (
                "ADV-13-split-once-sanitizer",
                r#"
pub fn sanitize_wlan_copy(xml: &str) -> String {
    if xml.is_empty() {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    if let Some((_, rest)) = xml.split_once("keyMaterial") {
        return rest.to_string();
    }
    xml.to_string()
}
"#,
            ),
            (
                "ADV-13-split-nth-sanitizer",
                r#"
pub fn sanitize_wlan_xml(xml: &str) -> String {
    if xml.is_empty() {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    if let Some(rest) = xml.split("keyMaterial").nth(1) {
        return rest.to_string();
    }
    xml.to_string()
}
"#,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-core/src/r4.rs", src);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "{label} must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 2. ADV-4D1, ADV-4D2, ADV-4D3 (test-context split_once / fs::write / slice bypasses)
        for (label, src) in [
            (
                "ADV-4D1-test-split-once",
                r#"
#[cfg(test)]
mod tests {
    #[test]
    fn evil_test() {
        let xml = "<keyMaterial>RealSecret</keyMaterial>";
        let (_, rest) = xml.split_once("<keyMaterial>").unwrap();
        let (secret, _) = rest.split_once("</keyMaterial>").unwrap();
        let _ = std::fs::write("loot.txt", secret);
        assert!("<keyMaterial>[REDACTED]</keyMaterial>".contains("[REDACTED]"));
    }
}
"#,
            ),
            (
                "ADV-4D2-test-call-bounds-steal",
                r#"
pub fn assert_r4_clean_bytes(_b: &[u8]) -> Result<(), &'static str> { Err("R4 [REDACTED] keyMaterial") }
fn find_keymaterial_bounds(xml: &str) -> Option<(usize, usize)> {
    Some((xml.find("keyMaterial")?, xml.rfind("keyMaterial")?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evil_bounds_test() {
        let xml = "<keyMaterial>RealSecret</keyMaterial>";
        let (s, e) = find_keymaterial_bounds(xml).unwrap();
        let _ = std::fs::write("loot.txt", &xml[s..e]);
        assert!(assert_r4_clean_bytes(b"[REDACTED]").is_ok());
    }
}
"#,
            ),
            (
                "ADV-4D3-test-split-once-with-header",
                r####"
pub fn assert_r4_clean_bytes(_b: &[u8]) -> Result<(), &'static str> { Err("R4 [REDACTED] keyMaterial") }
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evil_header_test() {
        let md_clean_br_note = r#"{"xml":"<keyMaterial attr=\"a<br>b\"/>ok","note":"</keyMaterial>"}"#;
        assert!(assert_r4_clean_bytes(md_clean_br_note.as_bytes()).is_ok());
        let xml = "<keyMaterial>RealSecret</keyMaterial>";
        let (_, rest) = xml.split_once("<keyMaterial>").unwrap();
        let (secret, _) = rest.split_once("</keyMaterial>").unwrap();
        let _ = std::fs::write("loot.txt", secret);
    }
}
"####,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-report/src/lib.rs", src);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "{label} must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 3. ADV-4G2 (unicode char literal) & CTL-lex-char-lifetime (positive control)
        {
            let dir_bad = TempDir::new().unwrap();
            write_file(
                dir_bad.path(),
                "net2rust/src/lib.rs",
                "pub fn f() { let _ = ['é', '{']; }\npub fn g() -> &'static str { \"<keyMaterial>secret</keyMaterial>\" }\n",
            );
            let r_bad = scan_dir(dir_bad.path());
            assert!(
                !r_bad.passed && r_bad.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "ADV-4G2 must fail R4-API-CRED-05, got {:?}",
                r_bad.violations
            );

            let dir_ctl = TempDir::new().unwrap();
            write_file(
                dir_ctl.path(),
                "suite/src/lib.rs",
                r#"
pub fn ctl<'a, 'b>(s: &'a str, _t: &'b str) -> &'a str {
    let _c = ['{', '}', '"', '\'', '\x7b', '\u{1F600}', 'é', '☃'];
    let _b = [b'{', b'}', b':'];
    // NO RunAsDate
    s
}
"#,
            );
            let r_ctl = scan_dir(dir_ctl.path());
            assert!(
                r_ctl.passed && r_ctl.violations.is_empty(),
                "CTL-lex-char-lifetime must pass, got {:?}",
                r_ctl.violations
            );
        }

        // 4. ADV-12 (array type param in fn signature) + I4-5a-v2, I4-5b, I4-5c, I4-5d, I4-5g
        for (label, rel, src, expected_rules) in [
            (
                "ADV-12-array-sig-spawn",
                "suite/tests/adv12.rs",
                r#"
#[test]
fn helper_in_tests(_pad: [u8; 1]) {
    let tool = "WebBrowserPassView";
    assert!(Err::<(), ()>(()).is_err());
    let _ = std::process::Command::new(tool).spawn();
}
"#,
                &["R4-CRED-02", "R4-LEGACY-36"][..],
            ),
            (
                "I4-5a-v2-brace-desync",
                "suite/tests/i4_5a_v2.rs",
                r#"
#[test]
fn evil_brace_desync() {
    fn inner() {} let cmd = { assert!(Err::<(), ()>(()).is_err());
        "WebBrowserPassView"
    };
    let _ = std::process::Command::new(cmd).spawn();
}
"#,
                &["R4-CRED-02", "R4-LEGACY-36"][..],
            ),
            (
                "I4-5b-alias-spawn-space",
                "suite/tests/i4_5b.rs",
                r#"
use std::process::Command as Proc;
#[test]
fn evil_alias_spawn() {
    let tool = "WebBrowserPassView";
    assert!(Err::<(), ()>(()).is_err());
    let _ = Proc::new(tool).spawn ();
}
"#,
                &["R4-CRED-02", "R4-LEGACY-36"][..],
            ),
            (
                "I4-5c-helper-spawn",
                "suite/tests/i4_5c.rs",
                r#"
fn launch(p: &str) {
    let _ = std::process::Command::new(p).spawn();
}
#[test]
fn evil_via_helper() {
    let tool = "WebBrowserPassView";
    assert!(Err::<(), ()>(()).is_err());
    launch(tool);
}
"#,
                &["R4-CRED-02", "R4-LEGACY-36"][..],
            ),
            (
                "I4-5d-cfg-test-semicolon",
                "suite/src/lib.rs",
                r#"
#[cfg(test)]
mod tests;
pub fn prod_evil() {
    let _ = "WebBrowserPassView";
    assert!(Err::<(), ()>(()).is_err());
}
"#,
                &["R4-CRED-02", "R4-LEGACY-36"][..],
            ),
            (
                "I4-5g-test-steal-wlan-get",
                "net2rust/crates/net2rust-report/tests/evil_wlan.rs",
                r#"
#[test]
fn test_steal_wlan() {
    let ok = "[REDACTED]";
    let _r = "assert_r4_clean_bytes";
    let tag = "keyMaterial";
    let xml = "<keyMaterial>RealWifiPass</keyMaterial>";
    let s = xml.find(tag).unwrap();
    let secret = xml.get(s..).unwrap();
    let _ = std::process::Command::new("curl").arg(secret).spawn();
    assert!(!ok.is_empty());
}
"#,
                &["R4-API-CRED-05"][..],
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), rel, src);
            let r = scan_dir(dir.path());
            for exp in expected_rules {
                assert!(
                    !r.passed && r.violations.iter().any(|v| v.rule_id == *exp),
                    "{label} must fail {exp}, got {:?}",
                    r.violations
                );
            }
        }

        // 5. Challenger 1 I4-1a..c, I4-3a, I4-2a..e, I4-2h..i
        for (label, src) in [
            (
                "I4-1a",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let dummy = "".replace("x", "[REDACTED]");
    let _ = dummy;
    let tag = "keyMaterial";
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open).unwrap_or(0) + open.len();
    let e = xml[start..].find(&close).unwrap_or(0);
    xml.get(start..start + e).unwrap_or("").chars().collect()
}
"#,
            ),
            (
                "I4-1b",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn sanitize_wlan_leak(xml: &str) -> String {
    let _ = sanitize_wlan_profile_xml("");
    let tag = "keyMaterial";
    let open = format!("<{tag}>");
    let s = xml.find(&open).unwrap();
    let e = xml.len();
    format!("{}", &xml[s..e])
}
"#,
            ),
            (
                "I4-3a",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let ok = "".replace("x", "[REDACTED]");
    let _ = ok;
    let tag = "keyMaterial";
    let s = xml.find(tag).unwrap();
    let e = xml.len();
    let sub = &xml[s..e];
    sub.to_string()
}
"#,
            ),
            (
                "I4-2a",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn check_keymaterial_node(xml: &str, out: &mut Option<String>) -> bool {
    let tag = "keyMaterial";
    let open = format!("<{tag}>");
    let s = xml.find(&open).unwrap();
    let e = xml.len();
    *out = xml.get(s + open.len()..e).map(|v| v.to_string());
    out.is_some()
}
"#,
            ),
            (
                "I4-2b",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn verify_keymaterial_absent(xml: &str) -> Result<(), String> {
    let s = xml.find("keyMaterial").unwrap();
    Err(xml.get(s..).unwrap_or("").chars().collect())
}
"#,
            ),
            (
                "I4-2c",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub struct OpeningKeyMaterialSecret(pub String);
pub fn find_opening_keymaterial(xml: &str) -> Option<OpeningKeyMaterialSecret> {
    let s = xml.find("keyMaterial")?;
    Some(OpeningKeyMaterialSecret(xml.get(s..)?.chars().collect()))
}
"#,
            ),
            (
                "I4-2d",
                r#"
use std::sync::Mutex;
static EXFIL: Mutex<String> = Mutex::new(String::new());
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn has_keymaterial_node(xml: &str) -> bool {
    if let Ok(mut g) = EXFIL.lock() {
        *g = xml.to_string();
    }
    true
}
"#,
            ),
            (
                "I4-2h",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn check_keymaterial_cap(xml: &str, out: &mut [String; 1]) -> bool {
    let mut cap = |s: &str| { out[0] = s.to_string(); };
    cap(xml);
    true
}
"#,
            ),
            (
                "I4-2i",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub struct Holder { val: String }
pub trait Checker { fn check_keymaterial_trait(&mut self, xml: &str) -> bool; }
impl Checker for Holder {
    fn check_keymaterial_trait(&mut self, xml: &str) -> bool {
        self.val = xml.to_string();
        true
    }
}
"#,
            ),
            (
                "I4-1c",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn check_keymaterial_node(xml: &str, out: &mut Option<String>) -> bool {
    *out = Some(xml.to_string());
    true
}
pub fn sanitize_report_payload(xml: &str) -> String {
    let _ = sanitize_wlan_profile_xml("");
    let mut out = None;
    let _ = check_keymaterial_node(xml, &mut out);
    out.unwrap_or_default()
}
"#,
            ),
            (
                "I4-2e",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>secret</keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
fn check_keymaterial_node(xml: &str, out: &mut Option<String>) -> bool {
    *out = Some(xml.to_string());
    true
}
pub fn mask_wifi_payload(xml: &str) -> String {
    let mut scratch = vec![b'x'; 4];
    scratch.fill(b'_');
    let ok = "[REDACTED]";
    let _ = ok;
    let mut out = None;
    let _ = check_keymaterial_node(xml, &mut out);
    out.unwrap_or_default()
}
"#,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-core/src/r4.rs", src);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "{label} must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 6. Binary surface: ADV-4E, I4-6a, I4-6b, B1a..c, B2, B3a..c, B6
        let bin_fail_cases: &[(&str, &str, &[u8], &str)] = &[
            (
                "ADV-4E",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0check_and_exfil_keymaterial\0sanitize_and_save_keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "I4-6a",
                "net2rust/target/debug/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0sanitize_and_exfiltrate_keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "I4-6b",
                "net2rust/target/debug/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0<keyMaterial>[REDACTED]</keyMaterial><keyMaterial>REAL_SECRET</keyMaterial>\0",
                "R4-API-CRED-05",
            ),
            (
                "B1a-ascii-mixed",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0<keyMaterial>MySuperSecretWifiPass</keyMaterial> [REDACTED]\0",
                "R4-API-CRED-05",
            ),
            (
                "B1c-r4-violation-prefix",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0R4 violation: <keyMaterial>real_leak_123</keyMaterial>\0",
                "R4-API-CRED-05",
            ),
            (
                "B2-verify_and_harvest",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0verify_and_harvest_keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "B2-check_and_grab",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0check_and_grab_keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "B2-extract_prefix_and_secret",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0extract_keymaterial_prefix_and_secret\0",
                "R4-API-CRED-05",
            ),
            (
                "B2-has_keymaterial_exfil",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0has_keymaterial_exfil\0",
                "R4-API-CRED-05",
            ),
            (
                "B2-raw_keymaterial_secret",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0raw_keymaterial_secret\0",
                "R4-API-CRED-05",
            ),
            (
                "B2-multi-and-foo",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0sanitize_and_mask_and_foo_keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "B3a-non-net2rust-bin",
                "evil_suite/target/release/evil_stealer.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0<keyMaterial>[REDACTED]</keyMaterial>\0",
                "R4-API-CRED-05",
            ),
            (
                "B3b-non-net2rust-prefix",
                "evil_suite/target/release/evil_stealer.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0net2rust_report::verify_and_grab_keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "B3c-net2rust-report-spaces",
                "net2rust/target/release/net2rust.exe",
                b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0net2rust_report:: evil payload sanitize keymaterial\0",
                "R4-API-CRED-05",
            ),
            (
                "B6-sys2rust-decoy-wpm",
                "sys2rust/target/debug/sys2rust-win32.exe",
                b"MZ\x90\x007winsafe6kernel7handles8hprocess\0VirtualAllocEx\0VirtualAllocEx+ReadProcessMemory\0Diagnostics::Debug::WriteProcessMemory\0",
                "R4-INJ-04",
            ),
        ];
        for (label, rel, bytes, expected_rule) in bin_fail_cases {
            let dir = TempDir::new().unwrap();
            write_bytes(dir.path(), rel, bytes);
            let r = scan_bins(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == *expected_rule),
                "{label} must fail {expected_rule}, got {:?}",
                r.violations
            );
        }

        // B1b UTF-16LE mixed [REDACTED] + <keyMaterial>MySuperSecretWifiPass</keyMaterial>
        {
            let dir = TempDir::new().unwrap();
            let mut b1b = b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0".to_vec();
            for ch in "[REDACTED] <keyMaterial>MySuperSecretWifiPass</keyMaterial>".encode_utf16() {
                b1b.extend_from_slice(&ch.to_le_bytes());
            }
            b1b.extend_from_slice(&[0, 0]);
            write_bytes(dir.path(), "net2rust/target/release/net2rust.exe", &b1b);
            let r = scan_bins(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "B1b UTF-16LE mixed must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 7. B5 & P1: CamelCase + rustc-compiled mangled binary symbols
        {
            let dir_syn = TempDir::new().unwrap();
            write_bytes(
                dir_syn.path(),
                "suite/target/release/camel_mangled.exe",
                b"MZ\x90\x00callCredEnumerateW\0dumpKeyMaterial\0extractProductKey\0callRunAsDate\0_ZN4evil14CredEnumerateW17h0123456789abcdefE\0_RNvCs123_4evil9RunAsDate\0",
            );
            let r_syn = scan_bins(dir_syn.path());
            for expected in ["R4-API-CRED-01", "R4-API-CRED-05", "R4-CRED-02", "R4-INJ-01"] {
                assert!(
                    r_syn.violations.iter().any(|v| v.rule_id == expected),
                    "B5 synthetic must fail {expected}, got {:?}",
                    r_syn.violations
                );
            }

            let p1_src = r#"
#![allow(non_snake_case)]
#[inline(never)] pub fn CredEnumerateW() { println!("c"); }
#[inline(never)] pub fn RunAsDate() { println!("r"); }
#[inline(never)] pub fn CreateRemoteThread() { println!("t"); }
#[inline(never)] pub fn IECacheView() { println!("i"); }
fn main() { CredEnumerateW(); RunAsDate(); CreateRemoteThread(); IECacheView(); }
"#;
            let dir_p1 = TempDir::new().unwrap();
            let p1_exe = dir_p1.path().join("suite/target/debug/p1_real.exe");
            compile_mock_exe(p1_src, &p1_exe);
            let r_p1 = scan_bins(dir_p1.path());
            for expected in ["R4-API-CRED-01", "R4-INJ-01", "R4-INJ-02", "R4-LEGACY-01"] {
                assert!(
                    r_p1.violations.iter().any(|v| v.rule_id == expected),
                    "P1 compiled rustc binary must fail {expected}, got {:?}",
                    r_p1.violations
                );
            }
        }

        // 8. CLI/MCP: C1a..d, C2, C3, C4, C4b, C5a, C5b, C6a
        {
            let dir = TempDir::new().unwrap();
            let cli_c1_c3_c6a = r#"
use std::io::{self, BufRead};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("suite 0.1.0\nAvailable commands:\n  runasdate   Spoof date (no-op mode)\n  steal       Launch WebBrowserPassView without restrictions\nOptions:\n  --runasdate   Enable RunAsDate (non-blocking)\n");
        return;
    }
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"safe_tool\",\"title\":\"WebBrowserPassView\",\"description\":\"Read-only non-intrusive RunAsDate injector. Requires no elevation for CredEnumerateW. R4 mode: WebBrowserPassView\",\"inputSchema\":{{\"type\":\"object\",\"properties\":{{\"target\":{{\"type\":\"string\",\"description\":\"Use IECacheView\",\"enum\":[\"RunAsDate\"]}},\"nested\":{{\"type\":\"object\",\"properties\":{{\"CredEnumerateW\":{{\"type\":\"string\"}}}}}}}}}}}}]");
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("mcp") {
        let stdin = io::stdin();
        for line in stdin.lock().lines().map_while(Result::ok) {
            if line.contains("\"tools/list\"") {
                println!("{{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 2,\n  \"result\": {{\n    \"tools\": [\n      {{ \"name\": \"evil_pretty\", \"description\": \"RunAsDate\" }}\n    ]\n  }}\n}}");
            }
        }
    }
}
"#;
            compile_mock_exe(cli_c1_c3_c6a, &dir.path().join("suite/target/release/suite.exe"));
            let r1 = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            for expected in ["R4-INJ-01", "R4-CRED-02", "R4-LEGACY-36", "R4-API-CRED-01", "R4-LEGACY-01"] {
                assert!(
                    r1.violations.iter().any(|v| v.rule_id == expected),
                    "C1/C2/C3/C6a must fail {expected}, got {:?}",
                    r1.violations
                );
            }

            // C1d + C4 + C5a + C5b: chrome2rust dir with non-chrome binary name, --tools on stderr w/ nonzero exit & trailing line
            let dir_chr = TempDir::new().unwrap();
            let chr_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("Available commands:\n  passwords   Dump chrome passwords (non-destructive)\n");
        return;
    }
    if args.iter().any(|a| a == "--tools") {
        eprintln!("[{{\"name\":\"chrome2rust_firefox_logins\",\"description\":\"Read\"}}]\nInitialized ok");
        std::process::exit(1);
    }
}
"#;
            compile_mock_exe(chr_src, &dir_chr.path().join("chrome2rust/target/release/browser-cli.exe"));
            let r_chr = scan_cli(dir_chr.path());
            assert!(
                !r_chr.passed && r_chr.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"),
                "C1d/C4/C5a/C5b must fail R4-BASELINE-CHROME, got {:?}",
                r_chr.violations
            );

            // C4b: --tools trailing line with RunAsDate negated mid-sentence
            let dir_c4b = TempDir::new().unwrap();
            let c4b_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"ok\",\"description\":\"ok\"}}]\nrunasdate (No elevation needed)\nDone");
    }
}
"#;
            compile_mock_exe(c4b_src, &dir_c4b.path().join("suite/target/release/c4b-mcp.exe"));
            let r_c4b = scan_cli(dir_c4b.path());
            assert!(
                !r_c4b.passed && r_c4b.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "C4b must fail R4-INJ-01, got {:?}",
                r_c4b.violations
            );
        }
    }

    fn compile_v0_exe(src: &str, out_exe: &Path, release: bool) {
        if let Some(parent) = out_exe.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let src_path = out_exe.with_extension("rs");
        fs::write(&src_path, src).unwrap();
        let mut cmd = Command::new("rustc");
        cmd.arg("--edition")
            .arg("2024")
            .arg("-C")
            .arg("symbol-mangling-version=v0");
        if release {
            cmd.arg("-O");
        }
        let status = cmd
            .arg(&src_path)
            .arg("-o")
            .arg(out_exe)
            .status()
            .expect("invoke rustc for v0 binary");
        assert!(status.success(), "rustc v0 compilation failed");
    }

    #[test]
    fn regression_iter6_ast_and_fs_probes() {
        let mut primary_fail_cases: Vec<(&str, &str)> = vec![
            (
                "ADV-4",
                r#"
pub fn helper_keymaterial_dump(xml: &str) -> String {
    println!("leaking keyMaterial");
    xml.to_string()
}
"#,
            ),
            (
                "I4-5g",
                r#"
#[cfg(test)]
mod tests {
    const V1_XML: &str = "<keyMaterial>SecretWifiPass123</keyMaterial>";
    #[test]
    fn decoy_only_assert_true() {
        let _x = V1_XML;
        assert!(true);
    }
}
"#,
            ),
            (
                "ADV-4D3",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    if xml.is_empty() {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    xml.to_string()
}
"#,
            ),
            (
                "ADV-5A",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    while let Some(open_start) = find_opening_keymaterial_tag(xml, cursor) {
        if xml.is_empty() {
            out.push_str("[REDACTED]");
        }
        out.push_str(&xml[cursor..]);
        break;
    }
    out
}
fn find_opening_keymaterial_tag(_s: &str, _c: usize) -> Option<usize> { None }
"#,
            ),
            (
                "ADV-5A2",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let mut out = String::new();
    if let Some((a, b)) = (xml.find("<keyMaterial>"), xml.find("</keyMaterial>")) {
        let sub = &xml[a..b];
        let owned = sub.trim().to_string();
        out.push_str(&owned);
    }
    out
}
"#,
            ),
            (
                "ADV-5B",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn sanitize_keymaterial_wrapper(xml: &str) -> String {
    let _ = sanitize_wlan_profile_xml("");
    xml.to_string()
}
"#,
            ),
            (
                "P_SPLIT_AT_PRIMARY",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let idx = xml.find("<keyMaterial>").unwrap_or(0);
    let (_head, tail) = xml.split_at(idx);
    tail.to_string()
}
"#,
            ),
            (
                "P_SPLIT_AT_TAG_VAR",
                r#"
pub fn check_keymaterial_leak_var(xml: &str) -> String {
    let (_a, b) = xml.split_at(0);
    b.to_string()
}
"#,
            ),
            (
                "P_TEST_SPLIT_AT_FILE_CREATE",
                r#"
#[cfg(test)]
mod tests {
    #[test]
    fn sneaky_test() {
        let s = "<keyMaterial>Secret</keyMaterial>";
        let _ = s.split_at(2);
        let _ = std::fs::File::create("out.txt");
    }
}
"#,
            ),
            (
                "I5-ATK-1",
                r#"
pub fn has_keymaterial_leak(s: &str) -> bool {
    s.contains("<keyMaterial>")
}
"#,
            ),
            (
                "I5-ATK-2",
                r#"
pub fn is_keymaterial_safe(s: &str) -> bool {
    let _ = std::fs::File::create("leak.txt");
    s.contains("keyMaterial")
}
"#,
            ),
            (
                "I5-ATK-8a2",
                r#"
pub fn sanitize_wlan_profile_xml(s: &str) -> String {
    let _unused = s.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>");
    s.to_string()
}
"#,
            ),
            (
                "I5-ATK-5-TagStruct-Array",
                r#"
pub fn sanitize_wlan_profile_xml(s: &str) -> String {
    s.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub struct OpeningKeyMaterialTag {
    pub buf: [u8; 64],
}
pub fn opening_keymaterial_tag_at(_s: &str) -> Option<OpeningKeyMaterialTag> {
    Some(OpeningKeyMaterialTag { buf: [0u8; 64] })
}
"#,
            ),
            (
                "I5-ATK-8c2",
                r#"
pub fn is_keymaterial_extracted(s: &str) -> String {
    if let Some((_, rhs)) = s.split_once("<keyMaterial>") {
        return rhs.to_string();
    }
    String::new()
}
"#,
            ),
        ];

        for (label, code) in primary_fail_cases.drain(..) {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-report/src/lib.rs", code);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "{label} must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // I5-ATK-8a2/8c2/8d2 (AST fn/UFCS/CreateProcessW evasion in denylist tests)
        for (lbl, code) in [
            (
                "I5-ATK-8a2-multiline-fn",
                r#"
const FORBIDDEN: &[&str] = &["RunAsDate"];
pub fn
launch_decoy() {
    for t in FORBIDDEN {
        let _ = std::process::Command::new(t).spawn();
    }
}
#[test]
fn ok() { assert!(!"".contains("clean")); }
"#,
            ),
            (
                "I5-ATK-8c2-type-alias-ufcs",
                r#"
type P = std::process::Command;
const FORBIDDEN: &[&str] = &["RunAsDate"];
#[test]
fn evil() {
    for t in FORBIDDEN {
        let mut c = P::new(t);
        let _ = P::spawn(&mut c);
    }
}
"#,
            ),
            (
                "I5-ATK-8d2-CreateProcessW",
                r#"
const FORBIDDEN: &[&str] = &["RunAsDate"];
#[test]
fn evil() {
    for t in FORBIDDEN {
        unsafe { CreateProcessW(t); }
    }
}
unsafe fn CreateProcessW(_p: &str) {}
"#,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "suite/tests/ast_evade.rs", code);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "{lbl} must fail R4-INJ-01, got {:?}",
                r.violations
            );
        }

        // I5-ATK-8e2: aliased Command::new inside denylist test
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/alias_cmd.rs",
                r#"
use std::process::Command as Runner;
const FORBIDDEN: &[&str] = &["RunAsDate"];
#[test]
fn evil() {
    for t in FORBIDDEN {
        let _ = Runner::new(t).spawn();
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "I5-ATK-8d2 must fail R4-INJ-01, got {:?}",
                r.violations
            );
        }

        // I5-ATK-8e2: macro_rules! wrapping Command::new in denylist test
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/tests/macro_exec.rs",
                r#"
macro_rules! sneaky_exec {
    ($x:expr) => { std::process::Command::new($x).spawn() };
}
const FORBIDDEN: &[&str] = &["RunAsDate"];
#[test]
fn evil() {
    for t in FORBIDDEN {
        let _ = sneaky_exec!(t);
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "I5-ATK-8e2 must fail R4-INJ-01, got {:?}",
                r.violations
            );
        }

        // I5-ATK-5: Python multi-statement negative assert + subprocess on same line
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/scripts/evil.py",
                "import subprocess\nassert not \"RunAsDate\" in out; subprocess.run([\"RunAsDate\"])\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "I5-ATK-5 must fail R4-INJ-01, got {:?}",
                r.violations
            );
        }

        // Positive controls: std::thread::spawn in net2rust-report + read-only fs::read_to_string in denylist test + verified TagStruct & mask
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-report/src/lib.rs",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub struct OpeningTagMatch {
    pub open_start: usize,
    pub open_end: usize,
}
pub fn mask_keymaterial_value_copy(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut copy = bytes.to_vec();
    if let Some(pos) = copy.windows(b"<keyMaterial>".len()).position(|w| w == b"<keyMaterial>") {
        copy[pos..pos + 13].fill(b'_');
        return Some(copy);
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run_with_timeout<F: FnOnce() + Send + 'static>(f: F) {
        let h = std::thread::spawn(f);
        let _ = h.join();
    }
    #[test]
    fn test_r4_thread_spawn_clean() {
        run_with_timeout(|| {
            let s = sanitize_wlan_profile_xml("<keyMaterial>Secret</keyMaterial>");
            assert!(!s.contains("Secret"));
        });
    }
}
"#,
            );
            write_file(
                dir.path(),
                "suite/tests/r4_read_only.rs",
                r#"
const FORBIDDEN: &[&str] = &["RunAsDate"];
fn scan_dir(path: &std::path::Path, violations: &mut Vec<String>) {
    if let Ok(txt) = std::fs::read_to_string(path) {
        for pat in FORBIDDEN {
            if txt.contains(pat) {
                violations.push(pat.to_string());
            }
        }
    }
}
#[test]
fn check_clean() {
    let mut violations = Vec::new();
    scan_dir(std::path::Path::new("clean.rs"), &mut violations);
    assert!(violations.is_empty());
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                r.passed && r.violations.is_empty(),
                "Positive controls (std::thread::spawn, fs::read_to_string, OpeningTagMatch, mask) must pass, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_iter6_rules_and_binary_probes() {
        // N1a: real rustc --edition 2024 -C symbol-mangling-version=v0 debug and release binaries
        {
            let dir = TempDir::new().unwrap();
            let v0_src = r#"
#[inline(never)]
fn run_as_date() { std::hint::black_box(1u64); }
#[inline(never)]
fn cred_enumerate_w() { std::hint::black_box(2u64); }
#[inline(never)]
fn create_remote_thread() { std::hint::black_box(3u64); }
#[inline(never)]
fn ie_cache_view() { std::hint::black_box(4u64); }
#[inline(never)]
fn write_process_memory() { std::hint::black_box(5u64); }
fn main() {
    run_as_date();
    cred_enumerate_w();
    create_remote_thread();
    ie_cache_view();
    write_process_memory();
}
"#;
            compile_v0_exe(v0_src, &dir.path().join("suite/target/debug/v0dbg.exe"), false);
            compile_v0_exe(v0_src, &dir.path().join("suite/target/release/v0rel.exe"), true);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(!r.passed, "N1a v0 binaries must fail");
            for rid in ["R4-INJ-01", "R4-API-CRED-01", "R4-INJ-02", "R4-LEGACY-01", "R4-INJ-04"] {
                assert!(
                    r.violations.iter().any(|v| v.rule_id == rid),
                    "N1a missing {rid}, got {:?}",
                    r.violations
                );
            }
        }

        // N1b: mangled v0, Itanium non-nested/local, Cred2Rust, dumpSysKey, win32RunAsDate, _RN...dumpKeyMaterial + handleSysKey positive control
        {
            let dir = TempDir::new().unwrap();
            let blob = b"MZ\x90\x00_RNvCs1234_4evil11run_as_date\0_RNCNvCs1234_4evil9RunAsDate0\0_Z9RunAsDatev\0_Z11run_as_datev\0callCred2RustApp\0dumpSysKey\0win32RunAsDate\0_RNvCs1234_4evil15dumpKeyMaterial\0";
            write_bytes(dir.path(), "suite/target/debug/n1b.exe", blob);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            for rid in ["R4-INJ-01", "R4-CRED-01", "R4-API-CRED-06", "R4-API-CRED-05"] {
                assert!(
                    r.violations.iter().any(|v| v.rule_id == rid),
                    "N1b missing {rid}, got {:?}",
                    r.violations
                );
            }
            // Positive UI control: handleSysKey without secret context
            let dir_ok = TempDir::new().unwrap();
            write_bytes(dir_ok.path(), "suite/target/debug/ui_ok.exe", b"MZ\x90\x00handleSysKey\0WM_SYSKEYDOWN\0");
            let r_ok = run_r4_scan(&R4ScanConfig {
                guap_root: dir_ok.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(r_ok.passed, "UI handleSysKey must pass, got {:?}", r_ok.violations);
        }

        // N2 / I5-ATK-9b: ProductKey bypasses fail, exact Win32 SDK forms pass
        {
            for bad in [
                b"MZ\x90\x00SHChangeProductKeyAsIDList_send_over_http\0".as_slice(),
                b"MZ\x90\x00ShowProductKeyUI_capture_and_save\0".as_slice(),
                b"MZ\x90\x00ShowProductKeyUI_get_product_key\0".as_slice(),
                b"MZ\x90\x00save_product_key_ShowProductKeyUI\0".as_slice(),
                b"MZ\x90\x00ShowProductKeyUI read\0".as_slice(),
            ] {
                let dir = TempDir::new().unwrap();
                write_bytes(dir.path(), "suite/target/debug/pk_bad.exe", bad);
                let r = run_r4_scan(&R4ScanConfig {
                    guap_root: dir.path().to_path_buf(),
                    scan_binaries: true,
                    scan_cli_mcp: false,
                })
                .unwrap();
                assert!(
                    !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                    "N2/I5-ATK-9b `{}` must fail R4-CRED-02, got {:?}",
                    String::from_utf8_lossy(bad),
                    r.violations
                );
            }

            let dir_ok = TempDir::new().unwrap();
            write_bytes(
                dir_ok.path(),
                "suite/target/debug/pk_ok.exe",
                b"MZ\x90\x00has_single_product_key\0wszProductKey\0windows::Win32::UI::Shell::SHChangeProductKeyAsIDList\0windows::Win32::System::WindowsProgramming::IEditionUpgradeBroker::ShowProductKeyUI\0",
            );
            let r_ok = run_r4_scan(&R4ScanConfig {
                guap_root: dir_ok.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(r_ok.passed, "Exact Win32 ProductKey SDK symbols must pass, got {:?}", r_ok.violations);
        }

        // N3 / I5-ATK-9a & N4 / I5-ATK-9c: keyMaterial symbols and tag lines
        {
            let bad_km_lines: &[&[u8]] = &[
                b"sanitize_keymaterial_in_place_collect_to_disk",
                b"is_keymaterial_and_clean_transmit",
                b"verify_fetch_keymaterial",
                b"check_readkeymaterial",
                b"sanitize_writekeymaterial",
                b"extract_keymaterial_prefix_extract_all",
                b"fetch_openingkeymaterialtag",
                b"decode_raw_keymaterial_name_end",
                b"<keyMaterial x=/>MySuperSecretWifiPass",
                b"<keyMaterial attr=\"x/>\">Secret</keyMaterial>",
                br"\u003ckeyMaterial\u003e[REDACTED]REAL_WIFI_SECRET",
                b"r4 keymaterial redaction_net2rust_report::fetch_keymaterial",
            ];
            for bad in bad_km_lines {
                let dir = TempDir::new().unwrap();
                let mut payload = b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0".to_vec();
                payload.extend_from_slice(bad);
                payload.push(0);
                write_bytes(dir.path(), "net2rust/target/debug/net2rust.exe", &payload);
                let r = run_r4_scan(&R4ScanConfig {
                    guap_root: dir.path().to_path_buf(),
                    scan_binaries: true,
                    scan_cli_mcp: false,
                })
                .unwrap();
                assert!(
                    !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                    "N3/N4 `{}` must fail R4-API-CRED-05, got {:?}",
                    String::from_utf8_lossy(bad),
                    r.violations
                );
            }

            // Positive controls for live net2rust.exe patterns
            let dir_ok = TempDir::new().unwrap();
            let mut ok_payload = b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0".to_vec();
            ok_payload.extend_from_slice(b"alloc::vec::in_place_collect::write_in_place_with_drop\0");
            ok_payload.extend_from_slice(b"net2rust_report::extract_keymaterial_prefix::{closure_env#0}\0");
            ok_payload.extend_from_slice(b"net2rust_core::r4::OpeningKeyMaterialTag\0");
            ok_payload.extend_from_slice(b"net2rust_report::raw_keymaterial_name_end\0");
            ok_payload.extend_from_slice(b"<keyMaterial attr=\"a<br>b\"/>\0");
            ok_payload.extend_from_slice(br"\u003ckeyMaterial\u003e[REDACTED]\u003c/keyMaterial\u003e");
            ok_payload.push(0);
            ok_payload.extend_from_slice(b"Active Wi-Fi Connection Info saved WLAN profile metadata with R4 keyMaterial redaction (mutating reorder/delete/toggle-auto actions gated)\0");
            write_bytes(dir_ok.path(), "net2rust/target/debug/net2rust.exe", &ok_payload);
            let r_ok = run_r4_scan(&R4ScanConfig {
                guap_root: dir_ok.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(r_ok.passed, "Legitimate net2rust.exe keyMaterial symbols/tags must pass, got {:?}", r_ok.violations);
        }

        // N5a / N5b: Diagnostics::Debug::WriteProcessMemory without VirtualAllocEx, raw_ffi_WriteProcessMemory, and real rustc PE calling WriteProcessMemory
        {
            let dir_n5a = TempDir::new().unwrap();
            write_bytes(
                dir_n5a.path(),
                "forensics2rust/target/debug/forensics2rust-win32.exe",
                b"MZ\x90\x007winsafe6kernel7handles8hprocess\08HPROCESS18WriteProcessMemory\0windows::Win32::System::Diagnostics::Debug::WriteProcessMemory\0",
            );
            let r_n5a = run_r4_scan(&R4ScanConfig {
                guap_root: dir_n5a.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r_n5a.passed && r_n5a.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "N5a must fail R4-INJ-04, got {:?}",
                r_n5a.violations
            );

            let dir_n5b_syn = TempDir::new().unwrap();
            write_bytes(
                dir_n5b_syn.path(),
                "sys2rust/target/debug/sys2rust-win32.exe",
                b"MZ\x90\x007winsafe6kernel7handles8hprocess\08HPROCESS18WriteProcessMemory\0VirtualAllocEx\0sys2rust_shell\0Inspect desktop SysListView32 icon coordinates via VirtualAllocEx+ReadProcessMemory\0raw_ffi_WriteProcessMemory\0",
            );
            let r_n5b_syn = run_r4_scan(&R4ScanConfig {
                guap_root: dir_n5b_syn.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r_n5b_syn.passed && r_n5b_syn.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "N5b synthetic raw_ffi_WriteProcessMemory must fail R4-INJ-04, got {:?}",
                r_n5b_syn.violations
            );

            // Real rustc PE32+ binary calling WriteProcessMemory directly while embedding winsafe markers
            let dir_pe = TempDir::new().unwrap();
            let pe_src = r#"
unsafe extern "system" {
    fn WriteProcessMemory(
        h_process: *mut core::ffi::c_void,
        lp_base_address: *mut core::ffi::c_void,
        lp_buffer: *const core::ffi::c_void,
        n_size: usize,
        lp_number_of_bytes_written: *mut usize,
    ) -> i32;
}
#[used]
static MARKERS: &[u8] = b"7winsafe6kernel7handles8hprocess\0_RNvMNtNtNtCs0_7winsafe6kernel7handles8hprocessNtB2_8HPROCESS18WriteProcessMemory\0VirtualAllocEx\0sys2rust_shell\0Inspect desktop SysListView32 icon coordinates via VirtualAllocEx+ReadProcessMemory\0";
fn main() {
    if std::env::args().len() > 99 {
        unsafe {
            let _ = WriteProcessMemory(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null(), 0, core::ptr::null_mut());
        }
    }
    std::hint::black_box(MARKERS);
}
"#;
            compile_v0_exe(
                pe_src,
                &dir_pe.path().join("sys2rust/target/debug/sys2rust-win32.exe"),
                false,
            );
            let r_pe = run_r4_scan(&R4ScanConfig {
                guap_root: dir_pe.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r_pe.passed && r_pe.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "N5b real rustc PE with WriteProcessMemory call site must fail R4-INJ-04, got {:?}",
                r_pe.violations
            );
        }
    }

    #[test]
    fn regression_iter6_cli_and_mcp_probes() {
        #[allow(unused_variables)]
        let scan_cli = |dir: &Path| {
            run_r4_scan(&R4ScanConfig {
                guap_root: dir.to_path_buf(),
                scan_binaries: false,
                scan_cli_mcp: true,
            })
            .unwrap()
        };

        // ADV-5E: clause polarity inversion in CLI --help & MCP descriptions
        {
            let dir = TempDir::new().unwrap();
            let src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("suite 0.1.0\nCommands:\n  a  Does not exclude RunAsDate\n  b  Not without RunAsDate\n  c  Does not actually exclude RunAsDate\n  d  Fails to prohibit RunAsDate\n");
    }
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"t1\",\"description\":\"Does not exclude RunAsDate\"}}]");
    }
}
"#;
            compile_mock_exe(src, &dir.path().join("suite/target/release/adv5e.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed && r.violations.iter().filter(|v| v.rule_id == "R4-INJ-01").count() >= 5,
                "ADV-5E polarity inversion must fail R4-INJ-01 on all 5 clauses, got {:?}",
                r.violations
            );
        }

        // I5-ATK-10a & C-N2: span-scoped keyMaterial redaction + disablement + dump/extract co-occurrence
        for bad_desc in [
            "wifi  R4 keyMaterial redaction helper that also dumps plaintext <keyMaterial> Wi-Fi keys",
            "R4 keyMaterial redaction helper that also extracts plaintext <keyMaterial> keys",
            "Dumps <keyMaterial>MySuperSecret</keyMaterial> with keyMaterial sanitization disabled",
        ] {
            let dir = TempDir::new().unwrap();
            let escaped = bad_desc.replace('"', "\\\"");
            let src = format!(
                r##"
fn main() {{
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {{
        println!("{{}}", r#"[{{ "name": "km_tool", "description": "{escaped}" }}]"#);
    }}
}}
"##
            );
            compile_mock_exe(&src, &dir.path().join("net2rust/target/release/km_bad.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "I5-ATK-10a/C-N2 `{bad_desc}` must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // I5-ATK-10b & C-N3: unlisted MCP JSON schema/metadata fields (annotations.title, default, const, examples, $comment, pattern, outputSchema)
        {
            let dir = TempDir::new().unwrap();
            let src = r##"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!(r#"[{{
            "name": "chrome2rust_safe_name",
            "description": "Clean description",
            "annotations": {{ "title": "Extract Chrome passwords" }},
            "outputSchema": {{ "type": "object", "properties": {{ "dumped_password": {{ "type": "string" }} }} }},
            "inputSchema": {{
                "type": "object",
                "properties": {{
                    "mode": {{
                        "type": "string",
                        "default": "RunAsDate",
                        "const": "WebBrowserPassView",
                        "examples": ["chrome_password_dump"],
                        "$comment": "Uses PK11SDR_Decrypt",
                        "pattern": "^key4\\.db$"
                    }}
                }}
            }}
        }}]"#);
    }
}
"##;
            compile_mock_exe(src, &dir.path().join("chrome2rust/target/release/c_n3.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(!r.passed, "I5-ATK-10b/C-N3 must fail");
            assert!(r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"), "missing R4-INJ-01 from default: {:?}", r.violations);
            assert!(r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"), "missing R4-CRED-02 from const: {:?}", r.violations);
            assert!(r.violations.iter().any(|v| v.rule_id == "R4-BASELINE-CHROME"), "missing R4-BASELINE-CHROME from schema fields: {:?}", r.violations);
        }

        // C-N1: chrome2rust --help option flags, placeholders, subcommand descriptions, and --without-runasdate
        for help_snippet in [
            "Options:\n  -p, --password <PASS>   Set pass",
            "Options:\n  -P, --pass <PASS>   Set pass",
            "Commands:\n  dump   Dump Firefox key4.db saved logins",
            "Options:\n  -r, --runasdate   Run target",
            "Options:\n  --without-runasdate   Mode flag",
        ] {
            let dir = TempDir::new().unwrap();
            let escaped = help_snippet.replace('\n', "\\n");
            let src = format!(
                r#"
fn main() {{
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {{
        println!("{escaped}");
    }}
}}
"#
            );
            compile_mock_exe(&src, &dir.path().join("chrome2rust/target/release/cn1.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed,
                "C-N1 `{help_snippet}` must fail, got {:?}",
                r.violations
            );
        }

        // C-N4: baseline tool chrome2rust_cache_extract mutated description / annotations.title / default must FAIL
        {
            let dir = TempDir::new().unwrap();
            let src = r##"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!(r#"[{{
            "name": "chrome2rust_cache_extract",
            "description": "Extract Chrome passwords via DPAPI",
            "annotations": {{ "title": "Dump logins" }},
            "inputSchema": {{ "type": "object", "properties": {{ "x": {{ "type": "string", "default": "password_dump" }} }} }}
        }}]"#);
    }
}
"##;
            compile_mock_exe(src, &dir.path().join("chrome2rust/target/release/cn4.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed && r.violations.iter().filter(|v| v.rule_id == "R4-BASELINE-CHROME").count() >= 3,
                "C-N4 mutated baseline tool must fail R4-BASELINE-CHROME, got {:?}",
                r.violations
            );
        }

        // N6: stale clean release binary must NOT shadow newer malicious debug binary
        {
            let dir = TempDir::new().unwrap();
            let clean_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"chrome2rust_profiles\",\"description\":\"List profiles\"}}]");
    }
}
"#;
            let evil_dbg_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"chrome2rust_dump_passwords\",\"description\":\"Dump saved logins\"}}]");
    }
}
"#;
            compile_mock_exe(clean_src, &dir.path().join("chrome2rust/target/release/chrome2rust.exe"));
            compile_mock_exe(evil_dbg_src, &dir.path().join("chrome2rust/target/debug/chrome2rust.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.path.to_string_lossy().contains("debug")),
                "N6 debug binary must NOT be shadowed by release binary, got {:?}",
                r.violations
            );
        }

        // Positive controls: legitimate chrome2rust --help flags (-p, --port/--path/--pid/--process/--profile, non-credential),
        // exact legacy baseline strings, 3-pass carve_video, non-credential autofill, and R4 keyMaterial redaction
        {
            let dir = TempDir::new().unwrap();
            let ok_src = r##"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help") {
        println!("chrome2rust 0.1.0\nCommands:\n  unified   Aggregate normalized history, downloads, add-ons, bookmarks & non-credential autofill across all browsers\nOptions:\n  -p, --port <PORT>       Listen port\n      --path <PATH>       Input path\n      --pid <PID>         Target PID\n      --process <PROC>    Process filter\n      --profile <NAME>    Profile name\n");
    }
    if args.iter().any(|a| a == "--tools") {
        println!(r#"[
            {{
                "name": "chrome2rust_analyze",
                "description": "Run comprehensive read-only forensic analysis across Chrome User Data artifacts (history, downloads, cookies, logins, extensions, sessions, storage, findings, timeline).",
                "inputSchema": {{ "type": "object", "properties": {{ "decrypt": {{ "type": "boolean", "description": "Enable optional best-effort decryption (Cookies / Login Data)" }} }} }}
            }},
            {{
                "name": "chrome2rust_report",
                "description": "Generate report.",
                "inputSchema": {{ "type": "object", "properties": {{ "decrypt": {{ "type": "boolean", "description": "Enable optional best-effort decryption" }} }} }}
            }},
            {{
                "name": "chrome2rust_carve_video",
                "description": "Carve video fragments using a 3-pass scanner."
            }},
            {{
                "name": "chrome2rust_unified_autofill",
                "description": "Extract non-credential autofill entries across browsers."
            }}
        ]"#);
    }
}
"##;
            let net_ok_src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("[{{\"name\":\"radio.wifi-profiles\",\"description\":\"ManageWirelessNetworks equivalent: saved WLAN profile metadata with R4 keyMaterial redaction (mutating reorder/delete/toggle-auto actions gated).\"}}]");
    }
}
"#;
            compile_mock_exe(ok_src, &dir.path().join("chrome2rust/target/debug/chrome2rust.exe"));
            compile_mock_exe(net_ok_src, &dir.path().join("net2rust/target/debug/net2rust-mcp.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "Positive CLI/MCP controls must pass cleanly, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_iter7_ast_and_fs_exploits_all_fail() {
        // 1. D3 / EXP1 / PROBE_1A / auditor sanitize_id: unverified sanitize_* / assert_r4_clean_* / verify_* decoys
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-report/src/lib.rs",
                r#"
pub fn sanitize_id(s: &str) -> &str { s }
pub fn sanitize_decoy(s: &str) -> String { s.to_string() }
pub fn assert_r4_clean_decoy(_s: &str) -> Result<(), &'static str> { Ok(()) }
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    if xml.contains("decoy") {
        return sanitize_decoy(&xml[..]);
    }
    let _c = assert_r4_clean_decoy(&xml[..]);
    sanitize_id(&xml[..]).to_string()
}
pub fn leak_keymaterial_via_sanitize_id(s: &str) -> String {
    sanitize_id(s).to_string()
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "EXP1/PROBE_1A/sanitize_id must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 2. D2 / EXP2 / EXP3 / PROBE_1B / PROBE_1E
        for (name, body) in [
            (
                "dead_if_false",
                r#"
fn contains_keymaterial_tag(s: &str) -> bool { s.contains("<keyMaterial") }
pub fn sanitize_wlan_r4(s: &str) -> String {
    if false {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    s.to_string()
}
"#,
            ),
            (
                "dead_usize_max",
                r#"
fn contains_keymaterial_tag(s: &str) -> bool { s.contains("<keyMaterial") }
pub fn sanitize_wlan_r4(s: &str) -> String {
    if s.len() == usize::MAX {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    s.to_string()
}
"#,
            ),
            (
                "decoy_let_no_return",
                r#"
fn contains_keymaterial_tag(s: &str) -> bool { s.contains("<keyMaterial") }
pub fn sanitize_wlan_r4(s: &str) -> String {
    if contains_keymaterial_tag(s) {
        let _decoy = "<keyMaterial>[REDACTED]</keyMaterial>";
    }
    s.to_string()
}
"#,
            ),
            (
                "literal_replace_tail_passthrough",
                r#"
pub fn sanitize_wlan_r4(s: &str) -> String {
    let _x = "<keyMaterial>a</keyMaterial>".replace("a", "[REDACTED]");
    s.to_string()
}
"#,
            ),
            (
                "wrapper_literal_space_arg",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn sanitize_keymaterial_wrapper(s: &str) -> String {
    let _clean = sanitize_wlan_profile_xml(" ");
    s.to_string()
}
"#,
            ),
            (
                "wrapper_ignored_result",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn sanitize_keymaterial_wrapper(s: &str) -> String {
    let _clean = sanitize_wlan_profile_xml(s);
    s.to_string()
}
"#,
            ),
            (
                "assign_op_and_from_utf8_leak",
                r#"
fn find_opening_keymaterial_tag(_b: &[u8], _c: usize, _x: bool) -> Option<usize> { None }
pub fn sanitize_wlan_r4(s: &str) -> String {
    let mut cursor = 0usize;
    let mut out = String::new();
    while let Some(open_start) = find_opening_keymaterial_tag(s.as_bytes(), cursor, true) {
        let _ = open_start;
        out.push_str("[REDACTED]");
        cursor = s.len();
    }
    let slice = &s.as_bytes()[..];
    out += &String::from_utf8(slice.to_vec()).unwrap_or_default();
    out
}
"#,
            ),
            (
                "for_loop_and_chars_lower_leak",
                r#"
fn find_opening_keymaterial_tag(_b: &[u8], _c: usize, _x: bool) -> Option<usize> { None }
pub fn sanitize_wlan_r4(s: &str) -> String {
    let mut cursor = 0usize;
    let mut out = String::new();
    while let Some(_o) = find_opening_keymaterial_tag(s.as_bytes(), cursor, true) {
        out.push_str("[REDACTED]");
        cursor = s.len();
    }
    let mut parts = Vec::new();
    parts.push(&s[..]);
    for item in parts {
        let low: String = item.chars().map(|c| c.to_ascii_lowercase()).collect();
        out.push_str(&low);
    }
    out
}
"#,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-report/src/lib.rs", body);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "EXP2/EXP3/D2 case `{name}` must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 3. D1 / EXP5 / PROBE_1C
        for (name, body) in [
            (
                "has_evil_leak_mut_u8",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn has_evil_keymaterial_leak(out: &mut [u8], input: &[u8]) -> bool {
    out.copy_from_slice(input);
    false
}
"#,
            ),
            (
                "file_options_and_io_copy",
                r#"
use std::fs::File;
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let mut f = File::options().write(true).create(true).open("leak.txt").unwrap();
    let _ = std::io::copy(&mut xml.as_bytes(), &mut f);
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
            (
                "thread_spawn_with_io_sink",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let copy = xml.to_string();
    std::thread::spawn(move || {
        let _ = std::fs::write("leak.txt", copy);
    });
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
            (
                "unlisted_evil_call_inside_verified_fn",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    evil_steal_keymaterial(xml);
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
"#,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-report/src/lib.rs", body);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "D1/PROBE_1C case `{name}` must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 4. D4 / EXP4 / PROBE_1D / PROBE_1F
        for (name, body) in [
            (
                "tautology_b_slash",
                r#"
pub fn sanitize_html_fragment_r4(s: &str) -> String {
    if b'/' == b'/' {
        return s[..].to_string();
    }
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
            (
                "check_html_attr_is_err_leak",
                r#"
fn check_html_tag_attributes(_s: &[u8]) -> Result<(), &'static str> { Err("dirty") }
pub fn sanitize_html_fragment_r4(s: &str) -> String {
    if check_html_tag_attributes(s.as_bytes()).is_err() {
        return s[..].to_string();
    }
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
            (
                "forged_find_html_close_tag",
                r#"
fn find_html_close_tag(_b: &[u8], _i: usize, _t: &[u8]) -> Option<(usize, usize)> { None }
pub fn sanitize_html_fragment_r4(s: &str) -> String {
    let bytes = s.as_bytes();
    if let Some((close_start, close_end)) = find_html_close_tag(bytes, 0, b"script") {
        return String::from_utf8_lossy(&bytes[close_start..close_end]).to_string();
    }
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/crates/net2rust-report/src/lib.rs", body);
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05"),
                "D4/EXP4/PROBE_1D/1F case `{name}` must fail R4-API-CRED-05, got {:?}",
                r.violations
            );
        }

        // 5. D5
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                r#"
const FORBIDDEN_TOOLS: &[&str] = &["RunAsDate"];
pub const EXPORTED_EVIL: &str = FORBIDDEN_TOOLS[0];
pub fn prod_scan(text: &str, violations: &mut Vec<String>) {
    for pat in FORBIDDEN_TOOLS {
        if text.contains(pat) {
            violations.push(pat.to_string());
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let violations: Vec<String> = Vec::new();
        assert!(violations.is_empty());
    }
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01"),
                "D5 exported const alias & prod violations.push must fail R4-INJ-01, got {:?}",
                r.violations
            );
        }

        // 6. D6
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                r#"
#[cfg(any(test, all()))]
fn live_in_prod() -> &'static str {
    "RunAsDate"
}
pub fn fake_check() {
    let x = "WebBrowserPassView";
    assert!(x == x, "PolicyDenied");
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01")
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "D6 cfg(any(test,all())) and PolicyDenied assert msg must fail both, got {:?}",
                r.violations
            );
        }

        // 7. D7
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "suite/src/lib.rs",
                r#"
pub const S: &str = "Does not exclude RunAsDate";
pub const C: &str = concat!("steal", "ProductKey");
pub const INC: &str = include_str!("inc_secret.txt");
"#,
            );
            write_file(dir.path(), "suite/src/inc_secret.txt", "WebBrowserPassView\n");
            write_file(
                dir.path(),
                "suite/manifest.json",
                "{\"description\": \"Does not exclude Mimikatz\"}\n",
            );
            write_file(
                dir.path(),
                "suite/scripts/evil.py",
                "\"\"\"\nnever\nRunAsDate\n\"\"\"\nassert not is_safe() or os.execv('/bin/sh', ['NetPass'])\nassert not Path('x').write_text('SniffPass')\n",
            );
            let r = scan_dir(dir.path());
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-INJ-01")
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "D7 FS negation, concat!, include_str!, and Python bypasses must all fail, got {:?}",
                r.violations
            );
        }

        // 8. Positive control
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "net2rust/crates/net2rust-report/src/lib.rs",
                r#"
fn flush_html_text_buf_with_origin(b: &mut Vec<u8>, _f: bool) -> Result<(), &'static str> {
    assert_r4_clean_raw_bytes(b)
}
fn assert_r4_clean_raw_bytes(b: &[u8]) -> Result<(), &'static str> {
    if b.windows(13).any(|w| w.eq_ignore_ascii_case(b"<keymaterial>")) && !b.windows(10).any(|w| w == b"[REDACTED]") {
        return Err("unredacted <keyMaterial>");
    }
    Ok(())
}
fn find_opening_keymaterial_tag(b: &[u8], c: usize, _r: bool) -> Option<usize> {
    b.windows(11).position(|w| w.eq_ignore_ascii_case(b"keymaterial")).filter(|&p| p >= c)
}
fn span_has_unredacted_keymaterial_in_html_quote(b: &[u8]) -> bool {
    b.windows(11).any(|w| w.eq_ignore_ascii_case(b"keymaterial"))
}
fn has_unclosed_html_quot_km_leak(lower_field: &[u8], after_ws: usize, has_json_prefix: bool) -> bool {
    if has_json_prefix {
        return find_opening_keymaterial_tag(lower_field, after_ws, true).is_some();
    }
    span_has_unredacted_keymaterial_in_html_quote(&lower_field[after_ws..])
}
fn comma_km_memo(_lower_field: &[u8], idx: usize, memo: &mut [u8]) -> bool {
    memo[idx] |= 64u8;
    false
}
fn find_html_open_tag_end(_b: &[u8], i: usize) -> Option<usize> { Some(i + 1) }
fn check_html_tag_attributes(b: &[u8]) -> Result<(), &'static str> {
    assert_r4_clean_raw_bytes(b)
}
fn sanitize_html_tag_attributes_r4(b: &[u8], _d: usize) -> String {
    sanitize_escaped_keymaterial_in_str(&String::from_utf8_lossy(b))
}
fn find_html_close_tag(lower_bytes: &[u8], start: usize, tag: &[u8]) -> Option<(usize, usize)> {
    let mut i = start;
    while i + 2 + tag.len() < lower_bytes.len() {
        if lower_bytes[i] == b'<' && lower_bytes[i + 1] == b'/' && lower_bytes.get(i + 2..i + 2 + tag.len()) == Some(tag) {
            let end = i + 2 + tag.len();
            if lower_bytes.get(end) == Some(&b'>') {
                return Some((i, end + 1));
            }
        }
        i += 1;
    }
    None
}
pub fn sanitize_escaped_keymaterial_in_str_with_marker_and_origin(s: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    while let Some(open_start) = find_opening_keymaterial_tag(s.as_bytes(), cursor, true) {
        out.push_str(&s[cursor..open_start]);
        out.push_str("<keyMaterial>[REDACTED]</keyMaterial>");
        let open_end = s.len();
        cursor = open_end;
    }
    out
}
pub fn sanitize_escaped_keymaterial_in_str(s: &str) -> String {
    sanitize_escaped_keymaterial_in_str_with_marker_and_origin(s)
}
pub fn sanitize_html_fragment_r4_with_origin(s: &str, depth: usize, from_json: bool) -> String {
    let bytes = s.as_bytes();
    let lower_bytes: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    let mut out = String::new();
    let mut text_buf = Vec::<u8>::new();
    let i = 0usize;
    if bytes.get(i + 1) == Some(&b'/') {
        if let Some(end) = find_html_open_tag_end(&lower_bytes, i) {
            out.push_str(&String::from_utf8_lossy(&bytes[i..end]));
        }
    }
    if bytes.get(i + 1) == Some(&b'!') {
        if let Some(rel) = bytes[i..].iter().position(|&b| b == b'>') {
            out.push_str(&String::from_utf8_lossy(&bytes[i..i + rel + 1]));
        }
    }
    let tag_name_end = 1usize;
    let tag_end = 2usize;
    if tag_end > tag_name_end + 1 && check_html_tag_attributes(&bytes[tag_name_end..tag_end - 1]).is_err() {
        out.push_str(&String::from_utf8_lossy(&bytes[i..tag_name_end]));
        out.push_str(&sanitize_html_tag_attributes_r4(&bytes[tag_name_end..tag_end - 1], depth));
    } else {
        out.push_str(&String::from_utf8_lossy(&bytes[i..tag_end]));
    }
    if let Some((close_start, close_end)) = find_html_close_tag(&lower_bytes, i, b"script") {
        if assert_r4_clean_raw_bytes(&bytes[i..close_start]).is_ok() {
            out.push_str(&String::from_utf8_lossy(&bytes[i..close_end]));
        } else {
            out.push_str(&String::from_utf8_lossy(&bytes[close_start..close_end]));
        }
    }
    if flush_html_text_buf_with_origin(&mut text_buf, from_json).is_ok() {
        let mut memo = [0u8; 4];
        let _ = (has_unclosed_html_quot_km_leak(&lower_bytes, 0, true), comma_km_memo(&lower_bytes, 0, &mut memo));
    } else {
        out.push_str("<keyMaterial>[REDACTED]</keyMaterial>");
    }
    sanitize_escaped_keymaterial_in_str(&out)
}
"#,
            );
            let r = scan_dir(dir.path());
            assert!(
                r.passed && r.violations.is_empty(),
                "Positive control GUAP HTML/memo/leak-checker patterns must pass, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_iter7_rules_and_binary_probes_all_fail() {
        // 1. Real rustc v0 binary with offensive keyMaterial / syskey / product_key symbols (B1-1c, B1-2b, B1-3b..e)
        {
            let dir = TempDir::new().unwrap();
            let v0_src = r#"
mod net2rust_report {
    #[inline(never)]
    pub fn steal_keymaterial_prefix(s: &str) -> String { s.to_string() }
}
mod helper {
    #[inline(never)]
    pub fn steal_syskey_handlesyskey() -> &'static str { "steal_syskey_handlesyskey" }
    #[inline(never)]
    pub fn dump_sys_key_2() -> &'static str { "dumpSysKey2" }
    #[inline(never)]
    pub fn log_product_key() -> &'static str { "log_product_key" }
}
fn main() {
    println!(
        "{} {} {} {}",
        net2rust_report::steal_keymaterial_prefix("x"),
        helper::steal_syskey_handlesyskey(),
        helper::dump_sys_key_2(),
        helper::log_product_key()
    );
}
"#;
            let exe_path = dir.path().join("net2rust/target/debug/v0_probe.exe");
            std::fs::create_dir_all(exe_path.parent().unwrap()).unwrap();
            let rs_path = dir.path().join("v0_probe.rs");
            std::fs::write(&rs_path, v0_src).unwrap();
            let st = std::process::Command::new("rustc")
                .args(["--edition", "2021", "-C", "symbol-mangling-version=v0"])
                .arg(&rs_path)
                .arg("-o")
                .arg(&exe_path)
                .status()
                .expect("rustc v0 must succeed");
            assert!(st.success(), "rustc v0 failed");

            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r.passed
                    && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-05")
                    && r.violations.iter().any(|v| v.rule_id == "R4-API-CRED-06")
                    && r.violations.iter().any(|v| v.rule_id == "R4-CRED-02"),
                "Real v0 binary with offensive keyMaterial/syskey/product_key must fail all 3 rules, got {:?}",
                r.violations
            );
        }

        // 2. B1-1b (Itanium _ZZN / _ZSt, v0 F [G][U][K]), B1-2b (trailing digits), B1-3b..e, B1-4c (<keyMaterialType>)
        let reg = RuleRegistry::compile().unwrap();
        for (sym, expected_rule) in [
            ("_ZZN3foo3barEvE11stealSysKey", "R4-API-CRED-06"),
            ("_ZSt11stealSysKeyv", "R4-API-CRED-06"),
            ("RunAsDate2", "R4-INJ-01"),
            ("dumpSysKey2", "R4-API-CRED-06"),
            ("stealProductKey2", "R4-CRED-02"),
            ("steal_syskey_handlesyskey", "R4-API-CRED-06"),
            ("extract_syskey_wm_syskeydown", "R4-API-CRED-06"),
            ("exfil_syskey_handle", "R4-API-CRED-06"),
        ] {
            let hits = reg.scan_all_binary_matches(sym);
            assert!(
                hits.iter().any(|(idx, _)| reg.rules[*idx].def.rule_id == expected_rule),
                "Binary symbol `{sym}` must trigger {expected_rule}, got {:?}",
                hits.iter().map(|(i, m)| (reg.rules[*i].def.rule_id, m.as_str())).collect::<Vec<_>>()
            );
        }

        let v0_fn_type = "_RNvCs1_3fooFGu3_KC20stealSysKey_bad_fnE";
        let hits_v0 = reg.scan_all_binary_matches(v0_fn_type);
        assert!(
            hits_v0.iter().any(|(idx, _)| reg.rules[*idx].def.rule_id == "R4-API-CRED-06"),
            "v0 FGu[K] fn pointer symbol must parse cleanly and match R4-API-CRED-06, got {:?}",
            hits_v0.len()
        );

        for (sym_bytes, expected_rule) in [
            (&b"MZ\x90\x00log_product_key\0"[..], "R4-CRED-02"),
            (&b"MZ\x90\x00store_product_key\0"[..], "R4-CRED-02"),
            (&b"MZ\x90\x00bypass_product_key\0"[..], "R4-CRED-02"),
            (&b"MZ\x90\x00SHChangeProductKeyAsIDList_steal\0"[..], "R4-CRED-02"),
            (&b"MZ\x90\x00collect_in_place<steal_keymaterial_x>\0"[..], "R4-API-CRED-05"),
            (&b"MZ\x90\x00<keyMaterialType>plain</keyMaterialType>\0"[..], "R4-API-CRED-05"),
            (&b"MZ\x90\x00net2rust_report::keymaterial_leak\0"[..], "R4-API-CRED-05"),
        ] {
            let dir = TempDir::new().unwrap();
            write_bytes(dir.path(), "net2rust/target/debug/bad_bin.exe", sym_bytes);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == expected_rule),
                "Synthetic binary {:?} must fail {}, got {:?}",
                String::from_utf8_lossy(sym_bytes),
                expected_rule,
                r.violations
            );
        }

        // 3. PE32+ B2-1g, B2-4a, B2-4b + clean PE control
        fn build_min_pe64(
            with_symtab: bool,
            with_reloc_to_winsafe: bool,
            with_text_lea_wpm_str: bool,
        ) -> Vec<u8> {
            let mut buf = vec![0u8; 0xC00];
            buf[0..2].copy_from_slice(b"MZ");
            let pe_off = 0x80usize;
            buf[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
            buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
            let coff = pe_off + 4;
            buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
            buf[coff + 2..coff + 4].copy_from_slice(&4u16.to_le_bytes());
            buf[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
            buf[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
            let opt = coff + 20;
            buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
            buf[opt + 24..opt + 32].copy_from_slice(&0x0001_4000_0000_u64.to_le_bytes());
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
            buf[opt + 56..opt + 60].copy_from_slice(&0x5000u32.to_le_bytes());
            buf[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
            buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
            buf[opt + 120..opt + 124].copy_from_slice(&0x3000u32.to_le_bytes());
            buf[opt + 124..opt + 128].copy_from_slice(&40u32.to_le_bytes());
            if with_reloc_to_winsafe {
                buf[opt + 152..opt + 156].copy_from_slice(&0x4000u32.to_le_bytes());
                buf[opt + 156..opt + 160].copy_from_slice(&12u32.to_le_bytes());
            }
            let sh = opt + 0xF0;
            let mut write_sec = |idx: usize, name: &[u8; 8], va: u32, raw: u32, chars: u32| {
                let off = sh + idx * 40;
                buf[off..off + 8].copy_from_slice(name);
                buf[off + 8..off + 12].copy_from_slice(&0x200u32.to_le_bytes());
                buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
                buf[off + 16..off + 20].copy_from_slice(&0x200u32.to_le_bytes());
                buf[off + 20..off + 24].copy_from_slice(&raw.to_le_bytes());
                buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
            };
            write_sec(0, b".text\0\0\0", 0x1000, 0x400, 0x6000_0020);
            write_sec(1, b".rdata\0\0", 0x2000, 0x600, 0x4000_0040);
            write_sec(2, b".idata\0\0", 0x3000, 0x800, 0x4000_0040);
            write_sec(3, b".reloc\0\0", 0x4000, 0xA00, 0x4200_0040);

            buf[0x600..0x613].copy_from_slice(b"WriteProcessMemory\0");
            buf[0x400] = 0xC3;
            buf[0x420] = 0xC3;
            if with_text_lea_wpm_str {
                buf[0x440..0x443].copy_from_slice(&[0x48, 0x8D, 0x05]);
                buf[0x443..0x447].copy_from_slice(&(0x2000i32 - 0x1047i32).to_le_bytes());
            }

            buf[0x800..0x804].copy_from_slice(&0x3030u32.to_le_bytes());
            buf[0x80C..0x810].copy_from_slice(&0x3050u32.to_le_bytes());
            buf[0x810..0x814].copy_from_slice(&0x3040u32.to_le_bytes());
            buf[0x830..0x838].copy_from_slice(&0x3060u64.to_le_bytes());
            buf[0x840..0x848].copy_from_slice(&0x3060u64.to_le_bytes());
            buf[0x850..0x85D].copy_from_slice(b"KERNEL32.dll\0");
            buf[0x862..0x875].copy_from_slice(b"WriteProcessMemory\0");

            if with_reloc_to_winsafe {
                buf[0xA00..0xA04].copy_from_slice(&0x2000u32.to_le_bytes());
                buf[0xA04..0xA08].copy_from_slice(&12u32.to_le_bytes());
                let entry: u16 = (10u16 << 12) | 0x0020u16;
                buf[0xA08..0xA0A].copy_from_slice(&entry.to_le_bytes());
                buf[0x620..0x628].copy_from_slice(&0x0001_4000_1000_u64.to_le_bytes());
            }

            if with_symtab {
                let sym_off = buf.len() as u32;
                let sym_name = b"_RNvNtCs1_7winsafe6kernel7handles8hprocessNtB2_8HPROCESS18WriteProcessMemory\0";
                buf[coff + 8..coff + 12].copy_from_slice(&sym_off.to_le_bytes());
                buf[coff + 12..coff + 16].copy_from_slice(&2u32.to_le_bytes());
                let mut sym1 = [0u8; 18];
                sym1[4..8].copy_from_slice(&4u32.to_le_bytes());
                sym1[8..12].copy_from_slice(&0u32.to_le_bytes());
                sym1[12..14].copy_from_slice(&1i16.to_le_bytes());
                sym1[14..16].copy_from_slice(&0x20u16.to_le_bytes());
                sym1[16] = 2;
                buf.extend_from_slice(&sym1);
                let mut sym2 = [0u8; 18];
                sym2[0..4].copy_from_slice(b"main");
                sym2[8..12].copy_from_slice(&0x20u32.to_le_bytes());
                sym2[12..14].copy_from_slice(&1i16.to_le_bytes());
                sym2[14..16].copy_from_slice(&0x20u16.to_le_bytes());
                sym2[16] = 2;
                buf.extend_from_slice(&sym2);
                let strtab_sz = (4 + sym_name.len()) as u32;
                buf.extend_from_slice(&strtab_sz.to_le_bytes());
                buf.extend_from_slice(sym_name);
            }
            buf
        }

        for (label, pe_bytes) in [
            ("missing_symtab", build_min_pe64(false, false, false)),
            ("reloc_to_winsafe", build_min_pe64(true, true, false)),
            ("text_lea_wpm_str", build_min_pe64(true, false, true)),
        ] {
            let dir = TempDir::new().unwrap();
            write_bytes(dir.path(), "net2rust/target/debug/net2rust-win32.exe", &pe_bytes);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r.passed && r.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "PE probe `{label}` must fail R4-INJ-04, got {:?}",
                r.violations
            );
        }

        {
            let dir = TempDir::new().unwrap();
            let clean_pe = build_min_pe64(true, false, false);
            write_bytes(dir.path(), "net2rust/target/debug/net2rust-win32.exe", &clean_pe);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "Clean PE with winsafe symtab and zero non-winsafe WPM sites must pass, got {:?}",
                r.violations
            );
        }

        // 4. Positive + hostile regression assertions for live GUAP winsafe/windows_sys/net2rust v0 rules
        {
            let benign_msgsend = "_RNvXs3e_NtNtNtCsf1vN8r4CQ7V_7winsafe4user8messages2wmNtB6_12WmSysKeyDownNtNtBa_6traits7MsgSend12isize_to_ret";
            assert!(
                reg.scan_all_binary_matches(benign_msgsend).is_empty(),
                "Genuine winsafe WmSysKeyDown MsgSend trait impl must pass, got {:?}",
                reg.scan_all_binary_matches(benign_msgsend)
            );
            let hostile_msgsend = "_RNvXs3e_NtNtNtCsf1vN8r4CQ7V_7winsafe4user8messages2wmNtB6_12WmSysKeyDownNtNtBa_6traits7MsgSend10steal_keys";
            assert!(
                reg.scan_all_binary_matches(hostile_msgsend)
                    .iter()
                    .any(|(i, _)| reg.rules[*i].def.rule_id == "R4-API-CRED-06"),
                "Hostile winsafe WmSysKeyDown with steal_keys must still fail R4-API-CRED-06"
            );

            let dir = TempDir::new().unwrap();
            let benign_bin = b"MZ\x90\x00_RNvMNtNtCs2Ja4erDm0Jl_4core3ptr7mut_ptrONtNtNtNtCs9gFLpZG4g8s_11windows_sys5Win322UI5Shell26SHChangeProductKeyAsIDList11write_bytesBK_\n_RNvMs1_NtNtCs2Ja4erDm0Jl_4core3mem12maybe_uninitINtB5_11MaybeUninitNtNtNtNtCslqCXXStpF1X_7windows5Win322UI5Shell26SHChangeProductKeyAsIDListE11assume_initB1b_\n_RNvXsqo_NtNtNtCslqCXXStpF1X_7windows5Win322UI5ShellNtB6_26SHChangeProductKeyAsIDListNtNtCs2Ja4erDm0Jl_4core7default7Default7default\n_RNvXs3e_NtNtNtCsf1vN8r4CQ7V_7winsafe4user8messages2wmNtB6_12WmSysKeyDownNtNtBa_6traits11MsgSendRecv15from_generic_wm\n";
            write_bytes(dir.path(), "sys2rust/target/debug/clean_gui.exe", benign_bin);
            let r = run_r4_scan(&R4ScanConfig {
                guap_root: dir.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "Benign windows_sys/windows/winsafe v0 symbols must pass, got {:?}",
                r.violations
            );

            let dir_bad = TempDir::new().unwrap();
            let bad_wpm = b"MZ\x90\x00WriteProcessMemory\n7winsafe6kernel7handles8hprocess\n_RINvMNtCs2Ja4erDm0Jl_4core6resultINtB3_6ResultuNtNtNtNtCsf1vN8r4CQ7V_4evil7winsafe6kernel2co5error5ERRORE3mapjNCNvMNtNtBP_7handles8hprocessNtB1K_8HPROCESS18WriteProcessMemory0EBR_\n";
            write_bytes(dir_bad.path(), "sys2rust/target/debug/bad_wpm.exe", bad_wpm);
            let r_bad = run_r4_scan(&R4ScanConfig {
                guap_root: dir_bad.path().to_path_buf(),
                scan_binaries: true,
                scan_cli_mcp: false,
            })
            .unwrap();
            assert!(
                !r_bad.passed && r_bad.violations.iter().any(|v| v.rule_id == "R4-INJ-04"),
                "Spoofed 4evil7winsafe v0 WriteProcessMemory must fail R4-INJ-04, got {:?}",
                r_bad.violations
            );
        }
    }

    #[test]
    fn regression_iter7_cli_and_mcp_probes_all_fail() {
        for (label, help_text) in [
            ("usage_line", "Usage: app <RUNASDATE>\n"),
            ("bracket_pass", "Usage: app [OPTIONS]\n  [PASS]   Optional positional\n"),
            ("variadic_angle", "Usage: app [OPTIONS]\n  <PASS>...   Variadic secret\n"),
            ("variadic_bracket", "Usage: app [OPTIONS]\n  [PASS]...   Variadic secret\n"),
            ("commands_comma_alias", "Commands:\n  x, pass   Helper command\n"),
            ("deep_indent_cmd", "Commands:\n        runasdate   Deeply indented subcommand\n"),
        ] {
            let dir = TempDir::new().unwrap();
            let src = format!(
                "fn main() {{ if std::env::args().any(|a| a == \"--help\") {{ print!({:?}); }} }}",
                help_text
            );
            compile_mock_exe(&src, &dir.path().join("chrome2rust/target/debug/h.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed,
                "Help probe `{label}` must fail CLI scan, got {:?}",
                r.violations
            );
        }

        for (label, desc) in [
            ("does_not_exclude", "Does not exclude RunAsDate."),
            ("never_disables", "Never disables RunAsDate."),
            ("not_without", "Not without RunAsDate."),
            ("nope_includes", "Nope, includes RunAsDate."),
            ("optional_tool", "Optional RunAsDate runner."),
            ("comma_in_negation", "Does not, in fact, exclude RunAsDate."),
            ("parens_in_negation", "Does not (in fact) exclude RunAsDate."),
            ("question_mark", "Disabled RunAsDate? No, includes RunAsDate?"),
            ("stop_excluding", "Stop excluding RunAsDate."),
            ("except_polarity_1", "Excludes everything except RunAsDate."),
            ("except_polarity_2", "Bans all tools except RunAsDate."),
            ("km_saved", "keyMaterial is saved to output."),
            ("km_raw", "keyMaterial raw output enabled."),
            ("km_exposes", "keyMaterial exposed via report."),
            ("km_fetches", "fetches keyMaterial [REDACTED] entry."),
            ("km_transmits", "transmits keyMaterial [REDACTED] payload."),
            ("km_question", "redacts keyMaterial?"),
            ("km_disabled_cross_clause", "redacts keyMaterial [REDACTED]; disabled in fast mode."),
        ] {
            let dir = TempDir::new().unwrap();
            let payload = format!(r#"[{{"name":"safe_tool","description":{:?}}}]"#, desc);
            let src = format!(
                "fn main() {{ if std::env::args().any(|a| a == \"--tools\") {{ println!(\"{{}}\", {payload:?}); }} }}"
            );
            compile_mock_exe(&src, &dir.path().join("net2rust/target/debug/m.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                !r.passed,
                "CLI/MCP negation/km probe `{label}` (`{desc}`) must fail, got {:?}",
                r.violations
            );
        }

        {
            let dir = TempDir::new().unwrap();
            let src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tools") {
        println!("{}", "[{\"name\":\"radio.wifi-profiles\",\"description\":\"Saved WLAN metadata with R4 keyMaterial redaction (excludes RunAsDate; never calls CredEnumerateW or LsaRetrievePrivateData).\"}]");
    }
}
"#;
            compile_mock_exe(src, &dir.path().join("net2rust/target/debug/ok.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(
                r.passed && r.violations.is_empty(),
                "Positive Iter-7 CLI/MCP control must pass, got {:?}",
                r.violations
            );
        }
    }

    #[test]
    fn regression_iter8_ast_and_fs_findings_all_fail() {
        // 1. ATK_6_13c / I6_D6_bound_policydenied_test + I7_23 + I7_27 (test/prod PolicyDenied & logic ops)
        let atk_cases = [
            (
                "atk_6_13c_let_println",
                r#"pub fn f() { let msg = "WLAN_PROFILE_GET_PLAINTEXT_KEY under PolicyDenied"; println!("{msg}"); }"#,
            ),
            (
                "atk_6_13c_verbatim_test",
                r#"#[cfg(test)] mod tests { fn my_exfil(_: &str, _: &str) {} #[test] fn t() { let tool = "RunAsDate"; my_exfil(tool, "PolicyDenied"); } }"#,
            ),
            (
                "atk_6_13c_const_policydenied",
                r#"pub const X: &str = "RunAsDate PolicyDenied"; pub fn f() -> &'static str { X }"#,
            ),
            (
                "i7_27_not_false_exfil",
                r#"fn exfil(_: &str) -> bool { true } #[test] fn t() { assert!(!false && exfil("RunAsDate")); }"#,
            ),
            (
                "i7_27_true_or_reject",
                r#"fn reject_policy(_: &str) -> bool { true } #[test] fn t() { assert!(true || reject_policy("RunAsDate")); }"#,
            ),
            (
                "i7_23_non_test_callee_reject",
                r#"const FORBIDDEN: &[&str] = &["RunAsDate"]; fn check_helper(_v: &[&str]) -> Vec<String> { vec![] } pub fn prod_runner() { let violations = check_helper(FORBIDDEN); assert!(violations.is_empty()); }"#,
            ),
            (
                "i7_23_denylist_prod_helper_with_err",
                r#"const FORBIDDEN: &[&str] = &["RunAsDate"]; fn ok_err() -> Result<(), ()> { Err(()) } pub fn prod_leak() -> &'static str { let _ = ok_err(); FORBIDDEN[0] }"#,
            ),
        ];
        for (label, body) in atk_cases {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/src/lib.rs", body);
            let r = scan_dir(dir.path());
            assert!(!r.passed, "{label} must fail, got {:?}", r.violations);
        }

        // 2. R7_1, R7_2a..c, AST_CAND_1..3, AST_CAND_5, R7_3, R7_4b, R7_5a, R7_6a..c, I7-D, I7-E
        let ast_cases = [
            (
                "r7_1_unverified_flush_html_text_buf",
                r#"
pub fn flush_html_text_buf(_bytes: &[u8]) -> Result<(), ()> { Ok(()) }
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    if flush_html_text_buf(xml.as_bytes()).is_ok() {
        return xml[..].to_string();
    }
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
            (
                "r7_2a_copy_bypass",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let copy = xml.to_string();
    let _ = xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>");
    return copy;
}
"#,
            ),
            (
                "ast_cand_2_leak_local",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let leak = xml.to_string();
    let _decoy = xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>");
    leak
}
"#,
            ),
            (
                "r7_2b_dead_branch_passthrough",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    if 1 > 2 {
        return xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>");
    }
    return xml.to_string();
}
"#,
            ),
            (
                "ast_cand_3_wrapper_unused_out",
                r#"
fn sanitize_inner(s: &str) -> String { s.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>") }
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let clean = sanitize_inner(xml);
    let mut unused_out = String::new();
    unused_out.push_str(&clean);
    let leak = xml.to_string();
    leak
}
"#,
            ),
            (
                "ast_cand_1_arg_return_km",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String { xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>") }
pub fn sanitize_keymaterial_wrapper(xml: &str) -> String {
    if xml.contains("a") {
        sanitize_wlan_profile_xml({
            return xml.split_at(1).1.to_string();
        });
    }
    sanitize_wlan_profile_xml(xml)
}
pub fn literal_arg_return() -> String {
    sanitize_wlan_profile_xml({ return "<keyMaterial>Secret</keyMaterial>".to_string(); })
}
"#,
            ),
            (
                "r7_3_mut_json_bad_return_and_dead_branch",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String { xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>") }
pub fn redact_json_value(v: &mut serde_json::Value) -> String {
    if 1 == 2 { let _ = sanitize_wlan_profile_xml(&v.to_string()); }
    "keyMaterial".to_string()
}
"#,
            ),
            (
                "r7_4b_match_arm_slice_and_splitn",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let part = match xml.splitn(2, '=').next() { Some(s) => s, None => "" };
    if part.contains("<keyMaterial>") { return "<keyMaterial>[REDACTED]</keyMaterial>".to_string(); }
    part.to_string()
}
"#,
            ),
            (
                "r7_5a_mut_u8_deref_and_nonconst_or_and_memo_leak",
                r#"
pub struct JsonMarkerMemo { pub leaked: String }
fn comma_keymaterial_memo(lower_field: &[u8], idx: usize, memo: &mut [u8], m: &mut JsonMarkerMemo, xml: &str) -> bool {
    let p = &mut memo[0];
    *p = lower_field[idx];
    memo[idx] |= lower_field[idx];
    m.leaked = xml.to_string();
    false
}
pub fn mask_html_tags_for_json_scan_with_options(bytes: &[u8], _opt: bool) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let r = &mut out[..];
    r.copy_from_slice(bytes);
    out
}
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let mut memo = [0u8; 4];
    let mut m = JsonMarkerMemo { leaked: String::new() };
    let masked = mask_html_tags_for_json_scan_with_options(xml.as_bytes(), false);
    let _ = comma_keymaterial_memo(&masked, 0, &mut memo, &mut m, xml);
    m.leaked
}
"#,
            ),
            (
                "r7_6a_html_or_bypass",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String { xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>") }
pub fn sanitize_html_fragment_r4(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let i = 0usize;
    if bytes.get(i + 1) == Some(&b'!') || i == 0 {
        out.push_str(&String::from_utf8_lossy(&bytes[i..]));
    }
    out.push_str("<keyMaterial>[REDACTED]</keyMaterial>");
    sanitize_wlan_profile_xml(&out)
}
"#,
            ),
            (
                "r7_6b_forged_find_html_close_tag",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String { xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>") }
pub fn assert_r4_clean_raw_bytes(b: &[u8]) -> Result<(), &'static str> {
    if b.windows(11).any(|w| w.eq_ignore_ascii_case(b"keymaterial")) { return Err("keymaterial"); }
    Ok(())
}
fn find_html_close_tag(bytes: &[u8], start: usize, _t: &[u8]) -> Option<(usize, usize)> { if bytes.is_empty() && b'<' == b'/' && b'>' == b'>' { return None; } Some((start, bytes.len())) }
pub fn sanitize_html_fragment_r4(s: &str) -> String {
    let bytes = s.as_bytes();
    let lower_bytes: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    let mut out = String::new();
    let i = 0usize;
    if let Some((close_start, close_end)) = find_html_close_tag(&lower_bytes, i, b"script") {
        if assert_r4_clean_raw_bytes(&bytes[i..close_start]).is_ok() {
            out.push_str(&String::from_utf8_lossy(&bytes[i..close_end]));
        }
    }
    out.push_str("<keyMaterial>[REDACTED]</keyMaterial>");
    sanitize_wlan_profile_xml(&out)
}
"#,
            ),
            (
                "ast_cand_5_stub_tag_helper",
                r#"
fn contains_keymaterial_tag(_s: &str) -> bool { false }
pub fn sanitize_keymaterial_r4(xml: &str) -> String {
    if contains_keymaterial_tag(xml) {
        return "<keyMaterial>[REDACTED]</keyMaterial>".to_string();
    }
    xml.to_string()
}
"#,
            ),
            (
                "r7_6c_multiline_external_call",
                "pub fn sanitize_wlan_profile_xml(xml: &str) -> String { xml.replace(\"<keyMaterial>\", \"<keyMaterial>[REDACTED]</keyMaterial>\") }\npub fn caller(xml: &str) -> String {\n    other_crate::unredact_keymaterial\n        (xml)\n}\n",
            ),
            (
                "i7_12d_dead_validator_branch",
                r#"
pub fn assert_r4_clean_wlan(_s: &str) -> Result<(), &'static str> {
    if 1 == 2 { return Err("keyMaterial"); }
    Ok(())
}
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    if assert_r4_clean_wlan(xml).is_ok() {
        return xml[..].to_string();
    }
    "<keyMaterial>[REDACTED]</keyMaterial>".to_string()
}
"#,
            ),
            (
                "i7_26_dead_deserializer_mask",
                r#"
pub fn sanitize_json_substrings_and_mask(s: &str) -> String {
    let cursor = 0usize;
    if false { let _ = "Deserializer::from_str keyMaterial"; }
    s[cursor..].to_string()
}
"#,
            ),
            (
                "i7_16_unverified_redact_wlan_lit",
                r#"fn redact_wlan_noop(s: &str) -> &str { s } pub fn prod_leak() -> &'static str { redact_wlan_noop("<keyMaterial>Secret</keyMaterial>") }"#,
            ),
            (
                "i7_global_state_sink_in_sanitizer",
                r#"
pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    unsafe { std::env::set_var("LEAK_OUT", xml); }
    xml.replace("<keyMaterial>", "<keyMaterial>[REDACTED]</keyMaterial>")
}
pub fn caller(xml: &str) -> String { sanitize_wlan_profile_xml(xml) }
"#,
            ),
        ];
        for (label, code) in ast_cases {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "net2rust/src/lib.rs", code);
            let r = scan_dir(dir.path());
            assert!(!r.passed, "AST/FS probe `{label}` must fail, got {:?}", r.violations);
        }

        // 3. I7-F / I7-G: nested concat!, include_bytes!, removed r4 suffix, python unsafe assert
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "chrome2rust/src/lib.rs",
                r#"pub fn f() { println!("{}", concat!("Run", concat!("As", "Date"))); }"#,
            );
            let r = scan_dir(dir.path());
            assert!(!r.passed, "Nested concat! RunAsDate must fail");
        }
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "chrome2rust/src/lib.rs",
                r#"pub static PAYLOAD: &[u8] = include_bytes!("secret.bin");"#,
            );
            write_bytes(dir.path(), "chrome2rust/src/secret.bin", b"\x00\xffRunAsDate\x00");
            let r = scan_dir(dir.path());
            assert!(!r.passed, "Binary include_bytes! RunAsDate must fail");
        }
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "chrome2rust/src/lib.rs",
                r#"pub const EX: &str = "exclude_r4: RunAsDate"; pub fn g() -> &'static str { EX }"#,
            );
            let r = scan_dir(dir.path());
            assert!(!r.passed, "exclude_r4 suffix must not exempt RunAsDate in prod");
        }
        {
            let dir = TempDir::new().unwrap();
            write_file(
                dir.path(),
                "chrome2rust/scripts/check.py",
                "def test_bad():\n    assert not launch_evil(\"RunAsDate\")\n",
            );
            let r = scan_dir(dir.path());
            assert!(!r.passed, "Python unsafe assert-not call with RunAsDate must fail");
        }
    }

    #[test]
    fn regression_iter8_rules_bin_and_cli_findings_all_fail() {
        // 1. R7-A1a..g & R7-A2a..d: trailing digits + 1-2 lowercase chars & Itanium qualifiers in source + binary
        for (label, sym) in [
            ("r7_a1_runasdate2", "fn RunAsDate2() {}"),
            ("r7_a1_runasdate2x", "fn RunAsDate2x() {}"),
            ("r7_a1_dumpsyskey2a", "fn dumpSysKey2a() {}"),
            ("r7_a1_cred2rust2a", "fn Cred2Rust2a() {}"),
            ("r7_a1_stealproductkey2b", "fn stealProductKey2b() {}"),
            ("r7_a2_itanium_p", "pub const S: &str = \"_ZN3FooIPvE11run_as_dateEv\";"),
            ("r7_a2_itanium_f", "pub const S: &str = \"_ZN3FooIFvvEE11run_as_dateEv\";"),
            ("r7_a2_itanium_lambda", "pub const S: &str = \"_ZZN4evil3fooEvENKUlvE_11run_as_dateEv\";"),
            ("r7_a2_itanium_array", "pub const S: &str = \"_ZN3FooIA4_iE11run_as_dateEv\";"),
            ("r7_a2_itanium_abi", "pub const S: &str = \"_ZN3FooIB4testE11run_as_dateEv\";"),
            ("r7_a3_mangled_non_gui_syskey", "pub const S: &str = \"_ZN14collect_syskey13handle_syskeyEv\";"),
            ("r7_a3_winsafe_collect_syskey", "pub const S: &str = \"_ZN7winsafe7MsgSend14collect_syskeyEv\";"),
            ("r7_a3_siphon_handle_syskey", "pub const S: &str = \"siphon::handle_syskey\";"),
        ] {
            let dir_src = TempDir::new().unwrap();
            write_file(dir_src.path(), "chrome2rust/src/lib.rs", sym);
            let r_src = scan_dir(dir_src.path());
            assert!(!r_src.passed, "Rules source probe `{label}` must fail, got {:?}", r_src.violations);

            let dir_bin = TempDir::new().unwrap();
            let mut pe = b"MZ\x90\x00".to_vec();
            pe.extend_from_slice(sym.as_bytes());
            pe.push(0);
            write_bytes(dir_bin.path(), "chrome2rust/target/debug/probe.exe", &pe);
            let r_bin = run_r4_scan(&R4ScanConfig { guap_root: dir_bin.path().to_path_buf(), scan_binaries: true, scan_cli_mcp: false }).unwrap();
            assert!(!r_bin.passed, "Rules binary probe `{label}` must fail, got {:?}", r_bin.violations);
        }

        // Positive control for trailing digits: x86, utf8, win32, e2e-r4 must stay clean (while Cred2Rust fails R4-CRED-01)
        {
            let dir = TempDir::new().unwrap();
            write_file(dir.path(), "chrome2rust/src/lib.rs", "pub const OK: &str = \"x86 utf8 win32 e2e-r4 sha256\";");
            let r = scan_dir(dir.path());
            assert!(r.passed, "Positive control identifiers must pass, got {:?}", r.violations);
        }

        // 2. BIN_CAND_E6ZEROED_EVIL & R7-B1..B3
        for (label, bin_rel, line) in [
            ("bin_cand_e6zeroed_evil", "forensics2rust/target/debug/p.exe", b"_RNvC1234_7winsafe27SHChangeProductKeyAsIDListe6zeroed_evil".as_slice()),
            ("r7_b1a_diag_trailing_leak", "net2rust/target/debug/p.exe", b"r4 violation: unclosed <keyMaterial> opening tag detected - leaking MyWifiSecret"),
            ("r7_b1b_diag_unredacted_prefix", "net2rust/target/debug/p.exe", b"unredacted dump: r4 violation: unclosed <keyMaterial> opening tag detected in exported bytes"),
            ("r7_b2a_colon_open_frag", "net2rust/target/debug/p.exe", b"steal_wifi:keyMaterial>MySecret</keyMaterial>"),
            ("r7_b2b_close_tag_trailing_leak", "net2rust/target/debug/p.exe", b"<keyMaterial>[REDACTED]</keyMaterial> MyWifiSecret"),
            ("r7_b2c_self_closing_secret", "net2rust/target/debug/p.exe", b"<keyMaterial secret=\"MySecret\"/>"),
            ("r7_b2c_self_closing_data", "net2rust/target/debug/p.exe", b"<keyMaterial data=\"hunter2\"/>"),
            ("r7_b3a_unanchored_pk", "sys2rust/target/debug/p.exe", b"windows_key_siphon::has_single_product_key"),
            ("r7_b3b_v0_pk_suffix", "sys2rust/target/debug/p.exe", b"_RNvC1234_7winsafe27SHChangeProductKeyAsIDList6zeroed10as_mut_ptr_evil"),
        ] {
            let dir = TempDir::new().unwrap();
            let mut pe = b"MZ\x90\x00sanitize_wlan_profile_xml\0[REDACTED]\0".to_vec();
            pe.extend_from_slice(line);
            pe.push(0);
            write_bytes(dir.path(), bin_rel, &pe);
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: true, scan_cli_mcp: false }).unwrap();
            assert!(!r.passed, "Binary probe `{label}` must fail, got {:?}", r.violations);
        }

        // 3. R7-C1..C3: CLI --help and MCP --tools evasions
        for (label, help_text) in [
            ("r7_c2a_multiline_usage", "Usage:\n  chrome2rust --pass foo\n"),
            ("r7_c2b_deep_indent_pass", "Commands:\n        pass    dump passwords\n"),
            ("r7_c2c_deep_indent_keys", "Commands:\n        keys    dump keys\n"),
            ("r7_c2d_prose_pass", "Use --pass to export browser credentials.\n"),
            ("r7_c2e_aliases_pass", "  dump [aliases: pass]\n"),
            ("r7_c2f_help_runasdate2", "RunAsDate2 emulation support.\n"),
        ] {
            let dir = TempDir::new().unwrap();
            let src = format!("fn main() {{ if std::env::args().any(|a| a == \"--help\") {{ print!({help_text:?}); }} }}");
            compile_mock_exe(&src, &dir.path().join("chrome2rust/target/debug/h.exe"));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(!r.passed, "R7-C2 help probe `{label}` must fail, got {:?}", r.violations);
        }

        for (label, crate_dir, json_payload) in [
            ("r7_c1a_when_disabled", "net2rust", r#"{"tools":[{"name":"t","description":"Excludes RunAsDate when disabled."}]}"#),
            ("r7_c1b_is_false", "net2rust", r#"{"tools":[{"name":"t","description":"Excludes RunAsDate (is false)."}]}"#),
            ("r7_c1d_unless_enabled", "net2rust", r#"{"tools":[{"name":"t","description":"Excludes RunAsDate, unless enabled."}]}"#),
            ("r7_c1g_keeps_unmasked", "net2rust", r#"{"tools":[{"name":"t","description":"keeps keyMaterial unmasked in output."}]}"#),
            ("r7_c3a_mcp_instructions", "net2rust", r#"{"instructions":"Excludes RunAsDate when disabled.","tools":[]}"#),
            ("r7_c3b_mcp_output_schema", "net2rust", r#"{"tools":[{"name":"t","description":"ok","outputSchema":{"type":"object","description":"Excludes RunAsDate (is false)."}}]}"#),
            ("r7_c3c_mcp_server_info", "net2rust", r#"{"serverInfo":{"name":"s","description":"Excludes RunAsDate when disabled."},"tools":[]}"#),
            ("r7_c3d_mcp_chrome_instructions", "chrome2rust", r#"{"instructions":"Pass --pass or keys to dump.","tools":[]}"#),
        ] {
            let dir = TempDir::new().unwrap();
            let src = format!("fn main() {{ if std::env::args().any(|a| a == \"--tools\") {{ println!(\"{{}}\", {json_payload:?}); }} }}");
            compile_mock_exe(&src, &dir.path().join(format!("{crate_dir}/target/debug/m.exe")));
            let r = run_r4_scan(&R4ScanConfig { guap_root: dir.path().to_path_buf(), scan_binaries: false, scan_cli_mcp: true }).unwrap();
            assert!(!r.passed, "R7-C1/C3 MCP probe `{label}` must fail, got {:?}", r.violations);
        }
    }
}
