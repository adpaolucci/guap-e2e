use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::{DirEntry, WalkDir};

use crate::R4Violation;
use crate::rules::{RuleKind, RuleRegistry};
use crate::surface_fs::is_skipped_dir_name;

const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const OVERLAP_SIZE: usize = 4096;

pub fn discover_binaries(guap_root: &Path) -> Result<Vec<PathBuf>> {
    let mut binaries = Vec::new();

    for entry in WalkDir::new(guap_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| should_visit_binary_tree(guap_root, e))
    {
        let entry =
            entry.with_context(|| format!("walking binaries in {}", guap_root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if ext == "exe" || ext == "dll" {
            binaries.push(entry.path().to_path_buf());
        }
    }

    binaries.sort();
    Ok(binaries)
}

fn should_visit_binary_tree(guap_root: &Path, entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    if !entry.file_type().is_dir() {
        return true;
    }

    let name = entry.file_name().to_string_lossy();
    if name.eq_ignore_ascii_case("target") {
        return true;
    }
    if is_skipped_dir_name(&name) {
        return false;
    }

    let rel = entry.path().strip_prefix(guap_root).unwrap_or(entry.path());
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    if let Some(target_idx) = comps.iter().position(|c| c.eq_ignore_ascii_case("target")) {
        let after_target = &comps[target_idx + 1..];
        return match after_target.len() {
            0 => true,
            1 => {
                let c = &after_target[0];
                // Allow target/debug, target/release, or target/<triple>
                c.eq_ignore_ascii_case("debug")
                    || c.eq_ignore_ascii_case("release")
                    || (c.contains('-') && !c.eq_ignore_ascii_case("CACHEDIR.TAG"))
            }
            2 => {
                let parent = &after_target[0];
                let child = &after_target[1];
                // Inside target/<triple>/{debug,release}, do not allow subdirs of target/debug or target/release
                !parent.eq_ignore_ascii_case("debug")
                    && !parent.eq_ignore_ascii_case("release")
                    && (child.eq_ignore_ascii_case("debug")
                        || child.eq_ignore_ascii_case("release"))
            }
            _ => false,
        };
    }

    true
}

fn contains_ascii_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if haystack.len() < needle_lower.len() {
        return false;
    }
    let first = needle_lower[0];
    let first_upper = first.to_ascii_uppercase();
    let last_start = haystack.len() - needle_lower.len();
    for i in 0..=last_start {
        let b = haystack[i];
        if (b == first || b == first_upper)
            && haystack[i..i + needle_lower.len()]
                .iter()
                .zip(needle_lower)
                .all(|(h, n)| h.to_ascii_lowercase() == *n)
        {
            return true;
        }
    }
    false
}

fn pk11_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^a-zA-Z0-9])(PK11SDR_Decrypt)(?:$|[^a-zA-Z0-9])")
            .expect("valid pk11 regex")
    })
}

fn strict_inj_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:PAGE_EXECUTE\w*|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|shellcode)\b",
        )
        .expect("valid strict_inj regex")
    })
}

fn dll_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b([a-z0-9_.-]+\.dll)\b").expect("valid dll regex"))
}

fn suspicious_dll_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[^a-z0-9])(?:evil|hook|inject[a-z0-9_-]*|payload[a-z0-9_-]*|detour[a-z0-9_-]*)\.dll(?:$|[^a-z0-9])",
        )
        .expect("valid suspicious_dll regex")
    })
}

pub fn scan_binaries(
    guap_root: &Path,
    registry: &RuleRegistry,
    files_scanned: &mut usize,
    violations: &mut Vec<R4Violation>,
) -> Result<()> {
    let binaries = discover_binaries(guap_root)?;
    let pk11_re = pk11_regex();

    for bin_path in binaries {
        *files_scanned += 1;
        scan_single_binary(&bin_path, registry, pk11_re, violations)?;
    }

    Ok(())
}

fn scan_single_binary(
    bin_path: &Path,
    registry: &RuleRegistry,
    pk11_re: &Regex,
    violations: &mut Vec<R4Violation>,
) -> Result<()> {
    let stem = bin_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // Check binary filename stem
    for idx in registry.source_set.matches(&stem) {
        let rule = &registry.rules[idx];
        if !matches!(
            rule.def.category,
            "cred2rust" | "credential_tool" | "injection_tool" | "legacy_tool"
        ) {
            continue;
        }
        if rule.def.kind == RuleKind::LegacyAcm && registry.acm_audio_context_regex.is_match(&stem)
        {
            continue;
        }
        for (_, _, matched) in registry.find_all_matches(idx, &stem) {
            violations.push(R4Violation {
                category: rule.def.category.to_string(),
                rule_id: rule.def.rule_id.to_string(),
                path: bin_path.to_path_buf(),
                line: None,
                matched_symbol: matched,
                detail: format!(
                    "Binary filename matches prohibited R4 tool ({})",
                    rule.def.description
                ),
            });
        }
    }

    let path_norm_lower = bin_path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let stem_lower = stem.to_ascii_lowercase();
    let is_winctl_bin = path_norm_lower.contains("winctl2rust");
    let is_winctl_desktop_bin = is_winctl_bin
        && (matches!(
            stem_lower.as_str(),
            "winctl2rust" | "winctl2rust-win32" | "winctl2rust-iced" | "winctl2rust-mcp"
        ) || stem_lower.contains("desktop")
            || stem_lower.contains("ctrl_export"));
    let is_debug_bin = path_norm_lower.contains("/debug/");
    let is_win32_gui_bin = stem_lower.ends_with("-win32");
    let is_sys2rust_bin = path_norm_lower.contains("sys2rust");
    let is_net2rust_bin = path_norm_lower.contains("net2rust");

    let mut file =
        File::open(bin_path).with_context(|| format!("opening binary {}", bin_path.display()))?;
    let mut buf = vec![0u8; CHUNK_SIZE + OVERLAP_SIZE];
    let mut carry_len = 0usize;
    let mut prev_ascii_cont = false;
    let mut prev_utf16_even_cont = false;
    let mut prev_utf16_odd_cont = false;
    let mut strings_buf = String::with_capacity(512 * 1024);

    let mut seen_dedup: HashSet<(String, String)> = HashSet::new();
    let mut saw_wpm = false;
    let mut wpm_symbols: Vec<String> = Vec::new();
    let mut saw_lvitem_tvitem = false;
    let mut saw_wpm_exec_inj = false;
    let mut saw_wpm_strict_inj = false;
    let mut saw_winsafe_hproc = false;
    let mut saw_virtual_alloc_ex = false;
    let mut saw_sys2rust_shell_ro_vae = false;
    let mut saw_sys2rust_shell_crate = false;
    let mut saw_winsafe_hproc_wpm = false;
    let mut saw_windows_crate_wpm = false;
    let mut saw_non_winsafe_wpm_line = false;

    let mut saw_set_hook = false;
    let mut set_hook_symbols: Vec<String> = Vec::new();
    let mut saw_wh_ll = false;
    let mut saw_wh_dangerous = false;
    let mut wh_dangerous_symbols: Vec<String> = Vec::new();
    let mut saw_winsafe_hhook_mod = false;
    let mut saw_winsafe_hhook_fn = false;
    let mut saw_any_non_system_dll = false;
    let mut saw_suspicious_hook_dll = false;

    let mut saw_keymaterial = false;
    let mut keymaterial_symbols: Vec<String> = Vec::new();
    let mut saw_wlan_sanitizer_fn = false;
    let mut saw_wlan_redacted = false;
    let mut saw_wlan_get_profile = false;
    let mut saw_unsafe_keymaterial = false;

    let strict_inj_re = strict_inj_regex();
    let dll_re = dll_regex();
    let suspicious_dll_re = suspicious_dll_regex();

    loop {
        let n = file
            .read(&mut buf[carry_len..carry_len + CHUNK_SIZE])
            .with_context(|| format!("reading binary {}", bin_path.display()))?;
        if n == 0 {
            break;
        }
        let total = carry_len + n;
        let chunk = &buf[..total];

        strings_buf.clear();
        extract_ascii_runs(chunk, &mut strings_buf, prev_ascii_cont);
        extract_utf16le_runs(chunk, 0, &mut strings_buf, prev_utf16_even_cont);
        extract_utf16le_runs(chunk, 1, &mut strings_buf, prev_utf16_odd_cont);

        if is_debug_bin && is_win32_gui_bin {
            if strings_buf.contains("7winsafe4user7handles5hhook") {
                saw_winsafe_hhook_mod = true;
            }
            if strings_buf.contains("5HHOOK16SetWindowsHookEx")
                || strings_buf.contains("winsafe::user::handles::hhook::")
            {
                saw_winsafe_hhook_fn = true;
            }
            if strings_buf.contains("7winsafe6kernel7handles8hprocess") {
                saw_winsafe_hproc = true;
            }
            if !saw_wpm_strict_inj && strict_inj_re.is_match(&strings_buf) {
                saw_wpm_strict_inj = true;
            }
            if !saw_any_non_system_dll {
                for caps in dll_re.captures_iter(&strings_buf) {
                    if let Some(m) = caps.get(1)
                        && !is_known_windows_system_dll(m.as_str())
                    {
                        saw_any_non_system_dll = true;
                        break;
                    }
                }
            }
        }
        if !saw_suspicious_hook_dll && suspicious_dll_re.is_match(&strings_buf) {
            saw_suspicious_hook_dll = true;
        }
        if !saw_virtual_alloc_ex && strings_buf.contains("VirtualAllocEx") {
            saw_virtual_alloc_ex = true;
        }
        if is_sys2rust_bin
            && !saw_sys2rust_shell_ro_vae
            && strings_buf.contains("Inspect desktop SysListView32 icon coordinates via VirtualAllocEx+ReadProcessMemory")
        {
            saw_sys2rust_shell_ro_vae = true;
        }
        if is_sys2rust_bin && !saw_sys2rust_shell_crate && strings_buf.contains("sys2rust_shell") {
            saw_sys2rust_shell_crate = true;
        }
        if !saw_winsafe_hproc_wpm
            && (strings_buf.contains("HPROCESS18WriteProcessMemory")
                || (strings_buf.contains("winsafe::kernel::handles::hprocess::")
                    && strings_buf.contains("WriteProcessMemory")))
        {
            saw_winsafe_hproc_wpm = true;
        }
        if !saw_windows_crate_wpm
            && (strings_buf.contains("Diagnostics5Debug18WriteProcessMemory")
                || strings_buf.contains("Diagnostics::Debug::WriteProcessMemory")
                || strings_buf.contains("memoryapi18WriteProcessMemory")
                || strings_buf.contains("memoryapi::WriteProcessMemory"))
        {
            saw_windows_crate_wpm = true;
        }
        if !saw_non_winsafe_wpm_line
            && contains_ascii_ci(strings_buf.as_bytes(), b"writeprocessmemory")
        {
            for wline in strings_buf.lines() {
                if !contains_ascii_ci(wline.as_bytes(), b"writeprocessmemory") {
                    continue;
                }
                let t = wline.trim();
                let tl = t.to_ascii_lowercase();
                let is_iat_or_thunk = t == "WriteProcessMemory" || t == "__imp_WriteProcessMemory";
                let is_v0_winsafe = is_v0_crate_root_winsafe_hprocess(t)
                    && !tl.contains("windows::")
                    && !tl.contains("windows_sys")
                    && !tl.contains("memoryapi")
                    && !tl.contains("diagnostics");
                let is_demangled_winsafe = tl.contains("winsafe::kernel::handles::hprocess::")
                    && t.contains("::WriteProcessMemory")
                    && !tl.contains("windows::")
                    && !tl.contains("windows_sys::")
                    && !tl.contains("memoryapi")
                    && !tl.contains("diagnostics");
                if !is_iat_or_thunk && !is_v0_winsafe && !is_demangled_winsafe {
                    saw_non_winsafe_wpm_line = true;
                    break;
                }
            }
        }

        if is_winctl_desktop_bin {
            if !saw_lvitem_tvitem && registry.wpm_struct_regex.is_match(&strings_buf) {
                saw_lvitem_tvitem = true;
            }
            if !saw_wpm_exec_inj && strict_inj_re.is_match(&strings_buf) {
                saw_wpm_exec_inj = true;
            }
        }
        if is_winctl_bin && !saw_wh_ll && registry.hook_ll_const_regex.is_match(&strings_buf) {
            saw_wh_ll = true;
        }

        if is_net2rust_bin
            && (strings_buf.contains("sanitize_wlan_profile_xml")
                || strings_buf.contains("redact_wlan"))
        {
            saw_wlan_sanitizer_fn = true;
        }
        if is_net2rust_bin && strings_buf.contains("[REDACTED]") {
            saw_wlan_redacted = true;
        }
        if strings_buf.contains("WLAN_PROFILE_GET_PLAINTEXT_KEY") {
            saw_wlan_get_profile = true;
        }
        if !saw_unsafe_keymaterial && has_unsafe_keymaterial_line(is_net2rust_bin, &strings_buf) {
            saw_unsafe_keymaterial = true;
        }

        if contains_ascii_ci(strings_buf.as_bytes(), b"pk11sdr_decrypt")
            && let Some(caps) = pk11_re.captures(&strings_buf)
            && let Some(m) = caps.get(1)
        {
            let sym = m.as_str().to_string();
            if seen_dedup.insert(("R4-BASELINE-CHROME".to_string(), sym.clone())) {
                violations.push(R4Violation {
                    category: "baseline_chrome".to_string(),
                    rule_id: "R4-BASELINE-CHROME".to_string(),
                    path: bin_path.to_path_buf(),
                    line: None,
                    matched_symbol: sym,
                    detail: "Prohibited PK11SDR_Decrypt symbol found in compiled binary"
                        .to_string(),
                });
            }
        }

        for (rule_idx, matched) in registry.scan_all_binary_matches(&strings_buf) {
            let rule = &registry.rules[rule_idx];
            {
                if rule.def.rule_id == "R4-INJ-02"
                    && matched.eq_ignore_ascii_case("QUEUE_USER_APC")
                    && is_only_queue_user_apc_flags(&strings_buf)
                {
                    continue;
                }
                if rule.def.rule_id == "R4-CRED-02"
                    && (matched.eq_ignore_ascii_case("product_key")
                        || matched.eq_ignore_ascii_case("productkey"))
                    && is_debug_bin
                    && is_only_benign_debug_product_key(&strings_buf)
                {
                    continue;
                }
                match rule.def.kind {
                    RuleKind::InjWriteProcessMemory => {
                        saw_wpm = true;
                        if !wpm_symbols.contains(&matched) {
                            wpm_symbols.push(matched);
                        }
                    }
                    RuleKind::InjSetWindowsHookEx => {
                        if registry.hook_dangerous_const_regex.is_match(&matched) {
                            saw_wh_dangerous = true;
                            if !wh_dangerous_symbols.contains(&matched) {
                                wh_dangerous_symbols.push(matched);
                            }
                        } else {
                            saw_set_hook = true;
                            if !set_hook_symbols.contains(&matched) {
                                set_hook_symbols.push(matched);
                            }
                        }
                    }
                    RuleKind::LegacyAcm => {
                        if matched.eq_ignore_ascii_case("acm")
                            && registry.acm_audio_context_regex.is_match(&strings_buf)
                        {
                            continue;
                        }
                        if seen_dedup.insert((rule.def.rule_id.to_string(), matched.clone())) {
                            violations.push(R4Violation {
                                category: rule.def.category.to_string(),
                                rule_id: rule.def.rule_id.to_string(),
                                path: bin_path.to_path_buf(),
                                line: None,
                                matched_symbol: matched,
                                detail: format!(
                                    "Binary strings match prohibited R4 rule ({})",
                                    rule.def.description
                                ),
                            });
                        }
                    }
                    RuleKind::ApiCredPek | RuleKind::Standard => {
                        if rule.def.rule_id == "R4-API-CRED-05"
                            && matched.eq_ignore_ascii_case("keymaterial")
                        {
                            saw_keymaterial = true;
                            if !keymaterial_symbols.contains(&matched) {
                                keymaterial_symbols.push(matched);
                            }
                            continue;
                        }
                        if seen_dedup.insert((rule.def.rule_id.to_string(), matched.clone())) {
                            violations.push(R4Violation {
                                category: rule.def.category.to_string(),
                                rule_id: rule.def.rule_id.to_string(),
                                path: bin_path.to_path_buf(),
                                line: None,
                                matched_symbol: matched,
                                detail: format!(
                                    "Binary strings match prohibited R4 rule ({})",
                                    rule.def.description
                                ),
                            });
                        }
                    }
                }
            }
        }

        if total > OVERLAP_SIZE {
            let overlap_start = total - OVERLAP_SIZE;
            let is_cont = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
            prev_ascii_cont = is_cont(buf[overlap_start - 1]);
            prev_utf16_even_cont = overlap_start >= 2
                && buf[overlap_start - 1] == 0
                && is_cont(buf[overlap_start - 2]);
            prev_utf16_odd_cont =
                overlap_start >= 2 && buf[overlap_start] == 0 && is_cont(buf[overlap_start - 1]);
            buf.copy_within(overlap_start..total, 0);
            carry_len = OVERLAP_SIZE;
        } else {
            prev_ascii_cont = false;
            prev_utf16_even_cont = false;
            prev_utf16_odd_cont = false;
            carry_len = 0;
        }
    }

    if (saw_keymaterial || saw_unsafe_keymaterial)
        && !(is_net2rust_bin
            && saw_wlan_sanitizer_fn
            && saw_wlan_redacted
            && !saw_wlan_get_profile
            && !saw_unsafe_keymaterial)
    {
        if keymaterial_symbols.is_empty() {
            keymaterial_symbols.push("keyMaterial".to_string());
        }
        for sym in keymaterial_symbols {
            violations.push(R4Violation {
                category: "credential_api".to_string(),
                rule_id: "R4-API-CRED-05".to_string(),
                path: bin_path.to_path_buf(),
                line: None,
                matched_symbol: sym,
                detail:
                    "Unredacted <keyMaterial> or WlanGetProfile plaintext key recovery in binary"
                        .to_string(),
            });
        }
    }

    let safe_debug_winsafe_hook = is_debug_bin
        && is_win32_gui_bin
        && !saw_wh_dangerous
        && !saw_suspicious_hook_dll
        && (saw_winsafe_hhook_fn || (saw_winsafe_hhook_mod && !saw_any_non_system_dll));

    if saw_wh_dangerous {
        for sym in wh_dangerous_symbols {
            violations.push(R4Violation {
                category: "injection_api".to_string(),
                rule_id: "R4-INJ-03".to_string(),
                path: bin_path.to_path_buf(),
                line: None,
                matched_symbol: sym,
                detail: "Dangerous SetWindowsHookEx constant found in binary".to_string(),
            });
        }
    } else if saw_set_hook
        && !(is_winctl_bin && saw_wh_ll && !saw_suspicious_hook_dll)
        && !safe_debug_winsafe_hook
    {
        for sym in set_hook_symbols {
            violations.push(R4Violation {
                category: "injection_api".to_string(),
                rule_id: "R4-INJ-03".to_string(),
                path: bin_path.to_path_buf(),
                line: None,
                matched_symbol: sym,
                detail: "SetWindowsHookEx in binary outside permitted winctl2rust low-level hook"
                    .to_string(),
            });
        }
    }

    let safe_winctl_desktop_wpm =
        is_winctl_desktop_bin && saw_lvitem_tvitem && !saw_wpm_exec_inj && !saw_suspicious_hook_dll;
    let safe_debug_winsafe_wpm = is_debug_bin
        && is_win32_gui_bin
        && saw_winsafe_hproc
        && !saw_wpm_strict_inj
        && !saw_suspicious_hook_dll
        && !saw_windows_crate_wpm
        && !saw_non_winsafe_wpm_line
        && (!saw_virtual_alloc_ex
            || (is_sys2rust_bin
                && saw_winsafe_hproc_wpm
                && saw_sys2rust_shell_ro_vae
                && saw_sys2rust_shell_crate));

    let pe_wpm_violation = saw_wpm
        && !safe_winctl_desktop_wpm
        && safe_debug_winsafe_wpm
        && pe_has_non_winsafe_wpm_call_sites(bin_path).unwrap_or(false);

    if saw_wpm && !safe_winctl_desktop_wpm && (!safe_debug_winsafe_wpm || pe_wpm_violation) {
        for sym in wpm_symbols {
            violations.push(R4Violation {
                category: "injection_api".to_string(),
                rule_id: "R4-INJ-04".to_string(),
                path: bin_path.to_path_buf(),
                line: None,
                matched_symbol: sym,
                detail: "WriteProcessMemory in binary outside permitted winctl2rust control-export LVITEMW/TVITEMW marshaling".to_string(),
            });
        }
    }

    Ok(())
}

fn extract_ascii_runs(bytes: &[u8], out: &mut String, skip_leading_alnum: bool) {
    let mut start_idx = 0usize;
    if skip_leading_alnum {
        while start_idx < bytes.len()
            && (bytes[start_idx].is_ascii_alphanumeric() || bytes[start_idx] == b'_')
        {
            start_idx += 1;
        }
    }
    let slice = &bytes[start_idx..];
    let mut start: Option<usize> = None;
    for (i, &b) in slice.iter().enumerate() {
        if b.wrapping_sub(0x20) <= 0x5E {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take()
            && i - s >= 3
            && let Ok(text) = std::str::from_utf8(&slice[s..i])
        {
            out.push_str(text);
            out.push('\n');
        }
    }
    if let Some(s) = start
        && slice.len() - s >= 3
        && let Ok(text) = std::str::from_utf8(&slice[s..])
    {
        out.push_str(text);
        out.push('\n');
    }
}

fn extract_utf16le_runs(bytes: &[u8], offset: usize, out: &mut String, skip_leading_alnum: bool) {
    let mut i = offset;
    if skip_leading_alnum {
        while i + 1 < bytes.len()
            && bytes[i + 1] == 0
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
        {
            i += 2;
        }
    }
    let mut run_start: Option<usize> = None;
    let mut run_chars = 0usize;
    while i + 1 < bytes.len() {
        let lo = bytes[i];
        let hi = bytes[i + 1];
        if hi == 0 && lo.wrapping_sub(0x20) <= 0x5E {
            if run_start.is_none() {
                run_start = Some(i);
                run_chars = 1;
            } else {
                run_chars += 1;
            }
        } else {
            if run_chars >= 3
                && let Some(s) = run_start
            {
                let mut k = s;
                while k < i {
                    out.push(bytes[k] as char);
                    k += 2;
                }
                out.push('\n');
            }
            run_start = None;
            run_chars = 0;
        }
        i += 2;
    }
    if run_chars >= 3
        && let Some(s) = run_start
    {
        let mut k = s;
        while k + 1 < bytes.len() {
            out.push(bytes[k] as char);
            k += 2;
        }
        out.push('\n');
    }
}

fn split_symbol_word_tokens(text: &str, special_mid: &str) -> Vec<String> {
    let mut raw_parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        let b = bytes[i];
        if !b.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                raw_parts.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            let prev = bytes[i - 1];
            let camel = (prev.is_ascii_lowercase() && b.is_ascii_uppercase())
                || (prev.is_ascii_uppercase()
                    && b.is_ascii_uppercase()
                    && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase));
            if camel && !cur.is_empty() {
                raw_parts.push(std::mem::take(&mut cur));
            }
        }
        cur.push((b as char).to_ascii_lowercase());
    }
    if !cur.is_empty() {
        raw_parts.push(cur);
    }

    let mut tokens = Vec::new();
    for part in raw_parts {
        let trimmed_digits = part.trim_start_matches(|c: char| c.is_ascii_digit());
        let candidate = if trimmed_digits.is_empty() {
            part.as_str()
        } else {
            trimmed_digits
        };
        if !special_mid.is_empty() && candidate.contains(special_mid) {
            let mut rem = candidate;
            while let Some(pos) = rem.find(special_mid) {
                if pos > 0 {
                    tokens.push(rem[..pos].to_string());
                }
                tokens.push(special_mid.to_string());
                rem = &rem[pos + special_mid.len()..];
            }
            if !rem.is_empty() {
                tokens.push(rem.to_string());
            }
        } else {
            tokens.push(candidate.to_string());
        }
    }
    tokens
}

fn count_non_overlapping(haystack: &str, needle: &str) -> usize {
    let mut count = 0usize;
    let mut pos = 0usize;
    while let Some(rel) = haystack[pos..].find(needle) {
        count += 1;
        pos += rel + needle.len();
    }
    count
}

fn is_benign_product_key_symbol_line(trimmed: &str, lower: &str) -> bool {
    if matches!(
        trimmed,
        "has_single_product_key"
            | "is_single_product_key"
            | "wszProductKey"
            | "SHChangeProductKeyAsIDList"
            | "ShowProductKeyUI"
    ) {
        return true;
    }

    let dangerous_substr = [
        "steal",
        "dump",
        "recover",
        "plaintext",
        "decrypt",
        "leak",
        "exfil",
        "harvest",
        "sniff",
        "grab",
        "scrape",
        "capture",
        "save",
        "export",
        "extract",
        "fetch",
        "retrieve",
        "decode",
        "transmit",
        "upload",
        "http",
        "to_disk",
        "to_file",
        "socket",
        "tcp",
        "secret",
        "password",
        "passwd",
        "store",
        "persist",
        "bypass",
        "unredacted",
        "siphon",
        "obtain",
        "acquire",
        "pull",
    ]
    .iter()
    .any(|v| lower.contains(v));
    if dangerous_substr {
        return false;
    }

    let write_bytes_ok = lower.contains("write_bytes")
        && (lower.starts_with("write_bytes<")
            || lower.contains("::write_bytes")
            || lower.contains("4core3ptr"))
        && lower.contains("shchangeproductkeyasidlist");
    let tokens = split_symbol_word_tokens(trimmed, "productkey");
    let dangerous_tok = tokens.iter().any(|t| {
        if t == "write" && write_bytes_ok {
            return false;
        }
        matches!(
            t.as_str(),
            "read"
                | "write"
                | "call"
                | "get"
                | "send"
                | "copy"
                | "collect"
                | "put"
                | "post"
                | "log"
                | "print"
                | "emit"
        )
    });
    if dangerous_tok {
        return false;
    }

    let collapsed = lower
        .replace(", ", ",")
        .replace("&mut ", "&mut")
        .replace("*mut ", "*mut")
        .replace("*const ", "*const")
        .replace(" -> ", "->");
    if collapsed.contains(' ') {
        return false;
    }

    let pk_snake = count_non_overlapping(lower, "product_key");
    let pk_camel = count_non_overlapping(lower, "productkey");
    let pk_count = pk_snake + pk_camel;
    if pk_count == 0 {
        return false;
    }

    let has_legit_pk_crate = [
        "forensics2rust",
        "net2rust",
        "fs2rust",
        "sys2rust",
        "winctl2rust",
        "guap_",
    ]
    .iter()
    .any(|c| has_v0_crate_seg_prefix(lower, c) || has_itanium_crate_seg_prefix(lower, c))
        || has_v0_crate_seg(lower, "7windows")
        || has_v0_crate_seg(lower, "11windows_sys");
    if (lower.starts_with("_rn") || lower.starts_with("_ri") || lower.starts_with("_zn"))
        && has_legit_pk_crate
        && (has_exact_symbol_boundary(lower, "has_single_product_key")
            || has_exact_symbol_boundary(lower, "is_single_product_key"))
        && pk_count == 1
    {
        return true;
    }

    if pk_snake == 0 && lower.contains("shchangeproductkeyasidlist") {
        let mut all_demangled_ok = true;
        let mut pos = 0usize;
        while let Some(rel) = lower[pos..].find("productkey") {
            let idx = pos + rel;
            let prefix = &lower[..idx];
            let suffix_ok = lower[idx..].starts_with("productkeyasidlist")
                && is_exact_symbol_right_boundary(&lower[idx + "productkeyasidlist".len()..]);
            let prefix_ok = (prefix.ends_with("windows::win32::ui::shell::shchange")
                && is_exact_module_left_boundary(
                    &prefix[..prefix.len() - "windows::win32::ui::shell::shchange".len()],
                ))
                || (prefix.ends_with("windows_sys::win32::ui::shell::shchange")
                    && is_exact_module_left_boundary(
                        &prefix[..prefix.len() - "windows_sys::win32::ui::shell::shchange".len()],
                    ));
            if !(prefix_ok && suffix_ok) {
                all_demangled_ok = false;
                break;
            }
            pos = idx + "productkey".len();
        }
        if all_demangled_ok {
            return true;
        }
        if (lower.starts_with("_rn") || lower.starts_with("_ri"))
            && (has_v0_crate_seg(lower, "7windows5win322ui5shell")
                || has_v0_crate_seg(lower, "11windows_sys5win322ui5shell"))
            && has_v0_shchange_pk_v0(lower)
            && pk_count == 1
        {
            return true;
        }
    }

    if pk_snake == 0 && lower.contains("showproductkeyui") && pk_count == 1 {
        let demangled_ok = [
            "windows::win32::system::windowsprogramming::ieditionupgradebroker::showproductkeyui",
            "windows::win32::system::windowsprogramming::ieditionupgradehelper::showproductkeyui",
            "windows_sys::win32::system::windowsprogramming::ieditionupgradebroker::showproductkeyui",
            "windows_sys::win32::system::windowsprogramming::ieditionupgradehelper::showproductkeyui",
        ]
        .iter()
        .any(|p| has_exact_anchored_path(lower, p));
        if demangled_ok {
            return true;
        }
        if (lower.starts_with("_rn") || lower.starts_with("_ri"))
            && (has_v0_crate_seg(lower, "7windows5win326system18windowsprogramming")
                || has_v0_crate_seg(lower, "11windows_sys5win326system18windowsprogramming"))
            && (has_v0_exact_ident(lower, "21ieditionupgradebroker16showproductkeyui")
                || has_v0_exact_ident(lower, "21ieditionupgradehelper16showproductkeyui"))
        {
            return true;
        }
    }

    false
}
fn is_only_benign_debug_product_key(strings_buf: &str) -> bool {
    let mut saw_benign = false;
    for line in strings_buf.lines() {
        let lb = line.as_bytes();
        if !contains_ascii_ci(lb, b"product_key") && !contains_ascii_ci(lb, b"productkey") {
            continue;
        }
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if is_benign_product_key_symbol_line(trimmed, &lower) {
            saw_benign = true;
        } else {
            return false;
        }
    }
    saw_benign
}

fn is_only_queue_user_apc_flags(strings_buf: &str) -> bool {
    let mut saw_flags = false;
    for line in strings_buf.lines() {
        let lb = line.as_bytes();
        if !contains_ascii_ci(lb, b"queue_user_apc") && !contains_ascii_ci(lb, b"queueuserapc") {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        if upper.contains("QUEUE_USER_APC_FLAGS") {
            saw_flags = true;
        } else {
            return false;
        }
    }
    saw_flags
}

fn is_exact_module_left_boundary(prefix: &str) -> bool {
    if prefix.is_empty()
        || prefix.ends_with('<')
        || prefix.ends_with(',')
        || prefix.ends_with('(')
        || prefix.ends_with(' ')
        || prefix.ends_with('&')
        || prefix.ends_with('*')
    {
        return true;
    }
    for kw in ["&mut", "*mut", "*const"] {
        if let Some(before) = prefix.strip_suffix(kw)
            && (before.is_empty()
                || before.ends_with('<')
                || before.ends_with(',')
                || before.ends_with('(')
                || before.ends_with(' '))
        {
            return true;
        }
    }
    false
}

fn is_exact_symbol_right_boundary(rem: &str) -> bool {
    rem.is_empty()
        || matches!(
            rem.as_bytes()[0],
            b':' | b'{' | b'<' | b'>' | b',' | b')' | b']'
        )
}

fn has_exact_symbol_boundary(lower: &str, name: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(name) {
        let s = pos + rel;
        let e = s + name.len();
        let left_ok = s == 0
            || lower[..s].ends_with("::")
            || (s >= 2
                && bytes[s - 2..s].iter().all(|b| b.is_ascii_digit())
                && (s == 2 || !bytes[s - 3].is_ascii_digit()))
            || (!bytes[s - 1].is_ascii_alphanumeric() && bytes[s - 1] != b'_');
        let rem = &lower[e..];
        let right_ok = is_exact_symbol_right_boundary(rem) || is_v0_closure_or_end_suffix(rem);
        if left_ok && right_ok {
            return true;
        }
        pos = s + 1;
    }
    false
}

fn has_exact_anchored_path(lower: &str, path: &str) -> bool {
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(path) {
        let s = pos + rel;
        let e = s + path.len();
        if is_exact_module_left_boundary(&lower[..s]) && is_exact_symbol_right_boundary(&lower[e..])
        {
            return true;
        }
        pos = s + 1;
    }
    false
}

fn is_v0_tag_prefix_before_crate(mut s: &str) -> bool {
    if let Some(rest) = s.strip_prefix('r') {
        s = rest;
    }
    while !s.is_empty() {
        if let Some(rest) = s
            .strip_prefix("nc")
            .or_else(|| s.strip_prefix("nv"))
            .or_else(|| s.strip_prefix("nt"))
            .or_else(|| s.strip_prefix("xs"))
            .or_else(|| s.strip_prefix("in"))
            .or_else(|| s.strip_prefix("m"))
            .or_else(|| s.strip_prefix("i"))
            .or_else(|| s.strip_prefix("y"))
            .or_else(|| s.strip_prefix("o"))
            .or_else(|| s.strip_prefix("k"))
            .or_else(|| s.strip_prefix("e"))
        {
            s = rest;
        } else {
            return false;
        }
    }
    true
}

fn has_v0_crate_seg(lower: &str, crate_seg: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(crate_seg) {
        let s = pos + rel;
        if s >= 2 && bytes[s - 1] == b'_' {
            let mut run_start = s - 1;
            while run_start > 0 && bytes[run_start - 1].is_ascii_alphanumeric() {
                run_start -= 1;
            }
            let prefix_run = &lower[run_start..s - 1];
            if prefix_run == "c" || (prefix_run.starts_with("cs") && prefix_run.len() >= 3) {
                return true;
            }
            if is_v0_tag_prefix_before_crate(prefix_run) {
                return true;
            }
            // Also handle `...<v0-tag>cs<hash>` inside a longer alphanumeric run (e.g. `11maybeuninitntntntntcs..._`)
            let mut search = 0usize;
            while let Some(cs_rel) = prefix_run[search..].find("cs") {
                let cs_idx = search + cs_rel;
                let hash_part = &prefix_run[cs_idx + 2..];
                let before_cs = &prefix_run[..cs_idx];
                if !hash_part.is_empty()
                    && hash_part.len() <= 16
                    && hash_part.bytes().all(|b| b.is_ascii_alphanumeric())
                    && (is_v0_tag_prefix_before_crate(before_cs)
                        || before_cs.ends_with("nt")
                        || before_cs.ends_with("nv")
                        || before_cs.ends_with("nc"))
                {
                    return true;
                }
                search = cs_idx + 2;
            }
        }
        pos = s + 1;
    }
    false
}

fn has_v0_crate_seg_prefix(lower: &str, crate_prefix: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(crate_prefix) {
        let s = pos + rel;
        let mut d_start = s;
        while d_start > 0 && bytes[d_start - 1].is_ascii_digit() {
            d_start -= 1;
        }
        if d_start < s && d_start >= 2 && bytes[d_start - 1] == b'_' {
            let mut run_start = d_start - 1;
            while run_start > 0 && bytes[run_start - 1].is_ascii_alphanumeric() {
                run_start -= 1;
            }
            let prefix_run = &lower[run_start..d_start - 1];
            let len_val: usize = lower[d_start..s].parse().unwrap_or(0);
            let seg_end = d_start + (s - d_start) + len_val;
            if len_val >= crate_prefix.len()
                && seg_end <= lower.len()
                && (prefix_run == "c"
                    || (prefix_run.starts_with("cs") && prefix_run.len() >= 3)
                    || is_v0_tag_prefix_before_crate(prefix_run))
            {
                return true;
            }
        }
        pos = s + 1;
    }
    false
}

fn has_itanium_crate_seg_prefix(lower: &str, crate_prefix: &str) -> bool {
    if !lower.starts_with("_zn") {
        return false;
    }
    let bytes = lower.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(crate_prefix) {
        let s = pos + rel;
        let mut d_start = s;
        while d_start > 0 && bytes[d_start - 1].is_ascii_digit() {
            d_start -= 1;
        }
        if d_start < s && d_start >= 3 && matches!(bytes[d_start - 1], b'n' | b'z' | b'e') {
            let len_val: usize = lower[d_start..s].parse().unwrap_or(0);
            if len_val >= crate_prefix.len() && s + len_val <= lower.len() {
                return true;
            }
        }
        pos = s + 1;
    }
    false
}

fn has_v0_shchange_pk_v0(lower: &str) -> bool {
    if has_v0_exact_ident(lower, "26shchangeproductkeyasidlist") {
        return true;
    }
    const PAT: &str = "26shchangeproductkeyasidlist";
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(PAT) {
        let s = pos + rel;
        let e = s + PAT.len();
        let left_ok = s == 0 || !lower.as_bytes()[s - 1].is_ascii_digit();
        let rem = &lower[e..];
        let safe_rem = is_v0_closure_or_end_suffix(rem)
            || rem
                .strip_prefix("11write_bytes")
                .is_some_and(|r| r.starts_with('b') && r.ends_with('_'))
            || rem
                .strip_prefix("e6zeroed")
                .is_some_and(is_v0_closure_or_end_suffix)
            || rem
                .strip_prefix("e10as_mut_ptr")
                .is_some_and(is_v0_closure_or_end_suffix)
            || rem
                .strip_prefix("e11assume_init")
                .is_some_and(is_v0_closure_or_end_suffix)
            || (rem.starts_with("ntntcs")
                && (rem.ends_with("4core7default7default7default")
                    || rem.ends_with("4core5clone5clone5clone")));
        if left_ok && safe_rem {
            return true;
        }
        pos = s + 1;
    }
    false
}

fn has_v0_exact_ident(lower: &str, len_and_ident: &str) -> bool {
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(len_and_ident) {
        let s = pos + rel;
        let e = s + len_and_ident.len();
        let left_ok = s == 0 || !lower.as_bytes()[s - 1].is_ascii_digit();
        let rem = &lower[e..];
        if left_ok && (rem.is_empty() || is_v0_closure_or_end_suffix(rem)) {
            return true;
        }
        pos = s + 1;
    }
    false
}

fn is_v0_verified_report_suffix(rem: &str) -> bool {
    let valid_head = rem.starts_with('0')
        || rem.starts_with('e')
        || rem
            .strip_prefix('s')
            .and_then(|after_s| after_s.split_once('_'))
            .is_some_and(|(id, _)| id.bytes().all(|b| b.is_ascii_alphanumeric()));
    if !valid_head {
        return false;
    }
    if !rem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return false;
    }
    let Some(no_trail) = rem.strip_suffix('_') else {
        return false;
    };
    let bytes = no_trail.as_bytes();
    (2..=5).any(|k| {
        bytes.len() >= k
            && bytes[bytes.len() - k] == b'b'
            && bytes[bytes.len() - k + 1..]
                .iter()
                .all(|c| c.is_ascii_alphanumeric())
    })
}

fn is_v0_closure_or_end_suffix(mut rem: &str) -> bool {
    if rem.is_empty() {
        return true;
    }
    let mut steps = 0usize;
    while !rem.is_empty() {
        steps += 1;
        if steps > 16 {
            return false;
        }
        if let Some(after_zero) = rem.strip_prefix('0') {
            if after_zero.is_empty() {
                return true;
            }
            if after_zero.starts_with('0')
                || after_zero.starts_with('e')
                || after_zero.starts_with('b')
                || after_zero.starts_with('s')
            {
                rem = after_zero;
                continue;
            }
            if after_zero.starts_with("nc")
                || after_zero.starts_with("nv")
                || after_zero.starts_with("nt")
                || after_zero.starts_with("in")
            {
                let rest = &after_zero[2..];
                return (rest.starts_with("cs")
                    || rest.starts_with('b')
                    || rest.starts_with("nc")
                    || rest.starts_with("nv")
                    || rest.starts_with("nt")
                    || rest.bytes().next().is_some_and(|b| b.is_ascii_digit()))
                    && rest.ends_with('_');
            }
            return false;
        }
        if let Some(after_e) = rem.strip_prefix('e') {
            if after_e.is_empty() {
                return true;
            }
            if after_e.starts_with('e')
                || after_e.starts_with('b')
                || after_e.starts_with('0')
                || after_e.starts_with('s')
            {
                rem = after_e;
                continue;
            }
            if after_e.starts_with("nt")
                || after_e.starts_with("nv")
                || after_e.starts_with("nc")
                || after_e.starts_with("in")
            {
                let rest = &after_e[2..];
                return (rest.starts_with("cs")
                    || rest.starts_with('b')
                    || rest.starts_with("nc")
                    || rest.starts_with("nv")
                    || rest.starts_with("nt")
                    || rest.bytes().next().is_some_and(|b| b.is_ascii_digit()))
                    && rest.ends_with('_');
            }
            return false;
        }
        if let Some(after_b) = rem.strip_prefix('b') {
            let Some(u) = after_b.find('_') else {
                return false;
            };
            if !after_b[..u].bytes().all(|b| b.is_ascii_alphanumeric()) {
                return false;
            }
            rem = &after_b[u + 1..];
            continue;
        }
        if let Some(after_s) = rem.strip_prefix('s') {
            let Some(u) = after_s.find('_') else {
                return false;
            };
            if !after_s[..u].bytes().all(|b| b.is_ascii_alphanumeric()) {
                return false;
            }
            let after_u = &after_s[u + 1..];
            if after_u.starts_with('0') || after_u.starts_with('e') || after_u.starts_with('b') {
                rem = after_u;
                continue;
            }
            return false;
        }
        return false;
    }
    true
}

fn is_v0_crate_root_winsafe_hprocess(s: &str) -> bool {
    if !s.starts_with("_R") || s.contains(' ') || !s.contains("8HPROCESS18WriteProcessMemory") {
        return false;
    }
    let bytes = s.as_bytes();
    let mut pos = 2usize;
    while pos < bytes.len() {
        match bytes[pos] {
            b'N' if pos + 1 < bytes.len() && bytes[pos + 1].is_ascii_alphabetic() => {
                pos += 2;
            }
            b'M' | b'I' => {
                pos += 1;
            }
            b'C' => {
                pos += 1;
                if bytes.get(pos) == Some(&b's') {
                    pos += 1;
                    while pos < bytes.len() && bytes[pos].is_ascii_alphanumeric() {
                        pos += 1;
                    }
                    if bytes.get(pos) == Some(&b'_') {
                        pos += 1;
                    } else {
                        return false;
                    }
                }
                let rest = &s[pos..];
                if rest.starts_with("7winsafe6kernel7handles8hprocess")
                    || (rest.starts_with("7winsafe6kernel") && s.contains("7handles8hprocess"))
                {
                    return true;
                }
                if s.starts_with("_RINvMNt")
                    && rest.starts_with("4core6result")
                    && s.contains("6Result")
                    && s.contains("3map")
                    && s.contains("7winsafe6kernel2co5error5ERROR")
                    && s.contains("7handles8hprocess")
                    && s.contains("8HPROCESS18WriteProcessMemory0")
                {
                    let lower = s.to_ascii_lowercase();
                    return has_v0_crate_seg(&lower, "7winsafe6kernel")
                        && !lower.contains("windows::")
                        && !lower.contains("windows_sys")
                        && !lower.contains("memoryapi")
                        && !lower.contains("kernel32");
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

fn strip_stdlib_in_place_collect(lower: &str) -> String {
    let mut out = lower.to_string();
    let has_alloc_vec = out.contains("alloc::vec::in_place_collect")
        || out.contains("5alloc3vec16in_place_collect")
        || out.contains("16in_place_collect24write_in_place_with_drop")
        || (out.contains("alloc::vec") && out.contains("collect_in_place<"))
        || (out.contains("5alloc3vec") && out.contains("16collect_in_place"));
    if has_alloc_vec {
        out = out.replace("write_in_place_with_drop", "");
        out = out.replace("alloc::vec::in_place_collect", "alloc::vec::");
        out = out.replace("5alloc3vec16in_place_collect", "5alloc3vec");
        out = out.replace(
            "16in_place_collect18from_iter_in_place",
            "18from_iter_in_place",
        );
        out = out.replace("16in_place_collect", "");
        out = out.replace("collect_in_place<", "<");
        out = out.replace("16collect_in_place", "");
    }
    if out.contains("alloc::vec::vec<") && out.contains("collect<core::iter::") {
        out = out.replace("collect<core::iter::", "<core::iter::");
    }
    if out.contains("core::iter::adapters::copied::copy_try_fold") {
        out = out.replace(
            "core::iter::adapters::copied::copy_try_fold",
            "core::iter::adapters::copied::",
        );
    }
    if out.contains("6copied13copy_try_fold") {
        out = out.replace("6copied13copy_try_fold", "6copied");
    }
    if out.contains("get_or_insert_with<") {
        out = out.replace("get_or_insert_with<", "<");
    }
    out
}

fn strip_exact_extract_keymaterial_prefix(input: &str) -> String {
    const NEEDLE: &str = "extract_keymaterial_prefix";
    let mut out = String::with_capacity(input.len());
    let mut pos = 0usize;
    let bytes = input.as_bytes();
    while let Some(rel) = input[pos..].find(NEEDLE) {
        let start = pos + rel;
        let end = start + NEEDLE.len();
        let left_ok = start == 0
            || input[..start].ends_with("::")
            || input[..start].ends_with("26")
            || (!bytes[start - 1].is_ascii_alphanumeric() && bytes[start - 1] != b'_');
        let right_rem = &input[end..];
        let right_ok = right_rem.is_empty()
            || matches!(right_rem.as_bytes()[0], b':' | b'{' | b'<')
            || is_v0_closure_or_end_suffix(right_rem);
        if left_ok && right_ok {
            out.push_str(&input[pos..start]);
        } else {
            out.push_str(&input[pos..end]);
        }
        pos = end;
    }
    out.push_str(&input[pos..]);
    out
}

fn is_benign_keymaterial_symbol_line(is_net2rust_bin: bool, lower: &str) -> bool {
    if !is_net2rust_bin {
        return false;
    }
    let collapsed = lower
        .replace(", ", ",")
        .replace("&mut ", "&mut")
        .replace(" -> ", "->");
    if collapsed.contains(' ') {
        return false;
    }
    let is_rust_symbol = collapsed.starts_with("_r")
        || collapsed.starts_with("_z")
        || collapsed.contains("net2rust_report::")
        || collapsed.contains("net2rust_core::r4::")
        || collapsed.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b':'
                        | b'<'
                        | b'>'
                        | b','
                        | b'{'
                        | b'}'
                        | b'#'
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'&'
                        | b'-'
                        | b'!'
                        | b'*'
                )
        });
    if !is_rust_symbol {
        return false;
    }

    let stripped_stdlib = strip_stdlib_in_place_collect(lower);
    let mut verb_check_str = strip_exact_extract_keymaterial_prefix(&stripped_stdlib);
    for exact_safe in [
        "span_has_unredacted_keymaterial_in_html_quote",
        "has_unredacted_inner_keymaterial_in_span_depth",
        "has_unredacted_inner_keymaterial_in_span",
        "raw_string_has_unredacted_closing_keymaterial_tag",
        "has_unredacted_closing_keymaterial_tag_json",
        "has_unredacted_closing_keymaterial_tag_with_depth",
    ] {
        verb_check_str = verb_check_str.replace(exact_safe, "");
    }
    let has_dangerous_substr = [
        "steal",
        "dump",
        "recover",
        "plaintext",
        "decrypt",
        "leak",
        "exfil",
        "harvest",
        "sniff",
        "grab",
        "scrape",
        "capture",
        "save",
        "export",
        "read_",
        "copy_",
        "_copy",
        "collect_",
        "_collect",
        "write_",
        "_write",
        "send_",
        "_send",
        "fetch",
        "retrieve",
        "decode",
        "transmit",
        "upload",
        "http",
        "to_disk",
        "to_file",
        "socket",
        "tcp",
        "post_",
        "_post",
        "get_keymaterial",
        "get_wlan",
        "secret",
        "password",
        "passwd",
        "extract",
        "bypass",
        "persist",
        "store",
    ]
    .iter()
    .any(|v| verb_check_str.contains(v));
    if has_dangerous_substr {
        return false;
    }

    let tokens = split_symbol_word_tokens(&verb_check_str, "keymaterial");
    let has_dangerous_tok = tokens.iter().any(|t| {
        matches!(
            t.as_str(),
            "read"
                | "write"
                | "copy"
                | "collect"
                | "send"
                | "get"
                | "put"
                | "post"
                | "log"
                | "print"
                | "emit"
                | "unredacted"
        )
    });
    if has_dangerous_tok {
        return false;
    }

    const VERIFIED_CORE_KM: &[&str] = &[
        "openingkeymaterialtag",
        "find_opening_keymaterial_tag",
        "find_closing_keymaterial_tag",
        "sanitize_wlan_profile_xml",
    ];
    const VERIFIED_REPORT_KM: &[&str] = &[
        "compute_open_keymaterial_tag_ranges",
        "find_split_keymaterial_in_attr",
        "has_unredacted_inner_keymaterial_in_span_depth",
        "is_raw_keymaterial_close_at",
        "contains_keymaterial_word",
        "extract_keymaterial_prefix",
        "sanitize_escaped_keymaterial_in_str",
        "sanitize_escaped_keymaterial_in_str_with_marker_and_origin",
        "sanitize_escaped_keymaterial_in_str_with_options",
        "opening_keymaterial_tag_at",
        "raw_keymaterial_name_end",
        "is_raw_keymaterial_open_at",
        "span_has_unredacted_keymaterial_in_html_quote",
        "field_has_html_encoded_json_or_keymaterial",
        "slice_contains_closing_keymaterial_tag",
        "has_unredacted_inner_keymaterial_in_span",
        "raw_string_has_unredacted_closing_keymaterial_tag",
        "has_unredacted_closing_keymaterial_tag_json",
        "has_unredacted_closing_keymaterial_tag_with_depth",
        "find_opening_keymaterial_tag",
        "find_closing_keymaterial_tag",
    ];

    if VERIFIED_CORE_KM.contains(&collapsed.as_str())
        || VERIFIED_REPORT_KM.contains(&collapsed.as_str())
    {
        return true;
    }

    let is_v0 = collapsed.starts_with("_r");
    let has_core_v0 = is_v0 && has_v0_crate_seg(&collapsed, "13net2rust_core2r4");
    let has_report_v0 = is_v0 && has_v0_crate_seg(&collapsed, "15net2rust_report");

    let mut pos = 0usize;
    let mut matched_any = false;
    while let Some(rel) = collapsed[pos..].find("keymaterial") {
        let km_s = pos + rel;
        let km_e = km_s + "keymaterial".len();

        let mut found_match: Option<usize> = None;
        for &(crate_prefix, names) in &[
            ("net2rust_core::r4::", VERIFIED_CORE_KM),
            ("net2rust_report::", VERIFIED_REPORT_KM),
        ] {
            for &name in names {
                let Some(km_in_name) = name.find("keymaterial") else {
                    continue;
                };
                if km_s >= km_in_name {
                    let sym_s = km_s - km_in_name;
                    let sym_e = sym_s + name.len();
                    if sym_e <= collapsed.len() && &collapsed[sym_s..sym_e] == name {
                        if is_exact_symbol_right_boundary(&collapsed[sym_e..])
                            && sym_s >= crate_prefix.len()
                            && &collapsed[sym_s - crate_prefix.len()..sym_s] == crate_prefix
                            && is_exact_module_left_boundary(
                                &collapsed[..sym_s - crate_prefix.len()],
                            )
                        {
                            found_match = Some(sym_e);
                            break;
                        }
                        if ((crate_prefix == "net2rust_core::r4::" && has_core_v0)
                            || (crate_prefix == "net2rust_report::" && has_report_v0))
                            && (is_v0_closure_or_end_suffix(&collapsed[sym_e..])
                                || is_v0_verified_report_suffix(&collapsed[sym_e..]))
                        {
                            let len_tag = format!("{}", name.len());
                            if sym_s >= len_tag.len()
                                && collapsed[sym_s - len_tag.len()..sym_s] == *len_tag
                                && (sym_s == len_tag.len()
                                    || !collapsed.as_bytes()[sym_s - len_tag.len() - 1]
                                        .is_ascii_digit()
                                    || (crate_prefix == "net2rust_core::r4::"
                                        && sym_s >= len_tag.len() + 3
                                        && &collapsed
                                            [sym_s - len_tag.len() - 3..sym_s - len_tag.len()]
                                            == "2r4"))
                            {
                                found_match = Some(sym_e);
                                break;
                            }
                        }
                    }
                }
            }
            if found_match.is_some() {
                break;
            }
        }

        let Some(next_pos) = found_match else {
            return false;
        };
        matched_any = true;
        pos = next_pos.max(km_e);
    }

    matched_any
}

fn check_quote_token_at(bytes: &[u8], i: usize) -> Option<usize> {
    let rem = &bytes[i..];
    if rem.starts_with(b"\\\"") {
        Some(2)
    } else if rem.starts_with(b"&quot;") || rem.starts_with(br"\u0022") {
        Some(6)
    } else if rem.starts_with(b"\"") || rem.starts_with(b"'") {
        Some(1)
    } else {
        None
    }
}

fn is_valid_self_closing_attrs(attrs: &str) -> bool {
    let lower = attrs.to_ascii_lowercase();
    for bad in [
        "secret",
        "password",
        "passwd",
        "passphrase",
        "psk",
        "token",
        "credential",
        "plaintext",
        "leak",
        "dump",
        "steal",
        "wifi",
        "exfil",
        "siphon",
        "unredact",
        "raw",
    ] {
        if lower.contains(bad) {
            return false;
        }
    }
    let bytes = attrs.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(q_len) = check_quote_token_at(bytes, i) {
            let q = &bytes[i..i + q_len];
            i += q_len;
            let val_start = i;
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'\\' && q == b"\"" && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i..].starts_with(q) {
                    let val = attrs[val_start..i].trim().to_ascii_lowercase();
                    if !val.is_empty()
                        && !matches!(
                            val.as_str(),
                            "true"
                                | "false"
                                | "0"
                                | "1"
                                | "ok"
                                | "x/>"
                                | "a<br>b"
                                | "[redacted]"
                                | "synthetic-protected-blob"
                        )
                    {
                        return false;
                    }
                    i += q_len;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                return false;
            }
            continue;
        }
        if bytes[i] == b'=' {
            let mut k_end = i;
            while k_end > 0 && bytes[k_end - 1].is_ascii_whitespace() {
                k_end -= 1;
            }
            let mut k_start = k_end;
            while k_start > 0
                && (bytes[k_start - 1].is_ascii_alphanumeric()
                    || matches!(bytes[k_start - 1], b'_' | b'-' | b':'))
            {
                k_start -= 1;
            }
            let attr_key = attrs[k_start..k_end].to_ascii_lowercase();
            if matches!(
                attr_key.as_str(),
                "key" | "value" | "data" | "content" | "pass" | "pwd"
            ) {
                return false;
            }
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let Some(q_len) = check_quote_token_at(bytes, i) else {
                return false;
            };
            let q = &bytes[i..i + q_len];
            i += q_len;
            let val_start = i;
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'\\' && q == b"\"" && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i..].starts_with(q) {
                    let val = attrs[val_start..i].trim().to_ascii_lowercase();
                    if !val.is_empty()
                        && !matches!(
                            val.as_str(),
                            "true"
                                | "false"
                                | "0"
                                | "1"
                                | "ok"
                                | "x/>"
                                | "a<br>b"
                                | "[redacted]"
                                | "synthetic-protected-blob"
                        )
                    {
                        return false;
                    }
                    i += q_len;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                return false;
            }
            continue;
        }
        i += 1;
    }
    true
}

fn find_keymaterial_tag_close(after: &str) -> Option<(usize, usize, bool)> {
    let bytes = after.as_bytes();
    let mut i = 0usize;
    let mut in_quote: Option<&'static [u8]> = None;

    while i < bytes.len() {
        let rem = &bytes[i..];
        if let Some(q) = in_quote {
            if bytes[i] == b'\\' && q == b"\"" && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if rem.starts_with(q) {
                i += q.len();
                in_quote = None;
            } else {
                i += 1;
            }
            continue;
        }

        if rem.starts_with(b"\\\"") {
            in_quote = Some(b"\\\"");
            i += 2;
            continue;
        }
        if rem.starts_with(b"&quot;") {
            in_quote = Some(b"&quot;");
            i += 6;
            continue;
        }
        if rem.starts_with(br"\u0022") {
            in_quote = Some(br"\u0022");
            i += 6;
            continue;
        }
        if bytes[i] == b'"' {
            in_quote = Some(b"\"");
            i += 1;
            continue;
        }
        if bytes[i] == b'\'' {
            in_quote = Some(b"'");
            i += 1;
            continue;
        }

        let gt_len = if bytes[i] == b'>' {
            Some(1usize)
        } else if rem.starts_with(b"&gt;") {
            Some(4usize)
        } else if rem.starts_with(br"\u003e") {
            Some(6usize)
        } else if rem.starts_with(b"u003e") {
            Some(5usize)
        } else {
            None
        };

        if let Some(glen) = gt_len {
            let before_gt = after[..i].trim_end();
            if let Some(attrs) = before_gt.strip_suffix('/') {
                let valid_sc =
                    !attrs.trim_end().ends_with('=') && is_valid_self_closing_attrs(attrs);
                return Some((i, glen, valid_sc));
            }
            return Some((i, glen, false));
        }
        i += 1;
    }
    None
}

fn has_unapproved_diag_context(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    [
        "disabled",
        "dump",
        "plaintext",
        "cleartext",
        "wifi",
        "steal",
        "leak",
        "secret",
        "password",
        "passwd",
        "unredact",
        "bypass",
        "extract",
        "recover",
        "exfil",
        "siphon",
        "raw",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

fn is_safe_keymaterial_tag_line(lower: &str) -> bool {
    const SAFE_DIAG_EXACT: &[&str] = &[
        "r4 violation: unclosed <keymaterial> opening tag detected in exported bytes",
        "r4 violation: truncated unclosed <keymaterial> value detected in exported bytes",
        "r4 violation: unredacted <keymaterial> inside <keymaterial> attributes detected in exported bytes",
        "r4 violation: unredacted <keymaterial> value detected in exported bytes",
        "r4 violation: unclosed <keymaterial> opening tag detected",
        "r4 violation: truncated unclosed <keymaterial> value detected",
        "r4 violation: unredacted <keymaterial> inside <keymaterial> attributes detected",
        "r4 violation: unredacted <keymaterial> value detected",
        "saved wlan profile metadata with r4 keymaterial redaction (mutating reorder/delete/toggle-auto gated).",
        "saved wlan profile metadata with r4 keymaterial redaction (mutating reorder/delete/toggle-auto gated)",
        "managewirelessnetworks equivalent: saved wlan profile metadata with r4 keymaterial redaction (mutating reorder/delete/toggle-auto actions gated).",
        "saved wlan profile metadata with r4 keymaterial redaction (mutating reorder/delete/toggle-auto actions gated).",
        "saved wlan profile metadata with r4 keymaterial redaction (mutating reorder/delete/toggle-auto actions gated)",
    ];
    let bytes = lower.as_bytes();
    let mut pos = 0usize;
    let mut saw_any_tag_syntax = false;
    let mut saw_safe_diag = false;

    while let Some(rel) = lower[pos..].find("keymaterial") {
        let km_pos = pos + rel;
        let after_km = km_pos + "keymaterial".len();

        let matched_diag = SAFE_DIAG_EXACT.iter().find_map(|p| {
            if let Some(p_km_rel) = p.find("keymaterial")
                && km_pos >= p_km_rel
            {
                let start = km_pos - p_km_rel;
                if lower[start..].starts_with(p) {
                    return Some((start, start + p.len()));
                }
            }
            None
        });
        if let Some((diag_start, end_pos)) = matched_diag {
            let matched_str = &lower[diag_start..end_pos];
            let before_diag = lower[pos..diag_start].trim();
            let after_diag = lower[end_pos..].trim();
            let scrub_radio_meta = |s: &str| -> String {
                let mut t = s.replace("zero key extraction", "");
                for slug in [
                    "radio.wifi-info",
                    "radio.wifi-scan",
                    "radio.wifi-console",
                    "radio.wifi-conn",
                    "radio.wifi-profiles",
                    "radio.wifi-hosted",
                    "wifi-info",
                    "wifi-scan",
                    "wifi-console",
                    "wifi-conn",
                    "wifi-profiles",
                    "wifi-hosted",
                    "wifiinfoview",
                ] {
                    t = t.replace(slug, "");
                }
                t
            };
            if has_unapproved_diag_context(&scrub_radio_meta(before_diag)) {
                return false;
            }
            if matched_str.ends_with("detected")
                && !after_diag.is_empty()
                && !after_diag.starts_with('.')
            {
                return false;
            }
            let after_scrubbed = scrub_radio_meta(after_diag);
            if !after_diag.is_empty()
                && !after_diag.contains("keymaterial")
                && has_unapproved_diag_context(&after_scrubbed)
            {
                return false;
            }
            let is_merged_rdata_after_gated = (matched_str.ends_with("gated).")
                || matched_str.ends_with("in exported bytes"))
                && !lower[end_pos..].starts_with(' ')
                && !lower[end_pos..].starts_with('\t')
                && !has_unapproved_diag_context(&after_scrubbed);
            if !after_diag.is_empty()
                && !after_diag.contains("keymaterial")
                && !is_merged_rdata_after_gated
                && after_diag.split_whitespace().count() <= 12
                && !after_diag.starts_with('"')
                && !after_diag.starts_with('<')
                && after_diag != "."
            {
                return false;
            }
            saw_safe_diag = true;
            pos = end_pos;
            continue;
        }

        let mut prefix_start = km_pos;
        if prefix_start > 0 && bytes[prefix_start - 1] == b':' {
            let mut p = prefix_start - 1;
            while p > 0
                && (bytes[p - 1].is_ascii_alphanumeric()
                    || matches!(bytes[p - 1], b'_' | b'.' | b'-'))
            {
                p -= 1;
            }
            if p < prefix_start - 1 {
                prefix_start = p;
            }
        }
        let is_close_tag = lower[..prefix_start].ends_with("</")
            || lower[..prefix_start].ends_with("&lt;/")
            || lower[..prefix_start].ends_with("u003c/");
        let is_open_tag = !is_close_tag
            && (lower[..prefix_start].ends_with('<')
                || lower[..prefix_start].ends_with("&lt;")
                || lower[..prefix_start].ends_with("u003c"));
        let is_colon_open_frag = !is_close_tag
            && !is_open_tag
            && km_pos > 0
            && bytes[km_pos - 1] == b':'
            && prefix_start == km_pos
            && (lower[after_km..].starts_with('>') || lower[after_km..].starts_with("&gt;"));

        if is_close_tag {
            saw_any_tag_syntax = true;
            let close_prefix_len = if lower[..prefix_start].ends_with("</") {
                2
            } else if lower[..prefix_start].ends_with("&lt;/") {
                5
            } else if lower[..prefix_start].ends_with("\\u003c/") {
                7
            } else {
                6
            };
            let before_close = lower[..prefix_start - close_prefix_len].trim_end();
            let matched_redacted_before = [
                ">[redacted]",
                "&gt;[redacted]",
                "u003e[redacted]",
                ">synthetic-protected-blob",
                "&gt;synthetic-protected-blob",
                "u003esynthetic-protected-blob",
            ]
            .iter()
            .find_map(|suf| before_close.strip_suffix(suf));
            let Some(pre_redacted) = matched_redacted_before else {
                return false;
            };
            if has_unapproved_diag_context(pre_redacted)
                || (!pre_redacted.is_empty() && pre_redacted.trim_end().ends_with(':'))
            {
                return false;
            }
            let after_close_ws = lower[after_km..].trim_start();
            let after_gt = after_close_ws
                .strip_prefix('>')
                .or_else(|| after_close_ws.strip_prefix("&gt;"))
                .or_else(|| after_close_ws.strip_prefix("\\u003e"))
                .or_else(|| after_close_ws.strip_prefix("u003e"));
            let Some(tail_after_gt) = after_gt else {
                return false;
            };
            let consumed_close = lower.len() - tail_after_gt.len();
            let tail_trim = tail_after_gt.trim_start();
            if !tail_trim.is_empty()
                && !tail_trim.contains("keymaterial")
                && !tail_trim.starts_with('<')
                && !tail_trim.starts_with("&lt;")
                && !tail_trim.starts_with("\\u003c")
                && !tail_trim.starts_with("u003c")
                && !tail_trim.starts_with('"')
                && !tail_trim.starts_with('\'')
                && !tail_trim.starts_with(',')
                && !tail_trim.starts_with('}')
                && !tail_trim.starts_with(']')
            {
                return false;
            }
            pos = consumed_close.max(after_km);
            continue;
        }

        if is_open_tag || is_colon_open_frag {
            saw_any_tag_syntax = true;
            let after = &lower[after_km..];
            if is_colon_open_frag {
                if has_unapproved_diag_context(&lower[..km_pos - 1]) {
                    return false;
                }
                let after_gt = after
                    .strip_prefix('>')
                    .or_else(|| after.strip_prefix("&gt;"))
                    .unwrap_or("");
                if after_gt.is_empty() {
                    if !lower[..km_pos - 1].trim().is_empty() {
                        return false;
                    }
                    pos = after_km;
                    continue;
                }
                let t = after_gt.trim_start();
                if !(t.starts_with("[redacted]</")
                    || t.starts_with("[redacted]&lt;/")
                    || t.starts_with("[redacted]\\u003c/")
                    || t.starts_with("[redacted]u003c/"))
                {
                    return false;
                }
                pos = after_km;
                continue;
            }
            if !matches!(
                after.as_bytes().first().copied(),
                Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
            ) && !after.starts_with("&gt;")
                && !after.starts_with("\\u003e")
                && !after.starts_with("u003e")
            {
                return false;
            }
            if let Some((gt_rel, gt_len, is_valid_self_closing)) = find_keymaterial_tag_close(after)
            {
                let before_gt = after[..gt_rel].trim_end();
                if before_gt.ends_with('/') {
                    if !is_valid_self_closing {
                        return false;
                    }
                    pos = after_km + gt_rel + gt_len;
                    continue;
                }
                let body_after_gt = after[gt_rel + gt_len..].trim_start();
                if body_after_gt.starts_with("[redacted]</")
                    || body_after_gt.starts_with("[redacted]&lt;/")
                    || body_after_gt.starts_with("[redacted]\\u003c/")
                    || body_after_gt.starts_with("[redacted]u003c/")
                    || body_after_gt.starts_with("synthetic-protected-blob</")
                    || body_after_gt.starts_with("synthetic-protected-blob&lt;/")
                    || body_after_gt.starts_with("synthetic-protected-blob\\u003c/")
                    || body_after_gt.starts_with("synthetic-protected-blobu003c/")
                {
                    pos = after_km + gt_rel + gt_len;
                    continue;
                }
                return false;
            }
            return false;
        }

        if !is_benign_keymaterial_symbol_line(true, lower) {
            return false;
        }
        pos = after_km;
    }

    saw_any_tag_syntax || saw_safe_diag
}
fn has_unsafe_keymaterial_line(is_net2rust_bin: bool, strings_buf: &str) -> bool {
    if !contains_ascii_ci(strings_buf.as_bytes(), b"keymaterial") {
        return false;
    }
    for line in strings_buf.lines() {
        if !contains_ascii_ci(line.as_bytes(), b"keymaterial") {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if !is_net2rust_bin {
            return true;
        }
        if lower == "keymaterial" || lower == ":keymaterial" {
            continue;
        }
        let has_tag_or_diag_syntax = lower.contains("<keymaterial")
            || lower.contains("</keymaterial")
            || lower.contains("&lt;keymaterial")
            || lower.contains("&lt;/keymaterial")
            || lower.contains("u003ckeymaterial")
            || lower.contains("u003c/keymaterial")
            || lower.contains(":keymaterial>")
            || lower.contains(":keymaterial&gt;")
            || lower.contains("r4 violation:")
            || lower.contains("r4 keymaterial redaction");
        if has_tag_or_diag_syntax {
            if !is_safe_keymaterial_tag_line(&lower) {
                return true;
            }
        } else if !is_benign_keymaterial_symbol_line(is_net2rust_bin, &lower) {
            return true;
        }
    }
    false
}

fn is_known_windows_system_dll(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("api-ms-win-")
        || matches!(
            lower.as_str(),
            "advapi32.dll"
                | "bcrypt.dll"
                | "bcryptprimitives.dll"
                | "cfgmgr32.dll"
                | "combase.dll"
                | "comctl32.dll"
                | "comdlg32.dll"
                | "crypt32.dll"
                | "d2d1.dll"
                | "d3d11.dll"
                | "dbghelp.dll"
                | "dwmapi.dll"
                | "dxgi.dll"
                | "gdi32.dll"
                | "imm32.dll"
                | "iphlpapi.dll"
                | "kernel32.dll"
                | "kernelbase.dll"
                | "libgcc_s_dw2-1.dll"
                | "mfplat.dll"
                | "msi.dll"
                | "msimg32.dll"
                | "ntdll.dll"
                | "ole32.dll"
                | "oleaut32.dll"
                | "powrprof.dll"
                | "propsys.dll"
                | "psapi.dll"
                | "rpcrt4.dll"
                | "secur32.dll"
                | "setupapi.dll"
                | "shell32.dll"
                | "shlwapi.dll"
                | "thumbcache.dll"
                | "user32.dll"
                | "userenv.dll"
                | "uxtheme.dll"
                | "version.dll"
                | "wininet.dll"
                | "winmm.dll"
                | "wlanapi.dll"
                | "ws2_32.dll"
        )
}

struct PeSecHdr {
    virtual_size: u32,
    virtual_addr: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
}

fn rva_to_file_off(secs: &[PeSecHdr], rva: u32) -> Option<u64> {
    for s in secs {
        let span = s.raw_size.max(s.virtual_size);
        if rva >= s.virtual_addr && rva < s.virtual_addr.saturating_add(span) {
            let off = rva - s.virtual_addr;
            if off < s.raw_size {
                return Some(s.raw_ptr as u64 + off as u64);
            }
        }
    }
    None
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn read_cstr_at(f: &mut File, file_len: u64, off: u64, max_len: usize) -> Option<Vec<u8>> {
    if off >= file_len {
        return None;
    }
    f.seek(SeekFrom::Start(off)).ok()?;
    let to_read = max_len.min((file_len - off) as usize);
    let mut buf = vec![0u8; to_read];
    f.read_exact(&mut buf).ok()?;
    if let Some(nul) = buf.iter().position(|&c| c == 0) {
        buf.truncate(nul);
    }
    Some(buf)
}

fn pe_has_non_winsafe_wpm_call_sites(bin_path: &Path) -> Result<bool> {
    let mut f = File::open(bin_path)?;
    let file_len = f.metadata()?.len();
    if file_len < 0x100 {
        return Ok(false);
    }
    let hdr_read_len = (file_len as usize).min(16384);
    let mut hdr = vec![0u8; hdr_read_len];
    f.read_exact(&mut hdr)?;
    if &hdr[0..2] != b"MZ" {
        return Ok(false);
    }
    let Some(e_lfanew) = read_u32_le(&hdr, 0x3C) else {
        return Ok(false);
    };
    let pe_off = e_lfanew as usize;
    if e_lfanew < 0x40 || pe_off + 24 > hdr.len() || &hdr[pe_off..pe_off + 4] != b"PE\0\0" {
        return Ok(false);
    }
    let coff_off = pe_off + 4;
    let machine = read_u16_le(&hdr, coff_off).unwrap_or(0);
    if machine != 0x8664 {
        return Ok(false);
    }
    let num_sections = read_u16_le(&hdr, coff_off + 2).unwrap_or(0) as usize;
    let sym_off = read_u32_le(&hdr, coff_off + 8).unwrap_or(0);
    let num_syms = read_u32_le(&hdr, coff_off + 12).unwrap_or(0);
    let opt_hdr_size = read_u16_le(&hdr, coff_off + 16).unwrap_or(0) as usize;
    let opt_off = coff_off + 20;
    let sec_tbl_off = opt_off + opt_hdr_size;
    if opt_hdr_size < 128 || sec_tbl_off + num_sections * 40 > hdr.len() {
        return Ok(false);
    }
    if read_u16_le(&hdr, opt_off).unwrap_or(0) != 0x020B {
        return Ok(false);
    }
    let image_base = read_u64_le(&hdr, opt_off + 24).unwrap_or(0);
    let num_dd = read_u32_le(&hdr, opt_off + 108).unwrap_or(0);
    if num_dd < 2 {
        return Ok(true);
    }
    let import_rva = read_u32_le(&hdr, opt_off + 120).unwrap_or(0);
    if import_rva == 0 {
        return Ok(true);
    }
    let (reloc_rva, reloc_sz) = if num_dd >= 6 {
        (
            read_u32_le(&hdr, opt_off + 152).unwrap_or(0),
            read_u32_le(&hdr, opt_off + 156).unwrap_or(0),
        )
    } else {
        (0, 0)
    };

    let mut secs = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let so = sec_tbl_off + i * 40;
        secs.push(PeSecHdr {
            virtual_size: read_u32_le(&hdr, so + 8).unwrap_or(0),
            virtual_addr: read_u32_le(&hdr, so + 12).unwrap_or(0),
            raw_size: read_u32_le(&hdr, so + 16).unwrap_or(0),
            raw_ptr: read_u32_le(&hdr, so + 20).unwrap_or(0),
            characteristics: read_u32_le(&hdr, so + 36).unwrap_or(0),
        });
    }

    let Some(imp_file_off) = rva_to_file_off(&secs, import_rva) else {
        return Ok(true);
    };
    let mut wpm_iat_rva: Option<u32> = None;
    let mut wpm_hint_name_rva: Option<u32> = None;
    let mut desc_idx = 0u64;
    loop {
        let desc_off = imp_file_off + desc_idx * 20;
        if desc_off + 20 > file_len {
            break;
        }
        f.seek(SeekFrom::Start(desc_off))?;
        let mut d = [0u8; 20];
        f.read_exact(&mut d)?;
        let oft = read_u32_le(&d, 0).unwrap_or(0);
        let name_rva = read_u32_le(&d, 12).unwrap_or(0);
        let ft = read_u32_le(&d, 16).unwrap_or(0);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let lookup_rva = if oft != 0 { oft } else { ft };
        if let Some(mut lt_off) = rva_to_file_off(&secs, lookup_rva) {
            let mut slot = 0u32;
            while lt_off + 8 <= file_len && slot < 65536 {
                f.seek(SeekFrom::Start(lt_off))?;
                let mut eb = [0u8; 8];
                f.read_exact(&mut eb)?;
                let entry = read_u64_le(&eb, 0).unwrap_or(0);
                if entry == 0 {
                    break;
                }
                if (entry & (1u64 << 63)) == 0 {
                    let hn_rva = (entry & 0x7FFF_FFFF) as u32;
                    if let Some(hn_off) = rva_to_file_off(&secs, hn_rva)
                        && let Some(cname) = read_cstr_at(&mut f, file_len, hn_off + 2, 64)
                        && cname.as_slice() == b"WriteProcessMemory"
                    {
                        wpm_iat_rva = Some(ft.saturating_add(slot.saturating_mul(8)));
                        wpm_hint_name_rva = Some(hn_rva.saturating_add(2));
                        break;
                    }
                }
                lt_off += 8;
                slot += 1;
            }
        }
        if wpm_iat_rva.is_some() {
            break;
        }
        desc_idx += 1;
        if desc_idx > 4096 {
            break;
        }
    }

    let Some(wpm_iat_rva) = wpm_iat_rva else {
        return Ok(true);
    };

    let mut wpm_thunk_rva: Option<u32> = None;
    let mut winsafe_wpm_ranges: Vec<(u32, u32)> = Vec::new();
    let has_symtab = sym_off != 0 && num_syms > 0;
    if !has_symtab {
        return Ok(true);
    }

    let sym_bytes_len = (num_syms as u64).saturating_mul(18);
    let str_tbl_off = (sym_off as u64).saturating_add(sym_bytes_len);
    if str_tbl_off + 4 <= file_len {
        f.seek(SeekFrom::Start(str_tbl_off))?;
        let mut sz_b = [0u8; 4];
        f.read_exact(&mut sz_b)?;
        let str_tbl_size = u32::from_le_bytes(sz_b) as u64;
        let capped_str_size = str_tbl_size
            .min(file_len - str_tbl_off)
            .min(128 * 1024 * 1024) as usize;
        let mut str_tbl = vec![0u8; capped_str_size];
        if capped_str_size >= 4 {
            f.seek(SeekFrom::Start(str_tbl_off))?;
            f.read_exact(&mut str_tbl)?;
        }

        let mut text_syms: Vec<(u32, Option<String>)> = Vec::new();
        let mut wpm_winsafe_starts: Vec<u32> = Vec::new();
        f.seek(SeekFrom::Start(sym_off as u64))?;
        let mut sym_rec = [0u8; 18];
        let mut idx = 0u32;
        while idx < num_syms {
            if f.read_exact(&mut sym_rec).is_err() {
                break;
            }
            let aux = sym_rec[17] as u32;
            let sec_num = i16::from_le_bytes([sym_rec[12], sym_rec[13]]);
            let val = read_u32_le(&sym_rec, 8).unwrap_or(0);
            if sec_num > 0 && ((sec_num as usize) <= secs.len()) {
                let sec = &secs[(sec_num - 1) as usize];
                if (sec.characteristics & 0x20) != 0 {
                    let rva = sec.virtual_addr.saturating_add(val);
                    let name_bytes: &[u8] = if read_u32_le(&sym_rec, 0) == Some(0) {
                        let soff = read_u32_le(&sym_rec, 4).unwrap_or(0) as usize;
                        if soff < str_tbl.len() {
                            let rem = &str_tbl[soff..];
                            let nul = rem.iter().position(|&b| b == 0).unwrap_or(rem.len());
                            &rem[..nul]
                        } else {
                            b""
                        }
                    } else {
                        let raw = &sym_rec[0..8];
                        let nul = raw.iter().position(|&b| b == 0).unwrap_or(8);
                        &raw[..nul]
                    };
                    let name_s = String::from_utf8_lossy(name_bytes);
                    let keep_name = if name_s == "WriteProcessMemory" {
                        wpm_thunk_rva = Some(rva);
                        Some(name_s.into_owned())
                    } else if is_v0_crate_root_winsafe_hprocess(&name_s)
                        && !name_s.starts_with("_RNC")
                    {
                        wpm_winsafe_starts.push(rva);
                        Some(name_s.into_owned())
                    } else {
                        None
                    };
                    text_syms.push((rva, keep_name));
                }
            }
            if aux > 0 {
                let skip = (aux as i64).saturating_mul(18);
                let _ = f.seek(SeekFrom::Current(skip));
            }
            idx = idx.saturating_add(1 + aux);
        }

        text_syms.sort_unstable_by_key(|(rva, _)| *rva);
        for start_rva in wpm_winsafe_starts {
            let end_rva = text_syms
                .iter()
                .find(|(rva, _)| *rva > start_rva)
                .map(|(rva, _)| *rva)
                .unwrap_or_else(|| start_rva.saturating_add(4096));
            winsafe_wpm_ranges.push((start_rva, end_rva));
        }
    }

    if winsafe_wpm_ranges.is_empty() {
        return Ok(true);
    }

    let targets_any_wpm_addr = |tgt: u32| -> bool {
        tgt == wpm_iat_rva
            || wpm_thunk_rva.is_some_and(|t| tgt == t)
            || winsafe_wpm_ranges
                .iter()
                .any(|&(ws, we)| tgt >= ws && tgt < we)
    };

    if reloc_rva != 0
        && reloc_sz >= 8
        && let Some(reloc_off) = rva_to_file_off(&secs, reloc_rva)
        && reloc_off + (reloc_sz as u64) <= file_len
    {
        let mut rbuf = vec![0u8; (reloc_sz as usize).min(16 * 1024 * 1024)];
        f.seek(SeekFrom::Start(reloc_off))?;
        f.read_exact(&mut rbuf)?;
        let mut rpos = 0usize;
        while rpos + 8 <= rbuf.len() {
            let page_rva = read_u32_le(&rbuf, rpos).unwrap_or(0);
            let block_sz = read_u32_le(&rbuf, rpos + 4).unwrap_or(0) as usize;
            if block_sz < 8 || rpos + block_sz > rbuf.len() {
                break;
            }
            let count = (block_sz - 8) / 2;
            for k in 0..count {
                let ent = read_u16_le(&rbuf, rpos + 8 + k * 2).unwrap_or(0);
                if (ent >> 12) == 10 {
                    let slot_rva = page_rva.wrapping_add((ent & 0x0FFF) as u32);
                    if let Some(slot_off) = rva_to_file_off(&secs, slot_rva)
                        && slot_off + 8 <= file_len
                    {
                        f.seek(SeekFrom::Start(slot_off))?;
                        let mut vb = [0u8; 8];
                        f.read_exact(&mut vb)?;
                        let abs_val = u64::from_le_bytes(vb);
                        if abs_val >= image_base {
                            let rel_target = abs_val - image_base;
                            if let Ok(tgt32) = u32::try_from(rel_target)
                                && targets_any_wpm_addr(tgt32)
                            {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
            rpos += block_sz;
        }
    }

    let mut wpm_str_rvas: Vec<u32> = Vec::new();
    if let Some(hn) = wpm_hint_name_rva {
        wpm_str_rvas.push(hn);
    }
    let wpm_needle = b"WriteProcessMemory\0";
    let mut data_buf = vec![0u8; CHUNK_SIZE + 64];
    for sec in &secs {
        if (sec.characteristics & 0x20) != 0
            || (sec.characteristics & 0x0200_0000) != 0
            || sec.raw_size == 0
        {
            continue;
        }
        let sec_start = sec.raw_ptr as u64;
        let sec_end = sec_start.saturating_add(sec.raw_size as u64).min(file_len);
        let mut off = sec_start;
        while off < sec_end {
            let chunk_len = ((sec_end - off) as usize).min(CHUNK_SIZE);
            let read_len = ((sec_end - off) as usize).min(chunk_len + 64);
            f.seek(SeekFrom::Start(off))?;
            f.read_exact(&mut data_buf[..read_len])?;
            let bytes = &data_buf[..read_len];
            let base_rva = sec.virtual_addr.saturating_add((off - sec_start) as u32);
            for i in 0..chunk_len {
                if i + wpm_needle.len() <= read_len && &bytes[i..i + wpm_needle.len()] == wpm_needle
                {
                    let str_rva = base_rva.saturating_add(i as u32);
                    if !wpm_str_rvas.contains(&str_rva) {
                        wpm_str_rvas.push(str_rva);
                    }
                }
                if reloc_sz == 0 && i % 8 == 0 && i + 8 <= read_len {
                    let abs_val = u64::from_le_bytes([
                        bytes[i],
                        bytes[i + 1],
                        bytes[i + 2],
                        bytes[i + 3],
                        bytes[i + 4],
                        bytes[i + 5],
                        bytes[i + 6],
                        bytes[i + 7],
                    ]);
                    if abs_val >= image_base
                        && let Ok(tgt32) = u32::try_from(abs_val - image_base)
                        && targets_any_wpm_addr(tgt32)
                    {
                        return Ok(true);
                    }
                }
            }
            off += chunk_len as u64;
        }
    }

    let mut text_buf = vec![0u8; CHUNK_SIZE + 16];
    for sec in &secs {
        if (sec.characteristics & 0x20) == 0 || sec.raw_size == 0 {
            continue;
        }
        let sec_start = sec.raw_ptr as u64;
        let sec_end = sec_start.saturating_add(sec.raw_size as u64).min(file_len);
        let mut off = sec_start;
        while off < sec_end {
            let chunk_len = ((sec_end - off) as usize).min(CHUNK_SIZE);
            let read_len = ((sec_end - off) as usize).min(chunk_len + 16);
            f.seek(SeekFrom::Start(off))?;
            f.read_exact(&mut text_buf[..read_len])?;
            let bytes = &text_buf[..read_len];
            let base_rva = sec.virtual_addr.saturating_add((off - sec_start) as u32);

            for i in 0..chunk_len {
                let insn_rva = base_rva.saturating_add(i as u32);
                let in_thunk =
                    wpm_thunk_rva.is_some_and(|t| insn_rva >= t && insn_rva < t.saturating_add(8));
                let in_winsafe = winsafe_wpm_ranges
                    .iter()
                    .any(|&(ws, we)| insn_rva >= ws && insn_rva < we);

                if i + 6 <= read_len
                    && bytes[i] == 0xFF
                    && (bytes[i + 1] == 0x15 || bytes[i + 1] == 0x25)
                {
                    let disp = i32::from_le_bytes([
                        bytes[i + 2],
                        bytes[i + 3],
                        bytes[i + 4],
                        bytes[i + 5],
                    ]);
                    let target = insn_rva.wrapping_add(6).wrapping_add(disp as u32);
                    if target == wpm_iat_rva && !in_thunk && !in_winsafe {
                        return Ok(true);
                    }
                } else if i + 5 <= read_len && (bytes[i] == 0xE8 || bytes[i] == 0xE9) {
                    let rel = i32::from_le_bytes([
                        bytes[i + 1],
                        bytes[i + 2],
                        bytes[i + 3],
                        bytes[i + 4],
                    ]);
                    let target = insn_rva.wrapping_add(5).wrapping_add(rel as u32);
                    let targets_thunk =
                        wpm_thunk_rva.is_some_and(|t| target == t) && !in_thunk && !in_winsafe;
                    let targets_winsafe =
                        winsafe_wpm_ranges.iter().any(|&(ws, _)| target == ws) && !in_winsafe;
                    if targets_thunk || targets_winsafe {
                        return Ok(true);
                    }
                } else if i + 7 <= read_len
                    && (bytes[i] == 0x48 || bytes[i] == 0x4C)
                    && (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B)
                    && (bytes[i + 2] & 0xC7) == 0x05
                {
                    let disp = i32::from_le_bytes([
                        bytes[i + 3],
                        bytes[i + 4],
                        bytes[i + 5],
                        bytes[i + 6],
                    ]);
                    let target = insn_rva.wrapping_add(7).wrapping_add(disp as u32);
                    let targets_iat = target == wpm_iat_rva && !in_thunk && !in_winsafe;
                    let targets_thunk =
                        wpm_thunk_rva.is_some_and(|t| target == t) && !in_thunk && !in_winsafe;
                    let targets_winsafe =
                        winsafe_wpm_ranges.iter().any(|&(ws, _)| target == ws) && !in_winsafe;
                    let targets_wpm_str =
                        wpm_str_rvas.contains(&target) && !in_thunk && !in_winsafe;
                    if targets_iat || targets_thunk || targets_winsafe || targets_wpm_str {
                        return Ok(true);
                    }
                }
            }
            off += chunk_len as u64;
        }
    }
    Ok(false)
}
