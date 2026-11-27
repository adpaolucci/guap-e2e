use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::R4Violation;
use crate::rules::{RuleKind, RuleRegistry};
use crate::surface_bin::discover_binaries;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(6);

const CHROME2RUST_BASELINE_MCP_TOOLS: &[&str] = &[
    "chrome2rust_profiles",
    "chrome2rust_sniff",
    "chrome2rust_cache_list",
    "chrome2rust_cache_inspect",
    "chrome2rust_cache_extract",
    "chrome2rust_analyze",
    "chrome2rust_report",
    "chrome2rust_custody",
];

struct RunOutput {
    stdout: String,
    stderr: String,
}

fn run_with_timeout(exe: &Path, args: &[&str], stdin_payload: Option<&[u8]>) -> RunOutput {
    let mut cmd = Command::new(exe);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let Ok(mut child) = cmd.spawn() else {
        return RunOutput {
            stdout: String::new(),
            stderr: String::new(),
        };
    };

    if let Some(payload) = stdin_payload
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = stdin.write_all(payload);
        let _ = stdin.flush();
        drop(stdin);
    }

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).into_owned()
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).into_owned()
    });

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= PROCESS_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break,
        }
    }

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    RunOutput { stdout, stderr }
}

fn combine_stdout_stderr(out: &RunOutput) -> String {
    match (out.stdout.trim().is_empty(), out.stderr.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => out.stdout.clone(),
        (true, false) => out.stderr.clone(),
        (false, false) => format!("{}\n{}", out.stdout, out.stderr),
    }
}

fn select_cli_mcp_executables(guap_root: &Path) -> Result<Vec<PathBuf>> {
    let all_bins = discover_binaries(guap_root)?;
    let mut selected: BTreeSet<PathBuf> = BTreeSet::new();

    for path in all_bins {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if ext != "exe" {
            continue;
        }
        let stem_lower = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if stem_lower.ends_with("-win32")
            || stem_lower.ends_with("-iced")
            || stem_lower.ends_with("-gui")
        {
            continue;
        }
        selected.insert(path);
    }

    Ok(selected.into_iter().collect())
}

pub fn scan_cli_and_mcp(
    guap_root: &Path,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) -> Result<()> {
    let exes = select_cli_mcp_executables(guap_root)?;
    let chrome_new_cred_id_re = Regex::new(
        r"(?i)(?:login|password|passwd|creds?|credential|auth|secret|token|vault|dpapi|key4|key3|keychain|keyring|nss|pk11sdr|decrypt|unprotect|pass|(?:^|[_-])key(?:s|[_-]|$))",
    )?;
    let chrome_new_cred_desc_re = Regex::new(
        r#"(?i)(?:login|password|passwd|creds?|credential|auth|secret|token|vault|dpapi|key4|key3|keychain|keyring|nss_decrypt|pk11sdr|decrypt|unprotect|passview|master.?key|encryption.?key|decryption.?key|(?:^|[\s(\[/,"':=])--?pass\b|\balias(?:es)?\s*[:=]\s*pass\b|(?:^|[\s(\[/,"':=])pass\b|\bkeys\b)"#,
    )?;
    let jsonrpc_req = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-r4","version":"0.1.0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        "\n"
    );

    for exe in exes {
        let stem_lower = exe
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let norm_lower = exe
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let is_chrome_bin = stem_lower.starts_with("chrome2rust")
            || norm_lower
                .split('/')
                .any(|seg| seg == "chrome2rust" || seg.starts_with("chrome2rust-"));
        let is_standalone_mcp = stem_lower.ends_with("-mcp");

        if !is_standalone_mcp {
            let help_out = run_with_timeout(&exe, &["--help"], None);
            let combined_help = combine_stdout_stderr(&help_out);
            if !combined_help.is_empty() {
                scan_help_text(
                    &exe,
                    &combined_help,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }

            let tools_out = run_with_timeout(&exe, &["mcp", "--tools"], None);
            let combined_tools = combine_stdout_stderr(&tools_out);
            if !combined_tools.is_empty() {
                scan_mcp_payload(
                    &exe,
                    &combined_tools,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }

            let rpc_out = run_with_timeout(&exe, &["mcp"], Some(jsonrpc_req.as_bytes()));
            if !rpc_out.stdout.trim().is_empty() {
                scan_mcp_jsonrpc_stream(
                    &exe,
                    &rpc_out.stdout,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
            if !rpc_out.stderr.trim().is_empty() {
                scan_mcp_jsonrpc_stream(
                    &exe,
                    &rpc_out.stderr,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
        } else {
            let tools_out = run_with_timeout(&exe, &["--tools"], None);
            let combined_tools = combine_stdout_stderr(&tools_out);
            if !combined_tools.is_empty() {
                scan_mcp_payload(
                    &exe,
                    &combined_tools,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }

            let rpc_out = run_with_timeout(&exe, &[], Some(jsonrpc_req.as_bytes()));
            if !rpc_out.stdout.trim().is_empty() {
                scan_mcp_jsonrpc_stream(
                    &exe,
                    &rpc_out.stdout,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
            if !rpc_out.stderr.trim().is_empty() {
                scan_mcp_jsonrpc_stream(
                    &exe,
                    &rpc_out.stderr,
                    is_chrome_bin,
                    &chrome_new_cred_id_re,
                    &chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
        }
    }

    Ok(())
}

fn direct_exclusion_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:no|not|never|without|except|unless|exclude[ds]?|excluding|prohibit(?:ed|s)?|prohibiting|forbid(?:den|s)?|forbidding|disallow(?:ed|s)?|disallowing|ban(?:ned|s)?|banning|omit(?:ted|s)?|omitting|skip(?:ped|s)?|skipping|instead\s+of|rather\s+than|replaces?|replaced|replacing|(?:never|not)\s+(?:calls?|call(?:ed|ing)?|uses?|use[ds]?|using|invokes?|invoked|invoking|includes?|included|including|supports?|supported|supporting|exposes?|exposed|exposing|implements?|implemented|implementing|contains?|contained|containing|runs?|running|executes?|executed|executing|emits?|emitted|emitting)|does\s+not\s+(?:include|use|call|support|expose|implement|contain)|do\s+not\s+(?:include|use|call|support|expose|implement|contain))(?:\s+(?:the|any|all))?[\s:,-]*)$",
        )
        .expect("valid direct exclusion suffix regex")
    })
}

fn exclusion_list_conjunction_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:no|not|never|without|forbid(?:s|den|ding)?|exclude[ds]?|excluding|prohibit(?:s|ed|ing)?|disallow(?:s|ed|ing)?|never\s+(?:calls?|uses?|invokes?|includes?|emits?|runs?|executes?)|does\s+not\s+(?:include|use|call|support|expose|implement|contain)|do\s+not\s+(?:include|use|call|support|expose|implement|contain))(?:\s+(?:the|any|all))?\s+[A-Za-z0-9_.-]+(?:\s+(?:or|and|nor)\s+[A-Za-z0-9_.-]+)*\s+(?:or|and|nor)\s+)$",
        )
        .expect("valid exclusion list conjunction regex")
    })
}

fn fs_extra_exclusion_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:zero|retired|obsolete|deprecated)(?:\s+(?:the|any|all))?[\s:,-]*)$",
        )
        .expect("valid fs extra exclusion suffix regex")
    })
}

fn after_qualifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:is|when|if|while|where|unless)\s+(?:false|off|disabled?|inactive|skipped|enabled?|true|on|active)\b|\(\s*(?:is\s+)?(?:false|off|disabled?|optional)\s*\)|,\s*actually\b",
        )
        .expect("valid after qualifier regex")
    })
}

fn clause_negator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:no|not|never|none|neither|nor|hardly|scarcely|barely|without|except|unless|nope|optional|stop(?:s|ped|ping)?|avoid(?:s|ed|ing)?|cease[sd]?|quit(?:s|ted|ting)?|forget(?:s|ting)?|forgot|does\s+not|doesn't|do\s+not|don't|did\s+not|didn't|cannot|can't|won't|will\s+not|wouldn't|shouldn't|mustn't|isn't|aren't|wasn't|weren't|hasn't|haven't|fail(?:s|ed|ing)?\s+to|unable\s+to|refuse[sd]?\s+to|no\s+longer|used\s+to|disabled|disable[ds]?|bypass(?:ed|es|ing)?)\b",
        )
        .expect("valid clause negator regex")
    })
}

fn except_pre_trigger_blocks_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:exclude[ds]?|excluding|prohibit\w*|ban(?:ned|s|ning)?|forbid\w*|disallow\w*|omit\w*|skip\w*|stop(?:s|ped|ping)?|avoid(?:s|ed|ing)?|all|everything|anything|every)\b",
        )
        .expect("valid except pre trigger blocks regex")
    })
}

fn after_negator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(?:(?::|=)\s*|[\(\[]\s*)?(?:not|false|off|disabled?|none|nope|optional|0)\b|^\s*(?:unless|except)\b|^\s*\?",
        )
        .expect("valid after negator regex")
    })
}

fn km_after_bound_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^[>\s_-]*(?:redaction|redacted|redact(?:s|ing)?|sanitiz(?:ation|ed|er|es|ing)|mask(?:ing|ed|s)?|scrub(?:bing|bed|s)?|strip(?:ping|ped|s)?|omission|omitted|removal|removed)\b",
        )
        .expect("valid km after bound regex")
    })
}

fn km_before_bound_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:redact(?:s|ed|ing|ion)?|sanitiz(?:e|es|ed|ing|ation)|mask(?:s|ed|ing)?|scrub(?:s|bed|bing)?|strip(?:s|ped|ping)?|remov(?:e|es|ed|ing)|omit(?:s|ted|ting)?)(?:\s+(?:the|any|all|plaintext))?[\s<_-]*$",
        )
        .expect("valid km before bound regex")
    })
}

fn km_disabled_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:disabled?|off|false|bypass(?:ed|es|ing)?|inactive|skipped|optional|nope|maybe|questionable|conditional)\b",
        )
        .expect("valid km disabled regex")
    })
}

fn km_danger_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:dump\w*|extract\w*|recover\w*|steal\w*|stolen|leak\w*|exfil\w*|harvest\w*|decrypt\w*|unprotect\w*|unredacted|unsanitized|unmasked|disclos\w*|raw|intact|preserved|unmodified|verbatim|keep|keeps|kept|outputs?|returns?|saves?|saving|reads?|writes?|writing|exposes?|fetches|fetch|transmits?|prints?|logs?|emits?|sends?|copy|copies|collects?|stores?|persists?|uploads?|decodes?|streams?|shows?|displays?)\b",
        )
        .expect("valid km danger regex")
    })
}

fn km_plaintext_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:plaintext|cleartext)\b").expect("valid km plaintext regex")
    })
}

fn km_redact_verb_before_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:redact(?:s|ed|ing|ion)?|sanitiz(?:e|es|ed|ing|ation)|mask(?:s|ed|ing)?|scrub(?:s|bed|bing)?|strip(?:s|ped|ping)?|remov(?:e|es|ed|ing)|omit(?:s|ted|ting)?)(?:\s+(?:the|any|all))?\s*$",
        )
        .expect("valid km redact verb before regex")
    })
}

fn clause_bounds_around(text: &str, m_start: usize, m_end: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let s = m_start.min(text.len());
    let e = m_end.min(text.len());
    let is_delim = |i: usize| -> bool {
        let b = bytes[i];
        if matches!(b, b';' | b'!' | b'\n' | b'\r') {
            return true;
        }
        if b == b'.' {
            return i + 1 >= bytes.len() || bytes[i + 1].is_ascii_whitespace();
        }
        false
    };

    let mut c_start = 0usize;
    let mut i = s;
    while i > 0 {
        i -= 1;
        if is_delim(i) {
            c_start = i + 1;
            break;
        }
    }
    let mut c_end = text.len();
    let mut j = e;
    while j < bytes.len() {
        if is_delim(j) {
            c_end = j;
            break;
        }
        j += 1;
    }
    (c_start, c_end)
}

fn is_safe_keymaterial_redaction_span(text: &str, m_start: usize, m_end: usize) -> bool {
    let before = &text[..m_start.min(text.len())];
    let after = &text[m_end.min(text.len())..];
    let before_lower = before.to_ascii_lowercase();
    let after_lower = after.to_ascii_lowercase();

    if before.ends_with('<') || before_lower.ends_with("&lt;") || before_lower.ends_with("u003c") {
        let after_trim = after_lower.trim_start();
        let safe_tag = after_trim == "/>"
            || after_trim.starts_with("/> ")
            || after_trim.starts_with(">[redacted]</keymaterial>")
            || after_trim.starts_with("&gt;[redacted]&lt;/keymaterial&gt;");
        if !safe_tag {
            return false;
        }
    }

    let (c_start, c_end) = clause_bounds_around(text, m_start, m_end);
    let clause_before = &text[c_start..m_start.min(text.len())];
    let clause_after = &text[m_end.min(text.len())..c_end];

    let locally_bound =
        km_after_bound_re().is_match(after) || km_before_bound_re().is_match(clause_before);
    if !locally_bound {
        return false;
    }

    if clause_after.contains('?')
        || clause_negator_re().is_match(clause_before)
        || clause_negator_re().is_match(clause_after)
        || km_disabled_re().is_match(clause_before)
        || km_disabled_re().is_match(clause_after)
        || km_disabled_re().is_match(text)
    {
        return false;
    }

    if km_danger_re().is_match(text) {
        return false;
    }
    for pm in km_plaintext_re().find_iter(text) {
        let pb = &text[c_start.min(pm.start())..pm.start()];
        if !km_redact_verb_before_re().is_match(pb) {
            return false;
        }
    }

    true
}

pub(crate) fn is_negated_exclusion_at_span_with_fs(
    text: &str,
    m_start: usize,
    m_end: usize,
    rule_id: &str,
    matched: &str,
    allow_fs_extras: bool,
) -> bool {
    if rule_id == "R4-API-CRED-05" && matched.eq_ignore_ascii_case("keymaterial") {
        return is_safe_keymaterial_redaction_span(text, m_start, m_end);
    }
    let (c_start, c_end) = clause_bounds_around(text, m_start, m_end);
    let clause_before = &text[c_start..m_start.min(text.len())];
    let clause_after = &text[m_end.min(text.len())..c_end];
    if after_negator_re().is_match(clause_after)
        || clause_negator_re().is_match(clause_after)
        || after_qualifier_re().is_match(clause_after)
    {
        return false;
    }

    if (rule_id == "R4-BASELINE-CHROME" || allow_fs_extras)
        && clause_before.to_ascii_lowercase().ends_with("non-")
    {
        let pre = &clause_before[..clause_before.len() - 4];
        if !clause_negator_re().is_match(pre) {
            return true;
        }
    }

    if let Some(trig) = direct_exclusion_suffix_re().find(clause_before) {
        let pre_trigger = &clause_before[..trig.start()];
        let trig_lower = trig.as_str().trim_start().to_ascii_lowercase();
        let is_exception_trig = trig_lower.starts_with("except")
            || trig_lower.starts_with("unless")
            || trig_lower.starts_with("instead")
            || trig_lower.starts_with("rather");
        if is_exception_trig && except_pre_trigger_blocks_re().is_match(pre_trigger) {
            return false;
        }
        if !clause_negator_re().is_match(pre_trigger) {
            return true;
        }
        return false;
    }

    if let Some(trig) = exclusion_list_conjunction_suffix_re().find(clause_before) {
        let pre_trigger = &clause_before[..trig.start()];
        if !clause_negator_re().is_match(pre_trigger) {
            return true;
        }
    }

    if allow_fs_extras && let Some(trig) = fs_extra_exclusion_suffix_re().find(clause_before) {
        let pre_trigger = &clause_before[..trig.start()];
        if !clause_negator_re().is_match(pre_trigger) {
            return true;
        }
    }

    false
}

pub(crate) fn is_negated_exclusion_at_span(
    text: &str,
    m_start: usize,
    m_end: usize,
    rule_id: &str,
    matched: &str,
) -> bool {
    is_negated_exclusion_at_span_with_fs(text, m_start, m_end, rule_id, matched, false)
}

fn is_help_commands_header(line: &str, lower: &str) -> bool {
    let unindented = !line.starts_with(' ') && !line.starts_with('\t');
    lower == "commands:"
        || lower == "subcommands:"
        || lower == "available commands:"
        || lower == "additional commands:"
        || lower == "built-in commands:"
        || (unindented && lower.ends_with("commands:"))
}

fn is_help_options_header(line: &str, lower: &str) -> bool {
    let unindented = !line.starts_with(' ') && !line.starts_with('\t');
    lower == "options:"
        || lower == "flags:"
        || lower == "global options:"
        || lower == "arguments:"
        || lower == "args:"
        || (unindented
            && (lower.ends_with("options:")
                || lower.ends_with("flags:")
                || lower.ends_with("arguments:")))
}

fn extract_bracket_label_tokens(line: &str, label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = line.to_ascii_lowercase();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(label) {
        let start = pos + rel + label.len();
        if let Some(end_rel) = lower[start..].find(']') {
            let inner = &line[start..start + end_rel];
            for item in inner.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
                let clean =
                    item.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
                if !clean.is_empty() {
                    out.push(clean.to_string());
                }
            }
            pos = start + end_rel + 1;
        } else {
            break;
        }
    }
    out
}

fn scan_help_text(
    exe: &Path,
    help_text: &str,
    is_chrome_bin: bool,
    chrome_new_cred_id_re: &Regex,
    chrome_new_cred_desc_re: &Regex,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    let mut in_commands_section = false;
    let mut in_options_section = false;
    let mut in_usage_section = false;

    for (idx, line) in help_text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();

        if is_help_commands_header(line, &lower) {
            in_commands_section = true;
            in_options_section = false;
            in_usage_section = false;
            continue;
        }
        if is_help_options_header(line, &lower) {
            in_options_section = true;
            in_commands_section = false;
            in_usage_section = false;
            continue;
        }
        if lower.starts_with("usage:") {
            in_usage_section = true;
            in_commands_section = false;
            in_options_section = false;
        } else if trimmed.is_empty()
            || (!line.starts_with(' ') && !line.starts_with('\t') && lower.ends_with(':'))
        {
            in_usage_section = false;
            if !trimmed.is_empty() {
                in_commands_section = false;
                in_options_section = false;
            }
        }

        let in_listing_section = in_commands_section || in_options_section || in_usage_section;

        let is_usage_line = lower.starts_with("usage:");
        let cmd_col_prefix: Option<&str> = if in_commands_section && !trimmed.is_empty() {
            if let Some((before_gap, _)) = trimmed.split_once("  ") {
                Some(before_gap)
            } else if !trimmed.contains(' ') {
                Some(trimmed)
            } else {
                trimmed.split_whitespace().next()
            }
        } else {
            None
        };

        if is_chrome_bin && !trimmed.is_empty() {
            if in_options_section
                || in_usage_section
                || trimmed.starts_with(['-', '<', '['])
                || is_usage_line
            {
                let mut iter_tokens = trimmed.split_whitespace().peekable();
                if is_usage_line {
                    let _ = iter_tokens.next();
                    if iter_tokens
                        .peek()
                        .is_some_and(|t| t.ends_with(".exe") || !t.starts_with(['-', '<', '[']))
                    {
                        let _ = iter_tokens.next();
                    }
                } else if in_usage_section
                    && iter_tokens.peek().is_some_and(|t| {
                        let tl = t.to_ascii_lowercase();
                        tl.ends_with(".exe")
                            || tl == "chrome2rust"
                            || tl.contains('\\')
                            || tl.contains('/')
                    })
                {
                    let _ = iter_tokens.next();
                }
                for raw_tok in iter_tokens {
                    let clean_punct = raw_tok.trim_end_matches(',');
                    let no_var = clean_punct.trim_end_matches('.');
                    if clean_punct.starts_with('-') {
                        let flag_part = clean_punct.split('=').next().unwrap_or(clean_punct);
                        let stripped = flag_part.trim_start_matches('-');
                        if !stripped.is_empty() && chrome_new_cred_id_re.is_match(stripped) {
                            violations.push(R4Violation {
                                category: "baseline_chrome".to_string(),
                                rule_id: "R4-BASELINE-CHROME".to_string(),
                                path: exe.to_path_buf(),
                                line: Some(line_no),
                                matched_symbol: clean_punct.to_string(),
                                detail: "chrome2rust CLI --help exposes prohibited credential/login option flag".to_string(),
                            });
                        }
                        if let Some(eq_val) = clean_punct.split_once('=').map(|(_, v)| v) {
                            let inner = eq_val.trim_matches(|c: char| {
                                matches!(c, '<' | '>' | '[' | ']' | ',' | '.')
                            });
                            if !inner.is_empty() && chrome_new_cred_id_re.is_match(inner) {
                                violations.push(R4Violation {
                                    category: "baseline_chrome".to_string(),
                                    rule_id: "R4-BASELINE-CHROME".to_string(),
                                    path: exe.to_path_buf(),
                                    line: Some(line_no),
                                    matched_symbol: clean_punct.to_string(),
                                    detail: "chrome2rust CLI --help exposes prohibited credential/login option value".to_string(),
                                });
                            }
                        }
                    } else if (no_var.starts_with('<') && no_var.ends_with('>'))
                        || (no_var.starts_with('[') && no_var.ends_with(']'))
                    {
                        let inner = no_var
                            .trim_matches(|c: char| matches!(c, '<' | '>' | '[' | ']' | ',' | '.'));
                        if !inner.is_empty() && chrome_new_cred_id_re.is_match(inner) {
                            violations.push(R4Violation {
                                category: "baseline_chrome".to_string(),
                                rule_id: "R4-BASELINE-CHROME".to_string(),
                                path: exe.to_path_buf(),
                                line: Some(line_no),
                                matched_symbol: clean_punct.to_string(),
                                detail: "chrome2rust CLI --help exposes prohibited credential/login placeholder".to_string(),
                            });
                        }
                    } else if in_usage_section || is_usage_line {
                        let inner = clean_punct.trim_matches(|c: char| {
                            !c.is_ascii_alphanumeric() && c != '_' && c != '-'
                        });
                        if !inner.is_empty()
                            && !CHROME2RUST_BASELINE_MCP_TOOLS.contains(&inner)
                            && chrome_new_cred_id_re.is_match(inner)
                        {
                            violations.push(R4Violation {
                                category: "baseline_chrome".to_string(),
                                rule_id: "R4-BASELINE-CHROME".to_string(),
                                path: exe.to_path_buf(),
                                line: Some(line_no),
                                matched_symbol: clean_punct.to_string(),
                                detail: "chrome2rust CLI --help Usage exposes prohibited credential/login subcommand".to_string(),
                            });
                        }
                    }
                }
            }
            for tok in extract_bracket_label_tokens(trimmed, "[aliases:")
                .into_iter()
                .chain(extract_bracket_label_tokens(trimmed, "[alias:"))
                .chain(extract_bracket_label_tokens(trimmed, "[env:"))
            {
                if chrome_new_cred_id_re.is_match(&tok) {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: exe.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: tok,
                        detail:
                            "chrome2rust CLI --help exposes prohibited credential/login alias/env"
                                .to_string(),
                    });
                }
            }
            if let Some(cmd_col) = cmd_col_prefix {
                for raw_sub in cmd_col.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
                    let subcmd = raw_sub.trim_matches(|c: char| c == ',' || c == ':');
                    if !subcmd.is_empty() && chrome_new_cred_id_re.is_match(subcmd) {
                        violations.push(R4Violation {
                            category: "baseline_chrome".to_string(),
                            rule_id: "R4-BASELINE-CHROME".to_string(),
                            path: exe.to_path_buf(),
                            line: Some(line_no),
                            matched_symbol: subcmd.to_string(),
                            detail: "chrome2rust CLI --help exposes prohibited credential/login subcommand".to_string(),
                        });
                    }
                }
                for tok in extract_bracket_label_tokens(trimmed, "[aliases:") {
                    if chrome_new_cred_id_re.is_match(&tok) {
                        violations.push(R4Violation {
                            category: "baseline_chrome".to_string(),
                            rule_id: "R4-BASELINE-CHROME".to_string(),
                            path: exe.to_path_buf(),
                            line: Some(line_no),
                            matched_symbol: tok,
                            detail: "chrome2rust CLI --help exposes prohibited credential/login subcommand alias".to_string(),
                        });
                    }
                }
            }

            for m in chrome_new_cred_desc_re.find_iter(line) {
                if !is_negated_exclusion_at_span(
                    line,
                    m.start(),
                    m.end(),
                    "R4-BASELINE-CHROME",
                    m.as_str(),
                ) {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: exe.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: m.as_str().to_string(),
                        detail: "chrome2rust CLI --help prose references login/password/DPAPI extraction".to_string(),
                    });
                    break;
                }
            }
        }

        let flag_spans: Vec<(usize, usize)> =
            if in_listing_section || trimmed.starts_with('-') || is_usage_line {
                let mut spans = Vec::new();
                let mut scan_pos = 0usize;
                for tok in trimmed.split_whitespace() {
                    if let Some(rel) = line[scan_pos..].find(tok) {
                        let ts = scan_pos + rel;
                        let te = ts + tok.len();
                        if tok.starts_with('-') {
                            spans.push((ts, te));
                        }
                        scan_pos = te;
                    }
                }
                spans
            } else {
                Vec::new()
            };

        let cmd_col_end = cmd_col_prefix.and_then(|c| line.find(c).map(|p| p + c.len()));

        for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(line) {
            let rule = &registry.rules[rule_idx];
            if rule.def.kind == RuleKind::LegacyAcm && matched.eq_ignore_ascii_case("acm") {
                let is_cmd_token = in_listing_section && line.trim_start().starts_with(&matched);
                if !is_cmd_token && registry.acm_audio_context_regex.is_match(line) {
                    continue;
                }
            }

            let is_leading_cmd_tok = cmd_col_end.is_some_and(|ce| {
                let cs = line.len() - line.trim_start().len();
                m_start >= cs && m_start < ce
            });
            let is_flag_tok = flag_spans
                .iter()
                .any(|&(fs, fe)| m_start >= fs && m_start < fe);
            let is_ident_tok = is_leading_cmd_tok || is_flag_tok;

            if !is_ident_tok
                && is_negated_exclusion_at_span(line, m_start, m_end, rule.def.rule_id, &matched)
            {
                continue;
            }

            violations.push(R4Violation {
                category: rule.def.category.to_string(),
                rule_id: rule.def.rule_id.to_string(),
                path: exe.to_path_buf(),
                line: Some(line_no),
                matched_symbol: matched,
                detail: format!("CLI --help violation: {}", rule.def.description),
            });
        }
    }
}

fn extract_json_values_with_spans(text: &str) -> Vec<(usize, usize, Value)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut pos = 0usize;

    while pos < bytes.len() {
        while pos < bytes.len() && !matches!(bytes[pos], b'{' | b'[') {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        if !text.is_char_boundary(pos) {
            pos += 1;
            continue;
        }
        let mut stream = serde_json::Deserializer::from_str(&text[pos..]).into_iter::<Value>();
        if let Some(Ok(val)) = stream.next() {
            let consumed = stream.byte_offset();
            if consumed > 0 && pos + consumed <= bytes.len() {
                found.push((pos, pos + consumed, val));
                pos += consumed;
                continue;
            }
        }
        pos += 1;
    }

    found
}

fn scan_mcp_jsonrpc_stream(
    exe: &Path,
    stream_text: &str,
    is_chrome_bin: bool,
    chrome_new_cred_id_re: &Regex,
    chrome_new_cred_desc_re: &Regex,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    for (_, _, val) in extract_json_values_with_spans(stream_text) {
        if let Some(tools) = val
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
        {
            check_mcp_tools_array(
                exe,
                tools,
                is_chrome_bin,
                chrome_new_cred_id_re,
                chrome_new_cred_desc_re,
                registry,
                violations,
            );
        } else if let Some(tools) = val.get("tools").and_then(|t| t.as_array()) {
            check_mcp_tools_array(
                exe,
                tools,
                is_chrome_bin,
                chrome_new_cred_id_re,
                chrome_new_cred_desc_re,
                registry,
                violations,
            );
        }
        for container in [Some(&val), val.get("result")].into_iter().flatten() {
            if let Some(server_info) = container.get("serverInfo") {
                let mut path_stack = vec!["serverInfo".to_string()];
                scan_mcp_value(
                    exe,
                    "serverInfo",
                    server_info,
                    &mut path_stack,
                    None,
                    is_chrome_bin,
                    chrome_new_cred_id_re,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
            if let Some(instr) = container.get("instructions").and_then(|i| i.as_str()) {
                check_mcp_description_text(
                    exe,
                    "initialize",
                    "result.instructions",
                    instr,
                    &[],
                    is_chrome_bin,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
        }
    }
}

fn scan_mcp_payload(
    exe: &Path,
    payload: &str,
    is_chrome_bin: bool,
    chrome_new_cred_id_re: &Regex,
    chrome_new_cred_desc_re: &Regex,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    let mut consumed_spans: Vec<(usize, usize)> = Vec::new();

    for (start, end, val) in extract_json_values_with_spans(payload) {
        let mut matched_json = false;
        if let Some(tools) = val.as_array() {
            check_mcp_tools_array(
                exe,
                tools,
                is_chrome_bin,
                chrome_new_cred_id_re,
                chrome_new_cred_desc_re,
                registry,
                violations,
            );
            matched_json = true;
        } else if let Some(tools) = val.get("tools").and_then(|t| t.as_array()) {
            check_mcp_tools_array(
                exe,
                tools,
                is_chrome_bin,
                chrome_new_cred_id_re,
                chrome_new_cred_desc_re,
                registry,
                violations,
            );
            matched_json = true;
        } else if let Some(tools) = val
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
        {
            check_mcp_tools_array(
                exe,
                tools,
                is_chrome_bin,
                chrome_new_cred_id_re,
                chrome_new_cred_desc_re,
                registry,
                violations,
            );
            matched_json = true;
        }
        for container in [Some(&val), val.get("result")].into_iter().flatten() {
            if let Some(server_info) = container.get("serverInfo") {
                let mut path_stack = vec!["serverInfo".to_string()];
                scan_mcp_value(
                    exe,
                    "serverInfo",
                    server_info,
                    &mut path_stack,
                    None,
                    is_chrome_bin,
                    chrome_new_cred_id_re,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
                matched_json = true;
            }
            if let Some(instr) = container.get("instructions").and_then(|i| i.as_str()) {
                check_mcp_description_text(
                    exe,
                    "initialize",
                    "result.instructions",
                    instr,
                    &[],
                    is_chrome_bin,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
                matched_json = true;
            }
        }
        if matched_json {
            consumed_spans.push((start, end));
        }
    }

    let mut non_json = String::with_capacity(payload.len());
    let mut cursor = 0usize;
    for (s, e) in consumed_spans {
        if s > cursor {
            non_json.push_str(&payload[cursor..s]);
        }
        for b in payload[s..e].bytes() {
            non_json.push(if b == b'\n' { '\n' } else { ' ' });
        }
        cursor = e;
    }
    if cursor < payload.len() {
        non_json.push_str(&payload[cursor..]);
    }

    for (idx, line) in non_json.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(line) {
            let rule = &registry.rules[rule_idx];
            if rule.def.kind == RuleKind::LegacyAcm
                && registry.acm_audio_context_regex.is_match(line)
            {
                continue;
            }
            if is_negated_exclusion_at_span(line, m_start, m_end, rule.def.rule_id, &matched) {
                continue;
            }
            violations.push(R4Violation {
                category: rule.def.category.to_string(),
                rule_id: rule.def.rule_id.to_string(),
                path: exe.to_path_buf(),
                line: Some(idx + 1),
                matched_symbol: matched,
                detail: format!("MCP --tools violation: {}", rule.def.description),
            });
        }
        if is_chrome_bin {
            for tok in line.split_whitespace() {
                let clean =
                    tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
                if !clean.is_empty()
                    && !CHROME2RUST_BASELINE_MCP_TOOLS.contains(&clean)
                    && chrome_new_cred_id_re.is_match(clean)
                {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: exe.to_path_buf(),
                        line: Some(idx + 1),
                        matched_symbol: clean.to_string(),
                        detail: "chrome2rust --tools output exposes prohibited credential/login identifier".to_string(),
                    });
                }
            }
            for m in chrome_new_cred_desc_re.find_iter(line) {
                if !is_negated_exclusion_at_span(
                    line,
                    m.start(),
                    m.end(),
                    "R4-BASELINE-CHROME",
                    m.as_str(),
                ) {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: exe.to_path_buf(),
                        line: Some(idx + 1),
                        matched_symbol: m.as_str().to_string(),
                        detail: "chrome2rust --tools non-JSON prose references login/password/DPAPI extraction".to_string(),
                    });
                    break;
                }
            }
        }
    }
}

fn is_exact_baseline_tool_desc(tool_name: &str, desc: &str) -> bool {
    tool_name == "chrome2rust_analyze"
        && desc
            == "Run comprehensive read-only forensic analysis across Chrome User Data artifacts (history, downloads, cookies, logins, extensions, sessions, storage, findings, timeline)."
}

fn is_exact_baseline_decrypt_prop_key(tool_name: &str, path_stack: &[String], key: &str) -> bool {
    (tool_name == "chrome2rust_analyze" || tool_name == "chrome2rust_report")
        && key == "decrypt"
        && path_stack.len() == 2
        && path_stack[0] == "inputSchema"
        && path_stack[1] == "properties"
}

fn is_exact_baseline_decrypt_prop_desc(tool_name: &str, path_stack: &[String], desc: &str) -> bool {
    let in_decrypt_prop = path_stack.len() == 4
        && path_stack[0] == "inputSchema"
        && path_stack[1] == "properties"
        && path_stack[2] == "decrypt"
        && path_stack[3] == "description";
    if !in_decrypt_prop {
        return false;
    }
    (tool_name == "chrome2rust_analyze"
        && desc == "Enable optional best-effort decryption (Cookies / Login Data)")
        || (tool_name == "chrome2rust_report" && desc == "Enable optional best-effort decryption")
}

#[allow(clippy::too_many_arguments)]
fn check_mcp_description_text(
    exe: &Path,
    tool_name: &str,
    field_label: &str,
    desc: &str,
    path_stack: &[String],
    is_chrome_bin: bool,
    chrome_new_cred_desc_re: &Regex,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    if desc.is_empty() {
        return;
    }
    for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(desc) {
        let rule = &registry.rules[rule_idx];
        if rule.def.kind == RuleKind::LegacyAcm && registry.acm_audio_context_regex.is_match(desc) {
            continue;
        }
        if is_negated_exclusion_at_span(desc, m_start, m_end, rule.def.rule_id, &matched) {
            continue;
        }
        violations.push(R4Violation {
            category: rule.def.category.to_string(),
            rule_id: rule.def.rule_id.to_string(),
            path: exe.to_path_buf(),
            line: None,
            matched_symbol: matched,
            detail: format!(
                "MCP tool `{tool_name}` {field_label} violation: {}",
                rule.def.description
            ),
        });
    }

    if is_chrome_bin
        && !is_exact_baseline_tool_desc(tool_name, desc)
        && !is_exact_baseline_decrypt_prop_desc(tool_name, path_stack, desc)
    {
        for m in chrome_new_cred_desc_re.find_iter(desc) {
            if !is_negated_exclusion_at_span(
                desc,
                m.start(),
                m.end(),
                "R4-BASELINE-CHROME",
                m.as_str(),
            ) {
                violations.push(R4Violation {
                    category: "baseline_chrome".to_string(),
                    rule_id: "R4-BASELINE-CHROME".to_string(),
                    path: exe.to_path_buf(),
                    line: None,
                    matched_symbol: tool_name.to_string(),
                    detail: format!(
                        "chrome2rust MCP tool {field_label} references login/password/DPAPI extraction"
                    ),
                });
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_mcp_value(
    exe: &Path,
    tool_name: &str,
    val: &Value,
    path_stack: &mut Vec<String>,
    cur_key: Option<&str>,
    is_chrome_bin: bool,
    chrome_new_cred_id_re: &Regex,
    chrome_new_cred_desc_re: &Regex,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    let field_label = if path_stack.is_empty() {
        "value".to_string()
    } else {
        path_stack.join(".")
    };

    match val {
        Value::Object(map) => {
            for (k, v) in map {
                if path_stack.is_empty() && k == "name" {
                    continue;
                }
                let key_ctx = if path_stack.is_empty() {
                    format!("MCP tool key `{k}`")
                } else {
                    format!("MCP `{}.{k}` key", path_stack.join("."))
                };
                check_strict_mcp_text(exe, k, &key_ctx, registry, violations);
                if is_chrome_bin
                    && !is_exact_baseline_decrypt_prop_key(tool_name, path_stack, k)
                    && chrome_new_cred_id_re.is_match(k)
                {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: exe.to_path_buf(),
                        line: None,
                        matched_symbol: k.clone(),
                        detail: format!(
                            "chrome2rust MCP tool `{tool_name}` key `{k}` exposes prohibited credential/login parameter"
                        ),
                    });
                }
                path_stack.push(k.clone());
                scan_mcp_value(
                    exe,
                    tool_name,
                    v,
                    path_stack,
                    Some(k.as_str()),
                    is_chrome_bin,
                    chrome_new_cred_id_re,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
                path_stack.pop();
            }
        }
        Value::Array(items) => {
            for item in items {
                scan_mcp_value(
                    exe,
                    tool_name,
                    item,
                    path_stack,
                    None,
                    is_chrome_bin,
                    chrome_new_cred_id_re,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            }
        }
        Value::String(text) => {
            if cur_key == Some("description") {
                check_mcp_description_text(
                    exe,
                    tool_name,
                    &field_label,
                    text,
                    path_stack,
                    is_chrome_bin,
                    chrome_new_cred_desc_re,
                    registry,
                    violations,
                );
            } else if !text.is_empty() {
                let ctx = format!("MCP `{field_label}`");
                check_strict_mcp_text(exe, text, &ctx, registry, violations);
                if is_chrome_bin
                    && (chrome_new_cred_id_re.is_match(text)
                        || chrome_new_cred_desc_re.is_match(text))
                {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: exe.to_path_buf(),
                        line: None,
                        matched_symbol: text.clone(),
                        detail: format!(
                            "chrome2rust MCP tool `{tool_name}` field `{field_label}` exposes prohibited credential/login content"
                        ),
                    });
                }
            }
        }
        _ => {}
    }
}

fn check_mcp_tools_array(
    exe: &Path,
    tools: &[Value],
    is_chrome_bin: bool,
    chrome_new_cred_id_re: &Regex,
    chrome_new_cred_desc_re: &Regex,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();

        if !name.is_empty() {
            check_strict_mcp_text(exe, name, "MCP tool name", registry, violations);

            if is_chrome_bin
                && !CHROME2RUST_BASELINE_MCP_TOOLS.contains(&name)
                && chrome_new_cred_id_re.is_match(name)
            {
                violations.push(R4Violation {
                    category: "baseline_chrome".to_string(),
                    rule_id: "R4-BASELINE-CHROME".to_string(),
                    path: exe.to_path_buf(),
                    line: None,
                    matched_symbol: name.to_string(),
                    detail: "chrome2rust MCP exposes prohibited new login/password/credential tool beyond 8-tool baseline".to_string(),
                });
            }
        }

        let mut path_stack = Vec::new();
        scan_mcp_value(
            exe,
            name,
            tool,
            &mut path_stack,
            None,
            is_chrome_bin,
            chrome_new_cred_id_re,
            chrome_new_cred_desc_re,
            registry,
            violations,
        );
    }
}

fn check_strict_mcp_text(
    exe: &Path,
    text: &str,
    context_label: &str,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    for (rule_idx, _, _, matched) in registry.scan_all_source_matches(text) {
        let rule = &registry.rules[rule_idx];
        if rule.def.kind == RuleKind::LegacyAcm && registry.acm_audio_context_regex.is_match(text) {
            continue;
        }
        violations.push(R4Violation {
            category: rule.def.category.to_string(),
            rule_id: rule.def.rule_id.to_string(),
            path: exe.to_path_buf(),
            line: None,
            matched_symbol: matched,
            detail: format!(
                "{context_label} `{text}` matches prohibited R4 rule ({})",
                rule.def.description
            ),
        });
    }
}
