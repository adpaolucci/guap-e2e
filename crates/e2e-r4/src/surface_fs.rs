use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

use crate::R4Violation;
use crate::rules::{RuleKind, RuleRegistry};

const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    ".agents",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".cargo",
    "scratch",
    "guap-e2e",
    "e2e_harness",
];

const CHROME2RUST_BASELINE_FILES: &[&str] = &[
    "crates/chrome2rust-core/src/crypto.rs",
    "crates/chrome2rust-core/src/lib.rs",
    "crates/chrome2rust-forensics/src/logins.rs",
    "crates/chrome2rust-forensics/src/cookies.rs",
    "crates/chrome2rust-forensics/src/local_state.rs",
    "crates/chrome2rust-forensics/src/findings.rs",
    "crates/chrome2rust-forensics/src/lib.rs",
    "crates/chrome2rust-cli/src/main.rs",
    "crates/chrome2rust-mcp/src/lib.rs",
    "crates/chrome2rust-report/src/html.rs",
    "crates/chrome2rust-report/src/markdown.rs",
    "crates/chrome2rust-report/tests/integration_tests.rs",
    "crates/chrome2rust-win32/src/main.rs",
    "crates/chrome2rust-win32/src/win32_app.rs",
    "crates/chrome2rust-win32/src/win32_state.rs",
    "crates/chrome2rust-iced/src/main.rs",
    "crates/chrome2rust-iced/src/app.rs",
    "crates/chrome2rust-iced/src/views/forensic_tabs.rs",
    "crates/chrome2rust-iced/src/views/modals.rs",
];

pub struct FsScanStats {
    pub files_scanned: usize,
    pub crates_scanned: usize,
    pub violations: Vec<R4Violation>,
    pub baseline_notes: Vec<String>,
}

pub fn is_skipped_dir_name(name: &str) -> bool {
    SKIP_DIRS.iter().any(|skip| name.eq_ignore_ascii_case(skip))
}

fn should_visit(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    if entry.file_type().is_dir() {
        let name = entry.file_name().to_string_lossy();
        return !is_skipped_dir_name(&name);
    }
    true
}

fn normalize_rel_path(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

fn is_under_workspace(rel_norm: &str, workspace_name: &str) -> bool {
    rel_norm
        .split('/')
        .any(|seg| seg.eq_ignore_ascii_case(workspace_name))
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    is_string: bool,
    is_comment: bool,
    block_comment_id: Option<usize>,
}

#[derive(Default)]
struct RustLexerState {
    block_comment_depth: usize,
    active_block_comment_id: Option<usize>,
    next_block_comment_id: usize,
    in_string: bool,
    raw_string_hashes: Option<usize>,
}

fn lex_rust_line(line: &str, state: &mut RustLexerState) -> Vec<Span> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut spans = Vec::new();

    while i < len {
        if state.block_comment_depth > 0 {
            let start = i;
            let bc_id = state.active_block_comment_id;
            while i < len {
                if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    state.block_comment_depth += 1;
                    i += 2;
                } else if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    state.block_comment_depth -= 1;
                    i += 2;
                    if state.block_comment_depth == 0 {
                        state.active_block_comment_id = None;
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            spans.push(Span {
                start,
                end: i,
                is_string: false,
                is_comment: true,
                block_comment_id: bc_id,
            });
            continue;
        }

        if let Some(hashes) = state.raw_string_hashes {
            let start = i;
            while i < len {
                if bytes[i] == b'"' {
                    let mut count = 0usize;
                    let mut j = i + 1;
                    while count < hashes && j < len && bytes[j] == b'#' {
                        count += 1;
                        j += 1;
                    }
                    if count == hashes {
                        i = j;
                        state.raw_string_hashes = None;
                        break;
                    }
                }
                i += 1;
            }
            spans.push(Span {
                start,
                end: i,
                is_string: true,
                is_comment: false,
                block_comment_id: None,
            });
            continue;
        }

        if state.in_string {
            let start = i;
            while i < len {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(len);
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    state.in_string = false;
                    break;
                }
                i += 1;
            }
            spans.push(Span {
                start,
                end: i,
                is_string: true,
                is_comment: false,
                block_comment_id: None,
            });
            continue;
        }

        let code_start = i;
        while i < len {
            if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                if i > code_start {
                    spans.push(Span {
                        start: code_start,
                        end: i,
                        is_string: false,
                        is_comment: false,
                        block_comment_id: None,
                    });
                }
                spans.push(Span {
                    start: i,
                    end: len,
                    is_string: false,
                    is_comment: true,
                    block_comment_id: None,
                });
                i = len;
                break;
            }
            if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                if i > code_start {
                    spans.push(Span {
                        start: code_start,
                        end: i,
                        is_string: false,
                        is_comment: false,
                        block_comment_id: None,
                    });
                }
                state.block_comment_depth = 1;
                let bc_id = state.next_block_comment_id;
                state.next_block_comment_id += 1;
                state.active_block_comment_id = Some(bc_id);
                let c_start = i;
                i += 2;
                while i < len && state.block_comment_depth > 0 {
                    if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                        state.block_comment_depth += 1;
                        i += 2;
                    } else if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        state.block_comment_depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if state.block_comment_depth == 0 {
                    state.active_block_comment_id = None;
                }
                spans.push(Span {
                    start: c_start,
                    end: i,
                    is_string: false,
                    is_comment: true,
                    block_comment_id: Some(bc_id),
                });
                break;
            }
            if bytes[i] == b'r' {
                let is_ident_before = if i == 0 {
                    false
                } else if bytes[i - 1] == b'b' || bytes[i - 1] == b'c' {
                    i >= 2 && (bytes[i - 2].is_ascii_alphanumeric() || bytes[i - 2] == b'_')
                } else {
                    bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'
                };
                if !is_ident_before {
                    let mut j = i + 1;
                    let mut hashes = 0usize;
                    while j < len && bytes[j] == b'#' {
                        hashes += 1;
                        j += 1;
                    }
                    if j < len && bytes[j] == b'"' {
                        if i > code_start {
                            spans.push(Span {
                                start: code_start,
                                end: i,
                                is_string: false,
                                is_comment: false,
                                block_comment_id: None,
                            });
                        }
                        let s_start = i;
                        i = j + 1;
                        state.raw_string_hashes = Some(hashes);
                        while i < len {
                            if bytes[i] == b'"' {
                                let mut count = 0usize;
                                let mut k = i + 1;
                                while count < hashes && k < len && bytes[k] == b'#' {
                                    count += 1;
                                    k += 1;
                                }
                                if count == hashes {
                                    i = k;
                                    state.raw_string_hashes = None;
                                    break;
                                }
                            }
                            i += 1;
                        }
                        spans.push(Span {
                            start: s_start,
                            end: i,
                            is_string: true,
                            is_comment: false,
                            block_comment_id: None,
                        });
                        break;
                    }
                }
            }
            if bytes[i] == b'\'' {
                let char_end = if let Some(ch) = line[i + 1..].chars().next()
                    && ch != '\''
                    && ch != '\\'
                    && bytes.get(i + 1 + ch.len_utf8()) == Some(&b'\'')
                {
                    Some(i + 1 + ch.len_utf8() + 1)
                } else if i + 3 < len && bytes[i + 1] == b'\\' && bytes[i + 3] == b'\'' {
                    Some(i + 4)
                } else if i + 5 < len
                    && bytes[i + 1] == b'\\'
                    && bytes[i + 2] == b'x'
                    && bytes[i + 5] == b'\''
                {
                    Some(i + 6)
                } else if i + 5 < len
                    && bytes[i + 1] == b'\\'
                    && bytes[i + 2] == b'u'
                    && bytes[i + 3] == b'{'
                {
                    let mut j = i + 4;
                    while j < len && bytes[j] != b'}' {
                        j += 1;
                    }
                    if j + 1 < len && bytes[j] == b'}' && bytes[j + 1] == b'\'' {
                        Some(j + 2)
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(end_c) = char_end {
                    if i > code_start {
                        spans.push(Span {
                            start: code_start,
                            end: i,
                            is_string: false,
                            is_comment: false,
                            block_comment_id: None,
                        });
                    }
                    spans.push(Span {
                        start: i,
                        end: end_c,
                        is_string: true,
                        is_comment: false,
                        block_comment_id: None,
                    });
                    i = end_c;
                    break;
                }
            }
            if bytes[i] == b'"' {
                if i > code_start {
                    spans.push(Span {
                        start: code_start,
                        end: i,
                        is_string: false,
                        is_comment: false,
                        block_comment_id: None,
                    });
                }
                let s_start = i;
                i += 1;
                state.in_string = true;
                while i < len {
                    if bytes[i] == b'\\' {
                        i = (i + 2).min(len);
                        continue;
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        state.in_string = false;
                        break;
                    }
                    i += 1;
                }
                spans.push(Span {
                    start: s_start,
                    end: i,
                    is_string: true,
                    is_comment: false,
                    block_comment_id: None,
                });
                break;
            }
            i += 1;
            if i == len && i > code_start {
                spans.push(Span {
                    start: code_start,
                    end: i,
                    is_string: false,
                    is_comment: false,
                    block_comment_id: None,
                });
            }
        }
    }

    spans
}

#[derive(Default)]
struct PythonLexerState {
    triple_quote: Option<&'static str>,
}

fn lex_python_line(
    line: &str,
    state: &mut PythonLexerState,
    _registry: &RuleRegistry,
) -> Vec<(Span, bool)> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut out = Vec::new();

    if let Some(delim) = state.triple_quote {
        let start = 0;
        let delim_bytes = delim.as_bytes();
        while i < len {
            if bytes[i] == b'\\' {
                i = (i + 2).min(len);
                continue;
            }
            if i + 3 <= len && &bytes[i..i + 3] == delim_bytes {
                i += 3;
                state.triple_quote = None;
                out.push((
                    Span {
                        start,
                        end: i,
                        is_string: true,
                        is_comment: false,
                        block_comment_id: None,
                    },
                    false,
                ));
                break;
            }
            i += 1;
        }
        if state.triple_quote.is_some() {
            out.push((
                Span {
                    start,
                    end: len,
                    is_string: true,
                    is_comment: false,
                    block_comment_id: None,
                },
                false,
            ));
            return out;
        }
    }

    while i < len {
        let code_start = i;
        while i < len {
            if bytes[i] == b'#' {
                if i > code_start {
                    out.push((
                        Span {
                            start: code_start,
                            end: i,
                            is_string: false,
                            is_comment: false,
                            block_comment_id: None,
                        },
                        false,
                    ));
                }
                out.push((
                    Span {
                        start: i,
                        end: len,
                        is_string: false,
                        is_comment: true,
                        block_comment_id: None,
                    },
                    false,
                ));
                i = len;
                break;
            }
            if (bytes[i] == b'"' || bytes[i] == b'\'')
                && i + 3 <= len
                && bytes[i + 1] == bytes[i]
                && bytes[i + 2] == bytes[i]
            {
                if i > code_start {
                    out.push((
                        Span {
                            start: code_start,
                            end: i,
                            is_string: false,
                            is_comment: false,
                            block_comment_id: None,
                        },
                        false,
                    ));
                }
                let delim = if bytes[i] == b'"' { "\"\"\"" } else { "'''" };
                let s_start = i;
                i += 3;
                state.triple_quote = Some(delim);
                while i < len {
                    if bytes[i] == b'\\' {
                        i = (i + 2).min(len);
                        continue;
                    }
                    if i + 3 <= len && &bytes[i..i + 3] == delim.as_bytes() {
                        i += 3;
                        state.triple_quote = None;
                        break;
                    }
                    i += 1;
                }
                out.push((
                    Span {
                        start: s_start,
                        end: i,
                        is_string: true,
                        is_comment: false,
                        block_comment_id: None,
                    },
                    false,
                ));
                break;
            }
            if bytes[i] == b'"' || bytes[i] == b'\'' {
                if i > code_start {
                    out.push((
                        Span {
                            start: code_start,
                            end: i,
                            is_string: false,
                            is_comment: false,
                            block_comment_id: None,
                        },
                        false,
                    ));
                }
                let q = bytes[i];
                let s_start = i;
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' {
                        i = (i + 2).min(len);
                        continue;
                    }
                    if bytes[i] == q {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push((
                    Span {
                        start: s_start,
                        end: i,
                        is_string: true,
                        is_comment: false,
                        block_comment_id: None,
                    },
                    false,
                ));
                break;
            }
            i += 1;
            if i == len && i > code_start {
                out.push((
                    Span {
                        start: code_start,
                        end: i,
                        is_string: false,
                        is_comment: false,
                        block_comment_id: None,
                    },
                    false,
                ));
            }
        }
    }

    out
}

fn is_command_or_tool_id_line(line: &str, in_cmd_attr: bool) -> bool {
    let trimmed = line.trim();
    trimmed.contains("#[command(")
        || (in_cmd_attr && (trimmed.contains("name") || trimmed.contains("alias")))
        || trimmed.contains("\"name\"")
        || trimmed.contains("tool_id")
        || trimmed.contains("command_id")
        || (trimmed.starts_with('"') && trimmed.contains("=>"))
}

fn span_for_byte(spans: &[Span], pos: usize) -> Option<&Span> {
    spans.iter().find(|sp| pos >= sp.start && pos < sp.end)
}

fn strip_comments_from_line(line: &str, spans: &[Span]) -> String {
    let mut out = String::with_capacity(line.len());
    for sp in spans {
        if !sp.is_comment {
            out.push_str(&line[sp.start..sp.end]);
        }
    }
    out
}

fn compute_block_comment_negated(
    lines: &[&str],
    line_spans: &[Vec<Span>],
    registry: &RuleRegistry,
) -> HashSet<usize> {
    let mut grouped: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    for (idx, spans) in line_spans.iter().enumerate() {
        for sp in spans {
            if sp.is_comment
                && let Some(id) = sp.block_comment_id
            {
                let buf = grouped.entry(id).or_default();
                buf.push_str(&lines[idx][sp.start..sp.end]);
                buf.push('\n');
            }
        }
    }
    grouped
        .into_iter()
        .filter_map(|(id, text)| registry.is_negated_text(&text).then_some(id))
        .collect()
}

pub fn scan_fs(guap_root: &Path, registry: &RuleRegistry) -> Result<FsScanStats> {
    let mut files_scanned = 0usize;
    let mut crates_scanned = 0usize;
    let mut violations = Vec::new();
    let mut baseline_notes = Vec::new();

    let chrome_baseline_set: HashSet<&str> = CHROME2RUST_BASELINE_FILES.iter().copied().collect();
    let cross_ws_chrome_re = Regex::new(
        r"(?:chrome2rust_core::crypto|chrome2rust_forensics::logins|try_decrypt_chrome_blob|parse_logins)",
    )?;
    let chrome_new_expansion_re = Regex::new(
        r"(?i)(?:parse_logins|LoginRecord|try_decrypt_chrome_blob|key3\.db|key4\.db|logins\.json|PK11SDR_Decrypt|password_value|EncryptionScheme::Dpapi|\bdpapi\b)",
    )?;
    let chrome_banned_api_re = Regex::new(
        r"(?i)(?:^|[^a-zA-Z0-9])(CryptProtectData|PK11SDR_Decrypt|NSS_Init|NSSBase64_DecodeBuffer|IElevator)(?:$|[^a-zA-Z0-9])",
    )?;
    let cargo_dpapi_feat_re = Regex::new(
        r"(?i)(?:Win32_Security_Cryptography|Win32_Security_Credentials|crypt32|dpapi)",
    )?;

    for entry in WalkDir::new(guap_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_visit)
    {
        let entry = entry.with_context(|| format!("walking {}", guap_root.display()))?;
        let path = entry.path();
        let rel_norm = normalize_rel_path(guap_root, path);

        if entry.file_type().is_dir() {
            if entry.depth() > 0 {
                let dir_name = entry.file_name().to_string_lossy();
                check_name_token(
                    &dir_name,
                    path,
                    "Directory name matches prohibited R4 identifier",
                    registry,
                    &mut violations,
                );
            }
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        check_name_token(
            &stem,
            path,
            "File name matches prohibited R4 identifier",
            registry,
            &mut violations,
        );

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();

        if file_name.eq_ignore_ascii_case("Cargo.toml") {
            files_scanned += 1;
            let content =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            scan_cargo_toml(
                path,
                &rel_norm,
                &content,
                registry,
                &cargo_dpapi_feat_re,
                &mut crates_scanned,
                &mut violations,
            );
            continue;
        }

        match ext.as_str() {
            "rs" => {
                files_scanned += 1;
                let content = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                scan_rust_file(
                    path,
                    &rel_norm,
                    &content,
                    registry,
                    &chrome_baseline_set,
                    &cross_ws_chrome_re,
                    &chrome_new_expansion_re,
                    &chrome_banned_api_re,
                    &mut violations,
                );
            }
            "py" => {
                files_scanned += 1;
                let content = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                scan_python_file(path, &content, registry, &mut violations);
            }
            "json" => {
                files_scanned += 1;
                let content = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                scan_json_file(path, &content, registry, &mut violations);
            }
            _ => {}
        }
    }

    let chrome_dir = guap_root.join("chrome2rust");
    if chrome_dir.is_dir() {
        let logins_path = chrome_dir.join("crates/chrome2rust-forensics/src/logins.rs");
        let crypto_path = chrome_dir.join("crates/chrome2rust-core/src/crypto.rs");

        if logins_path.is_file() {
            baseline_notes.push(format!(
                "R4-BASELINE-CHROME: pre-existing baseline file present: {}",
                logins_path.display()
            ));
        }
        if crypto_path.is_file() {
            let crypto_src = fs::read_to_string(&crypto_path)
                .with_context(|| format!("reading {}", crypto_path.display()))?;
            let has_crypt_unprotect = crypto_src.contains("CryptUnprotectData");
            let dpapi_decrypted = check_crypto_rs_decrypts_dpapi(&crypto_src);
            if dpapi_decrypted {
                violations.push(R4Violation {
                    category: "baseline_chrome".to_string(),
                    rule_id: "R4-BASELINE-CHROME".to_string(),
                    path: crypto_path.clone(),
                    line: find_line_containing(&crypto_src, "EncryptionScheme::Dpapi"),
                    matched_symbol: "EncryptionScheme::Dpapi".to_string(),
                    detail:
                        "chrome2rust-core/src/crypto.rs must NOT decrypt EncryptionScheme::Dpapi"
                            .to_string(),
                });
            }
            baseline_notes.push(format!(
                "R4-BASELINE-CHROME: pre-existing baseline file verified DPAPI classification-only (CryptUnprotectData={}, dpapi_decrypted={}): {}",
                has_crypt_unprotect,
                dpapi_decrypted,
                crypto_path.display()
            ));
        }
    }

    Ok(FsScanStats {
        files_scanned,
        crates_scanned,
        violations,
        baseline_notes,
    })
}

fn find_line_containing(src: &str, needle: &str) -> Option<usize> {
    src.lines()
        .enumerate()
        .find(|(_, line)| line.contains(needle))
        .map(|(idx, _)| idx + 1)
}

fn check_crypto_rs_decrypts_dpapi(crypto_src: &str) -> bool {
    let lines: Vec<&str> = crypto_src.lines().collect();
    let mut lex_state = RustLexerState::default();
    let mut code_lines = Vec::with_capacity(lines.len());
    for line in &lines {
        let spans = lex_rust_line(line, &mut lex_state);
        code_lines.push(strip_comments_from_line(line, &spans));
    }

    let mut fn_body = String::new();
    let mut in_fn = false;
    let mut brace_depth = 0usize;
    let mut seen_open_brace = false;

    for code in &code_lines {
        if !in_fn {
            if code.contains("fn try_decrypt_chrome_blob") {
                in_fn = true;
            } else {
                continue;
            }
        }
        fn_body.push_str(code);
        fn_body.push(' ');
        for ch in code.chars() {
            if ch == '{' {
                brace_depth += 1;
                seen_open_brace = true;
            } else if ch == '}' && brace_depth > 0 {
                brace_depth -= 1;
            }
        }
        if seen_open_brace && brace_depth == 0 {
            break;
        }
    }

    let check_body = if fn_body.is_empty() {
        code_lines.join(" ")
    } else {
        fn_body
    };

    let collapsed = check_body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.contains("CryptUnprotectData") || collapsed.contains("CryptUnprotectMemory") {
        return true;
    }

    let mut offset = 0usize;
    while let Some(rel) = collapsed[offset..].find("EncryptionScheme::Dpapi") {
        let pos = offset + rel + "EncryptionScheme::Dpapi".len();
        let rest = collapsed[pos..].trim_start();
        if let Some(after_arrow) = rest.strip_prefix("=>") {
            let arm = after_arrow.trim_start();
            if !arm.starts_with("(scheme, None)")
                && !arm.starts_with("(EncryptionScheme::Dpapi, None)")
                && !arm.starts_with("return (scheme, None)")
                && !arm.starts_with("return (EncryptionScheme::Dpapi, None)")
                && !arm.starts_with("\"dpapi\"")
            {
                return true;
            }
        }
        offset = pos;
    }

    false
}

fn check_name_token(
    name: &str,
    path: &Path,
    detail_prefix: &str,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    for (idx, _, _, matched) in registry.scan_all_source_matches(name) {
        let rule = &registry.rules[idx];
        if !matches!(
            rule.def.category,
            "cred2rust" | "credential_tool" | "injection_tool" | "legacy_tool"
        ) {
            continue;
        }
        if rule.def.kind == RuleKind::LegacyAcm && registry.acm_audio_context_regex.is_match(name) {
            continue;
        }
        violations.push(R4Violation {
            category: rule.def.category.to_string(),
            rule_id: rule.def.rule_id.to_string(),
            path: path.to_path_buf(),
            line: None,
            matched_symbol: matched,
            detail: format!("{detail_prefix} ({})", rule.def.description),
        });
    }
}

fn scan_cargo_toml(
    path: &Path,
    rel_norm: &str,
    content: &str,
    registry: &RuleRegistry,
    cargo_dpapi_feat_re: &Regex,
    crates_scanned: &mut usize,
    violations: &mut Vec<R4Violation>,
) {
    let in_chrome2rust = is_under_workspace(rel_norm, "chrome2rust");

    if let Ok(parsed) = toml::from_str::<toml::Value>(content) {
        if let Some(pkg) = parsed.get("package").and_then(|v| v.as_table()) {
            *crates_scanned += 1;
            if let Some(pkg_name) = pkg.get("name").and_then(|v| v.as_str()) {
                check_name_token(
                    pkg_name,
                    path,
                    "Cargo [package].name matches prohibited R4 identifier",
                    registry,
                    violations,
                );
            }
        }

        if let Some(bins) = parsed.get("bin").and_then(|v| v.as_array()) {
            for bin in bins {
                if let Some(bin_name) = bin.get("name").and_then(|v| v.as_str()) {
                    check_name_token(
                        bin_name,
                        path,
                        "Cargo [[bin]].name matches prohibited R4 identifier",
                        registry,
                        violations,
                    );
                }
            }
        }

        if let Some(members) = parsed
            .get("workspace")
            .and_then(|v| v.get("members"))
            .and_then(|v| v.as_array())
        {
            for member in members {
                if let Some(m) = member.as_str() {
                    check_name_token(
                        m,
                        path,
                        "Cargo workspace member matches prohibited R4 identifier",
                        registry,
                        violations,
                    );
                }
            }
        }

        let mut dep_tables: Vec<&toml::map::Map<String, toml::Value>> = Vec::new();
        for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(t) = parsed.get(key).and_then(|v| v.as_table()) {
                dep_tables.push(t);
            }
        }
        if let Some(ws_deps) = parsed
            .get("workspace")
            .and_then(|v| v.get("dependencies"))
            .and_then(|v| v.as_table())
        {
            dep_tables.push(ws_deps);
        }
        if let Some(targets) = parsed.get("target").and_then(|v| v.as_table()) {
            for target_val in targets.values() {
                if let Some(target_tbl) = target_val.as_table() {
                    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                        if let Some(t) = target_tbl.get(key).and_then(|v| v.as_table()) {
                            dep_tables.push(t);
                        }
                    }
                }
            }
        }

        for tbl in dep_tables {
            for (dep_name, dep_val) in tbl {
                let effective_pkg = dep_val
                    .get("package")
                    .and_then(|v| v.as_str())
                    .unwrap_or(dep_name.as_str());

                if registry.cargo_hook_dep_regex.is_match(effective_pkg)
                    || registry.cargo_hook_dep_regex.is_match(dep_name)
                {
                    let matched_sym = if registry.cargo_hook_dep_regex.is_match(effective_pkg) {
                        effective_pkg.to_string()
                    } else {
                        dep_name.clone()
                    };
                    violations.push(R4Violation {
                        category: "injection_api".to_string(),
                        rule_id: "R4-INJ-02".to_string(),
                        path: path.to_path_buf(),
                        line: find_line_containing(content, dep_name),
                        matched_symbol: matched_sym,
                        detail: "Prohibited API hooking crate dependency in Cargo.toml".to_string(),
                    });
                }

                check_name_token(
                    effective_pkg,
                    path,
                    "Cargo dependency matches prohibited R4 identifier",
                    registry,
                    violations,
                );
                if effective_pkg != dep_name {
                    check_name_token(
                        dep_name,
                        path,
                        "Cargo dependency matches prohibited R4 identifier",
                        registry,
                        violations,
                    );
                }

                if in_chrome2rust
                    && (effective_pkg.eq_ignore_ascii_case("windows")
                        || effective_pkg.eq_ignore_ascii_case("windows-sys")
                        || effective_pkg.eq_ignore_ascii_case("winapi"))
                {
                    let dep_str = dep_val.to_string();
                    if cargo_dpapi_feat_re.is_match(&dep_str) {
                        violations.push(R4Violation {
                            category: "baseline_chrome".to_string(),
                            rule_id: "R4-BASELINE-CHROME".to_string(),
                            path: path.to_path_buf(),
                            line: find_line_containing(content, dep_name),
                            matched_symbol: effective_pkg.to_string(),
                            detail: "chrome2rust Cargo.toml must not add Windows DPAPI/Cryptography dependencies".to_string(),
                        });
                    }
                }
            }
        }
    } else if content.contains("[package]") {
        *crates_scanned += 1;
    }

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let (code_part, comment_part) = match line.find('#') {
            Some(pos) => (&line[..pos], Some(&line[pos..])),
            None => (line, None),
        };
        for (rule_idx, m_start, _, matched) in registry.scan_all_source_matches(line) {
            let rule = &registry.rules[rule_idx];
            if rule.def.kind == RuleKind::LegacyAcm
                && registry.acm_audio_context_regex.is_match(line)
            {
                continue;
            }
            let in_comment = comment_part.is_some() && m_start >= code_part.len();
            if in_comment
                && rule.def.allow_negation_in_comments
                && let Some(c) = comment_part
                && registry.is_negated_text(c)
            {
                continue;
            }
            if !in_comment
                && line.trim_start().starts_with("description")
                && registry.is_negated_text(line)
            {
                continue;
            }
            violations.push(R4Violation {
                category: rule.def.category.to_string(),
                rule_id: rule.def.rule_id.to_string(),
                path: path.to_path_buf(),
                line: Some(line_no),
                matched_symbol: matched,
                detail: format!("Cargo.toml violation: {}", rule.def.description),
            });
        }
    }
}

fn compute_command_attr_flags(lines: &[&str], line_spans: &[Vec<Span>]) -> Vec<bool> {
    let mut flags = vec![false; lines.len()];
    let mut in_cmd_attr = false;
    let mut paren_depth: i32 = 0;

    for (idx, line) in lines.iter().enumerate() {
        let code = strip_comments_and_strings(line, &line_spans[idx]);
        if in_cmd_attr {
            flags[idx] = true;
        }
        if let Some(pos) = code.find("#[command(") {
            in_cmd_attr = true;
            paren_depth = 0;
            flags[idx] = true;
            for ch in code[pos + 2..].chars() {
                if ch == '(' {
                    paren_depth += 1;
                } else if ch == ')' {
                    paren_depth -= 1;
                    if paren_depth <= 0 {
                        in_cmd_attr = false;
                        break;
                    }
                }
            }
        } else if in_cmd_attr {
            for ch in code.chars() {
                if ch == '(' {
                    paren_depth += 1;
                } else if ch == ')' {
                    paren_depth -= 1;
                    if paren_depth <= 0 {
                        in_cmd_attr = false;
                        break;
                    }
                }
            }
        }
    }
    flags
}

fn extract_paren_call_args_across_lines(
    lines: &[&str],
    line_spans: &[Vec<Span>],
    start_line: usize,
    start_col: usize,
) -> Option<Vec<String>> {
    let mut buf = String::new();
    let mut started = false;
    let mut paren_depth: i32 = 0;

    for l_idx in start_line..lines.len().min(start_line + 32) {
        let line = lines[l_idx];
        let spans = &line_spans[l_idx];
        let offset_base = if l_idx == start_line { start_col } else { 0 };

        for sp in spans {
            if sp.is_comment {
                continue;
            }
            let s = sp.start.max(offset_base);
            if s >= sp.end {
                continue;
            }
            let seg = &line[s..sp.end];
            if sp.is_string {
                if started {
                    buf.push_str(seg);
                }
                continue;
            }
            for ch in seg.chars() {
                if !started {
                    if ch == '(' {
                        started = true;
                        paren_depth = 1;
                    } else if ch == ';' {
                        return None;
                    }
                } else if ch == '(' {
                    paren_depth += 1;
                    buf.push(ch);
                } else if ch == ')' {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        return Some(split_top_level_args(&buf));
                    }
                    buf.push(ch);
                } else {
                    buf.push(ch);
                }
            }
        }
        if started {
            buf.push(' ');
        }
    }

    None
}

fn split_top_level_args(inner: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut paren_d = 0i32;
    let mut bracket_d = 0i32;
    let mut brace_d = 0i32;
    let mut angle_d = 0i32;
    let mut in_str = false;
    let mut escaped = false;

    for ch in inner.chars() {
        if in_str {
            cur.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_str = true;
                cur.push(ch);
            }
            '(' => {
                paren_d += 1;
                cur.push(ch);
            }
            ')' => {
                paren_d = (paren_d - 1).max(0);
                cur.push(ch);
            }
            '[' => {
                bracket_d += 1;
                cur.push(ch);
            }
            ']' => {
                bracket_d = (bracket_d - 1).max(0);
                cur.push(ch);
            }
            '{' => {
                brace_d += 1;
                cur.push(ch);
            }
            '}' => {
                brace_d = (brace_d - 1).max(0);
                cur.push(ch);
            }
            '<' => {
                angle_d += 1;
                cur.push(ch);
            }
            '>' => {
                angle_d = (angle_d - 1).max(0);
                cur.push(ch);
            }
            ',' if paren_d == 0 && bracket_d == 0 && brace_d == 0 && angle_d == 0 => {
                args.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let tail = cur.trim();
    if !tail.is_empty() {
        args.push(tail.to_string());
    }
    args
}

fn is_in_use_import_stmt(lines: &[&str], line_spans: &[Vec<Span>], idx: usize) -> bool {
    let start = idx.saturating_sub(20);
    for k in (start..=idx).rev() {
        let stripped = strip_comments_and_strings(lines[k], &line_spans[k]);
        let t = stripped.trim();
        if k < idx && t.ends_with(';') {
            return false;
        }
        if t.starts_with("use ")
            || t.starts_with("pub use ")
            || t.starts_with("pub(crate) use ")
            || t.starts_with("pub(super) use ")
        {
            return true;
        }
        if k < idx
            && (t.starts_with("fn ")
                || t.starts_with("pub fn ")
                || t.starts_with("let ")
                || t.starts_with("unsafe ")
                || t.starts_with("impl "))
        {
            return false;
        }
    }
    false
}

fn has_virtual_alloc_ex_unsafe_protect(lines: &[&str], line_spans: &[Vec<Span>]) -> bool {
    let safe_rw_protect_re = Regex::new(
        r"(?i)^(?:(?:[a-zA-Z0-9_]+::)*PAGE_READWRITE|(?:[a-zA-Z0-9_]+::)*PAGE_PROTECTION_FLAGS\s*\(\s*(?:0x0*4|4)(?:_?(?:u|i)(?:8|16|32|64|128|size))?\s*\)|(?:0x0*4|4)(?:_?(?:u|i)(?:8|16|32|64|128|size))?)$",
    )
    .expect("valid safe_rw_protect_re");

    for (idx, line) in lines.iter().enumerate() {
        let spans = &line_spans[idx];
        for (pos, _) in line.match_indices("VirtualAllocEx") {
            let Some(sp) = span_for_byte(spans, pos) else {
                continue;
            };
            if sp.is_comment || sp.is_string {
                continue;
            }
            if is_in_use_import_stmt(lines, line_spans, idx) {
                continue;
            }
            let Some(args) = extract_paren_call_args_across_lines(
                lines,
                line_spans,
                idx,
                pos + "VirtualAllocEx".len(),
            ) else {
                return true;
            };
            if args.len() != 5 || !safe_rw_protect_re.is_match(args[4].trim()) {
                return true;
            }
        }
    }
    false
}

fn has_multiline_wlan_get_profile_plaintext(
    lines: &[&str],
    line_spans: &[Vec<Span>],
) -> Vec<(usize, String)> {
    let flag_re = Regex::new(
        r"(?i)(?:\b0x[0_]*4(?:_?(?:u|i)(?:8|16|32|64|128|size))?\b|\bWLAN_PROFILE_GET_PLAINTEXT_KEY\b|\bFORBIDDEN_WLAN_PROFILE_FLAG\b)",
    )
    .expect("valid wlan flag regex");
    let pdw_flags_4_re = Regex::new(
        r"(?i)(?:^|[^a-zA-Z0-9_])(?:0x[0_]*4|0o0*4|0b0*100|4)(?:_?(?:u|i)(?:8|16|32|64|128|size))?(?:$|[^a-zA-Z0-9_])",
    )
    .expect("valid pdw_flags_4_re");
    let mut hits = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let spans = &line_spans[idx];
        for (pos, _) in line.match_indices("WlanGetProfile") {
            let Some(sp) = span_for_byte(spans, pos) else {
                continue;
            };
            if sp.is_comment || sp.is_string {
                continue;
            }
            if let Some(args) = extract_paren_call_args_across_lines(
                lines,
                line_spans,
                idx,
                pos + "WlanGetProfile".len(),
            ) {
                let joined = args.join(", ");
                if let Some(m) = flag_re.find(&joined) {
                    hits.push((idx + 1, format!("WlanGetProfile(..., {})", m.as_str())));
                } else if let Some(arg5) = args.get(5)
                    && pdw_flags_4_re.is_match(arg5)
                {
                    hits.push((idx + 1, format!("WlanGetProfile(..., {})", arg5.trim())));
                }
            }
        }
    }
    hits
}

#[allow(clippy::too_many_arguments)]
fn scan_rust_file(
    path: &Path,
    rel_norm: &str,
    content: &str,
    registry: &RuleRegistry,
    chrome_baseline_set: &HashSet<&str>,
    cross_ws_chrome_re: &Regex,
    chrome_new_expansion_re: &Regex,
    chrome_banned_api_re: &Regex,
    violations: &mut Vec<R4Violation>,
) {
    let in_chrome2rust = is_under_workspace(rel_norm, "chrome2rust");
    let in_winctl2rust = is_under_workspace(rel_norm, "winctl2rust");
    let rel_lower = rel_norm.to_ascii_lowercase();
    let is_path_test = rel_lower.contains("/tests/")
        || rel_lower.ends_with("/tests.rs")
        || rel_lower == "tests.rs";

    let chrome_rel = if in_chrome2rust {
        rel_norm
            .split_once("chrome2rust/")
            .map(|(_, rest)| rest)
            .unwrap_or(rel_norm)
    } else {
        ""
    };
    let is_chrome_baseline_file = in_chrome2rust && chrome_baseline_set.contains(chrome_rel);

    let lines: Vec<&str> = content.lines().collect();
    let mut lex_state = RustLexerState::default();
    let mut line_spans: Vec<Vec<Span>> = Vec::with_capacity(lines.len());
    for line in &lines {
        line_spans.push(lex_rust_line(line, &mut lex_state));
    }

    let block_comment_negated = compute_block_comment_negated(&lines, &line_spans, registry);
    let command_attr_flags = compute_command_attr_flags(&lines, &line_spans);

    let mut file_code_no_comments = String::with_capacity(content.len());
    let mut file_code_only = String::with_capacity(content.len());
    for (i, line) in lines.iter().enumerate() {
        file_code_no_comments.push_str(&strip_comments_from_line(line, &line_spans[i]));
        file_code_no_comments.push('\n');
        file_code_only.push_str(&strip_comments_and_strings(line, &line_spans[i]));
        file_code_only.push('\n');
    }

    let is_winctl_ctrl_export = in_winctl2rust
        && (rel_lower.ends_with("/ctrl_export.rs")
            || rel_lower == "ctrl_export.rs"
            || (rel_lower.ends_with("winctl2rust-desktop/src/win32_backend.rs")
                && (file_code_only.contains("LVM_GETITEM")
                    || file_code_only.contains("TVM_GETITEM"))));

    let file_has_audio_context = registry.acm_audio_context_regex.is_match(content);
    let file_has_wpm_struct_code = registry.wpm_struct_regex.is_match(&file_code_only);
    let file_has_wpm_exec = registry
        .wpm_exec_or_inj_regex
        .is_match(&file_code_no_comments)
        || has_virtual_alloc_ex_unsafe_protect(&lines, &line_spans);
    let file_has_wlan_get_profile = file_code_no_comments.contains("WlanGetProfile")
        || file_code_no_comments.contains("WLAN_PROFILE_GET_PLAINTEXT_KEY");

    for (line_no, sym) in has_multiline_wlan_get_profile_plaintext(&lines, &line_spans) {
        violations.push(R4Violation {
            category: "credential_api".to_string(),
            rule_id: "R4-API-CRED-05".to_string(),
            path: path.to_path_buf(),
            line: Some(line_no),
            matched_symbol: sym,
            detail: "Wi-Fi plaintext key recovery (WLAN_PROFILE_GET_PLAINTEXT_KEY / keyMaterial)"
                .to_string(),
        });
    }

    // Lazy AST index: parsed at most once on first R4 match in the file (fail-closed if syn::parse_file errors).
    let mut ast_cache: Option<Option<crate::rust_ast::RustAstIndex>> = None;
    let mut line_starts_cache: Option<Vec<usize>> = None;

    fn ensure_ast<'a>(
        ast_cache: &'a mut Option<Option<crate::rust_ast::RustAstIndex>>,
        rel_norm: &str,
        content: &str,
    ) -> Option<&'a crate::rust_ast::RustAstIndex> {
        if ast_cache.is_none() {
            *ast_cache = Some(crate::rust_ast::RustAstIndex::parse(rel_norm, content));
        }
        ast_cache.as_ref().and_then(|opt| opt.as_ref())
    }

    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let spans = &line_spans[idx];
        let in_cmd_attr = command_attr_flags[idx];
        let line_code_no_comments = strip_comments_from_line(line, spans);

        for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(line) {
            let rule = &registry.rules[rule_idx];
            if rule.def.rule_id == "R4-INJ-02"
                && matched.eq_ignore_ascii_case("QUEUE_USER_APC")
                && line[m_end..].to_ascii_uppercase().starts_with("_FLAGS")
            {
                continue;
            }
            let Some(span) = span_for_byte(spans, m_start) else {
                continue;
            };

            if rule.def.rule_id == "R4-CRED-02"
                && matched.eq_ignore_ascii_case("product_key")
                && !span.is_comment
                && !span.is_string
                && !in_cmd_attr
                && !is_command_or_tool_id_line(line, in_cmd_attr)
            {
                let full_ident = expand_ident_for_fs(line, m_start, m_end).to_ascii_lowercase();
                if full_ident == "has_single_product_key" || full_ident == "is_single_product_key" {
                    continue;
                }
            }

            if rule.def.rule_id == "R4-API-CRED-05"
                && (matched.eq_ignore_ascii_case("keymaterial")
                    || matched.eq_ignore_ascii_case("key_material"))
                && !span.is_comment
                && !span.is_string
                && !file_has_wlan_get_profile
            {
                let full_ident = expand_ident_for_fs(line, m_start, m_end);
                if let Some(ast) = ensure_ast(&mut ast_cache, rel_norm, content)
                    && !ast.file_has_wlan_get_profile
                {
                    let abs_pos = ast.abs_byte_from_line_offset(idx, m_start);
                    if ast.in_verified_wlan_item(abs_pos) {
                        let known_verified = ast.verified_wlan_idents.contains(full_ident)
                            || crate::rust_ast::is_known_cross_crate_wlan_ident(full_ident);
                        if known_verified {
                            continue;
                        }
                        if !crate::rust_ast::has_dangerous_wlan_fn_verb(full_ident, true)
                            && ast.verified_wlan_non_fn_idents.contains(full_ident)
                        {
                            let ident_start_line = {
                                let b = line.as_bytes();
                                let mut s = m_start;
                                while s > 0
                                    && (b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_')
                                {
                                    s -= 1;
                                }
                                s
                            };
                            let ident_end_line = {
                                let b = line.as_bytes();
                                let mut e = m_end;
                                while e < b.len() && (b[e].is_ascii_alphanumeric() || b[e] == b'_')
                                {
                                    e += 1;
                                }
                                e
                            };
                            let abs_ident_start =
                                ast.abs_byte_from_line_offset(idx, ident_start_line);
                            let abs_ident_end = ast.abs_byte_from_line_offset(idx, ident_end_line);
                            let before_ctx = content[..abs_ident_start].trim_end();
                            let after_ctx = content[abs_ident_end..].trim_start();
                            let is_external_path =
                                before_ctx.ends_with("::") || after_ctx.starts_with("::");
                            let is_call =
                                after_ctx.starts_with('(') || after_ctx.starts_with("::<");
                            if !is_external_path
                                && !is_call
                                && !ast.fns.iter().any(|fn_item| {
                                    fn_item.name == full_ident && !fn_item.is_verified_wlan
                                })
                            {
                                continue;
                            }
                        }
                    }
                    let in_test_context = ast.in_test_context(abs_pos);
                    if ast.file_has_verified_wlan
                        && ast.verified_wlan_idents.contains(full_ident)
                        && let Some(f) = ast.enclosing_fn(abs_pos)
                        && !f.has_exec_sink
                        && !f.has_io_sink
                        && !f.has_unsafe_wlan_extraction
                    {
                        let bad_verb = if in_test_context {
                            crate::rust_ast::has_dangerous_wlan_test_fn_verb(&f.name)
                        } else {
                            crate::rust_ast::has_dangerous_wlan_fn_verb(&f.name, false)
                        };
                        if !bad_verb {
                            let safe_test_caller = in_test_context && !f.has_slice_or_split;
                            let safe_prod_caller = f.is_verified_wlan
                                || (!f.has_mut_param
                                    && !f.has_slice_or_split
                                    && matches!(
                                        f.ret_type_str.as_deref(),
                                        None | Some("()")
                                            | Some("bool")
                                            | Some("usize")
                                            | Some("Option<usize>")
                                            | Some("Option<(usize,usize)>")
                                            | Some("Result<(),&'staticstr>")
                                            | Some("Result<(),ReportError>")
                                            | Some("Result<(),NetError>")
                                            | Some("Result<bool,&'staticstr>")
                                            | Some("Result<bool,ReportError>")
                                            | Some("Result<bool,NetError>")
                                    ));
                            if safe_test_caller || safe_prod_caller {
                                continue;
                            }
                        }
                    }
                    if in_test_context
                        && full_ident.starts_with("test_")
                        && (full_ident.contains("redact") || full_ident.contains("_r4_"))
                        && !crate::rust_ast::has_dangerous_wlan_test_fn_verb(full_ident)
                        && let Some(f) = ast.enclosing_fn(abs_pos)
                        && !f.has_exec_sink
                        && !f.has_io_sink
                        && !f.has_slice_or_split
                        && (f.callees.iter().any(|c| {
                            if c == "render_report" {
                                return true;
                            }
                            if let Some(local_f) = ast.fns.iter().find(|lf| lf.name == *c) {
                                local_f.is_verified_wlan
                            } else {
                                crate::rust_ast::is_known_cross_crate_wlan_ident(c)
                            }
                        }) || ast.macro_calls.iter().any(|m| {
                            m.span.0 >= f.span.0
                                && m.span.1 <= f.span.1
                                && m.is_negative_assert
                                && !m.has_sink
                        }))
                    {
                        continue;
                    }
                }
            }

            if span.is_comment {
                let mut is_r4_test_comment = false;
                if rule.def.rule_id == "R4-API-CRED-05"
                    && matched.eq_ignore_ascii_case("keymaterial")
                    && !file_has_wlan_get_profile
                    && let Some(ast) = ensure_ast(&mut ast_cache, rel_norm, content)
                    && !ast.file_has_wlan_get_profile
                {
                    let abs_pos = ast.abs_byte_from_line_offset(idx, m_start);
                    if ast.in_test_context(abs_pos)
                        && let Some(f) = ast.enclosing_fn(abs_pos)
                        && (f.name.starts_with("test_r4") || f.name.contains("_r4_"))
                        && !crate::rust_ast::has_dangerous_wlan_test_fn_verb(&f.name)
                        && !f.has_exec_sink
                        && !f.has_io_sink
                        && !f.has_slice_or_split
                        && f.callees.iter().any(|c| {
                            c.starts_with("assert_r4_clean") || c.starts_with("sanitize_wlan")
                        })
                    {
                        is_r4_test_comment = true;
                    }
                }
                let in_verified_wlan = rule.def.rule_id == "R4-API-CRED-05"
                    && matched.eq_ignore_ascii_case("keymaterial")
                    && ensure_ast(&mut ast_cache, rel_norm, content).is_some_and(|ast| {
                        let abs_pos = ast.abs_byte_from_line_offset(idx, m_start);
                        ast.in_verified_wlan_item(abs_pos)
                    });
                let is_neg = (rule.def.allow_negation_in_comments
                    && (registry.is_negated_text(&line[span.start..span.end])
                        || span
                            .block_comment_id
                            .is_some_and(|id| block_comment_negated.contains(&id))))
                    || in_verified_wlan
                    || is_r4_test_comment;
                if is_neg {
                    continue;
                }
            } else if span.is_string
                && !is_command_or_tool_id_line(line, in_cmd_attr)
                && rule.def.allow_negation_in_strings
            {
                let str_slice = &line[span.start..span.end];
                let rel_start = m_start.saturating_sub(span.start);
                let rel_end = m_end.saturating_sub(span.start).min(str_slice.len());
                if crate::surface_cli_mcp::is_negated_exclusion_at_span_with_fs(
                    str_slice,
                    rel_start,
                    rel_end,
                    rule.def.rule_id,
                    &matched,
                    true,
                ) {
                    continue;
                }
                if let Some(ast) = ensure_ast(&mut ast_cache, rel_norm, content) {
                    let abs_start = ast.abs_byte_from_line_offset(idx, span.start);
                    let abs_end = ast.abs_byte_from_line_offset(idx, span.end);
                    if ast.is_safe_string_literal(
                        content,
                        abs_start,
                        abs_end,
                        rule.def.rule_id,
                        &matched,
                    ) {
                        continue;
                    }
                }
            }

            match rule.def.kind {
                RuleKind::Standard => {
                    violations.push(R4Violation {
                        category: rule.def.category.to_string(),
                        rule_id: rule.def.rule_id.to_string(),
                        path: path.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: matched,
                        detail: rule.def.description.to_string(),
                    });
                }
                RuleKind::ApiCredPek => {
                    let start_w = idx.saturating_sub(2);
                    let end_w = (idx + 3).min(lines.len());
                    let window = lines[start_w..end_w].join("\n");
                    if matched.eq_ignore_ascii_case("PEK")
                        && !registry.pek_context_regex.is_match(&window)
                    {
                        continue;
                    }
                    let norm_m: String = matched
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .flat_map(|c| c.to_lowercase())
                        .collect();
                    if norm_m == "syskey" && !registry.pek_context_regex.is_match(&window) {
                        let raw_ident = expand_ident_for_fs(line, m_start, m_end);
                        let full_ident = raw_ident.to_ascii_lowercase();
                        let is_exact_ui = matches!(
                            full_ident.as_str(),
                            "handle_sys_key"
                                | "handlesyskey"
                                | "handle_syskey"
                                | "on_sys_key"
                                | "onsyskey"
                                | "on_syskey"
                                | "wm_syskey"
                                | "wm_syskeydown"
                                | "wm_syskeyup"
                                | "wm_syskeychar"
                                | "wm_sysdeadchar"
                                | "wmsyskeydown"
                                | "wmsyskeyup"
                                | "sys_key_down"
                                | "syskeydown"
                                | "sys_key_up"
                                | "syskeyup"
                                | "sys_key_event"
                                | "syskeyevent"
                                | "sys_key_code"
                                | "syskeycode"
                                | "sys_key_press"
                                | "syskeypress"
                                | "sys_key_char"
                                | "syskeychar"
                                | "translate_sys_key"
                                | "translatesyskey"
                                | "process_sys_key"
                                | "processsyskey"
                                | "dispatch_sys_key"
                                | "dispatchsyskey"
                        );
                        if is_exact_ui
                            && !crate::rules::has_syskey_offensive_context(raw_ident)
                            && !crate::rules::has_syskey_offensive_context(&window)
                        {
                            continue;
                        }
                    }
                    violations.push(R4Violation {
                        category: rule.def.category.to_string(),
                        rule_id: rule.def.rule_id.to_string(),
                        path: path.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: matched,
                        detail: rule.def.description.to_string(),
                    });
                }
                RuleKind::LegacyAcm => {
                    if matched.eq_ignore_ascii_case("acm") {
                        let is_cmd_acm = registry
                            .acm_standalone_id_regex
                            .is_match(&line_code_no_comments)
                            || (in_cmd_attr
                                && (line.to_ascii_lowercase().contains("name = \"acm\"")
                                    || line.to_ascii_lowercase().contains("name=\"acm\"")
                                    || line.to_ascii_lowercase().contains("alias = \"acm\"")
                                    || line.to_ascii_lowercase().contains("alias=\"acm\"")));
                        if !is_cmd_acm
                            && (registry.acm_audio_context_regex.is_match(line)
                                || file_has_audio_context)
                        {
                            continue;
                        }
                    }
                    violations.push(R4Violation {
                        category: rule.def.category.to_string(),
                        rule_id: rule.def.rule_id.to_string(),
                        path: path.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: matched,
                        detail: rule.def.description.to_string(),
                    });
                }
                RuleKind::InjSetWindowsHookEx => {
                    if registry.hook_dangerous_const_regex.is_match(&matched) {
                        violations.push(R4Violation {
                            category: rule.def.category.to_string(),
                            rule_id: rule.def.rule_id.to_string(),
                            path: path.to_path_buf(),
                            line: Some(line_no),
                            matched_symbol: matched,
                            detail: rule.def.description.to_string(),
                        });
                    } else if !span.is_comment && !span.is_string {
                        let is_safe_ll_hook = if in_winctl2rust
                            && let Some(args) = extract_paren_call_args_across_lines(
                                &lines,
                                &line_spans,
                                idx,
                                m_start,
                            )
                            && args.len() >= 4
                        {
                            let arg_hook = args[0].trim();
                            let arg_hmod = args[2].trim();
                            let arg_hmod_lower = arg_hmod.to_ascii_lowercase();
                            registry.hook_ll_const_regex.is_match(arg_hook)
                                && !registry.hook_dangerous_const_regex.is_match(arg_hook)
                                && arg_hook != "5"
                                && registry.hook_null_hinstance_regex.is_match(arg_hmod)
                                && !arg_hmod_lower.contains(".dll")
                                && !arg_hmod_lower.contains("loadlibrary")
                        } else {
                            false
                        };
                        if !is_safe_ll_hook {
                            violations.push(R4Violation {
                                category: rule.def.category.to_string(),
                                rule_id: rule.def.rule_id.to_string(),
                                path: path.to_path_buf(),
                                line: Some(line_no),
                                matched_symbol: matched,
                                detail: "SetWindowsHookEx outside permitted winctl2rust low-level null-HINSTANCE hook".to_string(),
                            });
                        }
                    } else {
                        violations.push(R4Violation {
                            category: rule.def.category.to_string(),
                            rule_id: rule.def.rule_id.to_string(),
                            path: path.to_path_buf(),
                            line: Some(line_no),
                            matched_symbol: matched,
                            detail: rule.def.description.to_string(),
                        });
                    }
                }
                RuleKind::InjWriteProcessMemory => {
                    let is_safe_ctrl_export = !span.is_comment
                        && !span.is_string
                        && is_winctl_ctrl_export
                        && file_has_wpm_struct_code
                        && !file_has_wpm_exec;
                    if !is_safe_ctrl_export {
                        violations.push(R4Violation {
                            category: rule.def.category.to_string(),
                            rule_id: rule.def.rule_id.to_string(),
                            path: path.to_path_buf(),
                            line: Some(line_no),
                            matched_symbol: matched,
                            detail: "WriteProcessMemory outside permitted winctl2rust-desktop control-export LVITEMW/TVITEMW marshaling".to_string(),
                        });
                    }
                }
            }
        }

        let mut banned_offset = 0usize;
        while banned_offset <= line.len() {
            let Some(caps) = chrome_banned_api_re.captures_at(line, banned_offset) else {
                break;
            };
            let Some(m) = caps.get(1) else {
                break;
            };
            let matched = m.as_str();
            let allow_here = !in_chrome2rust && matched.eq_ignore_ascii_case("CryptProtectData");
            if !allow_here
                && !is_line_negated_at_pos(
                    line,
                    m.start(),
                    m.end(),
                    spans,
                    in_cmd_attr,
                    &block_comment_negated,
                    registry,
                    content,
                    idx,
                    &mut ast_cache,
                    &mut line_starts_cache,
                    rel_norm,
                    "R4-BASELINE-CHROME",
                    matched,
                )
            {
                violations.push(R4Violation {
                    category: "baseline_chrome".to_string(),
                    rule_id: "R4-BASELINE-CHROME".to_string(),
                    path: path.to_path_buf(),
                    line: Some(line_no),
                    matched_symbol: matched.to_string(),
                    detail: "Prohibited browser/NSS/DPAPI credential API".to_string(),
                });
            }
            banned_offset = m.end().max(banned_offset + 1);
        }

        if !in_chrome2rust {
            for m in cross_ws_chrome_re.find_iter(line) {
                if !is_line_negated_at_pos(
                    line,
                    m.start(),
                    m.end(),
                    spans,
                    in_cmd_attr,
                    &block_comment_negated,
                    registry,
                    content,
                    idx,
                    &mut ast_cache,
                    &mut line_starts_cache,
                    rel_norm,
                    "R4-BASELINE-CHROME",
                    m.as_str(),
                ) {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: path.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: m.as_str().to_string(),
                        detail: "Non-chrome2rust crate must not import chrome2rust login/crypto baseline".to_string(),
                    });
                }
            }
        }

        if in_chrome2rust && !is_chrome_baseline_file && rel_norm.contains("chrome2rust/crates/") {
            for m in chrome_new_expansion_re.find_iter(line) {
                if !is_line_negated_at_pos(
                    line,
                    m.start(),
                    m.end(),
                    spans,
                    in_cmd_attr,
                    &block_comment_negated,
                    registry,
                    content,
                    idx,
                    &mut ast_cache,
                    &mut line_starts_cache,
                    rel_norm,
                    "R4-BASELINE-CHROME",
                    m.as_str(),
                ) {
                    violations.push(R4Violation {
                        category: "baseline_chrome".to_string(),
                        rule_id: "R4-BASELINE-CHROME".to_string(),
                        path: path.to_path_buf(),
                        line: Some(line_no),
                        matched_symbol: m.as_str().to_string(),
                        detail: "New chrome2rust module outside baseline must not expand login/credential/DPAPI parsing".to_string(),
                    });
                }
            }
        }
    }
    if (content.contains("concat!")
        || content.contains("include_str!")
        || content.contains("include_bytes!"))
        && let Some(ast) = ensure_ast(&mut ast_cache, rel_norm, content)
    {
        let line_of_byte = |bpos: usize| -> usize {
            match ast.line_starts.binary_search(&bpos) {
                Ok(i) => i + 1,
                Err(i) => i,
            }
        };
        for &(pos, ref joined) in &ast.concat_strings {
            let in_test_ctx = is_path_test || ast.in_test_context(pos);
            for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(joined) {
                let rule = &registry.rules[rule_idx];
                if rule.def.allow_negation_in_strings
                    && (crate::surface_cli_mcp::is_negated_exclusion_at_span_with_fs(
                        joined,
                        m_start,
                        m_end,
                        rule.def.rule_id,
                        &matched,
                        true,
                    ) || ast.is_safe_string_literal(
                        content,
                        pos,
                        (pos + 7).min(content.len()),
                        rule.def.rule_id,
                        &matched,
                    ))
                {
                    continue;
                }
                if rule.def.kind == RuleKind::ApiCredPek
                    && matched.eq_ignore_ascii_case("PEK")
                    && !registry.pek_context_regex.is_match(joined)
                {
                    continue;
                }
                if rule.def.kind == RuleKind::LegacyAcm
                    && matched.eq_ignore_ascii_case("acm")
                    && (registry.acm_audio_context_regex.is_match(joined) || file_has_audio_context)
                {
                    continue;
                }
                let _ = in_test_ctx;
                violations.push(R4Violation {
                    category: rule.def.category.to_string(),
                    rule_id: rule.def.rule_id.to_string(),
                    path: path.to_path_buf(),
                    line: Some(line_of_byte(pos)),
                    matched_symbol: matched,
                    detail: format!("concat! macro string violation: {}", rule.def.description),
                });
            }
        }
        for &(pos, ref inc_rel, is_bytes) in &ast.include_str_paths {
            let Some(parent_dir) = path.parent() else {
                continue;
            };
            let candidate = parent_dir.join(inc_rel);
            if let Ok(meta) = std::fs::metadata(&candidate)
                && meta.len() <= 2 * 1024 * 1024
                && let Ok(raw_bytes) = std::fs::read(&candidate)
            {
                let inc_line_no = line_of_byte(pos);
                let macro_kw = if is_bytes {
                    "include_bytes!"
                } else {
                    "include_str!"
                };
                if let Ok(inc_text) = std::str::from_utf8(&raw_bytes) {
                    for inc_line in inc_text.lines() {
                        for (rule_idx, m_start, m_end, matched) in
                            registry.scan_all_source_matches(inc_line)
                        {
                            let rule = &registry.rules[rule_idx];
                            if rule.def.allow_negation_in_strings
                                && crate::surface_cli_mcp::is_negated_exclusion_at_span_with_fs(
                                    inc_line,
                                    m_start,
                                    m_end,
                                    rule.def.rule_id,
                                    &matched,
                                    true,
                                )
                            {
                                continue;
                            }
                            if rule.def.kind == RuleKind::ApiCredPek
                                && matched.eq_ignore_ascii_case("PEK")
                                && !registry.pek_context_regex.is_match(inc_line)
                            {
                                continue;
                            }
                            if rule.def.kind == RuleKind::LegacyAcm
                                && matched.eq_ignore_ascii_case("acm")
                                && (registry.acm_audio_context_regex.is_match(inc_line)
                                    || file_has_audio_context)
                            {
                                continue;
                            }
                            violations.push(R4Violation {
                                category: rule.def.category.to_string(),
                                rule_id: rule.def.rule_id.to_string(),
                                path: path.to_path_buf(),
                                line: Some(inc_line_no),
                                matched_symbol: matched,
                                detail: format!(
                                    "{macro_kw}(\"{inc_rel}\") violation: {}",
                                    rule.def.description
                                ),
                            });
                        }
                    }
                } else {
                    let lossy = String::from_utf8_lossy(&raw_bytes);
                    for (rule_idx, matched) in registry.scan_all_binary_matches(&lossy) {
                        let rule = &registry.rules[rule_idx];
                        violations.push(R4Violation {
                            category: rule.def.category.to_string(),
                            rule_id: rule.def.rule_id.to_string(),
                            path: path.to_path_buf(),
                            line: Some(inc_line_no),
                            matched_symbol: matched,
                            detail: format!(
                                "{macro_kw}(\"{inc_rel}\") binary violation: {}",
                                rule.def.description
                            ),
                        });
                    }
                }
            }
        }
    }
    let _ = is_path_test;
}

fn expand_ident_for_fs(text: &str, m_start: usize, m_end: usize) -> &str {
    let b = text.as_bytes();
    let mut s = m_start;
    while s > 0 && (b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_') {
        s -= 1;
    }
    let mut e = m_end;
    while e < b.len() && (b[e].is_ascii_alphanumeric() || b[e] == b'_') {
        e += 1;
    }
    &text[s..e]
}

#[allow(clippy::too_many_arguments)]
fn is_line_negated_at_pos(
    line: &str,
    pos: usize,
    pos_end: usize,
    spans: &[Span],
    in_cmd_attr: bool,
    block_comment_negated: &HashSet<usize>,
    registry: &RuleRegistry,
    content: &str,
    line_idx: usize,
    ast_cache: &mut Option<Option<crate::rust_ast::RustAstIndex>>,
    line_starts_cache: &mut Option<Vec<usize>>,
    rel_norm: &str,
    rule_id: &str,
    matched: &str,
) -> bool {
    let Some(span) = span_for_byte(spans, pos) else {
        return false;
    };
    if span.is_comment {
        return registry.is_negated_text(&line[span.start..span.end])
            || span
                .block_comment_id
                .is_some_and(|id| block_comment_negated.contains(&id));
    }
    if span.is_string && !is_command_or_tool_id_line(line, in_cmd_attr) {
        let str_slice = &line[span.start..span.end];
        let rel_start = pos.saturating_sub(span.start);
        let rel_end = pos_end.saturating_sub(span.start).min(str_slice.len());
        if crate::surface_cli_mcp::is_negated_exclusion_at_span_with_fs(
            str_slice, rel_start, rel_end, rule_id, matched, true,
        ) {
            return true;
        }
        if ast_cache.is_none() {
            *ast_cache = Some(crate::rust_ast::RustAstIndex::parse(rel_norm, content));
        }
        if let Some(Some(ast)) = ast_cache.as_ref() {
            let _ = line_starts_cache;
            let abs_start = ast.abs_byte_from_line_offset(line_idx, span.start);
            let abs_end = ast.abs_byte_from_line_offset(line_idx, span.end);
            if ast.is_safe_string_literal(content, abs_start, abs_end, rule_id, matched) {
                return true;
            }
        }
    }
    false
}

fn has_top_level_python_boolean_joiner(stmt: &str) -> bool {
    let bytes = stmt.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(b, b'"' | b'\'') {
            quote = Some(b);
            i += 1;
            continue;
        }
        if matches!(b, b'(' | b'[' | b'{') {
            depth += 1;
        } else if matches!(b, b')' | b']' | b'}') {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            let rest = &stmt[i..];
            let rest_lower = rest.to_ascii_lowercase();
            if (rest_lower.starts_with(" or ") || rest_lower.starts_with(" and "))
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_python_safe_negated_assert_at(line: &str, m_start: usize, m_end: usize) -> bool {
    let mut seg_start = 0usize;
    let bytes = line.as_bytes();
    let mut seg_end = line.len();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b';' {
            if i < m_start {
                seg_start = i + 1;
            } else if i >= m_end {
                seg_end = i;
                break;
            }
        }
    }
    let stmt = line[seg_start..seg_end].trim();
    let lower = stmt.to_ascii_lowercase();
    let is_neg_assert = lower.starts_with("assert not ")
        || lower.starts_with("self.assertfalse(")
        || lower.starts_with("self.assertnotin(");
    if !is_neg_assert {
        return false;
    }
    if has_top_level_python_boolean_joiner(stmt) {
        return false;
    }
    const SIDE_EFFECT_PATTERNS: &[&str] = &[
        "subprocess",
        "os.",
        "sys.",
        "shutil",
        "pathlib",
        "path(",
        "exec(",
        "eval(",
        "compile(",
        "open(",
        ".write",
        ".unlink",
        ".rmdir",
        ".mkdir",
        "ctypes",
        "socket",
        "urllib",
        "requests",
        "popen",
        "spawn",
        "fork",
        "pty",
        "system(",
        "__import__",
    ];
    if SIDE_EFFECT_PATTERNS.iter().any(|pat| lower.contains(pat)) {
        return false;
    }

    let cond_body = if let Some(rest) = lower.strip_prefix("assert not ") {
        rest.split('#').next().unwrap_or(rest).trim()
    } else if let Some(rest) = lower.strip_prefix("self.assertfalse(") {
        rest.strip_suffix(')').unwrap_or(rest).trim()
    } else if let Some(rest) = lower.strip_prefix("self.assertnotin(") {
        let inner = rest.strip_suffix(')').unwrap_or(rest).trim();
        return inner.contains(',') && !python_cond_has_non_pure_call(inner);
    } else {
        return false;
    };

    let has_safe_cmp = cond_body.contains(" in ")
        || cond_body.contains(" not in ")
        || cond_body.contains(" == ")
        || cond_body.contains(" != ")
        || cond_body.contains(" is ");
    has_safe_cmp && !python_cond_has_non_pure_call(cond_body)
}

fn python_cond_has_non_pure_call(expr: &str) -> bool {
    let bytes = expr.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(b, b'"' | b'\'') {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'(' {
            let mut k = i;
            while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                k -= 1;
            }
            if k > 0 && (bytes[k - 1].is_ascii_alphanumeric() || bytes[k - 1] == b'_') {
                let mut id_start = k;
                while id_start > 0
                    && (bytes[id_start - 1].is_ascii_alphanumeric() || bytes[id_start - 1] == b'_')
                {
                    id_start -= 1;
                }
                let callee = &expr[id_start..k];
                if !matches!(
                    callee,
                    "lower" | "casefold" | "strip" | "lstrip" | "rstrip" | "str" | "len"
                ) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn scan_python_file(
    path: &Path,
    content: &str,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    let file_has_audio_context = registry.acm_audio_context_regex.is_match(content);
    let mut state = PythonLexerState::default();

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let spans = lex_python_line(line, &mut state, registry);

        for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(line) {
            let rule = &registry.rules[rule_idx];
            let Some((span, multi_negated)) = spans
                .iter()
                .find(|(sp, _)| m_start >= sp.start && m_start < sp.end)
            else {
                continue;
            };

            if span.is_comment {
                if rule.def.allow_negation_in_comments
                    && registry.is_negated_text(&line[span.start..span.end])
                {
                    continue;
                }
            } else if span.is_string && rule.def.allow_negation_in_strings {
                if *multi_negated || is_python_safe_negated_assert_at(line, m_start, m_end) {
                    continue;
                }
                let str_slice = &line[span.start..span.end];
                let rel_start = m_start.saturating_sub(span.start);
                let rel_end = m_end.saturating_sub(span.start).min(str_slice.len());
                if crate::surface_cli_mcp::is_negated_exclusion_at_span_with_fs(
                    str_slice,
                    rel_start,
                    rel_end,
                    rule.def.rule_id,
                    &matched,
                    true,
                ) {
                    continue;
                }
            }

            if rule.def.kind == RuleKind::LegacyAcm
                && matched.eq_ignore_ascii_case("acm")
                && (registry.acm_audio_context_regex.is_match(line) || file_has_audio_context)
            {
                continue;
            }

            violations.push(R4Violation {
                category: rule.def.category.to_string(),
                rule_id: rule.def.rule_id.to_string(),
                path: path.to_path_buf(),
                line: Some(line_no),
                matched_symbol: matched,
                detail: format!("Python source violation: {}", rule.def.description),
            });
        }
    }
}

fn scan_json_file(
    path: &Path,
    content: &str,
    registry: &RuleRegistry,
    violations: &mut Vec<R4Violation>,
) {
    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        let is_desc_line =
            trimmed.starts_with("\"description\"") || trimmed.starts_with("\"detail\"");
        for (rule_idx, m_start, m_end, matched) in registry.scan_all_source_matches(line) {
            let rule = &registry.rules[rule_idx];
            if rule.def.kind == RuleKind::LegacyAcm
                && registry.acm_audio_context_regex.is_match(line)
            {
                continue;
            }
            if is_desc_line
                && rule.def.allow_negation_in_strings
                && crate::surface_cli_mcp::is_negated_exclusion_at_span_with_fs(
                    line,
                    m_start,
                    m_end,
                    rule.def.rule_id,
                    &matched,
                    true,
                )
            {
                continue;
            }
            violations.push(R4Violation {
                category: rule.def.category.to_string(),
                rule_id: rule.def.rule_id.to_string(),
                path: path.to_path_buf(),
                line: Some(line_no),
                matched_symbol: matched,
                detail: format!("JSON manifest violation: {}", rule.def.description),
            });
        }
    }
}

fn strip_comments_and_strings(line: &str, spans: &[Span]) -> String {
    let mut out = String::with_capacity(line.len());
    for sp in spans {
        if !sp.is_comment && !sp.is_string {
            out.push_str(&line[sp.start..sp.end]);
            out.push(' ');
        }
    }
    out
}
