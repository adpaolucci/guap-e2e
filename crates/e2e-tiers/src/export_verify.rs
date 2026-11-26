use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyLeafView {
    pub index: usize,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyManifestView {
    pub generated_at: String,
    pub tool_id: String,
    pub tool_version: String,
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub merkle_root_sha256: String,
    pub merkle_root_sha512: String,
    pub leaves: Vec<CustodyLeafView>,
}

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    encode_hex_lower(&Sha256::digest(data))
}

pub fn sha512_hex(data: &[u8]) -> String {
    encode_hex_lower(&Sha512::digest(data))
}

fn compute_merkle_root<D: Digest>(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return encode_hex_lower(&D::digest(b""));
    }
    let mut layer: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| D::digest(leaf.as_bytes()).to_vec())
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let mut hasher = D::new();
            hasher.update(&pair[0]);
            if pair.len() == 2 {
                hasher.update(&pair[1]);
            } else {
                hasher.update(&pair[0]);
            }
            next.push(hasher.finalize().to_vec());
        }
        layer = next;
    }
    encode_hex_lower(&layer[0])
}

pub fn compute_merkle_root_sha256(leaves: &[String]) -> String {
    compute_merkle_root::<Sha256>(leaves)
}

pub fn compute_merkle_root_sha512(leaves: &[String]) -> String {
    compute_merkle_root::<Sha512>(leaves)
}

pub fn verify_custody_manifest(
    manifest_bytes: &[u8],
    verify_files_on_disk: bool,
) -> anyhow::Result<CustodyManifestView> {
    let manifest: CustodyManifestView =
        serde_json::from_slice(manifest_bytes).context("invalid CustodyManifest JSON")?;

    ensure!(
        !manifest.tool_id.trim().is_empty(),
        "CustodyManifest.tool_id must be non-empty"
    );
    ensure!(
        !manifest.generated_at.trim().is_empty(),
        "CustodyManifest.generated_at must be non-empty"
    );
    ensure!(
        !manifest.leaves.is_empty(),
        "CustodyManifest.leaves must contain at least 1 artifact leaf"
    );
    ensure!(
        manifest.artifact_count >= 1,
        "CustodyManifest.artifact_count must be >= 1"
    );
    ensure!(
        manifest.artifact_count == manifest.leaves.len(),
        "CustodyManifest.artifact_count ({}) != leaves.len() ({})",
        manifest.artifact_count,
        manifest.leaves.len()
    );

    let sum_bytes: u64 = manifest.leaves.iter().map(|l| l.size_bytes).sum();
    ensure!(
        manifest.total_bytes == sum_bytes,
        "CustodyManifest.total_bytes ({}) != sum(leaves.size_bytes) ({})",
        manifest.total_bytes,
        sum_bytes
    );

    for (expected_idx, leaf) in manifest.leaves.iter().enumerate() {
        ensure!(
            leaf.index == expected_idx,
            "leaf index mismatch at {}: got {}",
            expected_idx,
            leaf.index
        );
        ensure!(
            leaf.sha256.len() == 64 && leaf.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "leaf {} sha256 is not 64-char lowercase hex: {:?}",
            leaf.index,
            leaf.sha256
        );
        ensure!(
            leaf.sha512.len() == 128 && leaf.sha512.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "leaf {} sha512 is not 128-char lowercase hex: {:?}",
            leaf.index,
            leaf.sha512
        );

        if verify_files_on_disk {
            let p = Path::new(&leaf.path);
            ensure!(
                p.is_file(),
                "CustodyLeaf[{}] path does not exist on disk: {}",
                leaf.index,
                leaf.path
            );
            let disk_bytes = std::fs::read(p)
                .with_context(|| format!("failed reading CustodyLeaf path {}", leaf.path))?;
            ensure!(
                disk_bytes.len() as u64 == leaf.size_bytes,
                "CustodyLeaf[{}] disk size {} != manifest size_bytes {}",
                leaf.index,
                disk_bytes.len(),
                leaf.size_bytes
            );
            let actual_256 = sha256_hex(&disk_bytes);
            ensure!(
                actual_256 == leaf.sha256,
                "CustodyLeaf[{}] SHA-256 mismatch: disk={} manifest={}",
                leaf.index,
                actual_256,
                leaf.sha256
            );
            let actual_512 = sha512_hex(&disk_bytes);
            ensure!(
                actual_512 == leaf.sha512,
                "CustodyLeaf[{}] SHA-512 mismatch: disk={} manifest={}",
                leaf.index,
                actual_512,
                leaf.sha512
            );
        }
    }

    let sha256_leaves: Vec<String> = manifest.leaves.iter().map(|l| l.sha256.clone()).collect();
    let sha512_leaves: Vec<String> = manifest.leaves.iter().map(|l| l.sha512.clone()).collect();

    let expected_256 = compute_merkle_root_sha256(&sha256_leaves);
    ensure!(
        manifest.merkle_root_sha256 == expected_256,
        "merkle_root_sha256 mismatch: manifest={} expected={}",
        manifest.merkle_root_sha256,
        expected_256
    );

    let expected_512 = compute_merkle_root_sha512(&sha512_leaves);
    ensure!(
        manifest.merkle_root_sha512 == expected_512,
        "merkle_root_sha512 mismatch: manifest={} expected={}",
        manifest.merkle_root_sha512,
        expected_512
    );

    Ok(manifest)
}

pub fn parse_rfc4180_csv(bytes: &[u8]) -> anyhow::Result<Vec<Vec<String>>> {
    let text = std::str::from_utf8(bytes).context("CSV export is not valid UTF-8")?;
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    if text.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut just_closed_quote = false;
    let mut at_field_start = true;
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                    just_closed_quote = true;
                }
            } else {
                field.push(ch);
            }
            continue;
        }

        if just_closed_quote {
            match ch {
                ',' => {
                    row.push(std::mem::take(&mut field));
                    at_field_start = true;
                    just_closed_quote = false;
                    continue;
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    at_field_start = true;
                    just_closed_quote = false;
                    continue;
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    at_field_start = true;
                    just_closed_quote = false;
                    continue;
                }
                other => {
                    bail!("unexpected character {:?} after closing quote in CSV", other);
                }
            }
        }

        if at_field_start && ch == '"' {
            in_quotes = true;
            at_field_start = false;
            continue;
        }

        match ch {
            ',' => {
                row.push(std::mem::take(&mut field));
                at_field_start = true;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                at_field_start = true;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                at_field_start = true;
            }
            other => {
                field.push(other);
                at_field_start = false;
            }
        }
    }

    ensure!(!in_quotes, "unterminated quoted field in CSV");

    if !at_field_start || !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }

    Ok(rows)
}

pub fn is_formula_dangerous(raw: &str) -> bool {
    raw.starts_with(['=', '+', '-', '@', '\t', '\r', '\n'])
        || raw
            .trim_start_matches([' ', '\t', '\r', '\n'])
            .starts_with(['=', '+', '-', '@'])
}

pub fn neutralize_spreadsheet_cell(raw: &str) -> String {
    if is_formula_dangerous(raw) {
        format!("'{raw}")
    } else {
        raw.to_string()
    }
}

pub fn verify_csv_formula_neutralization(
    csv_bytes: &[u8],
    required_dangerous_raws: &[&str],
) -> anyhow::Result<usize> {
    let rows = parse_rfc4180_csv(csv_bytes)?;
    ensure!(!rows.is_empty(), "CSV export has zero rows");

    let expected_cols = rows[0].len();
    ensure!(expected_cols > 0, "CSV header has 0 columns");

    let mut seen_cells: BTreeSet<String> = BTreeSet::new();
    for (r_idx, row) in rows.iter().enumerate() {
        ensure!(
            row.len() == expected_cols,
            "CSV row {} has {} columns, expected {}",
            r_idx + 1,
            row.len(),
            expected_cols
        );
        for (c_idx, cell) in row.iter().enumerate() {
            let bom_stripped = cell.trim_start_matches('\u{FEFF}');
            ensure!(
                !is_formula_dangerous(bom_stripped),
                "unneutralized formula injection payload at CSV row {} col {}: {:?}",
                r_idx + 1,
                c_idx + 1,
                cell
            );
            seen_cells.insert(bom_stripped.to_string());
        }
    }

    for &raw in required_dangerous_raws {
        let expected_neutralized = neutralize_spreadsheet_cell(raw);
        ensure!(
            seen_cells.contains(&expected_neutralized),
            "CSV export missing expected neutralized payload {:?} (for raw {:?})",
            expected_neutralized,
            raw
        );
    }

    Ok(rows.len())
}

pub fn verify_csv_formula_neutralization_min_rows(
    csv_bytes: &[u8],
    required_dangerous_raws: &[&str],
    min_data_rows: usize,
) -> anyhow::Result<usize> {
    let total_rows = verify_csv_formula_neutralization(csv_bytes, required_dangerous_raws)?;
    ensure!(
        total_rows > min_data_rows,
        "CSV export has {} total row(s) (header + {} data row(s)), expected at least {} data row(s)",
        total_rows,
        total_rows.saturating_sub(1),
        min_data_rows
    );
    Ok(total_rows)
}

pub fn verify_tsv_bytes(tsv_bytes: &[u8], required_dangerous_raws: &[&str]) -> anyhow::Result<usize> {
    let text = std::str::from_utf8(tsv_bytes).context("TSV export is not valid UTF-8")?;
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    ensure!(!lines.is_empty(), "TSV export has zero lines");
    let expected_cols = lines[0].split('\t').count();
    ensure!(expected_cols > 0, "TSV header has 0 columns");

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        ensure!(
            cols.len() == expected_cols,
            "TSV line {} has {} columns, expected {}",
            idx + 1,
            cols.len(),
            expected_cols
        );
        for (c_idx, cell) in cols.iter().enumerate() {
            let bom_stripped = cell.trim_start_matches('\u{FEFF}');
            ensure!(
                !is_formula_dangerous(bom_stripped),
                "unneutralized formula payload at TSV line {} col {}: {:?}",
                idx + 1,
                c_idx + 1,
                cell
            );
            seen.insert(bom_stripped.to_string());
        }
    }

    for &raw in required_dangerous_raws {
        let expected = neutralize_spreadsheet_cell(raw).replace(['\t', '\r', '\n'], " ");
        ensure!(
            seen.contains(&expected),
            "TSV export missing expected neutralized cell {:?}",
            expected
        );
    }

    Ok(lines.len())
}

pub fn verify_json_bytes(json_bytes: &[u8]) -> anyhow::Result<usize> {
    let val: serde_json::Value =
        serde_json::from_slice(json_bytes).context("JSON export is invalid JSON")?;
    let arr = val
        .as_array()
        .context("JSON table export must be a JSON array")?;
    for (idx, item) in arr.iter().enumerate() {
        ensure!(
            item.is_object(),
            "JSON export element {} must be a JSON object",
            idx
        );
    }
    Ok(arr.len())
}

pub fn verify_jsonl_bytes(jsonl_bytes: &[u8]) -> anyhow::Result<usize> {
    let text = std::str::from_utf8(jsonl_bytes).context("JSONL export is not valid UTF-8")?;
    let mut count = 0usize;
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let val: serde_json::Value = serde_json::from_str(trimmed)
            .with_context(|| format!("JSONL line {} is invalid JSON", idx + 1))?;
        ensure!(val.is_object(), "JSONL line {} is not a JSON object", idx + 1);
        count += 1;
    }
    ensure!(count > 0, "JSONL export has zero records");
    Ok(count)
}

pub fn verify_html_bytes(html_bytes: &[u8], vertical: bool) -> anyhow::Result<()> {
    let text = std::str::from_utf8(html_bytes).context("HTML export is not valid UTF-8")?;
    ensure!(
        text.contains("<!DOCTYPE html>"),
        "HTML export missing <!DOCTYPE html>"
    );
    ensure!(
        text.contains("Content-Security-Policy"),
        "HTML export missing Content-Security-Policy meta tag"
    );
    ensure!(text.contains("<table>"), "HTML export missing <table>");
    ensure!(
        !text.contains("<script>"),
        "HTML export contains unescaped <script> tag"
    );
    if vertical {
        ensure!(
            text.contains("class=\"card\"") || text.contains("<tbody><tr><th>"),
            "HTML vertical export missing vertical card/row structure"
        );
    } else {
        ensure!(
            text.contains("<thead>") && text.contains("<tbody>"),
            "HTML horizontal export missing <thead>/<tbody>"
        );
    }
    Ok(())
}

pub fn verify_markdown_bytes(md_bytes: &[u8]) -> anyhow::Result<()> {
    let text = std::str::from_utf8(md_bytes).context("Markdown export is not valid UTF-8")?;
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with('|')).collect();
    ensure!(
        lines.len() >= 2,
        "Markdown export missing header and alignment separator rows"
    );
    ensure!(
        lines[1].contains("---") || lines[1].contains(":---") || lines[1].contains("---:"),
        "Markdown export missing table alignment row: {:?}",
        lines[1]
    );
    Ok(())
}

pub fn build_sample_custody_manifest(
    tool_id: &str,
    tool_version: &str,
    artifact_paths: &[&Path],
) -> anyhow::Result<Vec<u8>> {
    let mut leaves = Vec::with_capacity(artifact_paths.len());
    let mut total_bytes = 0u64;
    for (idx, p) in artifact_paths.iter().enumerate() {
        let bytes = std::fs::read(p)
            .with_context(|| format!("failed reading artifact {}", p.display()))?;
        total_bytes += bytes.len() as u64;
        leaves.push(CustodyLeafView {
            index: idx,
            path: p.display().to_string(),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            sha512: sha512_hex(&bytes),
        });
    }
    let sha256_leaves: Vec<String> = leaves.iter().map(|l| l.sha256.clone()).collect();
    let sha512_leaves: Vec<String> = leaves.iter().map(|l| l.sha512.clone()).collect();

    let manifest = CustodyManifestView {
        generated_at: "2026-11-22T14:30:00Z".to_string(),
        tool_id: tool_id.to_string(),
        tool_version: tool_version.to_string(),
        artifact_count: leaves.len(),
        total_bytes,
        merkle_root_sha256: compute_merkle_root_sha256(&sha256_leaves),
        merkle_root_sha512: compute_merkle_root_sha512(&sha512_leaves),
        leaves,
    };
    if manifest.leaves.is_empty() {
        bail!("expected at least one artifact leaf");
    }
    Ok(serde_json::to_vec_pretty(&manifest)?)
}