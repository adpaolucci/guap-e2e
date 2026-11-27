pub mod artifacts;
pub mod browser;
pub mod corrupt;
pub mod crash_posture;
pub mod evtx;
pub mod hive;
pub mod lz4_block;
pub mod mail_wpd;
pub mod net;
pub mod srum;
pub mod sys_fs;
pub mod util;
pub mod winctl;

use crate::util::{FIXED_ISO_TIMESTAMP, sha256_hex, write_file_deterministic};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializedFixtures {
    pub root: PathBuf,
    pub evtx_dir: PathBuf,
    pub hive_dir: PathBuf,
    pub srum_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    pub crash_dir: PathBuf,
    pub browser_dir: PathBuf,
    pub mail_dir: PathBuf,
    pub wpd_dir: PathBuf,
    pub winctl_dir: PathBuf,
    pub net_dir: PathBuf,
    pub sys_fs_dir: PathBuf,
    pub corrupt_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureVerificationReport {
    pub total_files: usize,
    pub verified_files: usize,
    pub details: Vec<String>,
}

impl FixtureVerificationReport {
    pub fn all_verified(&self) -> bool {
        self.total_files > 0 && self.verified_files == self.total_files
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FixtureManifest {
    schema_version: u32,
    generated_at: String,
    total_files: usize,
    total_bytes: u64,
    files: BTreeMap<String, ManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    size_bytes: u64,
    sha256: String,
}

fn recreate_subdir(root: &Path, name: &str) -> Result<PathBuf> {
    let dir = root.join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn materialize_all(base_dir: &Path) -> Result<MaterializedFixtures> {
    std::fs::create_dir_all(base_dir)?;

    let fixtures = MaterializedFixtures {
        root: base_dir.to_path_buf(),
        evtx_dir: recreate_subdir(base_dir, "evtx")?,
        hive_dir: recreate_subdir(base_dir, "hive")?,
        srum_dir: recreate_subdir(base_dir, "srum")?,
        artifacts_dir: recreate_subdir(base_dir, "artifacts")?,
        crash_dir: recreate_subdir(base_dir, "crash")?,
        browser_dir: recreate_subdir(base_dir, "browser")?,
        mail_dir: recreate_subdir(base_dir, "mail")?,
        wpd_dir: recreate_subdir(base_dir, "wpd")?,
        winctl_dir: recreate_subdir(base_dir, "winctl")?,
        net_dir: recreate_subdir(base_dir, "net")?,
        sys_fs_dir: recreate_subdir(base_dir, "sys_fs")?,
        corrupt_dir: recreate_subdir(base_dir, "corrupt")?,
    };

    evtx::generate_evtx_dir(&fixtures.evtx_dir)?;
    hive::generate_hive_dir(&fixtures.hive_dir)?;
    srum::generate_srum_dir(&fixtures.srum_dir)?;
    artifacts::generate_artifacts_dir(&fixtures.artifacts_dir)?;
    crash_posture::generate_crash_dir(&fixtures.crash_dir)?;
    browser::generate_browser_dir(&fixtures.browser_dir)?;
    mail_wpd::generate_mail_and_wpd_dirs(&fixtures.mail_dir, &fixtures.wpd_dir)?;
    winctl::generate_winctl_dir(&fixtures.winctl_dir)?;
    net::generate_net_dir(&fixtures.net_dir)?;
    sys_fs::generate_sys_fs_dir(&fixtures.sys_fs_dir)?;
    corrupt::generate_corrupt_dir(&fixtures.corrupt_dir)?;

    let mut files = BTreeMap::new();
    let mut total_bytes = 0u64;
    for entry in WalkDir::new(base_dir).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(base_dir)?
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "fixture_manifest.json" {
            continue;
        }
        let data = std::fs::read(path)?;
        total_bytes += data.len() as u64;
        files.insert(
            rel,
            ManifestEntry {
                size_bytes: data.len() as u64,
                sha256: sha256_hex(&data),
            },
        );
    }

    let manifest = FixtureManifest {
        schema_version: 1,
        generated_at: FIXED_ISO_TIMESTAMP.to_string(),
        total_files: files.len(),
        total_bytes,
        files,
    };
    write_file_deterministic(
        &base_dir.join("fixture_manifest.json"),
        serde_json::to_string_pretty(&manifest)?.as_bytes(),
    )?;

    Ok(fixtures)
}

fn verify_r4_zero_credentials(fixtures: &MaterializedFixtures) -> Result<String> {
    let valid_dirs = [
        &fixtures.evtx_dir,
        &fixtures.hive_dir,
        &fixtures.srum_dir,
        &fixtures.artifacts_dir,
        &fixtures.crash_dir,
        &fixtures.browser_dir,
        &fixtures.mail_dir,
        &fixtures.wpd_dir,
        &fixtures.winctl_dir,
        &fixtures.net_dir,
        &fixtures.sys_fs_dir,
    ];
    let forbidden = [
        "Authorization:",
        "Bearer ",
        "WLAN_PROFILE_GET_PLAINTEXT_KEY",
        "<keyMaterial>",
        "CredEnumerateW",
        "VaultEnumerateItems",
        "LsaRetrievePrivateData",
        "RunAsDate",
        "CreateRemoteThread",
    ];
    let mut scanned = 0usize;
    for dir in valid_dirs {
        for entry in WalkDir::new(dir) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let bytes = std::fs::read(entry.path())?;
            let text_utf8 = String::from_utf8_lossy(&bytes);
            let decode_utf16le = |slice: &[u8]| -> String {
                let u16s: Vec<u16> = slice
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .collect();
                String::from_utf16_lossy(&u16s)
            };
            let text_utf16_even = decode_utf16le(&bytes);
            let text_utf16_odd = if bytes.len() > 1 {
                decode_utf16le(&bytes[1..])
            } else {
                String::new()
            };
            for pat in &forbidden {
                ensure!(
                    !text_utf8.contains(pat)
                        && !text_utf16_even.contains(pat)
                        && !text_utf16_odd.contains(pat),
                    "R4 violation in valid fixture {}: matched {:?}",
                    entry.path().display(),
                    pat
                );
            }
            scanned += 1;
        }
    }
    Ok(format!(
        "R4 zero-credential scan: {} valid fixture files clean",
        scanned
    ))
}

pub fn verify_fixture_integrity(
    fixtures: &MaterializedFixtures,
) -> Result<FixtureVerificationReport> {
    let manifest_path = fixtures.root.join("fixture_manifest.json");
    let manifest: FixtureManifest = serde_json::from_slice(
        &std::fs::read(&manifest_path).with_context(|| "missing fixture_manifest.json")?,
    )?;

    let mut details = Vec::new();
    let mut verified_files = 0usize;
    for (rel, expected) in &manifest.files {
        let full = fixtures.root.join(rel);
        let data = std::fs::read(&full)
            .with_context(|| format!("missing materialized fixture {}", rel))?;
        ensure!(
            data.len() as u64 == expected.size_bytes,
            "size mismatch for {}: {} != {}",
            rel,
            data.len(),
            expected.size_bytes
        );
        let actual_sha = sha256_hex(&data);
        ensure!(
            actual_sha == expected.sha256,
            "sha256 mismatch for {}: {} != {}",
            rel,
            actual_sha,
            expected.sha256
        );
        verified_files += 1;
    }

    let (c1, d1) = evtx::verify_evtx_dir(&fixtures.evtx_dir)?;
    let (c2, d2) = hive::verify_hive_dir(&fixtures.hive_dir)?;
    let (c3, d3) = srum::verify_srum_dir(&fixtures.srum_dir)?;
    let (c4, d4) = artifacts::verify_artifacts_dir(&fixtures.artifacts_dir)?;
    let (c5, d5) = crash_posture::verify_crash_dir(&fixtures.crash_dir)?;
    let (c6, d6) = browser::verify_browser_dir(&fixtures.browser_dir)?;
    let (c7, d7) = mail_wpd::verify_mail_and_wpd_dirs(&fixtures.mail_dir, &fixtures.wpd_dir)?;
    let (c8, d8) = winctl::verify_winctl_dir(&fixtures.winctl_dir)?;
    let (c9, d9) = net::verify_net_dir(&fixtures.net_dir)?;
    let (c10, d10) = sys_fs::verify_sys_fs_dir(&fixtures.sys_fs_dir)?;
    let (c11, d11) = corrupt::verify_corrupt_dir(&fixtures.corrupt_dir)?;
    let domain_sum = c1 + c2 + c3 + c4 + c5 + c6 + c7 + c8 + c9 + c10 + c11;
    ensure!(
        domain_sum == manifest.total_files,
        "domain verifier file count {} != manifest.total_files {}",
        domain_sum,
        manifest.total_files
    );
    let mut disk_file_count = 0usize;
    for entry in WalkDir::new(&fixtures.root) {
        let entry = entry?;
        if entry.file_type().is_file() {
            disk_file_count += 1;
        }
    }
    ensure!(
        disk_file_count == manifest.total_files + 1,
        "disk file count {} != {} (manifest.total_files + 1); stray or missing file detected",
        disk_file_count,
        manifest.total_files + 1
    );
    let r4_msg = verify_r4_zero_credentials(fixtures)?;

    for d in [d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11] {
        details.extend(d);
    }
    details.push(r4_msg);

    Ok(FixtureVerificationReport {
        total_files: manifest.total_files,
        verified_files,
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sha1_rfc3174_nist_vector() {
        assert_eq!(
            hex::encode(util::sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(util::sha1_digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_lz4_block_and_mozlz4_roundtrip() {
        let sample = br#"{"windows":[{"tabs":[{"entries":[{"url":"https://example.org/docs","title":"Example Docs"}]}]}]}"#;
        let compressed = lz4_block::encode_mozlz4(sample);
        assert!(compressed.starts_with(b"mozLz40\0"));
        let decoded = lz4_block::decode_mozlz4(&compressed).unwrap();
        assert_eq!(decoded, sample);
    }

    #[test]
    fn test_ms_xca_huffman_roundtrip_all_byte_values() {
        let mut payload: Vec<u8> = (0u8..=255).collect();
        payload.extend_from_slice(b"SCCA_V30_TEST_PAYLOAD_255_\xff\xff\x00");
        let encoded = artifacts::encode_ms_xca_huffman(&payload).unwrap();
        assert!(encoded.starts_with(b"MAM\x04"));
        let decoded = artifacts::decode_ms_xca_huffman(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_materialize_all_and_verify_integrity() {
        let dir = TempDir::new().unwrap();
        let fixtures = materialize_all(dir.path()).unwrap();
        let report = verify_fixture_integrity(&fixtures).unwrap();
        assert!(report.all_verified());
        assert!(
            report.total_files >= 60,
            "expected >= 60 files, got {}",
            report.total_files
        );
        assert_eq!(report.verified_files, report.total_files);
    }

    #[test]
    fn test_materialize_determinism_across_tempdirs() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let _fa = materialize_all(dir_a.path()).unwrap();
        let _fb = materialize_all(dir_b.path()).unwrap();

        let man_a = std::fs::read(dir_a.path().join("fixture_manifest.json")).unwrap();
        let man_b = std::fs::read(dir_b.path().join("fixture_manifest.json")).unwrap();
        assert_eq!(
            man_a, man_b,
            "fixture_manifest.json must be byte-identical across runs"
        );
    }

    #[test]
    fn test_materialize_idempotent_on_existing_dir() {
        let dir = TempDir::new().unwrap();
        let f1 = materialize_all(dir.path()).unwrap();
        let f2 = materialize_all(dir.path()).unwrap();
        let r = verify_fixture_integrity(&f2).unwrap();
        assert!(r.all_verified());
        assert_eq!(f1.root, f2.root);
    }

    #[test]
    fn test_verify_integrity_detects_tampering() {
        let dir = TempDir::new().unwrap();
        let fixtures = materialize_all(dir.path()).unwrap();
        let edid_path = fixtures.winctl_dir.join("monitor_edid.bin");
        let mut bytes = std::fs::read(&edid_path).unwrap();
        bytes[10] ^= 0xFF;
        std::fs::write(&edid_path, bytes).unwrap();
        assert!(verify_fixture_integrity(&fixtures).is_err());
    }

    #[test]
    fn test_verify_integrity_rejects_stray_file() {
        let dir = TempDir::new().unwrap();
        let fixtures = materialize_all(dir.path()).unwrap();
        std::fs::write(fixtures.root.join("stray_extra.txt"), b"unexpected").unwrap();
        assert!(verify_fixture_integrity(&fixtures).is_err());
    }

    #[test]
    fn test_r4_zero_credentials_detects_utf16le_violation() {
        let dir = TempDir::new().unwrap();
        let fixtures = materialize_all(dir.path()).unwrap();
        let utf16_secret = util::utf16le_bytes("Authorization: Bearer leaked_token");
        std::fs::write(fixtures.sys_fs_dir.join("sample_page.html"), &utf16_secret).unwrap();
        assert!(verify_r4_zero_credentials(&fixtures).is_err());
    }
}
