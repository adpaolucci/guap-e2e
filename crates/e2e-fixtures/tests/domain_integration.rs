use e2e_fixtures::artifacts::decode_ms_xca_huffman;
use e2e_fixtures::lz4_block::decode_mozlz4;
use e2e_fixtures::util::rot13;
use e2e_fixtures::{materialize_all, verify_fixture_integrity};
use tempfile::TempDir;
use walkdir::WalkDir;

#[test]
fn test_all_domains_file_counts_and_byte_determinism() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let fa = materialize_all(dir_a.path()).unwrap();
    let fb = materialize_all(dir_b.path()).unwrap();

    let ra = verify_fixture_integrity(&fa).unwrap();
    let rb = verify_fixture_integrity(&fb).unwrap();
    assert!(ra.all_verified());
    assert!(rb.all_verified());
    assert_eq!(ra.total_files, rb.total_files);
    assert_eq!(
        ra.total_files, 79,
        "expected exact 79 materialized fixture files, got {}: {:?}",
        ra.total_files, ra.details
    );

    // Verify every single file is byte-for-byte identical across runs
    let mut files_a = Vec::new();
    for entry in WalkDir::new(dir_a.path()).sort_by_file_name() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(dir_a.path())
                .unwrap()
                .to_path_buf();
            files_a.push(rel);
        }
    }
    for rel in &files_a {
        let bytes_a = std::fs::read(dir_a.path().join(rel)).unwrap();
        let bytes_b = std::fs::read(dir_b.path().join(rel)).unwrap();
        assert_eq!(
            bytes_a,
            bytes_b,
            "non-deterministic file: {}",
            rel.display()
        );
    }
}

#[test]
fn test_domain_specific_semantic_contents() {
    let dir = TempDir::new().unwrap();
    let f = materialize_all(dir.path()).unwrap();

    // Domain 2: ROT13 UserAssist check
    assert_eq!(
        rot13(r"P:\Gbbyf\sberafvpf_fnzcyr.rkr"),
        r"C:\Tools\forensics_sample.exe"
    );
    let ntuser = std::fs::read(f.hive_dir.join("NTUSER.DAT")).unwrap();
    assert!(String::from_utf8_lossy(&ntuser).contains(r"P:\Gbbyf\sberafvpf_fnzcyr.rkr"));

    // Domain 4: XPRESS Huffman MAM\x04 decompresses to valid SCCA v30
    let mam = std::fs::read(f.artifacts_dir.join("DEMO_COMPRESSED-5678EF01.pf")).unwrap();
    let scca = decode_ms_xca_huffman(&mam).unwrap();
    assert_eq!(&scca[4..8], b"SCCA");
    assert_eq!(u32::from_le_bytes(scca[0..4].try_into().unwrap()), 30);

    // Domain 6: Firefox mozLz40 decompression & JSON parsing
    let sess = std::fs::read(
        f.browser_dir
            .join("firefox/profile_default/sessionstore.jsonlz4"),
    )
    .unwrap();
    let sess_json: serde_json::Value =
        serde_json::from_slice(&decode_mozlz4(&sess).unwrap()).unwrap();
    assert_eq!(
        sess_json["windows"][0]["tabs"][0]["entries"][0]["url"],
        "https://example.org/docs"
    );

    // Domain 7: EDID manufacturer GUP & model GUAP-27UHD
    let edid = std::fs::read(f.winctl_dir.join("monitor_edid.bin")).unwrap();
    assert_eq!(&edid[8..10], &[0x1E, 0xB0]);
    assert!(String::from_utf8_lossy(&edid).contains("GUAP-27UHD"));

    // Domain 8: PCAP HTTP without credentials
    let pcap = std::fs::read(f.net_dir.join("capture_ethernet.pcap")).unwrap();
    let pcap_str = String::from_utf8_lossy(&pcap);
    assert!(pcap_str.contains("Host: docs.example.org"));
    assert!(!pcap_str.contains("Authorization:"));

    // Domain 9: CSV formula payloads & PE32/PE32+
    let csv = std::fs::read_to_string(f.sys_fs_dir.join("sample_data.csv")).unwrap();
    assert!(csv.contains("=cmd|'/C calc'!A0"));
    let pe64 = std::fs::read(f.sys_fs_dir.join("sample_pe64_dotnet.exe")).unwrap();
    assert!(pe64.windows(4).any(|w| w == b"BSJB"));

    // Corrupt dir: 14 negative fixtures present
    let corrupt_count = std::fs::read_dir(&f.corrupt_dir).unwrap().count();
    assert_eq!(corrupt_count, 14);
}
