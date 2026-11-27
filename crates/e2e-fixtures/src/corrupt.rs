use crate::lz4_block::decode_mozlz4;
use crate::net::build_ethernet_pcap;
use crate::sys_fs::{build_ata_smart, build_sample_pe64_dotnet_exe};
use crate::util::{read_u32_le, write_file_deterministic};
use crate::winctl::build_valid_edid_256;
use anyhow::{Result, ensure};
use rusqlite::Connection;
use std::path::Path;

pub fn generate_corrupt_dir(corrupt_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(corrupt_dir)?;

    let mut bad_sqlite = vec![0u8; 512];
    bad_sqlite[0..16].copy_from_slice(b"NOT_SQLITE_3\0\0\0\0");
    write_file_deterministic(&corrupt_dir.join("bad_magic.sqlite"), &bad_sqlite)?;

    let mut trunc_sqlite = vec![0u8; 100];
    trunc_sqlite[0..16].copy_from_slice(b"SQLite format 3\0");
    write_file_deterministic(&corrupt_dir.join("truncated.sqlite"), &trunc_sqlite)?;

    let mut bad_bplist = Vec::from(&b"bplist99"[..]);
    bad_bplist.extend_from_slice(&[0u8; 24]);
    bad_bplist.extend_from_slice(&0xFFFF_FFFFu64.to_be_bytes());
    write_file_deterministic(&corrupt_dir.join("bad_bplist.plist"), &bad_bplist)?;

    let mut bad_mozlz4 = Vec::from(&b"mozLz40\0"[..]);
    bad_mozlz4.extend_from_slice(&0x1000_0000u32.to_le_bytes());
    bad_mozlz4.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    write_file_deterministic(&corrupt_dir.join("bad_mozlz4.jsonlz4"), &bad_mozlz4)?;

    let valid_edid = build_valid_edid_256();
    let mut bad_edid = valid_edid[0..128].to_vec();
    bad_edid[127] ^= 0x01;
    write_file_deterministic(&corrupt_dir.join("bad_edid_checksum.bin"), &bad_edid)?;
    write_file_deterministic(&corrupt_dir.join("truncated_edid.bin"), &valid_edid[0..64])?;

    let mut bad_pcap = vec![0u8; 24];
    bad_pcap[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    write_file_deterministic(&corrupt_dir.join("bad_pcap_magic.pcap"), &bad_pcap)?;

    let valid_pcap = build_ethernet_pcap();
    write_file_deterministic(&corrupt_dir.join("truncated_pcap.pcap"), &valid_pcap[0..32])?;

    let mut bad_pe = vec![0u8; 128];
    bad_pe[0..2].copy_from_slice(b"MZ");
    bad_pe[0x3C..0x40].copy_from_slice(&0x0000_1000u32.to_le_bytes());
    write_file_deterministic(&corrupt_dir.join("bad_pe_magic.exe"), &bad_pe)?;

    let valid_pe64 = build_sample_pe64_dotnet_exe();
    write_file_deterministic(&corrupt_dir.join("truncated_pe.exe"), &valid_pe64[0..96])?;

    let mut bad_smart = build_ata_smart();
    bad_smart[511] ^= 0x55;
    write_file_deterministic(&corrupt_dir.join("bad_smart_checksum.bin"), &bad_smart)?;

    let mut trunc_usn = vec![0u8; 64];
    trunc_usn[0..4].copy_from_slice(&256u32.to_le_bytes());
    trunc_usn[4..6].copy_from_slice(&2u16.to_le_bytes());
    write_file_deterministic(&corrupt_dir.join("truncated_usn.bin"), &trunc_usn)?;

    let bad_exif = [
        0xFFu8, 0xD8, 0xFF, 0xE1, 0x00, 0x10, b'E', b'x', b'i', b'f', 0, 0, b'I', b'I', b'*', 0,
    ];
    write_file_deterministic(&corrupt_dir.join("bad_exif.jpg"), &bad_exif)?;

    let mut bad_nk2 = Vec::new();
    bad_nk2.extend_from_slice(&0xBAAD_F00Du32.to_le_bytes());
    bad_nk2.extend_from_slice(&9999u32.to_le_bytes());
    bad_nk2.extend_from_slice(&[0u8; 4]);
    write_file_deterministic(&corrupt_dir.join("bad_nk2.nk2"), &bad_nk2)?;

    Ok(())
}

pub fn verify_corrupt_dir(corrupt_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    // 1 & 2 SQLite errors
    for sname in ["bad_magic.sqlite", "truncated.sqlite"] {
        let conn = Connection::open(corrupt_dir.join(sname));
        let ok = conn
            .and_then(|c| c.query_row("SELECT name FROM sqlite_master", [], |_| Ok(())))
            .is_ok();
        ensure!(!ok, "{} unexpectedly succeeded as valid SQLite", sname);
    }

    // 3 bad bplist
    let bp = std::fs::read(corrupt_dir.join("bad_bplist.plist"))?;
    ensure!(!bp.starts_with(b"bplist00"), "bad_bplist had valid magic");

    // 4 bad mozlz4
    let mlz = std::fs::read(corrupt_dir.join("bad_mozlz4.jsonlz4"))?;
    ensure!(
        decode_mozlz4(&mlz).is_err(),
        "bad_mozlz4 unexpectedly decompressed"
    );

    // 5 & 6 EDID
    let ed1 = std::fs::read(corrupt_dir.join("bad_edid_checksum.bin"))?;
    let sum1: u32 = ed1.iter().map(|&x| x as u32).sum();
    ensure!(
        !sum1.is_multiple_of(256),
        "bad_edid_checksum unexpectedly valid"
    );
    let ed2 = std::fs::read(corrupt_dir.join("truncated_edid.bin"))?;
    ensure!(ed2.len() < 128, "truncated_edid not truncated");

    // 7 & 8 PCAP
    let pc1 = std::fs::read(corrupt_dir.join("bad_pcap_magic.pcap"))?;
    ensure!(
        read_u32_le(&pc1, 0)? != 0xA1B2_C3D4,
        "bad_pcap_magic had valid magic"
    );
    let pc2 = std::fs::read(corrupt_dir.join("truncated_pcap.pcap"))?;
    ensure!(pc2.len() < 24 + 16, "truncated_pcap not truncated");

    // 9 & 10 PE
    let pe1 = std::fs::read(corrupt_dir.join("bad_pe_magic.exe"))?;
    ensure!(
        read_u32_le(&pe1, 0x3C)? as usize >= pe1.len(),
        "bad_pe_magic in bounds"
    );
    let pe2 = std::fs::read(corrupt_dir.join("truncated_pe.exe"))?;
    ensure!(pe2.len() < 0x84, "truncated_pe not truncated");

    // 11 SMART
    let sm = std::fs::read(corrupt_dir.join("bad_smart_checksum.bin"))?;
    let ssum: u32 = sm.iter().map(|&x| x as u32).sum();
    ensure!(
        !ssum.is_multiple_of(256),
        "bad_smart_checksum unexpectedly valid"
    );

    // 12 USN
    let usn = std::fs::read(corrupt_dir.join("truncated_usn.bin"))?;
    ensure!(
        read_u32_le(&usn, 0)? as usize > usn.len(),
        "truncated_usn not truncated"
    );

    // 13 EXIF
    let ex = std::fs::read(corrupt_dir.join("bad_exif.jpg"))?;
    ensure!(
        ex.len() == 16 && !ex.ends_with(&[0xFF, 0xD9]),
        "bad_exif invalid"
    );

    // 14 NK2
    let nk2 = std::fs::read(corrupt_dir.join("bad_nk2.nk2"))?;
    ensure!(
        read_u32_le(&nk2, 0)? != 0x0D0A_04BA,
        "bad_nk2 had valid magic"
    );

    details.push("corrupt_dir: all 14 negative fixtures verified".into());
    Ok((14, details))
}
