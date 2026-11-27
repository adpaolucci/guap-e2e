use crate::util::{
    FIXED_FILETIME, read_u16_le, read_u32_le, utf16le_bytes, utf16le_nul, write_file_deterministic,
};
use anyhow::{Result, ensure};
use std::path::Path;

fn build_nk2() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x0D0A_04BAu32.to_le_bytes());
    out.extend_from_slice(&10u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes()); // row_count = 2

    let push_unicode_prop = |dst: &mut Vec<u8>, tag: u32, val: &str| {
        dst.extend_from_slice(&tag.to_le_bytes());
        dst.extend_from_slice(&0u32.to_le_bytes());
        dst.extend_from_slice(&0u64.to_le_bytes());
        let raw = utf16le_nul(val);
        dst.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        dst.extend_from_slice(&raw);
    };
    let push_long_prop = |dst: &mut Vec<u8>, tag: u32, val: u32| {
        dst.extend_from_slice(&tag.to_le_bytes());
        dst.extend_from_slice(&0u32.to_le_bytes());
        dst.extend_from_slice(&val.to_le_bytes());
        dst.extend_from_slice(&0u32.to_le_bytes());
    };

    for (nick, name, email, weight) in [
        (
            "Alice Vance",
            "Alice Vance",
            "alice.vance@example.org",
            500u32,
        ),
        ("Bob Chen", "Bob Chen", "bob.chen@example.org", 250u32),
    ] {
        out.extend_from_slice(&7u32.to_le_bytes()); // prop_count = 7
        push_unicode_prop(&mut out, 0x6001_001F, nick);
        push_unicode_prop(&mut out, 0x3001_001F, name);
        push_unicode_prop(&mut out, 0x3002_001F, "SMTP");
        push_unicode_prop(&mut out, 0x3003_001F, email);
        push_long_prop(&mut out, 0x0C15_0003, 1);
        push_long_prop(&mut out, 0x6002_0003, weight);
        // PR_ENTRYID (0x0FFF0102)
        out.extend_from_slice(&0x0FFF_0102u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        let entry_id: [u8; 24] = [
            0, 0, 0, 0, 0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD,
            0x01, 0x0F, 0x54, 0x02, 0, 0, 0, 1,
        ];
        out.extend_from_slice(&(entry_id.len() as u32).to_le_bytes());
        out.extend_from_slice(&entry_id);
    }

    out.extend_from_slice(&FIXED_FILETIME.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

#[allow(clippy::too_many_arguments)]
fn msg_dir_entry(
    name: &str,
    obj_type: u8,
    color: u8,
    left: u32,
    right: u32,
    child: u32,
    start_sector: u32,
    stream_size: u64,
) -> [u8; 128] {
    let mut e = [0u8; 128];
    if obj_type != 0 {
        let u16s = utf16le_nul(name);
        let len = u16s.len().min(64);
        e[0..len].copy_from_slice(&u16s[..len]);
        e[0x40..0x42].copy_from_slice(&(len as u16).to_le_bytes());
    }
    e[0x42] = obj_type;
    e[0x43] = color;
    e[0x44..0x48].copy_from_slice(&left.to_le_bytes());
    e[0x48..0x4C].copy_from_slice(&right.to_le_bytes());
    e[0x4C..0x50].copy_from_slice(&child.to_le_bytes());
    e[0x74..0x78].copy_from_slice(&start_sector.to_le_bytes());
    e[0x78..0x80].copy_from_slice(&stream_size.to_le_bytes());
    e
}

fn build_msg_cfb() -> Vec<u8> {
    let mut hdr = vec![0u8; 512];
    hdr[0x00..0x08].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    hdr[0x18..0x1A].copy_from_slice(&0x003Eu16.to_le_bytes());
    hdr[0x1A..0x1C].copy_from_slice(&0x0003u16.to_le_bytes());
    hdr[0x1C..0x1E].copy_from_slice(&0xFFFEu16.to_le_bytes());
    hdr[0x1E..0x20].copy_from_slice(&0x0009u16.to_le_bytes());
    hdr[0x20..0x22].copy_from_slice(&0x0006u16.to_le_bytes());
    hdr[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // NumFATSectors
    hdr[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // FirstDirSector
    hdr[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes());
    hdr[0x3C..0x40].copy_from_slice(&4u32.to_le_bytes()); // FirstMiniFAT
    hdr[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // TotalMiniFAT
    hdr[0x44..0x48].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    hdr[0x4C..0x50].copy_from_slice(&0u32.to_le_bytes());
    for i in 1..109 {
        let off = 0x4C + i * 4;
        hdr[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }

    // Sector 0: FAT
    let mut fat = vec![0xFFu8; 512];
    let set_u32 = |buf: &mut [u8], idx: usize, val: u32| {
        buf[idx * 4..idx * 4 + 4].copy_from_slice(&val.to_le_bytes());
    };
    set_u32(&mut fat, 0, 0xFFFF_FFFD); // FATSECT
    set_u32(&mut fat, 1, 2);
    set_u32(&mut fat, 2, 3);
    set_u32(&mut fat, 3, 0xFFFF_FFFE); // Dir sectors 1..=3
    set_u32(&mut fat, 4, 0xFFFF_FFFE); // MiniFAT
    set_u32(&mut fat, 5, 6);
    set_u32(&mut fat, 6, 0xFFFF_FFFE); // MiniStream 5..=6

    let p0 = utf16le_bytes("Q4 Audit Report");
    let p1 = utf16le_bytes("Please review attached CSV.");
    let p2 = utf16le_bytes("alice@example.org");
    let p3 = utf16le_bytes("Alice Vance");
    let p4 = utf16le_bytes("<msg01@example.org>");
    let p5 = utf16le_bytes("audit_summary.txt");
    let p6 = b"GUAP Attachment Payload\n".to_vec();

    // Sectors 1..=3: Directory (12 x 128B slots, 9 used)
    // Valid [MS-CFB] §2.6.4 red-black tree ordered by (name_len, uppercase_utf16):
    // Root Entry (DID 0, child=3):
    //   1 (__substg1.0_0037001F) < 4 (__substg1.0_0C1A001F) < 3 (__substg1.0_0C1F001F)
    //   < 2 (__substg1.0_1000001F) < 5 (__substg1.0_1035001F) < 6 (__attach_version1.0_#00000000)
    // Attach (DID 6, child=7):
    //   8 (__substg1.0_37010102) < 7 (__substg1.0_3707001F)
    let no = 0xFFFF_FFFFu32;
    let mut dir = Vec::with_capacity(3 * 512);
    dir.extend_from_slice(&msg_dir_entry("Root Entry", 5, 1, no, no, 3, 5, 1024));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_0037001F",
        2,
        0,
        no,
        no,
        no,
        0,
        p0.len() as u64,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_1000001F",
        2,
        0,
        no,
        no,
        no,
        1,
        p1.len() as u64,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_0C1F001F",
        2,
        1,
        4,
        5,
        no,
        2,
        p2.len() as u64,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_0C1A001F",
        2,
        1,
        1,
        no,
        no,
        3,
        p3.len() as u64,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_1035001F",
        2,
        1,
        2,
        6,
        no,
        4,
        p4.len() as u64,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__attach_version1.0_#00000000",
        1,
        0,
        no,
        no,
        7,
        0,
        0,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_3707001F",
        2,
        1,
        8,
        no,
        no,
        5,
        p5.len() as u64,
    ));
    dir.extend_from_slice(&msg_dir_entry(
        "__substg1.0_37010102",
        2,
        0,
        no,
        no,
        no,
        6,
        p6.len() as u64,
    ));
    for _ in 9..12 {
        dir.extend_from_slice(&msg_dir_entry("", 0, 0, no, no, no, 0, 0));
    }

    // Sector 4: MiniFAT
    let mut minifat = vec![0xFFu8; 512];
    for i in 0..=6 {
        set_u32(&mut minifat, i, 0xFFFF_FFFE);
    }

    // Sectors 5..=6: MiniStream (1024B = 16 x 64B mini-sectors)
    let mut ministream = vec![0u8; 1024];
    for (idx, payload) in [&p0, &p1, &p2, &p3, &p4, &p5, &p6].iter().enumerate() {
        ministream[idx * 64..idx * 64 + payload.len()].copy_from_slice(payload);
    }

    let mut out = Vec::with_capacity(512 * 8);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&fat);
    out.extend_from_slice(&dir);
    out.extend_from_slice(&minifat);
    out.extend_from_slice(&ministream);
    out
}

pub fn generate_mail_and_wpd_dirs(mail_dir: &Path, wpd_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(mail_dir)?;
    std::fs::create_dir_all(wpd_dir)?;

    write_file_deterministic(&mail_dir.join("outlook.NK2"), &build_nk2())?;
    write_file_deterministic(&mail_dir.join("sample_attachment.msg"), &build_msg_cfb())?;

    let eml = "\
From: Alice Vance <alice@example.org>\r\n\
To: Bob Chen <bob@example.org>\r\n\
Subject: Q4 Audit Attachment\r\n\
Date: Sun, 22 Nov 2026 14:30:00 +0000\r\n\
Message-ID: <eml01@example.org>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"GUAP-BOUNDARY-01\"\r\n\
\r\n\
--GUAP-BOUNDARY-01\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
See attached audit_summary.txt.\r\n\
--GUAP-BOUNDARY-01\r\n\
Content-Type: text/plain; name=\"audit_summary.txt\"\r\n\
Content-Disposition: attachment; filename=\"audit_summary.txt\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
R1VBUCBBdHRhY2htZW50IFBheWxvYWQK\r\n\
--GUAP-BOUNDARY-01--\r\n";
    write_file_deterministic(&mail_dir.join("sample_attachment.eml"), eml.as_bytes())?;

    let wpd_json = serde_json::json!({
        "schema_version": 1,
        "devices": [{
            "device_id": "\\\\?\\usb#vid_18d1&pid_4ee1#guap0001#{6ac27878-a6fa-4155-ba85-f98f491d4f33}",
            "device_name": "Pixel 9 Test Device",
            "manufacturer": "Google",
            "serial_number": "GUAP0001",
            "storages": [{
                "object_id": "s10001",
                "storage_name": "Internal shared storage",
                "capacity_bytes": 128000000000u64,
                "free_bytes": 64000000000u64,
                "objects": [
                    {
                        "object_id": "o1001",
                        "parent_id": "s10001",
                        "full_path": "/Internal shared storage/DCIM/Camera/IMG_20261122_143000.jpg",
                        "filename": "IMG_20261122_143000.jpg",
                        "extension": "jpg",
                        "size_bytes": 245760u64,
                        "created_time": "2026-11-22T14:30:00Z",
                        "modified_time": "2026-11-22T14:30:00Z",
                        "content_type": "WPD_CONTENT_TYPE_IMAGE",
                        "is_folder": false
                    },
                    {
                        "object_id": "o1002",
                        "parent_id": "s10001",
                        "full_path": "/Internal shared storage/Download/report_2026.pdf",
                        "filename": "report_2026.pdf",
                        "extension": "pdf",
                        "size_bytes": 102400u64,
                        "created_time": "2026-11-22T13:00:00Z",
                        "modified_time": "2026-11-22T13:05:00Z",
                        "content_type": "WPD_CONTENT_TYPE_DOCUMENT",
                        "is_folder": false
                    }
                ]
            }]
        }]
    });
    write_file_deterministic(
        &wpd_dir.join("wpd_device_tree.json"),
        serde_json::to_string_pretty(&wpd_json)?.as_bytes(),
    )?;

    Ok(())
}

pub fn verify_mail_and_wpd_dirs(mail_dir: &Path, wpd_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    let nk2 = std::fs::read(mail_dir.join("outlook.NK2"))?;
    ensure!(read_u32_le(&nk2, 0)? == 0x0D0A_04BA, "bad NK2 magic");
    ensure!(read_u32_le(&nk2, 12)? == 2, "bad NK2 row count");
    details.push("mail/outlook.NK2: 0x0D0A04BA 2 rows verified".into());

    let msg = std::fs::read(mail_dir.join("sample_attachment.msg"))?;
    ensure!(
        msg[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "bad .msg CFBF magic"
    );
    ensure!(
        read_u16_le(&msg, 0x1E)? == 9 && read_u32_le(&msg, 512)? == 0xFFFF_FFFD,
        "bad .msg FAT"
    );
    verify_cfb_dir_rb_tree(&msg)?;
    details.push("mail/sample_attachment.msg: MS-CFB + MiniStream + RB-tree verified".into());

    let eml = std::fs::read_to_string(mail_dir.join("sample_attachment.eml"))?;
    ensure!(
        eml.contains("GUAP-BOUNDARY-01") && eml.contains("R1VBUCBBdHRhY2htZW50IFBheWxvYWQK"),
        "bad .eml"
    );
    details.push("mail/sample_attachment.eml: MIME verified".into());

    let wpd: serde_json::Value =
        serde_json::from_slice(&std::fs::read(wpd_dir.join("wpd_device_tree.json"))?)?;
    ensure!(
        wpd["devices"][0]["storages"][0]["objects"]
            .as_array()
            .map(|a| a.len())
            == Some(2),
        "bad wpd_device_tree.json"
    );
    details.push("wpd/wpd_device_tree.json: 2 objects verified".into());

    Ok((4, details))
}
#[derive(Clone)]
struct CfbDirEntry {
    name_upper: Vec<u16>,
    obj_type: u8,
    color: u8,
    left: u32,
    right: u32,
    child: u32,
}

fn cfb_name_cmp(a: &[u16], b: &[u16]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn validate_rb_subtree(
    entries: &[CfbDirEntry],
    did: u32,
    min_bound: Option<&[u16]>,
    max_bound: Option<&[u16]>,
    parent_red: bool,
    visited: &mut std::collections::BTreeSet<u32>,
) -> Result<usize> {
    const NOSTREAM: u32 = 0xFFFF_FFFF;
    if did == NOSTREAM {
        return Ok(1);
    }
    ensure!(
        (did as usize) < entries.len(),
        "CFB DID {} out of range",
        did
    );
    ensure!(
        visited.insert(did),
        "CFB directory cycle or shared node at DID {}",
        did
    );
    let node = &entries[did as usize];
    ensure!(
        matches!(node.obj_type, 1 | 2 | 5),
        "CFB DID {} invalid obj_type {}",
        did,
        node.obj_type
    );
    ensure!(
        node.color <= 1,
        "CFB DID {} invalid color {}",
        did,
        node.color
    );
    let is_red = node.color == 0;
    ensure!(
        !(parent_red && is_red),
        "CFB RB violation: red child DID {} under red parent",
        did
    );

    if let Some(lo) = min_bound {
        ensure!(
            cfb_name_cmp(&node.name_upper, lo) == std::cmp::Ordering::Greater,
            "CFB BST violation at DID {}: not > lower bound",
            did
        );
    }
    if let Some(hi) = max_bound {
        ensure!(
            cfb_name_cmp(&node.name_upper, hi) == std::cmp::Ordering::Less,
            "CFB BST violation at DID {}: not < upper bound",
            did
        );
    }

    let left_bh = validate_rb_subtree(
        entries,
        node.left,
        min_bound,
        Some(&node.name_upper),
        is_red,
        visited,
    )?;
    let right_bh = validate_rb_subtree(
        entries,
        node.right,
        Some(&node.name_upper),
        max_bound,
        is_red,
        visited,
    )?;
    ensure!(
        left_bh == right_bh,
        "CFB RB black-height mismatch at DID {}: {} != {}",
        did,
        left_bh,
        right_bh
    );

    if node.obj_type == 1 && node.child != NOSTREAM {
        ensure!(
            (node.child as usize) < entries.len(),
            "CFB storage DID {} child out of range",
            did
        );
        ensure!(
            entries[node.child as usize].color == 1,
            "CFB storage DID {} child root must be black",
            did
        );
        validate_rb_subtree(entries, node.child, None, None, false, visited)?;
    }

    Ok(left_bh + if is_red { 0 } else { 1 })
}

fn verify_cfb_dir_rb_tree(cfb: &[u8]) -> Result<()> {
    const NOSTREAM: u32 = 0xFFFF_FFFF;
    let fat_sector = read_u32_le(cfb, 0x4C)? as usize;
    let first_dir = read_u32_le(cfb, 0x30)?;
    let fat_off = (fat_sector + 1) * 512;
    ensure!(fat_off + 512 <= cfb.len(), "CFB FAT out of bounds");

    let mut entries = Vec::new();
    let mut sec = first_dir;
    let mut seen_secs = std::collections::BTreeSet::new();
    while sec != 0xFFFF_FFFE && sec != NOSTREAM {
        ensure!(
            seen_secs.insert(sec),
            "CFB directory sector cycle at {}",
            sec
        );
        let off = (sec as usize + 1) * 512;
        ensure!(
            off + 512 <= cfb.len(),
            "CFB dir sector {} out of bounds",
            sec
        );
        for slot in 0..4 {
            let e = &cfb[off + slot * 128..off + (slot + 1) * 128];
            let cb_name = read_u16_le(e, 0x40)? as usize;
            let obj_type = e[0x42];
            let color = e[0x43];
            let left = read_u32_le(e, 0x44)?;
            let right = read_u32_le(e, 0x48)?;
            let child = read_u32_le(e, 0x4C)?;
            let mut name_upper = Vec::new();
            if obj_type != 0 && cb_name >= 2 {
                let char_bytes = (cb_name - 2).min(62);
                for &chunk in e[0..char_bytes].as_chunks::<2>().0 {
                    let cu = u16::from_le_bytes([chunk[0], chunk[1]]);
                    let ch = char::from_u32(cu as u32).unwrap_or('\u{FFFD}');
                    for uc in ch.to_uppercase() {
                        let mut buf = [0u16; 2];
                        name_upper.extend_from_slice(uc.encode_utf16(&mut buf));
                    }
                }
            }
            entries.push(CfbDirEntry {
                name_upper,
                obj_type,
                color,
                left,
                right,
                child,
            });
        }
        sec = read_u32_le(cfb, fat_off + (sec as usize) * 4)?;
    }

    ensure!(
        !entries.is_empty() && entries[0].obj_type == 5,
        "CFB missing Root Entry"
    );
    ensure!(entries[0].color == 1, "CFB Root Entry must be black");
    let mut visited = std::collections::BTreeSet::new();
    visited.insert(0);
    if entries[0].child != NOSTREAM {
        ensure!(
            entries[entries[0].child as usize].color == 1,
            "CFB root child must be black"
        );
        validate_rb_subtree(&entries, entries[0].child, None, None, false, &mut visited)?;
    }
    let expected_used = entries.iter().filter(|e| e.obj_type != 0).count();
    ensure!(
        visited.len() == expected_used,
        "CFB directory unreachable entries: visited {} != used {}",
        visited.len(),
        expected_used
    );
    Ok(())
}
