use crate::util::{
    FIXED_FILETIME, read_u16_le, read_u32_le, utf16le_bytes, utf16le_nul, write_file_deterministic,
};
use anyhow::{Result, ensure};
use std::path::Path;

pub fn encode_ms_xca_huffman(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        raw.len() <= 65536,
        "single-chunk XPRESS Huffman input > 64 KiB"
    );
    let mut out = Vec::with_capacity(8 + 256 + raw.len() + 16);
    out.extend_from_slice(b"MAM\x04");
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());

    // 256-byte canonical Huffman code-length nibble table (512 symbols)
    // Symbols 0..=254 -> len 8; 255 -> len 9; 256 (EOF) -> len 9; 257..=511 -> len 0
    let mut lengths = [0u8; 512];
    for len in lengths.iter_mut().take(255) {
        *len = 8;
    }
    lengths[255] = 9;
    lengths[256] = 9;
    for pair in lengths.as_chunks::<2>().0 {
        out.push((pair[0] & 0x0F) | ((pair[1] & 0x0F) << 4));
    }

    let mut bitstream = Vec::new();
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;
    let push_bits = |val: u32, nbits: u32, accum: &mut u32, bits: &mut u32, bs: &mut Vec<u8>| {
        *accum = (*accum << nbits) | val;
        *bits += nbits;
        while *bits >= 16 {
            let shift = *bits - 16;
            let word = ((*accum >> shift) & 0xFFFF) as u16;
            bs.extend_from_slice(&word.to_le_bytes());
            *bits -= 16;
            *accum &= (1u32 << *bits) - 1;
        }
    };

    for &b in raw {
        if b <= 254 {
            push_bits(b as u32, 8, &mut accum, &mut bits, &mut bitstream);
        } else {
            push_bits(0x1FE, 9, &mut accum, &mut bits, &mut bitstream);
        }
    }
    // EOF symbol 256
    push_bits(0x1FF, 9, &mut accum, &mut bits, &mut bitstream);
    if bits > 0 {
        let word = ((accum << (16 - bits)) & 0xFFFF) as u16;
        bitstream.extend_from_slice(&word.to_le_bytes());
    }
    while bitstream.len() < 4 {
        bitstream.extend_from_slice(&[0x00, 0x00]);
    }
    out.extend_from_slice(&bitstream);
    Ok(out)
}

pub fn decode_ms_xca_huffman(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(data.len() >= 8 + 256 + 4, "MAM payload too short");
    ensure!(&data[0..4] == b"MAM\x04", "bad MAM\\x04 magic");
    let uncomp_len = read_u32_le(data, 4)? as usize;
    ensure!(
        uncomp_len <= 65536,
        "unexpected uncompressed size {}",
        uncomp_len
    );

    let mut lengths = [0u8; 512];
    for (i, &byte) in data[8..264].iter().enumerate() {
        lengths[i * 2] = byte & 0x0F;
        lengths[i * 2 + 1] = (byte >> 4) & 0x0F;
    }

    // Verify Kraft inequality == 1.0 (scaled by 2^15)
    let mut kraft: u32 = 0;
    for &l in &lengths {
        if l > 0 {
            ensure!(l <= 15, "invalid Huffman length {}", l);
            kraft += 1u32 << (15 - l as u32);
        }
    }
    ensure!(
        kraft == (1u32 << 15),
        "Huffman table Kraft sum mismatch: {}",
        kraft
    );

    // Build canonical code lookup (code, len, sym)
    let mut codes = Vec::new();
    let mut next_code = 0u32;
    for bits in 1u8..=15 {
        next_code <<= 1;
        for (sym, &l) in lengths.iter().enumerate() {
            if l == bits {
                codes.push((next_code, bits, sym as u16));
                next_code += 1;
            }
        }
    }

    let bs = &data[264..];
    let mut bs_off = 0usize;
    let mut accum: u32 = 0;
    let mut avail: u32 = 0;
    let mut out = Vec::with_capacity(uncomp_len);

    loop {
        while avail < 16 && bs_off + 1 < bs.len() {
            let word = u16::from_le_bytes([bs[bs_off], bs[bs_off + 1]]) as u32;
            bs_off += 2;
            accum = (accum << 16) | word;
            avail += 16;
        }
        ensure!(avail > 0, "unexpected EOF in XPRESS Huffman bitstream");

        let mut matched = None;
        for &(code, len, sym) in &codes {
            if avail >= len as u32 {
                let top = (accum >> (avail - len as u32)) & ((1u32 << len) - 1);
                if top == code {
                    matched = Some((len as u32, sym));
                    break;
                }
            }
        }
        let (len, sym) = matched.ok_or_else(|| anyhow::anyhow!("invalid Huffman prefix"))?;
        avail -= len;
        accum &= (1u32 << avail) - 1;

        if sym == 256 {
            break;
        }
        ensure!(
            sym < 256,
            "unexpected LZ77 match symbol {} in literal stream",
            sym
        );
        out.push(sym as u8);
        ensure!(
            out.len() <= uncomp_len,
            "decompressed output exceeded {}",
            uncomp_len
        );
    }

    ensure!(
        out.len() == uncomp_len,
        "decompressed {} != {}",
        out.len(),
        uncomp_len
    );
    Ok(out)
}

fn build_scca_v30_prefetch(exe_name: &str, hash: u32, run_count: u32) -> Vec<u8> {
    let mut header = vec![0u8; 84];
    header[0x00..0x04].copy_from_slice(&30u32.to_le_bytes());
    header[0x04..0x08].copy_from_slice(b"SCCA");
    header[0x08..0x0C].copy_from_slice(&0x11u32.to_le_bytes());
    let exe_u16 = utf16le_nul(exe_name);
    let copy_len = exe_u16.len().min(60);
    header[0x10..0x10 + copy_len].copy_from_slice(&exe_u16[..copy_len]);
    header[0x4C..0x50].copy_from_slice(&hash.to_le_bytes());

    let mut sec_c = Vec::new();
    let s1 =
        utf16le_nul(r"\VOLUME{01D90001-0000-0000-0000-000000000001}\WINDOWS\SYSTEM32\NTDLL.DLL");
    let s2_off = s1.len() as u32;
    let s2 = utf16le_nul(&format!(
        r"\VOLUME{{01D90001-0000-0000-0000-000000000001}}\TOOLS\{}",
        exe_name
    ));
    sec_c.extend_from_slice(&s1);
    sec_c.extend_from_slice(&s2);

    let sec_a_off = 0x130u32;
    let num_metrics = 2u32;
    let sec_b_off = sec_a_off + num_metrics * 32;
    let num_traces = 2u32;
    let sec_c_off = sec_b_off + num_traces * 8;
    let sec_c_sz = sec_c.len() as u32;
    let sec_d_off = sec_c_off + sec_c_sz;

    let vol_dev = utf16le_nul(r"\VOLUME{01D90001-0000-0000-0000-000000000001}");
    let dir_str = r"\VOLUME{01D90001-0000-0000-0000-000000000001}\TOOLS";
    let dir_chars = dir_str.encode_utf16().count() as u16;
    let mut sec_d = vec![0u8; 96];
    sec_d[0x00..0x04].copy_from_slice(&96u32.to_le_bytes());
    sec_d[0x04..0x08].copy_from_slice(&((vol_dev.len() / 2 - 1) as u32).to_le_bytes());
    sec_d[0x08..0x10].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    sec_d[0x10..0x14].copy_from_slice(&0xABCD_1234u32.to_le_bytes());
    let dir_off = (96 + vol_dev.len()) as u32;
    sec_d[0x1C..0x20].copy_from_slice(&dir_off.to_le_bytes());
    sec_d[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    sec_d.extend_from_slice(&vol_dev);
    sec_d.extend_from_slice(&dir_chars.to_le_bytes());
    sec_d.extend_from_slice(&utf16le_nul(dir_str));
    let sec_d_sz = sec_d.len() as u32;

    let mut file_info = vec![0u8; 220];
    file_info[0x00..0x04].copy_from_slice(&sec_a_off.to_le_bytes());
    file_info[0x04..0x08].copy_from_slice(&num_metrics.to_le_bytes());
    file_info[0x08..0x0C].copy_from_slice(&sec_b_off.to_le_bytes());
    file_info[0x0C..0x10].copy_from_slice(&num_traces.to_le_bytes());
    file_info[0x10..0x14].copy_from_slice(&sec_c_off.to_le_bytes());
    file_info[0x14..0x18].copy_from_slice(&sec_c_sz.to_le_bytes());
    file_info[0x18..0x1C].copy_from_slice(&sec_d_off.to_le_bytes());
    file_info[0x1C..0x20].copy_from_slice(&1u32.to_le_bytes());
    file_info[0x20..0x24].copy_from_slice(&sec_d_sz.to_le_bytes());
    // last_run_times at 0x80 relative to file -> 0x80 - 0x54 = 0x2C
    file_info[0x2C..0x34].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    // run_count at 0xD0 relative to file -> 0xD0 - 0x54 = 0x7C
    file_info[0x7C..0x80].copy_from_slice(&run_count.to_le_bytes());

    let mut sec_a = vec![0u8; 64];
    // entry 0
    sec_a[0x00..0x04].copy_from_slice(&0u32.to_le_bytes());
    sec_a[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
    sec_a[0x08..0x0C].copy_from_slice(&4u32.to_le_bytes());
    sec_a[0x0C..0x10].copy_from_slice(&0u32.to_le_bytes());
    sec_a[0x10..0x14].copy_from_slice(&((s1.len() / 2 - 1) as u32).to_le_bytes());
    sec_a[0x14..0x18].copy_from_slice(&0x002u32.to_le_bytes());
    sec_a[0x18..0x20].copy_from_slice(&100u64.to_le_bytes());
    // entry 1
    sec_a[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    sec_a[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
    sec_a[0x28..0x2C].copy_from_slice(&8u32.to_le_bytes());
    sec_a[0x2C..0x30].copy_from_slice(&s2_off.to_le_bytes());
    sec_a[0x30..0x34].copy_from_slice(&((s2.len() / 2 - 1) as u32).to_le_bytes());
    sec_a[0x34..0x38].copy_from_slice(&0x200u32.to_le_bytes());
    sec_a[0x38..0x40].copy_from_slice(&101u64.to_le_bytes());

    let mut sec_b = vec![0u8; 16];
    sec_b[0x00..0x04].copy_from_slice(&4u32.to_le_bytes());
    sec_b[0x08..0x0C].copy_from_slice(&8u32.to_le_bytes());

    let total_sz = (84 + 220 + sec_a.len() + sec_b.len() + sec_c.len() + sec_d.len()) as u32;
    header[0x0C..0x10].copy_from_slice(&total_sz.to_le_bytes());

    let mut out = Vec::with_capacity(total_sz as usize);
    out.extend_from_slice(&header);
    out.extend_from_slice(&file_info);
    out.extend_from_slice(&sec_a);
    out.extend_from_slice(&sec_b);
    out.extend_from_slice(&sec_c);
    out.extend_from_slice(&sec_d);
    out
}

fn shllink_string_data(s: &str) -> Vec<u8> {
    let chars: Vec<u16> = s.encode_utf16().collect();
    let mut out = Vec::with_capacity(2 + chars.len() * 2);
    out.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for cu in chars {
        out.extend_from_slice(&cu.to_le_bytes());
    }
    out
}

pub fn build_sample_lnk(target: &str, args: &str) -> Vec<u8> {
    let mut hdr = vec![0u8; 76];
    hdr[0x00..0x04].copy_from_slice(&0x0000_004Cu32.to_le_bytes());
    hdr[0x04..0x14].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    hdr[0x14..0x18].copy_from_slice(&0x0000_00FFu32.to_le_bytes());
    hdr[0x18..0x1C].copy_from_slice(&0x0000_0020u32.to_le_bytes());
    hdr[0x1C..0x24].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    hdr[0x24..0x2C].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    hdr[0x2C..0x34].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    hdr[0x34..0x38].copy_from_slice(&4096u32.to_le_bytes());
    hdr[0x3C..0x40].copy_from_slice(&1u32.to_le_bytes());
    hdr[0x40..0x42].copy_from_slice(&0x0641u16.to_le_bytes()); // Ctrl+Alt+A

    let mut id_list_body = Vec::new();
    // 0x1F My Computer
    id_list_body.extend_from_slice(&20u16.to_le_bytes());
    id_list_body.push(0x1F);
    id_list_body.push(0x50);
    id_list_body.extend_from_slice(&[
        0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30,
        0x9D,
    ]);
    // 0x2F C:\
    let mut vol = vec![0u8; 25];
    vol[0..2].copy_from_slice(&25u16.to_le_bytes());
    vol[2] = 0x2F;
    vol[3..6].copy_from_slice(b"C:\\");
    id_list_body.extend_from_slice(&vol);
    id_list_body.extend_from_slice(&0u16.to_le_bytes()); // TerminalID

    let mut link_target_id_list = Vec::new();
    link_target_id_list.extend_from_slice(&(id_list_body.len() as u16).to_le_bytes());
    link_target_id_list.extend_from_slice(&id_list_body);

    // LinkInfo
    let vol_label = b"SYSTEM\0";
    let vol_id_len = 16 + vol_label.len();
    let mut vol_id = Vec::with_capacity(vol_id_len);
    vol_id.extend_from_slice(&(vol_id_len as u32).to_le_bytes());
    vol_id.extend_from_slice(&3u32.to_le_bytes()); // DRIVE_FIXED
    vol_id.extend_from_slice(&0xABCD_1234u32.to_le_bytes());
    vol_id.extend_from_slice(&16u32.to_le_bytes());
    vol_id.extend_from_slice(vol_label);

    let mut local_base = target.as_bytes().to_vec();
    local_base.push(0);
    let common_suffix = b"\0";

    let vol_id_off = 0x1Cu32;
    let local_base_off = vol_id_off + vol_id.len() as u32;
    let common_suffix_off = local_base_off + local_base.len() as u32;
    let link_info_sz = common_suffix_off + common_suffix.len() as u32;

    let mut link_info = Vec::with_capacity(link_info_sz as usize);
    link_info.extend_from_slice(&link_info_sz.to_le_bytes());
    link_info.extend_from_slice(&0x1Cu32.to_le_bytes());
    link_info.extend_from_slice(&1u32.to_le_bytes());
    link_info.extend_from_slice(&vol_id_off.to_le_bytes());
    link_info.extend_from_slice(&local_base_off.to_le_bytes());
    link_info.extend_from_slice(&0u32.to_le_bytes());
    link_info.extend_from_slice(&common_suffix_off.to_le_bytes());
    link_info.extend_from_slice(&vol_id);
    link_info.extend_from_slice(&local_base);
    link_info.extend_from_slice(common_suffix);

    let mut out = Vec::new();
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&link_target_id_list);
    out.extend_from_slice(&link_info);
    out.extend_from_slice(&shllink_string_data("GUAP Forensics Sample"));
    out.extend_from_slice(&shllink_string_data(r".\forensics_sample.exe"));
    out.extend_from_slice(&shllink_string_data(r"C:\Tools"));
    out.extend_from_slice(&shllink_string_data(args));
    out.extend_from_slice(&shllink_string_data(target));
    out.extend_from_slice(&0u32.to_le_bytes()); // ExtraData TerminalBlock
    out
}

#[allow(clippy::too_many_arguments)]
fn cfb_dir_entry(
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

fn build_destlist_v4() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    // 32-byte DestList v4 header
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&1.0f32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());

    // 130 fixed bytes + UTF-16LE path + 4 zero bytes
    let mut entry = vec![0u8; 0x82];
    entry[0x00..0x08].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    let host = b"WORKSTATION01\0";
    entry[0x48..0x48 + host.len()].copy_from_slice(host);
    entry[0x58..0x5C].copy_from_slice(&1u32.to_le_bytes());
    entry[0x64..0x6C].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    entry[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes()); // pinned #0
    entry[0x74..0x78].copy_from_slice(&3.0f32.to_le_bytes()); // access_count
    let path_str = r"C:\Cases\report.docx";
    let path_chars = path_str.encode_utf16().count() as u16;
    entry[0x80..0x82].copy_from_slice(&path_chars.to_le_bytes());
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(&utf16le_bytes(path_str));
    buf.extend_from_slice(&[0u8; 4]);
    buf.resize(4096, 0u8);
    buf
}

fn build_automatic_destinations_cfb(lnk_payload: &[u8]) -> Vec<u8> {
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
    hdr[0x3C..0x40].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    hdr[0x44..0x48].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    hdr[0x4C..0x50].copy_from_slice(&0u32.to_le_bytes());
    for i in 1..109 {
        let off = 0x4C + i * 4;
        hdr[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }

    // Sector 0: FAT (128 u32 entries)
    let mut fat = vec![0xFFu8; 512];
    let set_fat = |f: &mut [u8], idx: usize, val: u32| {
        f[idx * 4..idx * 4 + 4].copy_from_slice(&val.to_le_bytes());
    };
    set_fat(&mut fat, 0, 0xFFFF_FFFD); // FATSECT
    set_fat(&mut fat, 1, 0xFFFF_FFFE); // Dir ENDOFCHAIN
    for s in 2..9 {
        set_fat(&mut fat, s, (s + 1) as u32);
    }
    set_fat(&mut fat, 9, 0xFFFF_FFFE); // DestList end
    for s in 10..17 {
        set_fat(&mut fat, s, (s + 1) as u32);
    }
    set_fat(&mut fat, 17, 0xFFFF_FFFE); // LNK "1" end

    // Sector 1: Directory (4 x 128B entries)
    let mut dir = Vec::with_capacity(512);
    let no = 0xFFFF_FFFFu32;
    dir.extend_from_slice(&cfb_dir_entry(
        "Root Entry",
        5,
        1,
        no,
        no,
        1,
        0xFFFF_FFFE,
        0,
    ));
    dir.extend_from_slice(&cfb_dir_entry("DestList", 2, 1, 2, no, no, 2, 4096));
    dir.extend_from_slice(&cfb_dir_entry("1", 2, 0, no, no, no, 10, 4096));
    dir.extend_from_slice(&cfb_dir_entry("", 0, 0, no, no, no, 0, 0));

    let destlist = build_destlist_v4();
    let mut lnk_padded = lnk_payload.to_vec();
    lnk_padded.resize(4096, 0u8);

    let mut out = Vec::with_capacity(512 + 18 * 512);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&fat);
    out.extend_from_slice(&dir);
    out.extend_from_slice(&destlist);
    out.extend_from_slice(&lnk_padded);
    out
}

pub fn generate_artifacts_dir(artifacts_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(artifacts_dir)?;

    let pf_uncomp = build_scca_v30_prefetch("FORENSICS_SAMPLE.EXE", 0x1234_ABCD, 7);
    write_file_deterministic(
        &artifacts_dir.join("DEMO_UNCOMPRESSED-1234ABCD.pf"),
        &pf_uncomp,
    )?;

    let pf_for_comp = build_scca_v30_prefetch("FORENSICS_COMPRESSED.EXE", 0x5678_EF01, 4);
    let pf_comp = encode_ms_xca_huffman(&pf_for_comp)?;
    write_file_deterministic(&artifacts_dir.join("DEMO_COMPRESSED-5678EF01.pf"), &pf_comp)?;

    let lnk = build_sample_lnk(
        r"C:\Tools\forensics_sample.exe",
        "--case C:\\Cases\\report.docx",
    );
    write_file_deterministic(&artifacts_dir.join("ForensicsSample.lnk"), &lnk)?;

    let jl = build_automatic_destinations_cfb(&lnk);
    write_file_deterministic(
        &artifacts_dir.join("1b4dd67f29cb1962.automaticDestinations-ms"),
        &jl,
    )?;

    let setupapi = "\
[Device Install Log]
     OS Version = 10.0.22631
     Service Pack = 0.0
     Suite = 0x0100
     ProductType = 1
     Architecture = amd64

[BeginLog]

>>>  [Device Install (Hardware initiated) - USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\4C530001231020118273&0]
>>>  Section start 2026/11/22 14:25:00.125
     dvi: {Build Driver List} 14:25:00.130
     dvi: Created Driver Node: disk.inf
<<<  Section end 2026/11/22 14:25:01.050
<<<  [Exit status: SUCCESS]

>>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5581\\4C530001231020118273]
>>>  Section start 2026/11/22 14:24:59.010
     dvi: {Install Device} 14:24:59.400
<<<  Section end 2026/11/22 14:25:00.010
<<<  [Exit status: SUCCESS]
";
    write_file_deterministic(&artifacts_dir.join("setupapi.dev.log"), setupapi.as_bytes())?;
    Ok(())
}

pub fn verify_artifacts_dir(artifacts_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    // 1. Uncompressed SCCA v30
    let pf_u = std::fs::read(artifacts_dir.join("DEMO_UNCOMPRESSED-1234ABCD.pf"))?;
    ensure!(
        read_u32_le(&pf_u, 0)? == 30 && &pf_u[4..8] == b"SCCA",
        "bad uncompressed .pf header"
    );
    ensure!(
        read_u32_le(&pf_u, 0x0C)? as usize == pf_u.len(),
        "bad uncompressed .pf size"
    );
    ensure!(read_u32_le(&pf_u, 0xD0)? == 7, "bad run_count");
    details.push("artifacts/DEMO_UNCOMPRESSED-1234ABCD.pf: SCCA v30 verified".into());

    // 2. MAM\x04 compressed + round-trip decompress
    let pf_c = std::fs::read(artifacts_dir.join("DEMO_COMPRESSED-5678EF01.pf"))?;
    let decomp = decode_ms_xca_huffman(&pf_c)?;
    ensure!(
        read_u32_le(&decomp, 0)? == 30 && &decomp[4..8] == b"SCCA",
        "decompressed MAM != SCCA v30"
    );
    ensure!(
        read_u32_le(&decomp, 0x0C)? as usize == decomp.len(),
        "decompressed SCCA size mismatch"
    );
    details.push(format!(
        "artifacts/DEMO_COMPRESSED-5678EF01.pf: MAM\\x04 -> {}B SCCA verified",
        decomp.len()
    ));

    // 3. LNK
    let lnk = std::fs::read(artifacts_dir.join("ForensicsSample.lnk"))?;
    ensure!(read_u32_le(&lnk, 0)? == 0x4C, "bad LNK header size");
    ensure!(read_u16_le(&lnk, 0x40)? == 0x0641, "bad LNK wHotKey");
    ensure!(
        lnk.ends_with(&[0, 0, 0, 0]),
        "LNK missing ExtraData terminal block"
    );
    details.push("artifacts/ForensicsSample.lnk: MS-SHLLINK verified".into());

    // 4. JumpList CFBF
    let jl = std::fs::read(artifacts_dir.join("1b4dd67f29cb1962.automaticDestinations-ms"))?;
    ensure!(
        jl[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "bad CFBF magic"
    );
    ensure!(read_u16_le(&jl, 0x1E)? == 9, "bad CFBF SectorShift");
    ensure!(read_u32_le(&jl, 512)? == 0xFFFF_FFFD, "bad CFBF FAT[0]");
    ensure!(read_u32_le(&jl, 3 * 512)? == 4, "bad DestList v4 version");
    ensure!(
        read_u32_le(&jl, 11 * 512)? == 0x4C,
        "CFBF stream '1' missing LNK header"
    );
    details.push(
        "artifacts/1b4dd67f29cb1962.automaticDestinations-ms: CFBF + DestList v4 + LNK verified"
            .into(),
    );

    // 5. setupapi.dev.log
    let setup = std::fs::read_to_string(artifacts_dir.join("setupapi.dev.log"))?;
    ensure!(
        setup.contains("[Device Install Log]") && setup.contains("USBSTOR\\DISK&VEN_SANDISK"),
        "bad setupapi.dev.log"
    );
    details.push("artifacts/setupapi.dev.log: verified".into());

    Ok((5, details))
}
