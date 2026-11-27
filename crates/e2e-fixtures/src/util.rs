use sha2::{Digest, Sha256};
use std::path::Path;

pub const FIXED_ISO_TIMESTAMP: &str = "2026-11-22T14:30:00Z";
pub const FIXED_UNIX_SECS: u64 = 1_795_357_800;
pub const FIXED_PRTIME_US: u64 = FIXED_UNIX_SECS * 1_000_000;
pub const FIXED_CHROME_US: u64 = (FIXED_UNIX_SECS + 11_644_473_600) * 1_000_000;
pub const FIXED_FILETIME: u64 = (FIXED_UNIX_SECS + 11_644_473_600) * 10_000_000;
pub const FIXED_CF_TIME: f64 = (FIXED_UNIX_SECS - 978_307_200) as f64;

pub fn crc32_ieee(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub fn xor32_u32s(data: &[u8]) -> u32 {
    let mut acc = 0u32;
    for chunk in data.as_chunks::<4>().0 {
        acc ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    acc
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Pure-Rust RFC 3174 SHA-1 digest.
pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(input.len() + 72);
    msg.extend_from_slice(input);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

pub fn sha1_hex_upper(input: &[u8]) -> String {
    hex::encode_upper(sha1_digest(input))
}

pub fn utf16le_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for cu in s.encode_utf16() {
        out.extend_from_slice(&cu.to_le_bytes());
    }
    out
}

pub fn utf16le_nul(s: &str) -> Vec<u8> {
    let mut out = utf16le_bytes(s);
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

pub fn write_file_deterministic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn read_u16_le(buf: &[u8], off: usize) -> anyhow::Result<u16> {
    let slice = buf
        .get(off..off + 2)
        .ok_or_else(|| anyhow::anyhow!("read_u16_le out of bounds at {off}"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32_le(buf: &[u8], off: usize) -> anyhow::Result<u32> {
    let slice = buf
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("read_u32_le out of bounds at {off}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_i32_le(buf: &[u8], off: usize) -> anyhow::Result<i32> {
    let slice = buf
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("read_i32_le out of bounds at {off}"))?;
    Ok(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_u64_le(buf: &[u8], off: usize) -> anyhow::Result<u64> {
    let slice = buf
        .get(off..off + 8)
        .ok_or_else(|| anyhow::anyhow!("read_u64_le out of bounds at {off}"))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn read_u16_be(buf: &[u8], off: usize) -> anyhow::Result<u16> {
    let slice = buf
        .get(off..off + 2)
        .ok_or_else(|| anyhow::anyhow!("read_u16_be out of bounds at {off}"))?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

pub fn read_u32_be(buf: &[u8], off: usize) -> anyhow::Result<u32> {
    let slice = buf
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("read_u32_be out of bounds at {off}"))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
