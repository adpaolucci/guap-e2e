use anyhow::{Result, bail, ensure};

pub const MOZLZZ4_MAGIC: &[u8; 8] = b"mozLz40\0";

fn write_ext_len(out: &mut Vec<u8>, mut len: usize) {
    while len >= 255 {
        out.push(255);
        len -= 255;
    }
    out.push(len as u8);
}

/// Pure-Rust LZ4 raw block compressor compatible with `lz4_flex::block::decompress`.
pub fn compress_block(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 16);
    if input.is_empty() {
        return out;
    }

    // Only attempt matches when input >= 13 bytes (LZ4 spec requires last 5 bytes as literals)
    let mut hash_table = [usize::MAX; 4096];
    let mut anchor = 0usize;
    let mut pos = 0usize;
    let mflimit = input.len().saturating_sub(12);

    while pos < mflimit {
        let seq = u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
        let h = ((seq.wrapping_mul(2654435761)) >> 20) as usize & 0xFFF;
        let candidate = hash_table[h];
        hash_table[h] = pos;

        if candidate != usize::MAX
            && pos > candidate
            && (pos - candidate) <= 65535
            && input[candidate..candidate + 4] == input[pos..pos + 4]
        {
            // Extend match up to input.len() - 5
            let max_match_end = input.len() - 5;
            let mut match_len = 4usize;
            while pos + match_len < max_match_end
                && input[candidate + match_len] == input[pos + match_len]
            {
                match_len += 1;
            }

            let lit_len = pos - anchor;
            let ml_code = match_len - 4;
            let token_lit = lit_len.min(15) as u8;
            let token_ml = ml_code.min(15) as u8;
            out.push((token_lit << 4) | token_ml);

            if lit_len >= 15 {
                write_ext_len(&mut out, lit_len - 15);
            }
            out.extend_from_slice(&input[anchor..pos]);

            let offset = (pos - candidate) as u16;
            out.extend_from_slice(&offset.to_le_bytes());

            if ml_code >= 15 {
                write_ext_len(&mut out, ml_code - 15);
            }

            pos += match_len;
            anchor = pos;
        } else {
            pos += 1;
        }
    }

    // Emit remaining literals
    let rem_lit = input.len() - anchor;
    let token_lit = rem_lit.min(15) as u8;
    out.push(token_lit << 4);
    if rem_lit >= 15 {
        write_ext_len(&mut out, rem_lit - 15);
    }
    out.extend_from_slice(&input[anchor..]);
    out
}

/// Pure-Rust LZ4 raw block decompressor with strict bounds checking.
pub fn decompress_block(block: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if expected_len > 64 * 1024 * 1024 {
        bail!("LZ4 expected_len {} exceeds safety cap", expected_len);
    }
    if block.is_empty() {
        ensure!(
            expected_len == 0,
            "empty LZ4 block for non-zero expected_len"
        );
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(expected_len);
    let mut ip = 0usize;

    while ip < block.len() {
        let token = block[ip];
        ip += 1;

        let mut lit_len = ((token >> 4) & 0x0F) as usize;
        if lit_len == 15 {
            loop {
                ensure!(ip < block.len(), "truncated LZ4 literal length");
                let b = block[ip] as usize;
                ip += 1;
                lit_len = lit_len
                    .checked_add(b)
                    .ok_or_else(|| anyhow::anyhow!("lit_len overflow"))?;
                if b != 255 {
                    break;
                }
            }
        }

        ensure!(
            ip.checked_add(lit_len)
                .is_some_and(|end| end <= block.len()),
            "truncated LZ4 literals"
        );
        out.extend_from_slice(&block[ip..ip + lit_len]);
        ip += lit_len;

        if ip == block.len() {
            break;
        }

        ensure!(
            ip.checked_add(2).is_some_and(|end| end <= block.len()),
            "truncated LZ4 match offset"
        );
        let offset = u16::from_le_bytes([block[ip], block[ip + 1]]) as usize;
        ip += 2;
        ensure!(
            offset > 0 && offset <= out.len(),
            "invalid LZ4 match offset {}",
            offset
        );

        let mut match_len = (token & 0x0F) as usize + 4;
        if (token & 0x0F) == 15 {
            loop {
                ensure!(ip < block.len(), "truncated LZ4 match length");
                let b = block[ip] as usize;
                ip += 1;
                match_len = match_len
                    .checked_add(b)
                    .ok_or_else(|| anyhow::anyhow!("match_len overflow"))?;
                if b != 255 {
                    break;
                }
            }
        }

        ensure!(
            out.len()
                .checked_add(match_len)
                .is_some_and(|end| end <= expected_len),
            "LZ4 output exceeds expected_len {}",
            expected_len
        );
        for _ in 0..match_len {
            let b = out[out.len() - offset];
            out.push(b);
        }
    }

    ensure!(
        out.len() == expected_len,
        "LZ4 decompressed {} bytes, expected {}",
        out.len(),
        expected_len
    );
    Ok(out)
}

pub fn encode_mozlz4(raw: &[u8]) -> Vec<u8> {
    let compressed = compress_block(raw);
    let mut out = Vec::with_capacity(12 + compressed.len());
    out.extend_from_slice(MOZLZZ4_MAGIC);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

pub fn decode_mozlz4(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        data.len() >= 12,
        "mozLz40 payload too short ({} bytes)",
        data.len()
    );
    ensure!(&data[0..8] == MOZLZZ4_MAGIC, "invalid mozLz40 magic");
    let expected_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    decompress_block(&data[12..], expected_len)
}
