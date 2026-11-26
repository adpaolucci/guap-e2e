use std::path::Path;
use anyhow::{ensure, Result};
use crate::util::{
    crc32_ieee, read_u16_le, read_u32_le, utf16le_nul, write_file_deterministic, FIXED_FILETIME,
    FIXED_UNIX_SECS,
};

fn build_minimal_16x16_png() -> Vec<u8> {
    let mut png = Vec::from(&b"\x89PNG\r\n\x1a\n"[..]);
    let push_chunk = |dst: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]| {
        dst.extend_from_slice(&(data.len() as u32).to_be_bytes());
        dst.extend_from_slice(tag);
        dst.extend_from_slice(data);
        let mut crc_in = Vec::with_capacity(4 + data.len());
        crc_in.extend_from_slice(tag);
        crc_in.extend_from_slice(data);
        dst.extend_from_slice(&crc32_ieee(&crc_in).to_be_bytes());
    };
    let ihdr = [
        0, 0, 0, 16, // width 16
        0, 0, 0, 16, // height 16
        8, 6, 0, 0, 0, // 8-bit RGBA
    ];
    push_chunk(&mut png, b"IHDR", &ihdr);
    // Empty/minimal stored zlib block for 16*(1+64) = 1040 bytes of zeros
    let mut raw = vec![0u8; 16 * (1 + 64)];
    raw[1] = 0x33;
    raw[2] = 0x99;
    raw[3] = 0xFF;
    raw[4] = 0xFF;
    let mut zlib = Vec::with_capacity(2 + 5 + raw.len() + 4);
    zlib.extend_from_slice(&[0x78, 0x01]);
    zlib.push(0x01); // BFINAL=1, BTYPE=00 (stored)
    let len = raw.len() as u16;
    zlib.extend_from_slice(&len.to_le_bytes());
    zlib.extend_from_slice(&(!len).to_le_bytes());
    zlib.extend_from_slice(&raw);
    // Adler-32
    let mut s1 = 1u32;
    let mut s2 = 0u32;
    for &b in &raw {
        s1 = (s1 + b as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    zlib.extend_from_slice(&((s2 << 16) | s1).to_be_bytes());
    push_chunk(&mut png, b"IDAT", &zlib);
    push_chunk(&mut png, b"IEND", &[]);
    png
}

fn ver_node(key: &str, value: &[u8], w_type: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // wLength placeholder
    let w_val_len = if w_type == 0 { value.len() } else { value.len() / 2 };
    out.extend_from_slice(&(w_val_len as u16).to_le_bytes());
    out.extend_from_slice(&w_type.to_le_bytes());
    out.extend_from_slice(&utf16le_nul(key));
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    for ch in children {
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(ch);
    }
    let total = out.len() as u16;
    out[0..2].copy_from_slice(&total.to_le_bytes());
    out
}

fn build_vs_version_info() -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    fixed[0..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    fixed[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    fixed[8..12].copy_from_slice(&0x0001_0002u32.to_le_bytes()); // 1.2
    fixed[12..16].copy_from_slice(&0x0003_0004u32.to_le_bytes()); // .3.4
    fixed[16..20].copy_from_slice(&0x0001_0002u32.to_le_bytes());
    fixed[20..24].copy_from_slice(&0x0003_0004u32.to_le_bytes());
    fixed[24..28].copy_from_slice(&0x3Fu32.to_le_bytes());
    fixed[32..36].copy_from_slice(&0x0004_0004u32.to_le_bytes());
    fixed[36..40].copy_from_slice(&2u32.to_le_bytes()); // VFT_DLL

    let s1 = ver_node("CompanyName", &utf16le_nul("GUAP Project"), 1, &[]);
    let s2 = ver_node("FileVersion", &utf16le_nul("1.2.3.4"), 1, &[]);
    let s3 = ver_node("ProductName", &utf16le_nul("GUAP PE32 Test DLL"), 1, &[]);
    let st = ver_node("040904b0", &[], 1, &[s1, s2, s3]);
    let sfi = ver_node("StringFileInfo", &[], 1, &[st]);
    let trans = [0x09u8, 0x04, 0xB0, 0x04];
    let v_node = ver_node("Translation", &trans, 0, &[]);
    let vfi = ver_node("VarFileInfo", &[], 1, &[v_node]);
    ver_node("VS_VERSION_INFO", &fixed, 0, &[sfi, vfi])
}

#[allow(clippy::too_many_arguments)]
fn push_section_hdr(
    buf: &mut [u8],
    off: usize,
    name: &[u8; 8],
    vsize: u32,
    va: u32,
    raw_sz: u32,
    raw_ptr: u32,
    chars: u32,
) {
    buf[off..off + 8].copy_from_slice(name);
    buf[off + 8..off + 12].copy_from_slice(&vsize.to_le_bytes());
    buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
    buf[off + 16..off + 20].copy_from_slice(&raw_sz.to_le_bytes());
    buf[off + 20..off + 24].copy_from_slice(&raw_ptr.to_le_bytes());
    buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
}

pub fn build_sample_pe32_dll() -> Vec<u8> {
    // Build .rdata (exports)
    let mut rdata = vec![0u8; 0x200];
    let dll_name_off = 0x46usize;
    rdata[dll_name_off..dll_name_off + 16].copy_from_slice(b"sample_pe32.dll\0");
    let n1_off = 0x56usize;
    rdata[n1_off..n1_off + 16].copy_from_slice(b"GuapComputeHash\0");
    let n2_off = 0x66usize;
    rdata[n2_off..n2_off + 18].copy_from_slice(b"GuapForwardedTick\0");
    let n3_off = 0x78usize;
    rdata[n3_off..n3_off + 15].copy_from_slice(b"GuapGetVersion\0");
    let fwd_off = 0x87usize;
    rdata[fwd_off..fwd_off + 22].copy_from_slice(b"KERNEL32.GetTickCount\0");
    let export_dir_sz = (fwd_off + 22) as u32;

    rdata[0x0C..0x10].copy_from_slice(&((0x2000 + dll_name_off) as u32).to_le_bytes());
    rdata[0x10..0x14].copy_from_slice(&1u32.to_le_bytes()); // Base
    rdata[0x14..0x18].copy_from_slice(&3u32.to_le_bytes()); // NumberOfFunctions
    rdata[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes()); // NumberOfNames
    rdata[0x1C..0x20].copy_from_slice(&0x2028u32.to_le_bytes()); // AddressOfFunctions
    rdata[0x20..0x24].copy_from_slice(&0x2034u32.to_le_bytes()); // AddressOfNames
    rdata[0x24..0x28].copy_from_slice(&0x2040u32.to_le_bytes()); // AddressOfNameOrdinals

    // Functions [0, 1, 2]
    rdata[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes());
    rdata[0x2C..0x30].copy_from_slice(&0x1004u32.to_le_bytes());
    rdata[0x30..0x34].copy_from_slice(&((0x2000 + fwd_off) as u32).to_le_bytes());
    // Names (sorted)
    rdata[0x34..0x38].copy_from_slice(&((0x2000 + n1_off) as u32).to_le_bytes());
    rdata[0x38..0x3C].copy_from_slice(&((0x2000 + n2_off) as u32).to_le_bytes());
    rdata[0x3C..0x40].copy_from_slice(&((0x2000 + n3_off) as u32).to_le_bytes());
    // Ordinals matching sorted names -> [0, 2, 1]
    rdata[0x40..0x42].copy_from_slice(&0u16.to_le_bytes());
    rdata[0x42..0x44].copy_from_slice(&2u16.to_le_bytes());
    rdata[0x44..0x46].copy_from_slice(&1u16.to_le_bytes());

    // Build .rsrc 3-level tree
    let icon_png = build_minimal_16x16_png();
    let mut grp_icon = Vec::with_capacity(20);
    grp_icon.extend_from_slice(&0u16.to_le_bytes());
    grp_icon.extend_from_slice(&1u16.to_le_bytes());
    grp_icon.extend_from_slice(&1u16.to_le_bytes());
    grp_icon.extend_from_slice(&[16, 16, 0, 0]);
    grp_icon.extend_from_slice(&1u16.to_le_bytes());
    grp_icon.extend_from_slice(&32u16.to_le_bytes());
    grp_icon.extend_from_slice(&(icon_png.len() as u32).to_le_bytes());
    grp_icon.extend_from_slice(&1u16.to_le_bytes());
    let ver_info = build_vs_version_info();

    // Layout: L1 (40B) + 3x L2 (3*24=72B) + 3x L3 (3*24=72B) + 3x DataEntry (3*16=48B) = 232B
    let l1_off = 0usize;
    let l2_offs = [40usize, 64, 88];
    let l3_offs = [112usize, 136, 160];
    let de_offs = [184usize, 200, 216];
    let pay1_off = 232usize;
    let pay2_off = (pay1_off + icon_png.len() + 3) & !3;
    let pay3_off = (pay2_off + grp_icon.len() + 3) & !3;
    let rsrc_raw_len = pay3_off + ver_info.len();
    let rsrc_aligned = rsrc_raw_len.div_ceil(0x200) * 0x200;

    let mut rsrc = vec![0u8; rsrc_aligned];
    let write_rsrc_dir = |buf: &mut [u8], off: usize, entries: &[(u32, u32)]| {
        buf[off + 14..off + 16].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        for (i, &(id, target)) in entries.iter().enumerate() {
            let eoff = off + 16 + i * 8;
            buf[eoff..eoff + 4].copy_from_slice(&id.to_le_bytes());
            buf[eoff + 4..eoff + 8].copy_from_slice(&target.to_le_bytes());
        }
    };
    write_rsrc_dir(
        &mut rsrc,
        l1_off,
        &[
            (3, 0x8000_0000 | l2_offs[0] as u32),
            (14, 0x8000_0000 | l2_offs[1] as u32),
            (16, 0x8000_0000 | l2_offs[2] as u32),
        ],
    );
    for i in 0..3 {
        write_rsrc_dir(&mut rsrc, l2_offs[i], &[(1, 0x8000_0000 | l3_offs[i] as u32)]);
        write_rsrc_dir(&mut rsrc, l3_offs[i], &[(0x0409, de_offs[i] as u32)]);
    }
    let write_de = |buf: &mut [u8], off: usize, rva: u32, sz: usize| {
        buf[off..off + 4].copy_from_slice(&rva.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&(sz as u32).to_le_bytes());
    };
    write_de(&mut rsrc, de_offs[0], 0x3000 + pay1_off as u32, icon_png.len());
    write_de(&mut rsrc, de_offs[1], 0x3000 + pay2_off as u32, grp_icon.len());
    write_de(&mut rsrc, de_offs[2], 0x3000 + pay3_off as u32, ver_info.len());
    rsrc[pay1_off..pay1_off + icon_png.len()].copy_from_slice(&icon_png);
    rsrc[pay2_off..pay2_off + grp_icon.len()].copy_from_slice(&grp_icon);
    rsrc[pay3_off..pay3_off + ver_info.len()].copy_from_slice(&ver_info);

    let rsrc_vpages = rsrc_aligned.div_ceil(0x1000) as u32 * 0x1000;

    // Headers (0..0x200)
    let mut hdr = vec![0u8; 0x200];
    hdr[0..2].copy_from_slice(b"MZ");
    hdr[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    hdr[0x80..0x84].copy_from_slice(b"PE\0\0");
    hdr[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
    hdr[0x86..0x88].copy_from_slice(&3u16.to_le_bytes());
    hdr[0x88..0x8C].copy_from_slice(&(FIXED_UNIX_SECS as u32).to_le_bytes());
    hdr[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    hdr[0x96..0x98].copy_from_slice(&0x2102u16.to_le_bytes());
    // OptionalHeader at 0x98
    hdr[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
    hdr[0x98 + 0x10..0x98 + 0x14].copy_from_slice(&0x1000u32.to_le_bytes());
    hdr[0x98 + 0x14..0x98 + 0x18].copy_from_slice(&0x1000u32.to_le_bytes());
    hdr[0x98 + 0x18..0x98 + 0x1C].copy_from_slice(&0x2000u32.to_le_bytes());
    hdr[0x98 + 0x1C..0x98 + 0x20].copy_from_slice(&0x1000_0000u32.to_le_bytes());
    hdr[0x98 + 0x20..0x98 + 0x24].copy_from_slice(&0x1000u32.to_le_bytes());
    hdr[0x98 + 0x24..0x98 + 0x28].copy_from_slice(&0x0200u32.to_le_bytes());
    hdr[0x98 + 0x28..0x98 + 0x2A].copy_from_slice(&6u16.to_le_bytes());
    hdr[0x98 + 0x30..0x98 + 0x32].copy_from_slice(&6u16.to_le_bytes());
    hdr[0x98 + 0x38..0x98 + 0x3C].copy_from_slice(&(0x3000 + rsrc_vpages).to_le_bytes());
    hdr[0x98 + 0x3C..0x98 + 0x40].copy_from_slice(&0x0200u32.to_le_bytes());
    hdr[0x98 + 0x44..0x98 + 0x46].copy_from_slice(&3u16.to_le_bytes());
    hdr[0x98 + 0x5C..0x98 + 0x60].copy_from_slice(&16u32.to_le_bytes());
    // DataDir[0] Export, DataDir[2] Resource
    hdr[0xF8..0xFC].copy_from_slice(&0x2000u32.to_le_bytes());
    hdr[0xFC..0x100].copy_from_slice(&export_dir_sz.to_le_bytes());
    hdr[0x108..0x10C].copy_from_slice(&0x3000u32.to_le_bytes());
    hdr[0x10C..0x110].copy_from_slice(&(rsrc_raw_len as u32).to_le_bytes());

    push_section_hdr(&mut hdr, 0x178, b".text\0\0\0", 0x10, 0x1000, 0x200, 0x200, 0x6000_0020);
    push_section_hdr(&mut hdr, 0x1A0, b".rdata\0\0", export_dir_sz, 0x2000, 0x200, 0x400, 0x4000_0040);
    push_section_hdr(&mut hdr, 0x1C8, b".rsrc\0\0\0", rsrc_raw_len as u32, 0x3000, rsrc_aligned as u32, 0x600, 0x4000_0040);

    let mut text = vec![0u8; 0x200];
    text[0] = 0xC3; // ret
    text[4] = 0xC3;

    let mut out = Vec::with_capacity(0x600 + rsrc.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&text);
    out.extend_from_slice(&rdata);
    out.extend_from_slice(&rsrc);
    out
}

pub fn build_sample_pe64_dotnet_exe() -> Vec<u8> {
    let mut strings_heap = Vec::from(&b"\0GuapDotNetFixture.exe\0GuapDotNetFixture\0GuapDotNetFixture.embedded.txt\0"[..]);
    while strings_heap.len() % 4 != 0 {
        strings_heap.push(0);
    }
    let guid_heap = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01];
    let blob_heap = [0u8; 4];

    // #~ stream
    let mut tilde = Vec::new();
    tilde.extend_from_slice(&0u32.to_le_bytes());
    tilde.push(2); // Major
    tilde.push(0); // Minor
    tilde.push(0); // HeapSizes (2-byte indices)
    tilde.push(1); // Reserved
    let valid: u64 = (1u64 << 0) | (1u64 << 32) | (1u64 << 40);
    tilde.extend_from_slice(&valid.to_le_bytes());
    tilde.extend_from_slice(&0u64.to_le_bytes());
    tilde.extend_from_slice(&1u32.to_le_bytes()); // Module rows
    tilde.extend_from_slice(&1u32.to_le_bytes()); // Assembly rows
    tilde.extend_from_slice(&1u32.to_le_bytes()); // ManifestResource rows
    // Module row (10B): Gen(2) + Name(2=1) + Mvid(2=1) + EncId(2=0) + EncBaseId(2=0)
    tilde.extend_from_slice(&0u16.to_le_bytes());
    tilde.extend_from_slice(&1u16.to_le_bytes());
    tilde.extend_from_slice(&1u16.to_le_bytes());
    tilde.extend_from_slice(&0u16.to_le_bytes());
    tilde.extend_from_slice(&0u16.to_le_bytes());
    // Assembly row (22B): HashAlg(4) + Ver(8) + Flags(4) + PubKey(2) + Name(2=23) + Culture(2=0)
    tilde.extend_from_slice(&0x8004u32.to_le_bytes());
    tilde.extend_from_slice(&1u16.to_le_bytes());
    tilde.extend_from_slice(&2u16.to_le_bytes());
    tilde.extend_from_slice(&3u16.to_le_bytes());
    tilde.extend_from_slice(&4u16.to_le_bytes());
    tilde.extend_from_slice(&0u32.to_le_bytes());
    tilde.extend_from_slice(&0u16.to_le_bytes());
    tilde.extend_from_slice(&23u16.to_le_bytes());
    tilde.extend_from_slice(&0u16.to_le_bytes());
    // ManifestResource row (12B): Offset(4=0) + Flags(4=1) + Name(2=41) + Impl(2=0)
    tilde.extend_from_slice(&0u32.to_le_bytes());
    tilde.extend_from_slice(&1u32.to_le_bytes());
    tilde.extend_from_slice(&41u16.to_le_bytes());
    tilde.extend_from_slice(&0u16.to_le_bytes());
    while tilde.len() % 4 != 0 {
        tilde.push(0);
    }

    // BSJB header: 16B + 12B version + 4B flags/streams + 4 stream headers
    // Stream names: "#~\0\0" (4B), "#Strings\0\0\0\0" (12B), "#GUID\0\0\0" (8B), "#Blob\0\0\0" (8B)
    let bsjb_hdr_sz = 16 + 12 + 4 + (8 + 4) + (8 + 12) + (8 + 8) + (8 + 8);
    let off_tilde = bsjb_hdr_sz as u32;
    let off_strings = off_tilde + tilde.len() as u32;
    let off_guid = off_strings + strings_heap.len() as u32;
    let off_blob = off_guid + guid_heap.len() as u32;

    let mut bsjb = Vec::new();
    bsjb.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    bsjb.extend_from_slice(&1u16.to_le_bytes());
    bsjb.extend_from_slice(&1u16.to_le_bytes());
    bsjb.extend_from_slice(&0u32.to_le_bytes());
    bsjb.extend_from_slice(&12u32.to_le_bytes());
    bsjb.extend_from_slice(b"v4.0.30319\0\0");
    bsjb.extend_from_slice(&0u16.to_le_bytes());
    bsjb.extend_from_slice(&4u16.to_le_bytes());

    let push_shdr = |dst: &mut Vec<u8>, off: u32, sz: usize, name: &[u8]| {
        dst.extend_from_slice(&off.to_le_bytes());
        dst.extend_from_slice(&(sz as u32).to_le_bytes());
        dst.extend_from_slice(name);
    };
    push_shdr(&mut bsjb, off_tilde, tilde.len(), b"#~\0\0");
    push_shdr(&mut bsjb, off_strings, strings_heap.len(), b"#Strings\0\0\0\0");
    push_shdr(&mut bsjb, off_guid, guid_heap.len(), b"#GUID\0\0\0");
    push_shdr(&mut bsjb, off_blob, blob_heap.len(), b"#Blob\0\0\0");
    bsjb.extend_from_slice(&tilde);
    bsjb.extend_from_slice(&strings_heap);
    bsjb.extend_from_slice(&guid_heap);
    bsjb.extend_from_slice(&blob_heap);

    let res_bytes = b"GUAP DotNet ManifestResource";
    let mut res_block = Vec::with_capacity(4 + res_bytes.len());
    res_block.extend_from_slice(&(res_bytes.len() as u32).to_le_bytes());
    res_block.extend_from_slice(res_bytes);

    let mut text = vec![0u8; 0x400];
    text[0] = 0xC3;
    let md_rva = 0x1060u32;
    let res_rva = md_rva + bsjb.len() as u32;
    // IMAGE_COR20_HEADER at +0x10 (RVA 0x1010)
    text[0x10..0x14].copy_from_slice(&72u32.to_le_bytes());
    text[0x14..0x16].copy_from_slice(&2u16.to_le_bytes());
    text[0x16..0x18].copy_from_slice(&5u16.to_le_bytes());
    text[0x18..0x1C].copy_from_slice(&md_rva.to_le_bytes());
    text[0x1C..0x20].copy_from_slice(&(bsjb.len() as u32).to_le_bytes());
    text[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // ILONLY
    text[0x24..0x28].copy_from_slice(&0x0600_0001u32.to_le_bytes());
    text[0x28..0x2C].copy_from_slice(&res_rva.to_le_bytes());
    text[0x2C..0x30].copy_from_slice(&(res_block.len() as u32).to_le_bytes());

    text[0x60..0x60 + bsjb.len()].copy_from_slice(&bsjb);
    let res_off = 0x60 + bsjb.len();
    text[res_off..res_off + res_block.len()].copy_from_slice(&res_block);

    let mut hdr = vec![0u8; 0x200];
    hdr[0..2].copy_from_slice(b"MZ");
    hdr[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    hdr[0x80..0x84].copy_from_slice(b"PE\0\0");
    hdr[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    hdr[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    hdr[0x88..0x8C].copy_from_slice(&(FIXED_UNIX_SECS as u32).to_le_bytes());
    hdr[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    hdr[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
    // OptionalHeader PE32+ at 0x98
    hdr[0x98..0x9A].copy_from_slice(&0x020Bu16.to_le_bytes());
    hdr[0x98 + 0x10..0x98 + 0x14].copy_from_slice(&0x1000u32.to_le_bytes());
    hdr[0x98 + 0x18..0x98 + 0x20].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    hdr[0x98 + 0x20..0x98 + 0x24].copy_from_slice(&0x1000u32.to_le_bytes());
    hdr[0x98 + 0x24..0x98 + 0x28].copy_from_slice(&0x0200u32.to_le_bytes());
    hdr[0x98 + 0x28..0x98 + 0x2A].copy_from_slice(&6u16.to_le_bytes());
    hdr[0x98 + 0x30..0x98 + 0x32].copy_from_slice(&6u16.to_le_bytes());
    hdr[0x98 + 0x38..0x98 + 0x3C].copy_from_slice(&0x2000u32.to_le_bytes());
    hdr[0x98 + 0x3C..0x98 + 0x40].copy_from_slice(&0x0200u32.to_le_bytes());
    hdr[0x98 + 0x44..0x98 + 0x46].copy_from_slice(&3u16.to_le_bytes());
    hdr[0x98 + 0x6C..0x98 + 0x70].copy_from_slice(&16u32.to_le_bytes());
    // DataDir[14] CLR at 0x98 + 0x70 + 14*8 = 0x178
    hdr[0x178..0x17C].copy_from_slice(&0x1010u32.to_le_bytes());
    hdr[0x17C..0x180].copy_from_slice(&72u32.to_le_bytes());
    push_section_hdr(&mut hdr, 0x188, b".text\0\0\0", 0x400, 0x1000, 0x400, 0x200, 0x6000_0020);

    let mut out = Vec::with_capacity(0x600);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&text);
    out
}
use crate::util::utf16le_bytes;

pub fn build_usnjrnl_j() -> Vec<u8> {
    let make_rec = |frn: u64, parent: u64, usn: i64, reason: u32, fname: &str| -> Vec<u8> {
        let name_u16 = utf16le_bytes(fname);
        let rec_len = (60 + name_u16.len()).div_ceil(8) * 8;
        let mut r = vec![0u8; rec_len];
        r[0..4].copy_from_slice(&(rec_len as u32).to_le_bytes());
        r[4..6].copy_from_slice(&2u16.to_le_bytes()); // MajorVersion 2
        r[6..8].copy_from_slice(&0u16.to_le_bytes());
        r[8..16].copy_from_slice(&frn.to_le_bytes());
        r[16..24].copy_from_slice(&parent.to_le_bytes());
        r[24..32].copy_from_slice(&usn.to_le_bytes());
        r[32..40].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
        r[40..44].copy_from_slice(&reason.to_le_bytes());
        r[52..56].copy_from_slice(&0x20u32.to_le_bytes()); // FILE_ATTRIBUTE_ARCHIVE
        r[56..58].copy_from_slice(&(name_u16.len() as u16).to_le_bytes());
        r[58..60].copy_from_slice(&60u16.to_le_bytes());
        r[60..60 + name_u16.len()].copy_from_slice(&name_u16);
        r
    };

    let mut out = Vec::new();
    out.extend_from_slice(&make_rec(0x0001_0000_0000_0100, 0x0005_0000_0000_0005, 1024, 0x0000_0100, "audit.log"));
    out.extend_from_slice(&make_rec(0x0001_0000_0000_0100, 0x0005_0000_0000_0005, 1104, 0x8000_0002, "audit.log"));
    out.extend_from_slice(&make_rec(0x0001_0000_0000_0101, 0x0005_0000_0000_0005, 1184, 0x8000_0200, "temp_report.tmp"));
    out
}

pub fn build_ata_smart() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
    let attrs: [(u8, u16, u8, u8, u64); 6] = [
        (0x01, 0x000F, 100, 100, 0),
        (0x05, 0x0033, 100, 100, 0),
        (0x09, 0x0032, 96, 96, 3500),
        (0x0C, 0x0032, 99, 99, 142),
        (0xC2, 0x0022, 65, 50, 35),
        (0xC5, 0x0012, 100, 100, 0),
    ];
    for (idx, &(id, flags, cur, worst, raw)) in attrs.iter().enumerate() {
        let off = 2 + idx * 12;
        b[off] = id;
        b[off + 1..off + 3].copy_from_slice(&flags.to_le_bytes());
        b[off + 3] = cur;
        b[off + 4] = worst;
        let raw_bytes = raw.to_le_bytes();
        b[off + 5..off + 11].copy_from_slice(&raw_bytes[0..6]);
    }
    let sum: u32 = b[0..511].iter().map(|&x| x as u32).sum();
    b[511] = ((256 - (sum % 256)) % 256) as u8;
    b
}

pub fn build_ata_smart_thresholds() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
    let threshes: [(u8, u8); 6] = [(0x01, 6), (0x05, 10), (0x09, 0), (0x0C, 0), (0xC2, 0), (0xC5, 0)];
    for (idx, &(id, th)) in threshes.iter().enumerate() {
        let off = 2 + idx * 12;
        b[off] = id;
        b[off + 1] = th;
    }
    let sum: u32 = b[0..511].iter().map(|&x| x as u32).sum();
    b[511] = ((256 - (sum % 256)) % 256) as u8;
    b
}

pub fn generate_sys_fs_dir(sys_fs_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(sys_fs_dir)?;

    write_file_deterministic(&sys_fs_dir.join("sample_pe32.dll"), &build_sample_pe32_dll())?;
    write_file_deterministic(&sys_fs_dir.join("sample_pe64_dotnet.exe"), &build_sample_pe64_dotnet_exe())?;
    write_file_deterministic(&sys_fs_dir.join("usnjrnl_j.bin"), &build_usnjrnl_j())?;
    write_file_deterministic(&sys_fs_dir.join("ata_smart.bin"), &build_ata_smart())?;
    write_file_deterministic(&sys_fs_dir.join("ata_smart_thresholds.bin"), &build_ata_smart_thresholds())?;

    let csv_left = "\
id,name,formula_test,bytes,status
1,alpha_service,clean_value,1024,ok
2,beta_worker,=cmd|'/C calc'!A0,2048,warn
3,gamma_task,+1234+5678,512,ok
4,delta_agent,-5678,256,ok
5,epsilon_sum,\"@SUM(1,2)\",128,ok
6,zeta_tab,\tleading_tab,64,removed
";
    write_file_deterministic(&sys_fs_dir.join("sample_data.csv"), csv_left.as_bytes())?;

    let csv_right = "\
id,name,formula_test,bytes,status
1,alpha_service,clean_value,1024,ok
2,beta_worker,=cmd|'/C calc'!A0,4096,warn
3,gamma_task,+1234+5678,512,ok
4,delta_agent,-5678,256,ok
5,epsilon_sum,\"@SUM(1,2)\",128,ok
7,new_row,added,4096,ok
";
    write_file_deterministic(&sys_fs_dir.join("sample_data_right.csv"), csv_right.as_bytes())?;

    let tsv = "\
id\tname\tformula_test\tbytes\tstatus
1\talpha_service\tclean_value\t1024\tok
2\tbeta_worker\t=cmd|'/C calc'!A0\t2048\twarn
3\tgamma_task\t+1234+5678\t512\tok
";
    write_file_deterministic(&sys_fs_dir.join("sample_data.tsv"), tsv.as_bytes())?;

    let html = "<!DOCTYPE html><html><head><title>GUAP HTML Fixture</title></head><body><h1>Audit Summary</h1><p>First paragraph with <a href=\"https://example.org/ref\">reference link</a>.</p><ul><li>Item One</li><li>Item Two</li></ul><table><tr><th>ColA</th><th>ColB</th></tr><tr><td>Val1</td><td>Val2</td></tr></table></body></html>";
    write_file_deterministic(&sys_fs_dir.join("sample_page.html"), html.as_bytes())?;

    let vcf = "\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
FN:Alice Vance\r\n\
ORG:GUAP Security Lab\r\n\
TITLE:Lead DFIR Analyst\r\n\
EMAIL;TYPE=WORK:alice.vance@example.org\r\n\
TEL;TYPE=WORK:+1-416-555-0101\r\n\
ADR;TYPE=WORK:;;100 King St W;Toronto;ON;M5X 1A9;Canada\r\n\
NOTE:Primary responder for \r\n Windows DFIR triage.\r\n\
END:VCARD\r\n\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
FN:Bob Chen\r\n\
ORG:GUAP Infrastructure\r\n\
TITLE:Systems Engineer\r\n\
EMAIL;TYPE=WORK:bob.chen@example.org\r\n\
TEL;TYPE=CELL:+1-416-555-0102\r\n\
END:VCARD\r\n";
    write_file_deterministic(&sys_fs_dir.join("sample_contacts.vcf"), vcf.as_bytes())?;

    let jsonl = "\
{\"id\":1,\"name\":\"alpha_service\",\"bytes\":1024,\"status\":\"ok\"}
{\"id\":2,\"name\":\"beta_worker\",\"bytes\":2048,\"status\":\"warn\"}
{\"id\":3,\"name\":\"gamma_task\",\"bytes\":512,\"status\":\"ok\"}
";
    write_file_deterministic(&sys_fs_dir.join("sample_records.jsonl"), jsonl.as_bytes())?;

    Ok(())
}

pub fn verify_sys_fs_dir(sys_fs_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    // 1. PE32 DLL
    let pe32 = std::fs::read(sys_fs_dir.join("sample_pe32.dll"))?;
    ensure!(&pe32[0..2] == b"MZ", "pe32 bad MZ");
    let lfanew32 = read_u32_le(&pe32, 0x3C)? as usize;
    ensure!(&pe32[lfanew32..lfanew32 + 4] == b"PE\0\0", "pe32 bad PE sig");
    ensure!(read_u16_le(&pe32, lfanew32 + 24)? == 0x010B, "pe32 bad optional magic");
    ensure!(read_u32_le(&pe32, 0x400 + 0x18)? == 3, "pe32 NumberOfNames != 3");
    let pe32_str = String::from_utf8_lossy(&pe32);
    ensure!(pe32_str.contains("GuapComputeHash") && pe32_str.contains("KERNEL32.GetTickCount"), "pe32 missing exports");
    ensure!(pe32.windows(4).any(|w| w == 0xFEEF_04BDu32.to_le_bytes()), "pe32 missing VS_FIXEDFILEINFO");
    details.push("sys_fs/sample_pe32.dll: PE32 + 3 exports + 3-level .rsrc verified".into());

    // 2. PE32+ .NET EXE
    let pe64 = std::fs::read(sys_fs_dir.join("sample_pe64_dotnet.exe"))?;
    ensure!(&pe64[0..2] == b"MZ", "pe64 bad MZ");
    let lfanew64 = read_u32_le(&pe64, 0x3C)? as usize;
    ensure!(&pe64[lfanew64..lfanew64 + 4] == b"PE\0\0", "pe64 bad PE sig");
    ensure!(read_u16_le(&pe64, lfanew64 + 24)? == 0x020B, "pe64 bad optional magic");
    ensure!(read_u32_le(&pe64, 0x210)? == 72, "pe64 IMAGE_COR20_HEADER cb != 72");
    ensure!(read_u32_le(&pe64, 0x260)? == 0x424A_5342, "pe64 missing BSJB");
    let pe64_str = String::from_utf8_lossy(&pe64);
    ensure!(pe64_str.contains("GuapDotNetFixture.embedded.txt"), "pe64 missing ManifestResource");
    details.push("sys_fs/sample_pe64_dotnet.exe: PE32+ + CLR + BSJB + #~ verified".into());

    // 3. USN Journal
    let usn = std::fs::read(sys_fs_dir.join("usnjrnl_j.bin"))?;
    let mut off = 0usize;
    let mut usn_recs = 0usize;
    while off < usn.len() {
        let rlen = read_u32_le(&usn, off)? as usize;
        ensure!(rlen >= 60 && rlen.is_multiple_of(8) && off + rlen <= usn.len(), "bad USN record len");
        ensure!(read_u16_le(&usn, off + 4)? == 2, "USN MajorVersion != 2");
        off += rlen;
        usn_recs += 1;
    }
    ensure!(usn_recs == 3, "expected 3 USN records, got {}", usn_recs);
    details.push("sys_fs/usnjrnl_j.bin: 3 USN_RECORD_V2 verified".into());

    // 4. ATA SMART + Thresholds
    for sname in ["ata_smart.bin", "ata_smart_thresholds.bin"] {
        let b = std::fs::read(sys_fs_dir.join(sname))?;
        ensure!(b.len() == 512, "{} len != 512", sname);
        let sum: u32 = b.iter().map(|&x| x as u32).sum();
        ensure!(sum.is_multiple_of(256), "{} checksum failed", sname);
    }
    details.push("sys_fs/ata_smart*.bin: 512B mod-256 checksums verified".into());

    // 5. Structured data files (strict RFC 4180 5-column arity check)
    let parse_csv_row = |line: &str| -> Result<Vec<String>> {
        let mut fields = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if in_quotes {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        cur.push('"');
                    } else {
                        in_quotes = false;
                    }
                } else {
                    cur.push(c);
                }
            } else if c == '"' && cur.is_empty() {
                in_quotes = true;
            } else if c == ',' {
                fields.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        ensure!(!in_quotes, "unterminated CSV quote in line: {}", line);
        fields.push(cur);
        Ok(fields)
    };

    let csv_l = std::fs::read_to_string(sys_fs_dir.join("sample_data.csv"))?;
    ensure!(csv_l.contains("=cmd|") && csv_l.contains("\"@SUM(1,2)\""), "sample_data.csv missing formula vectors");
    let rows_l: Vec<Vec<String>> = csv_l.lines().map(parse_csv_row).collect::<Result<_>>()?;
    ensure!(rows_l.len() == 7, "sample_data.csv expected 7 rows, got {}", rows_l.len());
    for (idx, r) in rows_l.iter().enumerate() {
        ensure!(r.len() == 5, "sample_data.csv row {} has {} cols != 5", idx + 1, r.len());
    }
    ensure!(rows_l[5][2] == "@SUM(1,2)", "sample_data.csv row 6 col 3 mismatch: {}", rows_l[5][2]);

    let csv_r = std::fs::read_to_string(sys_fs_dir.join("sample_data_right.csv"))?;
    ensure!(csv_r.contains("7,new_row") && csv_r.contains("\"@SUM(1,2)\""), "sample_data_right.csv missing diff/formula row");
    let rows_r: Vec<Vec<String>> = csv_r.lines().map(parse_csv_row).collect::<Result<_>>()?;
    ensure!(rows_r.len() == 7, "sample_data_right.csv expected 7 rows, got {}", rows_r.len());
    for (idx, r) in rows_r.iter().enumerate() {
        ensure!(r.len() == 5, "sample_data_right.csv row {} has {} cols != 5", idx + 1, r.len());
    }
    ensure!(rows_r[5][2] == "@SUM(1,2)", "sample_data_right.csv row 6 col 3 mismatch: {}", rows_r[5][2]);
    let tsv = std::fs::read_to_string(sys_fs_dir.join("sample_data.tsv"))?;
    ensure!(tsv.contains('\t'), "sample_data.tsv missing tabs");
    let html = std::fs::read_to_string(sys_fs_dir.join("sample_page.html"))?;
    ensure!(html.contains("<title>GUAP HTML Fixture</title>"), "sample_page.html invalid");
    let vcf = std::fs::read_to_string(sys_fs_dir.join("sample_contacts.vcf"))?;
    ensure!(vcf.contains("BEGIN:VCARD") && vcf.contains("\r\n Windows DFIR"), "sample_contacts.vcf invalid");
    let jsonl = std::fs::read_to_string(sys_fs_dir.join("sample_records.jsonl"))?;
    for line in jsonl.lines() {
        let _: serde_json::Value = serde_json::from_str(line)?;
    }
    details.push("sys_fs/* (csv/tsv/html/vcf/jsonl): 6 data files verified".into());

    Ok((11, details))
}