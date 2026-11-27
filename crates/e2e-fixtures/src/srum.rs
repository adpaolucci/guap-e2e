use crate::util::{
    FIXED_FILETIME, read_u16_le, read_u32_le, utf16le_bytes, write_file_deterministic, xor32_u32s,
};
use anyhow::{Result, ensure};
use std::path::Path;

const ESE_PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy)]
pub enum EseColTyp {
    UnsignedByte = 2,
    Short = 3,
    Long = 4,
    Binary = 9,
    Text = 10,
    LongBinary = 11,
    LongText = 12,
    LongLong = 15,
}

pub enum EseVal {
    U8(u8),
    I16(i16),
    I32(i32),
    I64(i64),
    Bytes(Vec<u8>),
}

struct EseColumnSpec {
    name: &'static str,
    coltyp: EseColTyp,
    fid: u16,
    cb_max: u32,
}

struct EseTableSpec {
    name: &'static str,
    objid_fdp: u32,
    columns: Vec<EseColumnSpec>,
    rows: Vec<Vec<(u16, EseVal)>>,
}

fn encode_ese_record(cols: &[EseColumnSpec], row: &[(u16, EseVal)]) -> Vec<u8> {
    let fixed_cols: Vec<&EseColumnSpec> = cols.iter().filter(|c| c.fid < 0x80).collect();
    let var_cols: Vec<&EseColumnSpec> = cols
        .iter()
        .filter(|c| c.fid >= 0x80 && c.fid < 0x100)
        .collect();

    let fid_fixed_last = fixed_cols.iter().map(|c| c.fid).max().unwrap_or(0) as u8;
    let fid_var_last = if var_cols.is_empty() {
        0x7Fu8
    } else {
        var_cols.iter().map(|c| c.fid).max().unwrap_or(0x80) as u8
    };

    let mut fixed_data = Vec::new();
    let null_bmp_len = (fid_fixed_last as usize).div_ceil(8);
    let mut null_bmp = vec![0u8; null_bmp_len];

    for fid in 1..=fid_fixed_last {
        let col = fixed_cols.iter().find(|c| c.fid == fid as u16);
        let val = row.iter().find(|(id, _)| *id == fid as u16).map(|(_, v)| v);
        match (col, val) {
            (Some(c), Some(v)) => match (c.coltyp, v) {
                (EseColTyp::UnsignedByte, EseVal::U8(b)) => fixed_data.push(*b),
                (EseColTyp::Short, EseVal::I16(x)) => {
                    fixed_data.extend_from_slice(&x.to_le_bytes())
                }
                (EseColTyp::Long, EseVal::I32(x)) => fixed_data.extend_from_slice(&x.to_le_bytes()),
                (EseColTyp::LongLong, EseVal::I64(x)) => {
                    fixed_data.extend_from_slice(&x.to_le_bytes())
                }
                _ => {
                    let sz = match c.coltyp {
                        EseColTyp::UnsignedByte => 1,
                        EseColTyp::Short => 2,
                        EseColTyp::Long => 4,
                        EseColTyp::LongLong => 8,
                        _ => 4,
                    };
                    fixed_data.resize(fixed_data.len() + sz, 0);
                    null_bmp[(fid as usize - 1) / 8] |= 1 << ((fid as usize - 1) % 8);
                }
            },
            (Some(c), None) => {
                let sz = match c.coltyp {
                    EseColTyp::UnsignedByte => 1,
                    EseColTyp::Short => 2,
                    EseColTyp::Long => 4,
                    EseColTyp::LongLong => 8,
                    _ => 4,
                };
                fixed_data.resize(fixed_data.len() + sz, 0);
                null_bmp[(fid as usize - 1) / 8] |= 1 << ((fid as usize - 1) % 8);
            }
            (None, _) => {}
        }
    }

    let var_count = if fid_var_last >= 0x80 {
        (fid_var_last - 0x80 + 1) as usize
    } else {
        0
    };
    let mut var_offsets = vec![0u16; var_count];
    let mut var_data = Vec::new();
    for (i, slot) in var_offsets.iter_mut().enumerate() {
        let fid = 0x80u16 + i as u16;
        if let Some((_, EseVal::Bytes(b))) = row.iter().find(|(id, _)| *id == fid) {
            var_data.extend_from_slice(b);
            *slot = var_data.len() as u16;
        } else {
            *slot = (var_data.len() as u16) | 0x8000;
        }
    }

    let ib_tagged = 4 + fixed_data.len() + null_bmp.len() + var_count * 2 + var_data.len();
    let mut out = Vec::with_capacity(ib_tagged);
    out.push(fid_fixed_last);
    out.push(fid_var_last);
    out.extend_from_slice(&(ib_tagged as u16).to_le_bytes());
    out.extend_from_slice(&fixed_data);
    out.extend_from_slice(&null_bmp);
    for off in var_offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(&var_data);
    out
}

fn compute_page_ecc(body: &[u8]) -> (u16, u16) {
    let mut ecc: u16 = 0;
    let mut parity: u32 = 0;
    for (byte_idx, &byte) in body.iter().enumerate() {
        let mut b = byte;
        for bit in 0..8 {
            if (b & 1) != 0 {
                let bit_index = ((byte_idx * 8) + bit) as u16;
                ecc ^= bit_index;
                parity ^= 1;
            }
            b >>= 1;
        }
    }
    let ecc_high = if parity == 1 { ecc ^ 0x7FFF } else { ecc };
    (ecc, ecc_high)
}

fn build_leaf_page(
    pgno: u32,
    pgno_prev: u32,
    pgno_next: u32,
    objid_fdp: u32,
    is_root: bool,
    records: &[(u32, Vec<u8>)],
) -> Vec<u8> {
    let mut page = vec![0u8; ESE_PAGE_SIZE];
    let mut cursor = 40usize;
    let mut tags: Vec<(u16, u16, u16)> = Vec::new(); // (cb, ib, flags)

    // Tag 0: External Header (16 bytes)
    let ext_hdr: [u8; 16] = [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    page[cursor..cursor + 16].copy_from_slice(&ext_hdr);
    tags.push((16, 0, 0));
    cursor += 16;

    for (key_idx, rec_bytes) in records {
        let ib = (cursor - 40) as u16;
        let mut entry = Vec::with_capacity(6 + rec_bytes.len());
        entry.extend_from_slice(&4u16.to_le_bytes()); // cbPageKey
        entry.extend_from_slice(&key_idx.to_be_bytes());
        entry.extend_from_slice(rec_bytes);
        let cb = entry.len() as u16;
        page[cursor..cursor + entry.len()].copy_from_slice(&entry);
        cursor += entry.len();
        tags.push((cb, ib, 0));
    }

    let tag_count = tags.len();
    let used_data = cursor - 40;
    let cb_free = (ESE_PAGE_SIZE - 40 - used_data - tag_count * 4) as u16;
    let ib_mic_free = used_data as u16;
    let itag_mic_free = tag_count as u16;
    let flags: u32 = if is_root { 0x0000_A803 } else { 0x0000_A802 };

    page[0x08..0x10].copy_from_slice(&1u64.to_le_bytes()); // dbtimeDirtied
    page[0x10..0x14].copy_from_slice(&pgno_prev.to_le_bytes());
    page[0x14..0x18].copy_from_slice(&pgno_next.to_le_bytes());
    page[0x18..0x1C].copy_from_slice(&objid_fdp.to_le_bytes());
    page[0x1C..0x1E].copy_from_slice(&cb_free.to_le_bytes());
    page[0x1E..0x20].copy_from_slice(&0u16.to_le_bytes());
    page[0x20..0x22].copy_from_slice(&ib_mic_free.to_le_bytes());
    page[0x22..0x24].copy_from_slice(&itag_mic_free.to_le_bytes());
    page[0x24..0x28].copy_from_slice(&flags.to_le_bytes());

    for (t, &(cb, ib, tflags)) in tags.iter().enumerate() {
        let off = ESE_PAGE_SIZE - 4 * (t + 1);
        let ib_and_flags = (ib & 0x1FFF) | ((tflags & 0x7) << 13);
        page[off..off + 2].copy_from_slice(&cb.to_le_bytes());
        page[off + 2..off + 4].copy_from_slice(&ib_and_flags.to_le_bytes());
    }

    let xor_ck = pgno ^ xor32_u32s(&page[8..ESE_PAGE_SIZE]);
    let (ecc_low, ecc_high) = compute_page_ecc(&page[8..ESE_PAGE_SIZE]);
    page[0x00..0x04].copy_from_slice(&xor_ck.to_le_bytes());
    page[0x04..0x06].copy_from_slice(&ecc_low.to_le_bytes());
    page[0x06..0x08].copy_from_slice(&ecc_high.to_le_bytes());
    page
}

fn build_catalog_records(
    msys_cols: &[EseColumnSpec],
    tables: &[EseTableSpec],
    pgno_firsts: &[u32],
) -> Vec<(u32, Vec<u8>)> {
    let mut catalog_records: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut key_seq = 1u32;
    for (tbl, &pgno_first) in tables.iter().zip(pgno_firsts.iter()) {
        let trow = vec![
            (1, EseVal::I32(tbl.objid_fdp as i32)),
            (2, EseVal::I16(1)), // Type 1 = Table
            (3, EseVal::I32(tbl.objid_fdp as i32)),
            (4, EseVal::I32(pgno_first as i32)),
            (5, EseVal::I32(1)),
            (6, EseVal::I32(0)),
            (7, EseVal::I32(1)),
            (0x80, EseVal::Bytes(tbl.name.as_bytes().to_vec())),
        ];
        catalog_records.push((key_seq, encode_ese_record(msys_cols, &trow)));
        key_seq += 1;

        for col in &tbl.columns {
            let crow = vec![
                (1, EseVal::I32(tbl.objid_fdp as i32)),
                (2, EseVal::I16(2)), // Type 2 = Column
                (3, EseVal::I32(col.fid as i32)),
                (4, EseVal::I32(col.coltyp as i32)),
                (5, EseVal::I32(col.cb_max as i32)),
                (6, EseVal::I32(0)),
                (7, EseVal::I32(1200)),
                (0x80, EseVal::Bytes(col.name.as_bytes().to_vec())),
            ];
            catalog_records.push((key_seq, encode_ese_record(msys_cols, &crow)));
            key_seq += 1;
        }
    }
    catalog_records
}

fn chunk_catalog_records(catalog_records: Vec<(u32, Vec<u8>)>) -> Vec<Vec<(u32, Vec<u8>)>> {
    let mut chunks: Vec<Vec<(u32, Vec<u8>)>> = vec![Vec::new()];
    let mut cur_used = 40 + 16;
    for rec in catalog_records {
        let need = 6 + rec.1.len() + 4;
        if cur_used + need > ESE_PAGE_SIZE - 64 && !chunks.last().unwrap().is_empty() {
            chunks.push(Vec::new());
            cur_used = 40 + 16;
        }
        cur_used += need;
        chunks.last_mut().unwrap().push(rec);
    }
    chunks
}

fn build_ese_db(tables: &[EseTableSpec]) -> Result<Vec<u8>> {
    let msys_cols = vec![
        EseColumnSpec {
            name: "ObjidTable",
            coltyp: EseColTyp::Long,
            fid: 1,
            cb_max: 4,
        },
        EseColumnSpec {
            name: "Type",
            coltyp: EseColTyp::Short,
            fid: 2,
            cb_max: 2,
        },
        EseColumnSpec {
            name: "Id",
            coltyp: EseColTyp::Long,
            fid: 3,
            cb_max: 4,
        },
        EseColumnSpec {
            name: "ColtypOrPgnoFDP",
            coltyp: EseColTyp::Long,
            fid: 4,
            cb_max: 4,
        },
        EseColumnSpec {
            name: "SpaceUsage",
            coltyp: EseColTyp::Long,
            fid: 5,
            cb_max: 4,
        },
        EseColumnSpec {
            name: "Flags",
            coltyp: EseColTyp::Long,
            fid: 6,
            cb_max: 4,
        },
        EseColumnSpec {
            name: "PagesOrLocale",
            coltyp: EseColTyp::Long,
            fid: 7,
            cb_max: 4,
        },
        EseColumnSpec {
            name: "Name",
            coltyp: EseColTyp::Text,
            fid: 0x80,
            cb_max: 255,
        },
    ];

    // Pass 1: determine exact catalog page count (ColtypOrPgnoFDP is always a fixed 4-byte Long)
    let placeholder_pgnos = vec![0u32; tables.len()];
    let cat_page_count = chunk_catalog_records(build_catalog_records(
        &msys_cols,
        tables,
        &placeholder_pgnos,
    ))
    .len() as u32;

    // Pass 2: assign contiguous pgno_first starting immediately after MSysObjects (no zero-page holes)
    let pgno_firsts: Vec<u32> = (0..tables.len())
        .map(|i| cat_page_count + 1 + i as u32)
        .collect();
    let chunks = chunk_catalog_records(build_catalog_records(&msys_cols, tables, &pgno_firsts));
    ensure!(
        chunks.len() as u32 == cat_page_count,
        "ESE catalog page count mismatch"
    );

    let mut pages: Vec<(u32, Vec<u8>)> = Vec::new();
    for (idx, chunk) in chunks.into_iter().enumerate() {
        let pgno = 1 + idx as u32;
        let prev = if idx == 0 { 0 } else { pgno - 1 };
        let next = if idx + 1 < cat_page_count as usize {
            pgno + 1
        } else {
            0
        };
        pages.push((pgno, build_leaf_page(pgno, prev, next, 2, idx == 0, &chunk)));
    }

    for (tbl, &pgno_first) in tables.iter().zip(pgno_firsts.iter()) {
        let mut recs = Vec::with_capacity(tbl.rows.len());
        for (i, row) in tbl.rows.iter().enumerate() {
            recs.push(((i + 1) as u32, encode_ese_record(&tbl.columns, row)));
        }
        pages.push((
            pgno_first,
            build_leaf_page(pgno_first, 0, 0, tbl.objid_fdp, true, &recs),
        ));
    }

    let max_pgno = pages.iter().map(|(p, _)| *p).max().unwrap_or(1);
    let max_objid = tables.iter().map(|t| t.objid_fdp).max().unwrap_or(2);

    let mut hdr = vec![0u8; ESE_PAGE_SIZE];
    hdr[0x04..0x08].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes()); // ulMagic
    hdr[0x08..0x0C].copy_from_slice(&0x0000_0620u32.to_le_bytes()); // ulVersion
    hdr[0x0C..0x10].copy_from_slice(&0u32.to_le_bytes()); // attrib (Database)
    hdr[0x10..0x18].copy_from_slice(&100u64.to_le_bytes()); // dbtimeDirtied
    // signDb (28B): deterministic ulRandom + fixed LOGTIME (2026-11-22T14:30:00Z)
    hdr[0x18..0x1C].copy_from_slice(&0x4755_4150u32.to_le_bytes());
    hdr[0x1C..0x24].copy_from_slice(&[0, 30, 14, 22, 11, 126, 0, 0]);
    hdr[0x34..0x38].copy_from_slice(&3u32.to_le_bytes()); // JET_dbstateCleanShutdown
    hdr[0xD4..0xD8].copy_from_slice(&max_objid.to_le_bytes()); // objidLast
    hdr[0xE4..0xE8].copy_from_slice(&0x0000_0620u32.to_le_bytes()); // ulVersion (format)
    hdr[0xE8..0xEC].copy_from_slice(&0x0000_012Cu32.to_le_bytes()); // ulUpdate
    hdr[0xEC..0xF0].copy_from_slice(&(ESE_PAGE_SIZE as u32).to_le_bytes());
    let hdr_cksum = 0x89AB_CDEFu32 ^ xor32_u32s(&hdr[4..ESE_PAGE_SIZE]);
    hdr[0x00..0x04].copy_from_slice(&hdr_cksum.to_le_bytes());

    let mut db = vec![0u8; (max_pgno as usize + 2) * ESE_PAGE_SIZE];
    db[0..ESE_PAGE_SIZE].copy_from_slice(&hdr);
    db[ESE_PAGE_SIZE..2 * ESE_PAGE_SIZE].copy_from_slice(&hdr);
    for (pgno, page_bytes) in pages {
        let off = (pgno as usize + 1) * ESE_PAGE_SIZE;
        db[off..off + ESE_PAGE_SIZE].copy_from_slice(&page_bytes);
    }
    Ok(db)
}

pub fn generate_srum_dir(srum_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(srum_dir)?;

    let alice_sid = vec![
        1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xE9, 0x03, 0, 0, 0xD2, 0x07, 0, 0, 0xBB, 0x0B, 0, 0,
        0xE9, 0x03, 0, 0,
    ];

    let srudb_tables = vec![
        EseTableSpec {
            name: "SruDbIdMapTable",
            objid_fdp: 10,
            columns: vec![
                EseColumnSpec {
                    name: "IdType",
                    coltyp: EseColTyp::UnsignedByte,
                    fid: 1,
                    cb_max: 1,
                },
                EseColumnSpec {
                    name: "IdIndex",
                    coltyp: EseColTyp::Long,
                    fid: 2,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "IdBlob",
                    coltyp: EseColTyp::LongBinary,
                    fid: 0x80,
                    cb_max: 512,
                },
            ],
            rows: vec![
                vec![
                    (1, EseVal::U8(0)),
                    (2, EseVal::I32(1)),
                    (
                        0x80,
                        EseVal::Bytes(utf16le_bytes(
                            r"\Device\HarddiskVolume3\Tools\forensics_sample.exe",
                        )),
                    ),
                ],
                vec![
                    (1, EseVal::U8(3)),
                    (2, EseVal::I32(2)),
                    (0x80, EseVal::Bytes(alice_sid)),
                ],
            ],
        },
        EseTableSpec {
            name: "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
            objid_fdp: 11,
            columns: vec![
                EseColumnSpec {
                    name: "AutoIncId",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "TimeStamp",
                    coltyp: EseColTyp::LongLong,
                    fid: 2,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "AppId",
                    coltyp: EseColTyp::Long,
                    fid: 3,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UserId",
                    coltyp: EseColTyp::Long,
                    fid: 4,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "InterfaceLuid",
                    coltyp: EseColTyp::LongLong,
                    fid: 5,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "L2ProfileId",
                    coltyp: EseColTyp::LongLong,
                    fid: 6,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "L2ProfileFlags",
                    coltyp: EseColTyp::Long,
                    fid: 7,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "BytesSent",
                    coltyp: EseColTyp::LongLong,
                    fid: 8,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "BytesRecvd",
                    coltyp: EseColTyp::LongLong,
                    fid: 9,
                    cb_max: 8,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(1)),
                (2, EseVal::I64(FIXED_FILETIME as i64)),
                (3, EseVal::I32(1)),
                (4, EseVal::I32(2)),
                (5, EseVal::I64(0x0006_0000_0000_0001)),
                (6, EseVal::I64(1)),
                (7, EseVal::I32(0)),
                (8, EseVal::I64(1_048_576)),
                (9, EseVal::I64(262_144)),
            ]],
        },
        EseTableSpec {
            name: "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
            objid_fdp: 12,
            columns: vec![
                EseColumnSpec {
                    name: "AutoIncId",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "TimeStamp",
                    coltyp: EseColTyp::LongLong,
                    fid: 2,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "AppId",
                    coltyp: EseColTyp::Long,
                    fid: 3,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UserId",
                    coltyp: EseColTyp::Long,
                    fid: 4,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "ForegroundCycleTime",
                    coltyp: EseColTyp::LongLong,
                    fid: 5,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "BackgroundCycleTime",
                    coltyp: EseColTyp::LongLong,
                    fid: 6,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "FaceTime",
                    coltyp: EseColTyp::LongLong,
                    fid: 7,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "ForegroundBytesRead",
                    coltyp: EseColTyp::LongLong,
                    fid: 8,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "ForegroundBytesWritten",
                    coltyp: EseColTyp::LongLong,
                    fid: 9,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "BackgroundBytesRead",
                    coltyp: EseColTyp::LongLong,
                    fid: 10,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "BackgroundBytesWritten",
                    coltyp: EseColTyp::LongLong,
                    fid: 11,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "ForegroundContextSwitches",
                    coltyp: EseColTyp::Long,
                    fid: 12,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "BackgroundContextSwitches",
                    coltyp: EseColTyp::Long,
                    fid: 13,
                    cb_max: 4,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(1)),
                (2, EseVal::I64(FIXED_FILETIME as i64)),
                (3, EseVal::I32(1)),
                (4, EseVal::I32(2)),
                (5, EseVal::I64(500_000_000)),
                (6, EseVal::I64(25_000_000)),
                (7, EseVal::I64(120_000_000)),
                (8, EseVal::I64(65_536)),
                (9, EseVal::I64(16_384)),
                (10, EseVal::I64(4_096)),
                (11, EseVal::I64(1_024)),
                (12, EseVal::I32(320)),
                (13, EseVal::I32(45)),
            ]],
        },
        EseTableSpec {
            name: "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
            objid_fdp: 13,
            columns: vec![
                EseColumnSpec {
                    name: "AutoIncId",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "TimeStamp",
                    coltyp: EseColTyp::LongLong,
                    fid: 2,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "AppId",
                    coltyp: EseColTyp::Long,
                    fid: 3,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UserId",
                    coltyp: EseColTyp::Long,
                    fid: 4,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "BinaryData",
                    coltyp: EseColTyp::LongBinary,
                    fid: 0x80,
                    cb_max: 64,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(1)),
                (2, EseVal::I64(FIXED_FILETIME as i64)),
                (3, EseVal::I32(1)),
                (4, EseVal::I32(2)),
                (
                    0x80,
                    EseVal::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
                ),
            ]],
        },
        EseTableSpec {
            name: "{DD6636C4-8929-4683-974E-22C046A43763}",
            objid_fdp: 14,
            columns: vec![
                EseColumnSpec {
                    name: "AutoIncId",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "TimeStamp",
                    coltyp: EseColTyp::LongLong,
                    fid: 2,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "AppId",
                    coltyp: EseColTyp::Long,
                    fid: 3,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UserId",
                    coltyp: EseColTyp::Long,
                    fid: 4,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "InterfaceLuid",
                    coltyp: EseColTyp::LongLong,
                    fid: 5,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "L2ProfileId",
                    coltyp: EseColTyp::LongLong,
                    fid: 6,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "ConnectedTime",
                    coltyp: EseColTyp::Long,
                    fid: 7,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "ConnectStartTime",
                    coltyp: EseColTyp::LongLong,
                    fid: 8,
                    cb_max: 8,
                },
                EseColumnSpec {
                    name: "L2ProfileFlags",
                    coltyp: EseColTyp::Long,
                    fid: 9,
                    cb_max: 4,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(1)),
                (2, EseVal::I64(FIXED_FILETIME as i64)),
                (3, EseVal::I32(1)),
                (4, EseVal::I32(2)),
                (5, EseVal::I64(0x0006_0000_0000_0001)),
                (6, EseVal::I64(1)),
                (7, EseVal::I32(3600)),
                (8, EseVal::I64((FIXED_FILETIME - 36_000_000_000) as i64)),
                (9, EseVal::I32(0)),
            ]],
        },
    ];
    write_file_deterministic(&srum_dir.join("SRUDB.dat"), &build_ese_db(&srudb_tables)?)?;

    let datastore_tables = vec![
        EseTableSpec {
            name: "tbHistory",
            objid_fdp: 10,
            columns: vec![
                EseColumnSpec {
                    name: "IdEvent",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "Status",
                    coltyp: EseColTyp::Long,
                    fid: 2,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "ServerSelection",
                    coltyp: EseColTyp::Long,
                    fid: 3,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "MappedResult",
                    coltyp: EseColTyp::Long,
                    fid: 4,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UnmappedResult",
                    coltyp: EseColTyp::Long,
                    fid: 5,
                    cb_max: 4,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(1)),
                (2, EseVal::I32(2)), // Succeeded
                (3, EseVal::I32(2)),
                (4, EseVal::I32(0)),
                (5, EseVal::I32(0)),
            ]],
        },
        EseTableSpec {
            name: "tbUpdates",
            objid_fdp: 11,
            columns: vec![
                EseColumnSpec {
                    name: "IdLocal",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "RevisionNumber",
                    coltyp: EseColTyp::Long,
                    fid: 2,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UpdateDataAvailable",
                    coltyp: EseColTyp::Long,
                    fid: 3,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "UpdateId",
                    coltyp: EseColTyp::Binary,
                    fid: 0x80,
                    cb_max: 16,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(101)),
                (2, EseVal::I32(1)),
                (3, EseVal::I32(1)),
                (0x80, EseVal::Bytes(vec![0x11; 16])),
            ]],
        },
        EseTableSpec {
            name: "tbUpdateLocalizedProps",
            objid_fdp: 12,
            columns: vec![
                EseColumnSpec {
                    name: "IdLocal",
                    coltyp: EseColTyp::Long,
                    fid: 1,
                    cb_max: 4,
                },
                EseColumnSpec {
                    name: "Title",
                    coltyp: EseColTyp::LongText,
                    fid: 0x80,
                    cb_max: 512,
                },
                EseColumnSpec {
                    name: "Description",
                    coltyp: EseColTyp::LongText,
                    fid: 0x81,
                    cb_max: 1024,
                },
                EseColumnSpec {
                    name: "SupportUrl",
                    coltyp: EseColTyp::LongText,
                    fid: 0x82,
                    cb_max: 512,
                },
            ],
            rows: vec![vec![
                (1, EseVal::I32(101)),
                (
                    0x80,
                    EseVal::Bytes(utf16le_bytes(
                        "2026-11 Cumulative Update for Windows 11 (KB5048685)",
                    )),
                ),
                (
                    0x81,
                    EseVal::Bytes(utf16le_bytes("Security and quality improvements.")),
                ),
                (
                    0x82,
                    EseVal::Bytes(utf16le_bytes("https://support.microsoft.com/kb/5048685")),
                ),
            ]],
        },
    ];
    write_file_deterministic(
        &srum_dir.join("DataStore.edb"),
        &build_ese_db(&datastore_tables)?,
    )?;

    Ok(())
}

pub fn verify_srum_dir(srum_dir: &Path) -> Result<(usize, Vec<String>)> {
    let checks: [(&str, &[&str]); 2] = [
        (
            "SRUDB.dat",
            &[
                "SruDbIdMapTable",
                "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
                "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
                "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
                "{DD6636C4-8929-4683-974E-22C046A43763}",
            ],
        ),
        (
            "DataStore.edb",
            &["tbHistory", "tbUpdates", "tbUpdateLocalizedProps"],
        ),
    ];

    let mut details = Vec::new();
    for (fname, required_tables) in &checks {
        let buf = std::fs::read(srum_dir.join(fname))?;
        ensure!(
            buf.len() >= 3 * ESE_PAGE_SIZE && buf.len() % ESE_PAGE_SIZE == 0,
            "{}: bad size",
            fname
        );
        let p0 = &buf[0..ESE_PAGE_SIZE];
        let p1 = &buf[ESE_PAGE_SIZE..2 * ESE_PAGE_SIZE];
        ensure!(
            p0 == p1,
            "{}: primary and backup header pages differ",
            fname
        );
        ensure!(
            read_u32_le(p0, 4)? == 0x89AB_CDEF,
            "{}: bad ESE signature",
            fname
        );
        ensure!(
            read_u32_le(p0, 0xEC)? == ESE_PAGE_SIZE as u32,
            "{}: bad page size",
            fname
        );
        let expected_hdr_ck = 0x89AB_CDEFu32 ^ xor32_u32s(&p0[4..ESE_PAGE_SIZE]);
        ensure!(
            read_u32_le(p0, 0)? == expected_hdr_ck,
            "{}: header XOR checksum mismatch",
            fname
        );

        let num_data_pages = (buf.len() / ESE_PAGE_SIZE) - 2;
        for idx in 0..num_data_pages {
            let pgno = (idx + 1) as u32;
            let page = &buf[(idx + 2) * ESE_PAGE_SIZE..(idx + 3) * ESE_PAGE_SIZE];
            let expected_xor = pgno ^ xor32_u32s(&page[8..ESE_PAGE_SIZE]);
            let stored_xor = read_u32_le(page, 0)?;
            let stored_ecc_low = read_u16_le(page, 4)?;
            let stored_ecc_high = read_u16_le(page, 6)?;
            let (calc_low, calc_high) = compute_page_ecc(&page[8..ESE_PAGE_SIZE]);
            ensure!(
                read_u32_le(page, 0x18)? != 0,
                "{}: page {} has zero objidFDP (uninitialized page)",
                fname,
                pgno
            );
            ensure!(
                stored_xor == expected_xor,
                "{}: page {} XOR mismatch",
                fname,
                pgno
            );
            ensure!(
                stored_ecc_low == calc_low && stored_ecc_high == calc_high,
                "{}: page {} ECC mismatch",
                fname,
                pgno
            );
        }

        let catalog_slice = &buf[2 * ESE_PAGE_SIZE..];
        let catalog_str = String::from_utf8_lossy(catalog_slice);
        for tname in *required_tables {
            ensure!(
                catalog_str.contains(tname),
                "{}: missing table {}",
                fname,
                tname
            );
        }
        details.push(format!(
            "srum/{}: {} data pages verified (ECC+XOR OK)",
            fname, num_data_pages
        ));
    }

    Ok((checks.len(), details))
}
