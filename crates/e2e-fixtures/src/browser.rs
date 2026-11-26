use std::path::Path;
use anyhow::{ensure, Result};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use crate::lz4_block::{decode_mozlz4, encode_mozlz4};
use crate::util::{
    crc32_ieee, read_u16_be, read_u32_be, sha1_hex_upper, write_file_deterministic,
    FIXED_CF_TIME, FIXED_CHROME_US, FIXED_PRTIME_US, FIXED_UNIX_SECS,
};

pub fn build_sample_exif_jpg() -> Vec<u8> {
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II");
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes());

    let ifd0_count = 6u16;
    let ifd0_end = 8 + 2 + (ifd0_count as usize) * 12 + 4;
    let mut extra = Vec::new();
    let mut push_extra = |bytes: &[u8]| -> u32 {
        let off = (ifd0_end + extra.len()) as u32;
        extra.extend_from_slice(bytes);
        if extra.len() % 2 != 0 {
            extra.push(0);
        }
        off
    };

    let make_off = push_extra(b"GUAPCamera\0");
    let model_off = push_extra(b"GX-1000\0");
    let dt_off = push_extra(b"2026:11:22 14:30:00\0");

    let exif_ifd_off = (ifd0_end + extra.len()) as u32;
    let exif_data_base = exif_ifd_off + 54;
    let exp_off = exif_data_base;
    let fnum_off = exif_data_base + 8;
    let dto_off = exif_data_base + 16;

    let mut exif_ifd = Vec::new();
    exif_ifd.extend_from_slice(&4u16.to_le_bytes());
    let push_ifd_entry = |dst: &mut Vec<u8>, tag: u16, ty: u16, cnt: u32, val: u32| {
        dst.extend_from_slice(&tag.to_le_bytes());
        dst.extend_from_slice(&ty.to_le_bytes());
        dst.extend_from_slice(&cnt.to_le_bytes());
        dst.extend_from_slice(&val.to_le_bytes());
    };
    push_ifd_entry(&mut exif_ifd, 0x829A, 5, 1, exp_off);
    push_ifd_entry(&mut exif_ifd, 0x829D, 5, 1, fnum_off);
    push_ifd_entry(&mut exif_ifd, 0x8827, 3, 1, 200);
    push_ifd_entry(&mut exif_ifd, 0x9003, 2, 20, dto_off);
    exif_ifd.extend_from_slice(&0u32.to_le_bytes());
    exif_ifd.extend_from_slice(&1u32.to_le_bytes());
    exif_ifd.extend_from_slice(&125u32.to_le_bytes());
    exif_ifd.extend_from_slice(&28u32.to_le_bytes());
    exif_ifd.extend_from_slice(&10u32.to_le_bytes());
    exif_ifd.extend_from_slice(b"2026:11:22 14:30:00\0");
    extra.extend_from_slice(&exif_ifd);

    let gps_ifd_off = (ifd0_end + extra.len()) as u32;
    let gps_data_base = gps_ifd_off + 54;
    let lat_off = gps_data_base;
    let lon_off = gps_data_base + 24;
    let mut gps_ifd = Vec::new();
    gps_ifd.extend_from_slice(&4u16.to_le_bytes());
    push_ifd_entry(&mut gps_ifd, 0x0001, 2, 2, u32::from_le_bytes(*b"N\0\0\0"));
    push_ifd_entry(&mut gps_ifd, 0x0002, 5, 3, lat_off);
    push_ifd_entry(&mut gps_ifd, 0x0003, 2, 2, u32::from_le_bytes(*b"W\0\0\0"));
    push_ifd_entry(&mut gps_ifd, 0x0004, 5, 3, lon_off);
    gps_ifd.extend_from_slice(&0u32.to_le_bytes());
    for (num, den) in [(43u32, 1u32), (39, 1), (1152, 100), (79, 1), (22, 1), (5952, 100)] {
        gps_ifd.extend_from_slice(&num.to_le_bytes());
        gps_ifd.extend_from_slice(&den.to_le_bytes());
    }
    extra.extend_from_slice(&gps_ifd);

    tiff.extend_from_slice(&ifd0_count.to_le_bytes());
    push_ifd_entry(&mut tiff, 0x010F, 2, 11, make_off);
    push_ifd_entry(&mut tiff, 0x0110, 2, 8, model_off);
    push_ifd_entry(&mut tiff, 0x0112, 3, 1, 1);
    push_ifd_entry(&mut tiff, 0x0132, 2, 20, dt_off);
    push_ifd_entry(&mut tiff, 0x8769, 4, 1, exif_ifd_off);
    push_ifd_entry(&mut tiff, 0x8825, 4, 1, gps_ifd_off);
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(&extra);

    let mut jpg = Vec::new();
    jpg.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE1]);
    let app1_len = (2 + 6 + tiff.len()) as u16;
    jpg.extend_from_slice(&app1_len.to_be_bytes());
    jpg.extend_from_slice(b"Exif\0\0");
    jpg.extend_from_slice(&tiff);
    jpg.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    jpg.extend_from_slice(&[1u8; 64]);
    jpg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00]);
    jpg.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x14, 0x00, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x00, 0xFF, 0xD9]);
    jpg
}

fn build_mp4_segment(is_init: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&24u32.to_be_bytes());
    if is_init {
        out.extend_from_slice(b"ftypisom");
        out.extend_from_slice(&0x0000_0200u32.to_be_bytes());
        out.extend_from_slice(b"isommp42");
    } else {
        out.extend_from_slice(b"stypmsdh");
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(b"msdhmsix");
    }
    out.extend_from_slice(&72u32.to_be_bytes());
    out.extend_from_slice(b"moof");
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(b"mfhd");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&48u32.to_be_bytes());
    out.extend_from_slice(b"traf");
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(b"tfhd");
    out.extend_from_slice(&0x0002_0000u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"trun");
    out.extend_from_slice(&0x0000_0201u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&0x0000_0050u32.to_be_bytes());
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"mdat");
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x0C, 0x65, 0x88, 0x84, 0x21, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
    out
}

fn build_firefox_cache2_entry(key: &str, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let p_len = payload.len();
    let mut out = Vec::with_capacity(p_len + 256);
    out.extend_from_slice(payload);
    for chunk in payload.chunks(256 * 1024) {
        let crc = crc32_ieee(chunk);
        let h16 = (((crc >> 16) ^ (crc & 0xFFFF)) & 0xFFFF) as u16;
        out.extend_from_slice(&h16.to_be_bytes());
    }
    out.extend_from_slice(&3u32.to_be_bytes());
    out.extend_from_slice(&5u32.to_be_bytes());
    out.extend_from_slice(&(FIXED_UNIX_SECS as u32).to_be_bytes());
    out.extend_from_slice(&((FIXED_UNIX_SECS - 600) as u32).to_be_bytes());
    out.extend_from_slice(&100u32.to_be_bytes());
    out.extend_from_slice(&((FIXED_UNIX_SECS + 86400) as u32).to_be_bytes());
    out.extend_from_slice(&(key.len() as u32).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(key.as_bytes());
    out.push(0x00);
    let resp_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nServer: guap-test\r\n\r\n",
        content_type, p_len
    );
    out.extend_from_slice(b"response-head\0");
    out.extend_from_slice(resp_head.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&(p_len as u32).to_be_bytes());
    out
}

#[derive(Clone)]
enum PlistVal {
    Int(i64),
    Date(f64),
    Ascii(String),
    Array(Vec<PlistVal>),
    Dict(Vec<(String, PlistVal)>),
}

fn encode_bplist(root: &PlistVal) -> Vec<u8> {
    let mut objects: Vec<Vec<u8>> = Vec::new();
    fn add_obj(val: &PlistVal, objects: &mut Vec<Vec<u8>>) -> u8 {
        let idx = objects.len() as u8;
        objects.push(Vec::new());
        let mut encoded = Vec::new();
        match val {
            PlistVal::Int(n) => {
                if (0..=255).contains(n) {
                    encoded.push(0x10);
                    encoded.push(*n as u8);
                } else if (0..=65535).contains(n) {
                    encoded.push(0x11);
                    encoded.extend_from_slice(&(*n as u16).to_be_bytes());
                } else {
                    encoded.push(0x13);
                    encoded.extend_from_slice(&n.to_be_bytes());
                }
            }
            PlistVal::Date(d) => {
                encoded.push(0x33);
                encoded.extend_from_slice(&d.to_be_bytes());
            }
            PlistVal::Ascii(s) => {
                let bytes = s.as_bytes();
                if bytes.len() < 15 {
                    encoded.push(0x50 | (bytes.len() as u8));
                } else {
                    encoded.push(0x5F);
                    encoded.push(0x10);
                    encoded.push(bytes.len() as u8);
                }
                encoded.extend_from_slice(bytes);
            }
            PlistVal::Array(items) => {
                if items.len() < 15 {
                    encoded.push(0xA0 | (items.len() as u8));
                } else {
                    encoded.push(0xAF);
                    encoded.push(0x10);
                    encoded.push(items.len() as u8);
                }
                let mut refs = Vec::with_capacity(items.len());
                for item in items {
                    refs.push(add_obj(item, objects));
                }
                encoded.extend_from_slice(&refs);
            }
            PlistVal::Dict(pairs) => {
                if pairs.len() < 15 {
                    encoded.push(0xD0 | (pairs.len() as u8));
                } else {
                    encoded.push(0xDF);
                    encoded.push(0x10);
                    encoded.push(pairs.len() as u8);
                }
                let mut k_refs = Vec::with_capacity(pairs.len());
                let mut v_refs = Vec::with_capacity(pairs.len());
                for (k, _) in pairs {
                    k_refs.push(add_obj(&PlistVal::Ascii(k.clone()), objects));
                }
                for (_, v) in pairs {
                    v_refs.push(add_obj(v, objects));
                }
                encoded.extend_from_slice(&k_refs);
                encoded.extend_from_slice(&v_refs);
            }
        }
        objects[idx as usize] = encoded;
        idx
    }

    add_obj(root, &mut objects);
    let mut out = Vec::from(&b"bplist00"[..]);
    let mut offsets = Vec::with_capacity(objects.len());
    for obj in &objects {
        offsets.push(out.len() as u16);
        out.extend_from_slice(obj);
    }
    let offset_table_off = out.len() as u64;
    for off in &offsets {
        out.extend_from_slice(&off.to_be_bytes());
    }
    out.extend_from_slice(&[0u8; 6]);
    out.push(2);
    out.push(1);
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&offset_table_off.to_be_bytes());
    out
}

fn build_opera_presto_dcache() -> (Vec<u8>, Vec<u8>) {
    let html = b"<html><body>Opera Presto Cached Page</body></html>".to_vec();
    let mut sub = Vec::new();
    let mut push_field = |tag: u8, data: &[u8]| {
        sub.push(tag);
        sub.extend_from_slice(&(data.len() as u16).to_be_bytes());
        sub.extend_from_slice(data);
    };
    push_field(0x03, b"https://example.org/opera/index.html");
    push_field(0x04, &(FIXED_UNIX_SECS as u32).to_be_bytes());
    push_field(0x05, &((FIXED_UNIX_SECS - 100) as u32).to_be_bytes());
    push_field(0x08, b"opr00001.tmp");
    push_field(0x0C, &(html.len() as u32).to_be_bytes());
    push_field(0x19, b"text/html");

    let mut idx = Vec::new();
    idx.extend_from_slice(&0x0000_1000u32.to_be_bytes());
    idx.extend_from_slice(&2u32.to_be_bytes());
    idx.extend_from_slice(&2u32.to_be_bytes());
    idx.push(0x01);
    idx.extend_from_slice(&(sub.len() as u16).to_be_bytes());
    idx.extend_from_slice(&sub);
    (idx, html)
}

fn build_chromium_simple_cache_entry() -> Vec<u8> {
    let key = b"1/0/_dk_https://example.org https://example.org https://example.org/opera-gx.txt";
    let payload = b"hello from opera gx simple cache";
    let headers = b"HTTP/1.1 200 OK\0Content-Type: text/plain\0Server: guap-opera-test\0\0";
    let h_aligned = headers.len().div_ceil(4) * 4;
    let pickle_payload_len = 4 + 8 + 8 + 4 + h_aligned + 4 + 12 + 4;
    let mut s0 = Vec::new();
    s0.extend_from_slice(&(pickle_payload_len as u32).to_le_bytes());
    s0.extend_from_slice(&3u32.to_le_bytes());
    s0.extend_from_slice(&(FIXED_CHROME_US as i64).to_le_bytes());
    s0.extend_from_slice(&(FIXED_CHROME_US as i64).to_le_bytes());
    s0.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    s0.extend_from_slice(headers);
    s0.resize(s0.len() + (h_aligned - headers.len()), 0);
    s0.extend_from_slice(&9u32.to_le_bytes());
    s0.extend_from_slice(b"127.0.0.1\0\0\0");
    s0.extend_from_slice(&443u32.to_le_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&0xFCFB_6D1B_A772_5C30u64.to_le_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(payload);
    out.extend_from_slice(&0xF4FA_6F45_970D_41D8u64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&s0);
    out.extend_from_slice(&Sha256::digest(key));
    out.extend_from_slice(&0xF4FA_6F45_970D_41D8u64.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&crc32_ieee(&s0).to_le_bytes());
    out.extend_from_slice(&(s0.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}
pub fn generate_browser_dir(browser_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(browser_dir)?;

    let media_dir = browser_dir.join("media");
    let jpg_bytes = build_sample_exif_jpg();
    write_file_deterministic(&media_dir.join("sample_exif.jpg"), &jpg_bytes)?;
    write_file_deterministic(&media_dir.join("sample_fmp4.mp4"), &build_mp4_segment(true))?;
    write_file_deterministic(&media_dir.join("sample_segment.m4s"), &build_mp4_segment(false))?;

    let fx_dir = browser_dir.join("firefox/profile_default");
    std::fs::create_dir_all(&fx_dir)?;

    let k1 = ":https://example.org/docs/report.html";
    let html_payload = b"<!DOCTYPE html><html><body><h1>Firefox Cache2</h1></body></html>";
    write_file_deterministic(
        &fx_dir.join("cache2/entries").join(sha1_hex_upper(k1.as_bytes())),
        &build_firefox_cache2_entry(k1, "text/html; charset=utf-8", html_payload),
    )?;
    let k2 = ":https://example.org/assets/sample_exif.jpg";
    write_file_deterministic(
        &fx_dir.join("cache2/entries").join(sha1_hex_upper(k2.as_bytes())),
        &build_firefox_cache2_entry(k2, "image/jpeg", &jpg_bytes),
    )?;

    {
        let conn = Connection::open(fx_dir.join("places.sqlite"))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = DELETE;
             CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR NOT NULL, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER NOT NULL, visit_date INTEGER, visit_type INTEGER, session INTEGER);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, position INTEGER, title LONGVARCHAR, dateAdded INTEGER, lastModified INTEGER, guid TEXT);
             CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
             CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 4, type INTEGER DEFAULT 1, dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
             INSERT INTO moz_places VALUES (1, 'https://example.org/search?q=rust+forensics', 'Search: rust forensics', 'gro.elpmaxe.', 3, 0, 1, 250, {t}, 'pl_guid_0001');
             INSERT INTO moz_places VALUES (2, 'https://example.org/downloads/report.pdf', 'Annual Report', 'gro.elpmaxe.', 1, 0, 0, 100, {t2}, 'pl_guid_0002');
             INSERT INTO moz_places VALUES (3, 'https://docs.rs/rusqlite', 'rusqlite - Rust', 'sr.scod.', 2, 0, 0, 180, {t3}, 'pl_guid_0003');
             INSERT INTO moz_historyvisits VALUES (1, NULL, 1, {t}, 2, 1);
             INSERT INTO moz_historyvisits VALUES (2, 1, 2, {t2}, 7, 1);
             INSERT INTO moz_historyvisits VALUES (3, 1, 3, {t3}, 1, 1);
             INSERT INTO moz_bookmarks VALUES (1, 2, NULL, 0, 0, '', {t3}, {t}, 'root________');
             INSERT INTO moz_bookmarks VALUES (2, 2, NULL, 1, 0, 'Bookmarks Toolbar', {t3}, {t}, 'toolbar_____');
             INSERT INTO moz_bookmarks VALUES (3, 1, 3, 2, 0, 'rusqlite Docs', {t3}, {t}, 'bm_guid_0001');
             INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
             INSERT INTO moz_anno_attributes VALUES (2, 'downloads/metaData');
             INSERT INTO moz_annos VALUES (1, 2, 1, 'file:///C:/Users/Public/Downloads/report.pdf', 0, 4, 1, {t2}, {t2});
             INSERT INTO moz_annos VALUES (2, 2, 2, '{{\"state\":1,\"endTime\":1795357505000,\"fileSize\":4096}}', 0, 4, 1, {t2}, {t2});",
            t = FIXED_PRTIME_US,
            t2 = FIXED_PRTIME_US - 300_000_000,
            t3 = FIXED_PRTIME_US - 600_000_000,
        ))?;
    }

    {
        let conn = Connection::open(fx_dir.join("cookies.sqlite"))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = DELETE;
             CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0);
             INSERT INTO moz_cookies VALUES (1, '', 'ui_theme', 'dark', '.example.org', '/', 1826893800, {t}, {t_c}, 1, 1, 0, 1, 1, 2);
             INSERT INTO moz_cookies VALUES (2, '', 'locale', 'en-US', 'docs.rs', '/', 1826893800, {t}, {t_c}, 1, 0, 0, 2, 2, 2);",
            t = FIXED_PRTIME_US,
            t_c = FIXED_PRTIME_US - 7_800_000_000,
        ))?;
    }

    {
        let conn = Connection::open(fx_dir.join("formhistory.sqlite"))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = DELETE;
             CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
             INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', 'rust windows dfir', 4, {t0}, {t}, 'fh_guid_0001');
             INSERT INTO moz_formhistory VALUES (2, 'city', 'Toronto', 2, {t0}, {t}, 'fh_guid_0002');",
            t = FIXED_PRTIME_US,
            t0 = FIXED_PRTIME_US - 57_800_000_000,
        ))?;
    }

    let addons = serde_json::json!({
        "schema": 6,
        "addons": [{
            "id": "ublock-fixture@example.org",
            "version": "1.60.0",
            "type": "extension",
            "active": true,
            "name": "Content Blocker Fixture",
            "description": "Synthetic read-only test addon",
            "installDate": (FIXED_UNIX_SECS - 7800) * 1000,
            "updateDate": FIXED_UNIX_SECS * 1000,
            "sourceURI": "https://addons.mozilla.org/firefox/downloads/file/12345/fixture.xpi",
            "permissions": ["storage", "tabs"]
        }]
    });
    let addons_bytes = serde_json::to_vec_pretty(&addons)?;
    write_file_deterministic(&fx_dir.join("addons.json"), &addons_bytes)?;
    write_file_deterministic(&fx_dir.join("extensions.json"), &addons_bytes)?;

    let session_json = br#"{"version":["sessionrestore",1],"windows":[{"tabs":[{"entries":[{"url":"https://example.org/docs","title":"Example Docs"}],"index":1,"lastAccessed":1795357800000,"pinned":true}]}]}"#;
    write_file_deterministic(&fx_dir.join("sessionstore.jsonlz4"), &encode_mozlz4(session_json))?;

    let bm_json = br#"{"guid":"root________","title":"","index":0,"typeCode":2,"children":[{"guid":"toolbar_____","title":"Bookmarks Toolbar","typeCode":2,"children":[{"guid":"bm_guid_0001","title":"rusqlite Docs","uri":"https://docs.rs/rusqlite","typeCode":1,"dateAdded":1795350000000000,"lastModified":1795357200000000}]}]}"#;
    write_file_deterministic(&fx_dir.join("bookmarkbackups/bookmarks-2026-11-22.jsonlz4"), &encode_mozlz4(bm_json))?;

    let saf_dir = browser_dir.join("safari");
    std::fs::create_dir_all(&saf_dir)?;

    let bm_plist = PlistVal::Dict(vec![
        ("Title".into(), PlistVal::Ascii(String::new())),
        ("WebBookmarkType".into(), PlistVal::Ascii("WebBookmarkTypeList".into())),
        ("Children".into(), PlistVal::Array(vec![PlistVal::Dict(vec![
            ("Title".into(), PlistVal::Ascii("BookmarksBar".into())),
            ("WebBookmarkType".into(), PlistVal::Ascii("WebBookmarkTypeList".into())),
            ("Children".into(), PlistVal::Array(vec![PlistVal::Dict(vec![
                ("WebBookmarkType".into(), PlistVal::Ascii("WebBookmarkTypeLeaf".into())),
                ("WebBookmarkUUID".into(), PlistVal::Ascii("SAFARI-BM-0001".into())),
                ("URLString".into(), PlistVal::Ascii("https://example.org/safari-guide".into())),
                ("URIDictionary".into(), PlistVal::Dict(vec![("title".into(), PlistVal::Ascii("Safari Guide".into()))])),
            ])])),
        ])])),
    ]);
    write_file_deterministic(&saf_dir.join("Bookmarks.plist"), &encode_bplist(&bm_plist))?;

    let hist_plist = PlistVal::Dict(vec![
        ("WebHistoryFileVersion".into(), PlistVal::Int(1)),
        ("WebHistoryDates".into(), PlistVal::Array(vec![PlistVal::Dict(vec![
            (String::new(), PlistVal::Ascii("https://example.org/safari-guide".into())),
            ("title".into(), PlistVal::Ascii("Safari Guide".into())),
            ("visitCount".into(), PlistVal::Int(2)),
            ("lastVisitedDate".into(), PlistVal::Date(FIXED_CF_TIME)),
        ])])),
    ]);
    write_file_deterministic(&saf_dir.join("History.plist"), &encode_bplist(&hist_plist))?;

    let saf_resp_bplist = encode_bplist(&PlistVal::Dict(vec![
        ("URL".into(), PlistVal::Ascii("https://example.org/safari.html".into())),
        ("StatusCode".into(), PlistVal::Int(200)),
        ("Headers".into(), PlistVal::Dict(vec![
            ("Content-Type".into(), PlistVal::Ascii("text/html".into())),
            ("Server".into(), PlistVal::Ascii("guap-safari-test".into())),
        ])),
    ]));
    {
        let conn = Connection::open(saf_dir.join("Cache.db"))?;
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             CREATE TABLE cfurl_cache_response (entry_ID INTEGER PRIMARY KEY, version INTEGER, hash_value INTEGER, storage_policy INTEGER, request_key TEXT, time_stamp TEXT, partition TEXT);
             CREATE TABLE cfurl_cache_receiver_data (entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);
             CREATE TABLE cfurl_cache_blob_data (entry_ID INTEGER PRIMARY KEY, response_object BLOB, request_object BLOB, proto_props BLOB, user_info BLOB);",
        )?;
        conn.execute("INSERT INTO cfurl_cache_response VALUES (1, 0, 12345, 0, 'https://example.org/safari.html', '2026-11-22 14:30:00 +0000', '')", [])?;
        conn.execute("INSERT INTO cfurl_cache_receiver_data VALUES (1, 0, ?1)", [&b"<html><body>Safari Cache</body></html>"[..]])?;
        conn.execute("INSERT INTO cfurl_cache_blob_data VALUES (1, ?1, NULL, NULL, NULL)", [&saf_resp_bplist[..]])?;
    }

    {
        let conn = Connection::open(saf_dir.join("History.db"))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = DELETE;
             CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, domain_expansion TEXT, visit_count INTEGER NOT NULL DEFAULT 0, daily_visit_counts BLOB, weekly_visit_counts BLOB, autocomplete_triggers BLOB, should_recompute_derived_visit_counts INTEGER NOT NULL DEFAULT 0, visit_count_score INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT, history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE, visit_time REAL NOT NULL, title TEXT NULL, load_successful INTEGER NOT NULL DEFAULT 1, http_non_get INTEGER NOT NULL DEFAULT 0, synthesized INTEGER NOT NULL DEFAULT 0, redirect_source INTEGER NULL, redirect_destination INTEGER NULL, origin INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0, attributes INTEGER NOT NULL DEFAULT 0, score INTEGER NOT NULL DEFAULT 0);
             INSERT INTO history_items (id, url, domain_expansion, visit_count) VALUES (1, 'https://example.org/safari-guide', 'example.org', 2);
             INSERT INTO history_items (id, url, domain_expansion, visit_count) VALUES (2, 'https://www.google.com/search?q=guap+dfir', 'google.com', 1);
             INSERT INTO history_visits (id, history_item, visit_time, title) VALUES (1, 1, {cf}, 'Safari Guide');
             INSERT INTO history_visits (id, history_item, visit_time, title) VALUES (2, 2, {cf2}, 'Google Search');",
            cf = FIXED_CF_TIME,
            cf2 = FIXED_CF_TIME - 600.0,
        ))?;
    }

    let opera_dir = browser_dir.join("opera");
    let (dcache, opr_html) = build_opera_presto_dcache();
    write_file_deterministic(&opera_dir.join("opcache/dcache4.url"), &dcache)?;
    write_file_deterministic(&opera_dir.join("opcache/opr00001.tmp"), &opr_html)?;
    write_file_deterministic(&opera_dir.join("Cache/Cache_Data/1122334455667788_0"), &build_chromium_simple_cache_entry())?;

    Ok(())
}

pub fn verify_browser_dir(browser_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();
    let mut count = 0usize;

    let jpg = std::fs::read(browser_dir.join("media/sample_exif.jpg"))?;
    ensure!(jpg.starts_with(&[0xFF, 0xD8, 0xFF, 0xE1]) && jpg.ends_with(&[0xFF, 0xD9]), "bad sample_exif.jpg");
    ensure!(&jpg[6..12] == b"Exif\0\0" && &jpg[12..16] == b"II*\0", "missing Exif TIFF header");
    count += 1;
    details.push("browser/media/sample_exif.jpg: EXIF APP1 + II*\\0 verified".into());

    for mname in ["sample_fmp4.mp4", "sample_segment.m4s"] {
        let mp4 = std::fs::read(browser_dir.join("media").join(mname))?;
        let mut off = 0usize;
        let mut boxes = Vec::new();
        while off < mp4.len() {
            let blen = read_u32_be(&mp4, off)? as usize;
            ensure!(blen >= 8 && off + blen <= mp4.len(), "{}: bad box len", mname);
            boxes.push(String::from_utf8_lossy(&mp4[off + 4..off + 8]).to_string());
            off += blen;
        }
        ensure!(boxes.len() == 3 && boxes[1] == "moof" && boxes[2] == "mdat", "{}: bad MP4 boxes {:?}", mname, boxes);
        count += 1;
        details.push(format!("browser/media/{}: boxes {:?} verified", mname, boxes));
    }

    let fx_dir = browser_dir.join("firefox/profile_default");
    let k1 = ":https://example.org/docs/report.html";
    let k2 = ":https://example.org/assets/sample_exif.jpg";
    for (k, prefix) in [(k1, b"<!DOC".as_slice()), (k2, &[0xFF, 0xD8, 0xFF, 0xE1])] {
        let fname = sha1_hex_upper(k.as_bytes());
        let buf = std::fs::read(fx_dir.join("cache2/entries").join(&fname))?;
        let p_len = read_u32_be(&buf, buf.len() - 4)? as usize;
        ensure!(buf[..p_len].starts_with(prefix), "cache2 payload mismatch for {}", k);
        let hdr_off = p_len + 2;
        ensure!(read_u32_be(&buf, hdr_off)? == 3, "cache2 mVersion != 3");
        let key_off = hdr_off + 32;
        ensure!(&buf[key_off..key_off + k.len()] == k.as_bytes(), "cache2 key mismatch");
        count += 1;
    }
    details.push("browser/firefox/cache2: 2 entries verified".into());

    for (db_name, sql, min_rows) in [
        ("places.sqlite", "SELECT COUNT(*) FROM moz_places", 3i64),
        ("cookies.sqlite", "SELECT COUNT(*) FROM moz_cookies", 2i64),
        ("formhistory.sqlite", "SELECT COUNT(*) FROM moz_formhistory", 2i64),
    ] {
        let conn = Connection::open(fx_dir.join(db_name))?;
        let integ: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(integ == "ok", "{} integrity failed", db_name);
        let n: i64 = conn.query_row(sql, [], |r| r.get(0))?;
        ensure!(n >= min_rows, "{} row count {} < {}", db_name, n, min_rows);
        count += 1;
    }
    details.push("browser/firefox/*.sqlite: integrity + rows verified".into());

    for jname in ["addons.json", "extensions.json"] {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(fx_dir.join(jname))?)?;
        ensure!(v["addons"].as_array().map(|a| !a.is_empty()).unwrap_or(false), "empty {}", jname);
        count += 1;
    }
    for lzname in ["sessionstore.jsonlz4", "bookmarkbackups/bookmarks-2026-11-22.jsonlz4"] {
        let raw = decode_mozlz4(&std::fs::read(fx_dir.join(lzname))?)?;
        let _: serde_json::Value = serde_json::from_slice(&raw)?;
        count += 1;
    }
    details.push("browser/firefox/jsonlz4+addons: verified".into());

    let saf_dir = browser_dir.join("safari");
    for pname in ["Bookmarks.plist", "History.plist"] {
        let b = std::fs::read(saf_dir.join(pname))?;
        ensure!(b.starts_with(b"bplist00") && b.len() > 40, "{}: bad bplist", pname);
        let off_tbl = u64::from_be_bytes(b[b.len() - 8..].try_into()?) as usize;
        ensure!(off_tbl < b.len() - 32, "{}: bad bplist trailer", pname);
        count += 1;
    }
    {
        let c1 = Connection::open(saf_dir.join("Cache.db"))?;
        let n1: i64 = c1.query_row("SELECT COUNT(*) FROM cfurl_cache_response", [], |r| r.get(0))?;
        ensure!(n1 >= 1, "Safari Cache.db empty");
        count += 1;
        let c2 = Connection::open(saf_dir.join("History.db"))?;
        let n2: i64 = c2.query_row("SELECT COUNT(*) FROM history_visits", [], |r| r.get(0))?;
        ensure!(n2 >= 2, "Safari History.db < 2");
        count += 1;
    }
    details.push("browser/safari: plists + Cache.db + History.db verified".into());

    let dcache = std::fs::read(browser_dir.join("opera/opcache/dcache4.url"))?;
    ensure!(read_u32_be(&dcache, 0)? == 0x1000 && dcache[12] == 0x01, "bad dcache4.url");
    let _ = read_u16_be(&dcache, 13)?;
    let _ = std::fs::read(browser_dir.join("opera/opcache/opr00001.tmp"))?;
    let sc = std::fs::read(browser_dir.join("opera/Cache/Cache_Data/1122334455667788_0"))?;
    ensure!(sc.starts_with(&0xFCFB_6D1B_A772_5C30u64.to_le_bytes()), "bad Opera Simple Cache");
    count += 3;
    details.push("browser/opera: dcache4.url + opr00001.tmp + SimpleCache verified".into());

    Ok((count, details))
}