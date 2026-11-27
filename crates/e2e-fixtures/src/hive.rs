use crate::util::{
    FIXED_FILETIME, read_i32_le, read_u16_le, read_u32_le, rot13, utf16le_nul,
    write_file_deterministic, xor32_u32s,
};
use anyhow::{Result, ensure};
use std::path::Path;

#[derive(Clone)]
pub enum RegValueData {
    Sz(String),
    ExpandSz(String),
    Binary(Vec<u8>),
    Dword(u32),
    MultiSz(Vec<String>),
    Qword(u64),
}

impl RegValueData {
    fn reg_type(&self) -> u32 {
        match self {
            RegValueData::Sz(_) => 1,
            RegValueData::ExpandSz(_) => 2,
            RegValueData::Binary(_) => 3,
            RegValueData::Dword(_) => 4,
            RegValueData::MultiSz(_) => 7,
            RegValueData::Qword(_) => 11,
        }
    }

    fn encode_bytes(&self) -> Vec<u8> {
        match self {
            RegValueData::Sz(s) | RegValueData::ExpandSz(s) => utf16le_nul(s),
            RegValueData::Binary(b) => b.clone(),
            RegValueData::Dword(v) => v.to_le_bytes().to_vec(),
            RegValueData::Qword(v) => v.to_le_bytes().to_vec(),
            RegValueData::MultiSz(items) => {
                let mut out = Vec::new();
                for item in items {
                    out.extend_from_slice(&utf16le_nul(item));
                }
                out.extend_from_slice(&[0x00, 0x00]);
                out
            }
        }
    }
}

pub struct RegKeyNode {
    pub name: String,
    pub values: Vec<(String, RegValueData)>,
    pub subkeys: Vec<RegKeyNode>,
}

impl RegKeyNode {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            values: Vec::new(),
            subkeys: Vec::new(),
        }
    }
}

struct HbinBuilder {
    buf: Vec<u8>,
}

impl HbinBuilder {
    fn new() -> Self {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(b"hbin");
        buf[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
        buf[0x14..0x1C].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
        Self { buf }
    }

    fn alloc_cell(&mut self, body: &[u8]) -> u32 {
        let offset = self.buf.len() as u32;
        let cell_bytes = (4 + body.len() + 7) & !7;
        let size_i32 = -(cell_bytes as i32);
        self.buf.extend_from_slice(&size_i32.to_le_bytes());
        self.buf.extend_from_slice(body);
        self.buf.resize(offset as usize + cell_bytes, 0u8);
        offset
    }

    fn alloc_placeholder(&mut self, body_len: usize) -> u32 {
        let body = vec![0u8; body_len];
        self.alloc_cell(&body)
    }

    fn write_cell_body(&mut self, offset: u32, body: &[u8]) {
        let start = offset as usize + 4;
        self.buf[start..start + body.len()].copy_from_slice(body);
    }

    fn finalize(mut self) -> Vec<u8> {
        let total = ((self.buf.len() + 4).div_ceil(4096).max(1)) * 4096;
        let free_size = (total - self.buf.len()) as i32;
        self.buf.extend_from_slice(&free_size.to_le_bytes());
        self.buf.resize(total, 0u8);
        self.buf[0x08..0x0C].copy_from_slice(&(total as u32).to_le_bytes());
        self.buf
    }
}

fn lh_hash(name: &str) -> u32 {
    let mut hash = 0u32;
    for b in name.bytes() {
        hash = hash
            .wrapping_mul(37)
            .wrapping_add(b.to_ascii_uppercase() as u32);
    }
    hash
}

fn lf_hint(name: &str) -> u32 {
    let mut bytes = [0u8; 4];
    for (i, b) in name.bytes().take(4).enumerate() {
        bytes[i] = b;
    }
    u32::from_le_bytes(bytes)
}

fn emit_nk_recursive(
    hb: &mut HbinBuilder,
    node: &RegKeyNode,
    parent_off: u32,
    sk_off: u32,
    use_lf: bool,
    is_root: bool,
) -> u32 {
    let name_bytes = node.name.as_bytes();
    let nk_body_len = 0x4C + name_bytes.len();
    let nk_off = hb.alloc_placeholder(nk_body_len);

    let values_list_off = if node.values.is_empty() {
        0xFFFF_FFFF
    } else {
        let mut vk_offsets = Vec::with_capacity(node.values.len());
        for (vname, vdata) in &node.values {
            let raw_bytes = vdata.encode_bytes();
            let vtype = vdata.reg_type();
            let vname_bytes = vname.as_bytes();
            let mut vk = Vec::with_capacity(0x14 + vname_bytes.len());
            vk.extend_from_slice(b"vk");
            vk.extend_from_slice(&(vname_bytes.len() as u16).to_le_bytes());
            if raw_bytes.len() <= 4 {
                let len_with_flag = 0x8000_0000u32 | (raw_bytes.len() as u32);
                vk.extend_from_slice(&len_with_flag.to_le_bytes());
                let mut inline = [0u8; 4];
                inline[..raw_bytes.len()].copy_from_slice(&raw_bytes);
                vk.extend_from_slice(&inline);
            } else {
                let data_off = hb.alloc_cell(&raw_bytes);
                vk.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
                vk.extend_from_slice(&data_off.to_le_bytes());
            }
            vk.extend_from_slice(&vtype.to_le_bytes());
            let flags: u16 = if vname_bytes.is_empty() { 0 } else { 0x0001 };
            vk.extend_from_slice(&flags.to_le_bytes());
            vk.extend_from_slice(&0u16.to_le_bytes());
            vk.extend_from_slice(vname_bytes);
            vk_offsets.push(hb.alloc_cell(&vk));
        }
        let mut list_body = Vec::with_capacity(vk_offsets.len() * 4);
        for off in vk_offsets {
            list_body.extend_from_slice(&off.to_le_bytes());
        }
        hb.alloc_cell(&list_body)
    };

    let subkeys_list_off = if node.subkeys.is_empty() {
        0xFFFF_FFFF
    } else {
        let mut list_body = Vec::with_capacity(4 + node.subkeys.len() * 8);
        list_body.extend_from_slice(if use_lf { b"lf" } else { b"lh" });
        list_body.extend_from_slice(&(node.subkeys.len() as u16).to_le_bytes());
        for sub in &node.subkeys {
            let sub_off = emit_nk_recursive(hb, sub, nk_off, sk_off, use_lf, false);
            list_body.extend_from_slice(&sub_off.to_le_bytes());
            let hint = if use_lf {
                lf_hint(&sub.name)
            } else {
                lh_hash(&sub.name)
            };
            list_body.extend_from_slice(&hint.to_le_bytes());
        }
        hb.alloc_cell(&list_body)
    };

    let max_sub_len = node
        .subkeys
        .iter()
        .map(|s| (s.name.len() * 2) as u32)
        .max()
        .unwrap_or(0);
    let max_val_name_len = node
        .values
        .iter()
        .map(|(n, _)| (n.len() * 2) as u32)
        .max()
        .unwrap_or(0);
    let max_val_data_len = node
        .values
        .iter()
        .map(|(_, d)| d.encode_bytes().len() as u32)
        .max()
        .unwrap_or(0);

    let mut nk = vec![0u8; nk_body_len];
    nk[0x00..0x02].copy_from_slice(b"nk");
    let flags: u16 = if is_root { 0x002C } else { 0x0020 };
    nk[0x02..0x04].copy_from_slice(&flags.to_le_bytes());
    nk[0x04..0x0C].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    nk[0x10..0x14].copy_from_slice(&parent_off.to_le_bytes());
    nk[0x14..0x18].copy_from_slice(&(node.subkeys.len() as u32).to_le_bytes());
    nk[0x1C..0x20].copy_from_slice(&subkeys_list_off.to_le_bytes());
    nk[0x20..0x24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    nk[0x24..0x28].copy_from_slice(&(node.values.len() as u32).to_le_bytes());
    nk[0x28..0x2C].copy_from_slice(&values_list_off.to_le_bytes());
    nk[0x2C..0x30].copy_from_slice(&sk_off.to_le_bytes());
    nk[0x30..0x34].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    nk[0x34..0x38].copy_from_slice(&max_sub_len.to_le_bytes());
    nk[0x3C..0x40].copy_from_slice(&max_val_name_len.to_le_bytes());
    nk[0x40..0x44].copy_from_slice(&max_val_data_len.to_le_bytes());
    nk[0x48..0x4A].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    nk[0x4C..].copy_from_slice(name_bytes);
    hb.write_cell_body(nk_off, &nk);

    nk_off
}

fn regf_checksum(header_prefix: &[u8]) -> u32 {
    let x = xor32_u32s(header_prefix);
    if x == 0xFFFF_FFFF {
        0xFFFF_FFFE
    } else if x == 0 {
        1
    } else {
        x
    }
}

fn build_hive(hive_filename: &str, root: &RegKeyNode, use_lf: bool) -> Vec<u8> {
    let mut hb = HbinBuilder::new();
    let sk_body_len = 0x28usize;
    let root_name_len = root.name.len();
    let root_cell_bytes = (4 + 0x4C + root_name_len + 7) & !7;
    let sk_off = 0x20u32 + root_cell_bytes as u32;

    let mut sk = vec![0u8; sk_body_len];
    sk[0x00..0x02].copy_from_slice(b"sk");
    sk[0x04..0x08].copy_from_slice(&sk_off.to_le_bytes());
    sk[0x08..0x0C].copy_from_slice(&sk_off.to_le_bytes());
    sk[0x0C..0x10].copy_from_slice(&1u32.to_le_bytes());
    sk[0x10..0x14].copy_from_slice(&20u32.to_le_bytes());
    sk[0x14..0x18].copy_from_slice(&[0x01, 0x00, 0x04, 0x80]);

    let root_off = hb.alloc_placeholder(0x4C + root_name_len);
    debug_assert_eq!(root_off, 0x20);
    let actual_sk_off = hb.alloc_cell(&sk);
    debug_assert_eq!(actual_sk_off, sk_off);

    let subkeys_list_off = if root.subkeys.is_empty() {
        0xFFFF_FFFF
    } else {
        let mut list_body = Vec::with_capacity(4 + root.subkeys.len() * 8);
        list_body.extend_from_slice(if use_lf { b"lf" } else { b"lh" });
        list_body.extend_from_slice(&(root.subkeys.len() as u16).to_le_bytes());
        for sub in &root.subkeys {
            let sub_off = emit_nk_recursive(&mut hb, sub, root_off, sk_off, use_lf, false);
            list_body.extend_from_slice(&sub_off.to_le_bytes());
            let hint = if use_lf {
                lf_hint(&sub.name)
            } else {
                lh_hash(&sub.name)
            };
            list_body.extend_from_slice(&hint.to_le_bytes());
        }
        hb.alloc_cell(&list_body)
    };

    let max_sub_len = root
        .subkeys
        .iter()
        .map(|s| (s.name.len() * 2) as u32)
        .max()
        .unwrap_or(0);
    let mut nk = vec![0u8; 0x4C + root_name_len];
    nk[0x00..0x02].copy_from_slice(b"nk");
    nk[0x02..0x04].copy_from_slice(&0x002Cu16.to_le_bytes());
    nk[0x04..0x0C].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    nk[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    nk[0x14..0x18].copy_from_slice(&(root.subkeys.len() as u32).to_le_bytes());
    nk[0x1C..0x20].copy_from_slice(&subkeys_list_off.to_le_bytes());
    nk[0x20..0x24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    nk[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
    nk[0x28..0x2C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    nk[0x2C..0x30].copy_from_slice(&sk_off.to_le_bytes());
    nk[0x30..0x34].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    nk[0x34..0x38].copy_from_slice(&max_sub_len.to_le_bytes());
    nk[0x48..0x4A].copy_from_slice(&(root_name_len as u16).to_le_bytes());
    nk[0x4C..].copy_from_slice(root.name.as_bytes());
    hb.write_cell_body(root_off, &nk);

    let hbin = hb.finalize();

    let mut base = vec![0u8; 4096];
    base[0x00..0x04].copy_from_slice(b"regf");
    base[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
    base[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
    base[0x0C..0x14].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    base[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    base[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
    base[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
    base[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    base[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    base[0x28..0x2C].copy_from_slice(&(hbin.len() as u32).to_le_bytes());
    base[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
    let name_u16 = utf16le_nul(hive_filename);
    let copy_len = name_u16.len().min(64);
    base[0x30..0x30 + copy_len].copy_from_slice(&name_u16[..copy_len]);
    let cksum = regf_checksum(&base[0..0x1FC]);
    base[0x1FC..0x200].copy_from_slice(&cksum.to_le_bytes());

    let mut out = Vec::with_capacity(base.len() + hbin.len());
    out.extend_from_slice(&base);
    out.extend_from_slice(&hbin);
    out
}

fn userassist_blob(run_count: u32, focus_count: u32, focus_time_ms: u32) -> Vec<u8> {
    let mut b = vec![0u8; 72];
    b[0x04..0x08].copy_from_slice(&run_count.to_le_bytes());
    b[0x08..0x0C].copy_from_slice(&focus_count.to_le_bytes());
    b[0x0C..0x10].copy_from_slice(&focus_time_ms.to_le_bytes());
    b[0x3C..0x44].copy_from_slice(&FIXED_FILETIME.to_le_bytes());
    b
}

fn shitemid_entry(item_type: u8, name: &str) -> Vec<u8> {
    let mut item = Vec::new();
    item.extend_from_slice(&0u16.to_le_bytes());
    item.push(item_type);
    item.push(0x00);
    item.extend_from_slice(name.as_bytes());
    item.push(0x00);
    if item.len() % 2 != 0 {
        item.push(0x00);
    }
    let ext_pos = item.len();
    item.extend_from_slice(&0u16.to_le_bytes());
    item.extend_from_slice(&0x0009u16.to_le_bytes());
    item.extend_from_slice(&0xBEEF_0004u32.to_le_bytes());
    item.extend_from_slice(&utf16le_nul(name));
    let ext_sz = (item.len() - ext_pos + 2) as u16;
    item[ext_pos..ext_pos + 2].copy_from_slice(&ext_sz.to_le_bytes());
    item.extend_from_slice(&(ext_pos as u16).to_le_bytes());
    let total = item.len() as u16;
    item[0..2].copy_from_slice(&total.to_le_bytes());
    item
}

fn build_sample_pidl() -> Vec<u8> {
    let mut pidl = Vec::new();
    pidl.extend_from_slice(&20u16.to_le_bytes());
    pidl.push(0x1F);
    pidl.push(0x50);
    pidl.extend_from_slice(&[
        0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30,
        0x9D,
    ]);
    let mut vol = vec![0u8; 25];
    vol[0..2].copy_from_slice(&25u16.to_le_bytes());
    vol[2] = 0x2F;
    vol[3..6].copy_from_slice(b"C:\\");
    pidl.extend_from_slice(&vol);
    pidl.extend_from_slice(&shitemid_entry(0x31, "Cases"));
    pidl.extend_from_slice(&shitemid_entry(0x32, "notes.txt"));
    pidl.extend_from_slice(&0u16.to_le_bytes());
    pidl
}

pub fn generate_hive_dir(hive_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(hive_dir)?;

    let mut ntuser = RegKeyNode::new("ROOT");
    let mut sw = RegKeyNode::new("Software");
    let mut ms = RegKeyNode::new("Microsoft");
    let mut win = RegKeyNode::new("Windows");
    let mut cv = RegKeyNode::new("CurrentVersion");
    let mut exp = RegKeyNode::new("Explorer");

    let mut ua = RegKeyNode::new("UserAssist");
    let mut ua_guid = RegKeyNode::new("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}");
    let mut ua_count = RegKeyNode::new("Count");
    ua_count.values.push((
        rot13(r"C:\Tools\forensics_sample.exe"),
        RegValueData::Binary(userassist_blob(5, 12, 45_000)),
    ));
    ua_count.values.push((
        rot13("UEME_CTLSESSION"),
        RegValueData::Binary(userassist_blob(1, 1, 1_000)),
    ));
    ua_guid.subkeys.push(ua_count);
    ua.subkeys.push(ua_guid);

    let mut comdlg = RegKeyNode::new("ComDlg32");
    let mut opensave = RegKeyNode::new("OpenSavePidlMRU");
    let mut os_txt = RegKeyNode::new("txt");
    os_txt
        .values
        .push(("0".into(), RegValueData::Binary(build_sample_pidl())));
    let mut mru_ex = Vec::new();
    mru_ex.extend_from_slice(&0u32.to_le_bytes());
    mru_ex.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    os_txt
        .values
        .push(("MRUListEx".into(), RegValueData::Binary(mru_ex)));
    opensave.subkeys.push(os_txt);
    comdlg.subkeys.push(opensave);

    exp.subkeys.push(ua);
    exp.subkeys.push(comdlg);

    let mut run = RegKeyNode::new("Run");
    run.values.push((
        "ForensicsAgent".into(),
        RegValueData::Sz(r"C:\Tools\forensics_sample.exe".into()),
    ));
    run.values.push((
        "Helper".into(),
        RegValueData::ExpandSz(r"%ProgramFiles%\GUAP\helper.exe".into()),
    ));
    run.values.push(("Enabled".into(), RegValueData::Dword(1)));
    run.values
        .push(("LastCheck".into(), RegValueData::Qword(FIXED_FILETIME)));
    run.values.push((
        "Tags".into(),
        RegValueData::MultiSz(vec!["audit".into(), "dfir".into()]),
    ));

    cv.subkeys.push(exp);
    cv.subkeys.push(run);
    win.subkeys.push(cv);
    ms.subkeys.push(win);
    sw.subkeys.push(ms);
    ntuser.subkeys.push(sw);
    write_file_deterministic(
        &hive_dir.join("NTUSER.DAT"),
        &build_hive("NTUSER.DAT", &ntuser, false),
    )?;

    let mut usrclass = RegKeyNode::new("ROOT");
    let mut ls = RegKeyNode::new("Local Settings");
    let mut uc_sw = RegKeyNode::new("Software");
    let mut uc_ms = RegKeyNode::new("Microsoft");
    let mut uc_win = RegKeyNode::new("Windows");
    let mut shell = RegKeyNode::new("Shell");

    let mut bagmru = RegKeyNode::new("BagMRU");
    bagmru
        .values
        .push(("NodeSlot".into(), RegValueData::Dword(1)));
    let mut mru0 = Vec::new();
    mru0.extend_from_slice(&0u32.to_le_bytes());
    mru0.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    bagmru
        .values
        .push(("MRUListEx".into(), RegValueData::Binary(mru0.clone())));
    let mut vol_pidl = vec![0u8; 25];
    vol_pidl[0..2].copy_from_slice(&25u16.to_le_bytes());
    vol_pidl[2] = 0x2F;
    vol_pidl[3..6].copy_from_slice(b"C:\\");
    bagmru
        .values
        .push(("0".into(), RegValueData::Binary(vol_pidl)));
    let mut bag0 = RegKeyNode::new("0");
    bag0.values
        .push(("NodeSlot".into(), RegValueData::Dword(2)));
    bag0.values
        .push(("MRUListEx".into(), RegValueData::Binary(mru0)));
    bag0.values.push((
        "0".into(),
        RegValueData::Binary(shitemid_entry(0x31, "Cases")),
    ));
    bagmru.subkeys.push(bag0);

    let mut muicache = RegKeyNode::new("MuiCache");
    muicache.values.push((
        r"C:\Tools\forensics_sample.exe.FriendlyAppName".into(),
        RegValueData::Sz("Forensics Sample Tool".into()),
    ));

    shell.subkeys.push(bagmru);
    shell.subkeys.push(muicache);
    uc_win.subkeys.push(shell);
    uc_ms.subkeys.push(uc_win);
    uc_sw.subkeys.push(uc_ms);
    ls.subkeys.push(uc_sw);
    usrclass.subkeys.push(ls);
    write_file_deterministic(
        &hive_dir.join("UsrClass.dat"),
        &build_hive("UsrClass.dat", &usrclass, false),
    )?;

    let mut sys_root = RegKeyNode::new("ROOT");
    let mut cs001 = RegKeyNode::new("ControlSet001");
    let mut enum_k = RegKeyNode::new("Enum");
    let mut usbstor = RegKeyNode::new("USBSTOR");
    let mut disk = RegKeyNode::new("Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00");
    let mut dev = RegKeyNode::new("4C530001231020118273&0");
    dev.values.push((
        "FriendlyName".into(),
        RegValueData::Sz("SanDisk Ultra USB Device".into()),
    ));
    dev.values.push((
        "HardwareID".into(),
        RegValueData::MultiSz(vec![
            r"USBSTOR\DiskSanDisk_Ultra___________1.00".into(),
            r"USBSTOR\DiskSanDisk_Ultra___________".into(),
        ]),
    ));
    dev.values
        .push(("Capabilities".into(), RegValueData::Dword(0x10)));
    disk.subkeys.push(dev);
    usbstor.subkeys.push(disk);
    enum_k.subkeys.push(usbstor);
    cs001.subkeys.push(enum_k);
    sys_root.subkeys.push(cs001);
    write_file_deterministic(
        &hive_dir.join("SYSTEM"),
        &build_hive("SYSTEM", &sys_root, true),
    )?;

    let mut sw_root = RegKeyNode::new("ROOT");
    let mut sw_ms = RegKeyNode::new("Microsoft");
    let mut sw_nt = RegKeyNode::new("Windows NT");
    let mut sw_cv = RegKeyNode::new("CurrentVersion");
    let mut plist = RegKeyNode::new("ProfileList");
    let mut prof = RegKeyNode::new("S-1-5-21-1001-2002-3003-1001");
    prof.values.push((
        "ProfileImagePath".into(),
        RegValueData::ExpandSz(r"C:\Users\alice".into()),
    ));
    prof.values.push((
        "Sid".into(),
        RegValueData::Binary(vec![
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xE9, 0x03, 0, 0, 0xD2, 0x07, 0, 0, 0xBB, 0x0B, 0,
            0, 0xE9, 0x03, 0, 0,
        ]),
    ));
    prof.values.push(("Flags".into(), RegValueData::Dword(0)));
    prof.values.push((
        "LocalProfileLoadTimeLow".into(),
        RegValueData::Dword((FIXED_FILETIME & 0xFFFF_FFFF) as u32),
    ));
    prof.values.push((
        "LocalProfileLoadTimeHigh".into(),
        RegValueData::Dword((FIXED_FILETIME >> 32) as u32),
    ));
    plist.subkeys.push(prof);
    sw_cv.subkeys.push(plist);
    sw_nt.subkeys.push(sw_cv);
    sw_ms.subkeys.push(sw_nt);
    sw_root.subkeys.push(sw_ms);
    write_file_deterministic(
        &hive_dir.join("SOFTWARE"),
        &build_hive("SOFTWARE", &sw_root, false),
    )?;

    Ok(())
}

pub fn verify_hive_dir(hive_dir: &Path) -> Result<(usize, Vec<String>)> {
    let expected = [
        (
            "NTUSER.DAT",
            "UserAssist",
            "P:\\Gbbyf\\sberafvpf_fnzcyr.rkr",
        ),
        ("UsrClass.dat", "BagMRU", "MuiCache"),
        ("SYSTEM", "USBSTOR", "SanDisk"),
        ("SOFTWARE", "ProfileList", "alice"),
    ];
    let mut details = Vec::new();
    for (fname, marker1, marker2) in &expected {
        let buf = std::fs::read(hive_dir.join(fname))?;
        ensure!(
            buf.len() >= 8192 && buf.len() % 4096 == 0,
            "{}: bad size",
            fname
        );
        ensure!(&buf[0..4] == b"regf", "{}: bad regf magic", fname);
        ensure!(
            read_u32_le(&buf, 4)? == read_u32_le(&buf, 8)?,
            "{}: seq mismatch",
            fname
        );
        ensure!(
            read_u32_le(&buf, 0x24)? == 0x20,
            "{}: root_cell_offset != 0x20",
            fname
        );
        ensure!(
            read_u32_le(&buf, 0x1FC)? == regf_checksum(&buf[0..0x1FC]),
            "{}: regf checksum mismatch",
            fname
        );
        let hbin_sz = read_u32_le(&buf, 0x28)? as usize;
        ensure!(buf.len() == 4096 + hbin_sz, "{}: hbin size mismatch", fname);
        ensure!(&buf[0x1000..0x1004] == b"hbin", "{}: bad hbin magic", fname);

        let mut cursor = 0x1020usize;
        let end = 0x1000 + hbin_sz;
        let mut cell_count = 0usize;
        let (mut saw_nk, mut saw_vk, mut saw_sk, mut saw_list) = (false, false, false, false);
        while cursor < end {
            let raw_sz = read_i32_le(&buf, cursor)?;
            ensure!(raw_sz != 0, "{}: zero-size cell", fname);
            let abs_sz = raw_sz.unsigned_abs() as usize;
            ensure!(
                abs_sz.is_multiple_of(8) && cursor + abs_sz <= end,
                "{}: bad cell align/bounds",
                fname
            );
            if raw_sz < 0 && abs_sz >= 6 {
                match &buf[cursor + 4..cursor + 6] {
                    b"nk" => saw_nk = true,
                    b"vk" => saw_vk = true,
                    b"sk" => saw_sk = true,
                    b"lf" | b"lh" => saw_list = true,
                    _ => {}
                }
            }
            cursor += abs_sz;
            cell_count += 1;
        }
        ensure!(cursor == end, "{}: cell walk incomplete", fname);
        ensure!(
            saw_nk && saw_vk && saw_sk && saw_list,
            "{}: missing nk/vk/sk/list cell",
            fname
        );
        ensure!(
            &buf[0x1024..0x1026] == b"nk",
            "{}: root cell is not nk",
            fname
        );
        ensure!(
            read_u32_le(&buf, 0x1020 + 4 + 0x14)? >= 1,
            "{}: root has 0 subkeys",
            fname
        );

        let haystack = String::from_utf8_lossy(&buf);
        let haystack_u16: Vec<u16> = buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded_u16 = String::from_utf16_lossy(&haystack_u16);
        ensure!(
            haystack.contains(marker1) || decoded_u16.contains(marker1),
            "{}: missing {}",
            fname,
            marker1
        );
        ensure!(
            haystack.contains(marker2) || decoded_u16.contains(marker2),
            "{}: missing {}",
            fname,
            marker2
        );
        let _ = read_u16_le(&buf, 0x14)?;
        details.push(format!("hive/{}: {} cells verified", fname, cell_count));
    }
    Ok((expected.len(), details))
}
