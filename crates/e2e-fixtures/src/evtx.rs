use std::collections::BTreeSet;
use std::path::Path;
use anyhow::{ensure, Result};
use crate::util::{crc32_ieee, read_u16_le, read_u32_le, read_u64_le, sha1_digest, utf16le_bytes, write_file_deterministic, FIXED_FILETIME};

const EVTX_FILE_HEADER_SIZE: usize = 4096;
const EVTX_CHUNK_SIZE: usize = 65536;
const EVTX_CHUNK_HEADER_SIZE: usize = 512;

#[derive(Clone)]
pub enum SubValue {
    String(String),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Guid([u8; 16]),
    FileTime(u64),
    Sid(Vec<u8>),
    HexInt32(u32),
    HexInt64(u64),
}

impl SubValue {
    fn val_type(&self) -> u8 {
        match self {
            SubValue::String(_) => 0x01,
            SubValue::UInt8(_) => 0x04,
            SubValue::UInt16(_) => 0x06,
            SubValue::UInt32(_) => 0x08,
            SubValue::UInt64(_) => 0x0A,
            SubValue::Guid(_) => 0x0F,
            SubValue::FileTime(_) => 0x11,
            SubValue::Sid(_) => 0x13,
            SubValue::HexInt32(_) => 0x14,
            SubValue::HexInt64(_) => 0x15,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            SubValue::String(s) => utf16le_bytes(s),
            SubValue::UInt8(v) => vec![*v],
            SubValue::UInt16(v) => v.to_le_bytes().to_vec(),
            SubValue::UInt32(v) => v.to_le_bytes().to_vec(),
            SubValue::UInt64(v) => v.to_le_bytes().to_vec(),
            SubValue::Guid(g) => g.to_vec(),
            SubValue::FileTime(v) => v.to_le_bytes().to_vec(),
            SubValue::Sid(b) => b.clone(),
            SubValue::HexInt32(v) => v.to_le_bytes().to_vec(),
            SubValue::HexInt64(v) => v.to_le_bytes().to_vec(),
        }
    }
}

fn system_sid_bytes() -> Vec<u8> {
    vec![0x01, 0x01, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}

fn provider_guid(provider: &str) -> [u8; 16] {
    let digest = sha1_digest(provider.as_bytes());
    let mut g = [0u8; 16];
    g.copy_from_slice(&digest[..16]);
    g[7] = (g[7] & 0x0F) | 0x50;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

fn binxml_name_hash(name: &str) -> u16 {
    let mut h: u32 = 0;
    for cu in name.encode_utf16() {
        h = h.wrapping_mul(65599).wrapping_add(cu as u32);
    }
    (h & 0xFFFF) as u16
}

fn write_inline_name(buf: &mut Vec<u8>, chunk_base: usize, name: &str) {
    let pos_in_chunk = chunk_base + buf.len();
    buf.extend_from_slice(&((pos_in_chunk + 4) as u32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&binxml_name_hash(name).to_le_bytes());
    let chars: Vec<u16> = name.encode_utf16().collect();
    buf.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for cu in chars {
        buf.extend_from_slice(&cu.to_le_bytes());
    }
    buf.extend_from_slice(&0u16.to_le_bytes());
}

enum ElementContent<'a> {
    TextSub(u16, u8),
    Empty,
    Children(&'a [XmlNode<'a>]),
}

struct XmlAttr<'a> {
    name: &'a str,
    val: XmlAttrVal<'a>,
}

enum XmlAttrVal<'a> {
    Literal(&'a str),
    OptSub(u16, u8),
}

struct XmlNode<'a> {
    name: &'a str,
    attrs: &'a [XmlAttr<'a>],
    content: ElementContent<'a>,
}

fn encode_xml_node(buf: &mut Vec<u8>, chunk_base: usize, node: &XmlNode<'_>) {
    let has_attrs = !node.attrs.is_empty();
    buf.push(if has_attrs { 0x41 } else { 0x01 });
    buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
    let data_size_pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());

    let after_data_size = buf.len();
    write_inline_name(buf, chunk_base, node.name);

    if has_attrs {
        let attr_len_pos = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes());
        let attr_start = buf.len();
        for (idx, attr) in node.attrs.iter().enumerate() {
            let is_last = idx + 1 == node.attrs.len();
            buf.push(if is_last { 0x06 } else { 0x46 });
            write_inline_name(buf, chunk_base, attr.name);
            match attr.val {
                XmlAttrVal::Literal(lit) => {
                    buf.push(0x05);
                    buf.push(0x01);
                    let chars: Vec<u16> = lit.encode_utf16().collect();
                    buf.extend_from_slice(&(chars.len() as u16).to_le_bytes());
                    for cu in chars {
                        buf.extend_from_slice(&cu.to_le_bytes());
                    }
                }
                XmlAttrVal::OptSub(sub_id, vtype) => {
                    buf.push(0x0E);
                    buf.extend_from_slice(&sub_id.to_le_bytes());
                    buf.push(vtype);
                }
            }
        }
        let attr_bytes = (buf.len() - attr_start) as u32;
        buf[attr_len_pos..attr_len_pos + 4].copy_from_slice(&attr_bytes.to_le_bytes());
    }

    match &node.content {
        ElementContent::Empty => buf.push(0x03),
        ElementContent::TextSub(sub_id, vtype) => {
            buf.push(0x02);
            buf.push(0x0D);
            buf.extend_from_slice(&sub_id.to_le_bytes());
            buf.push(*vtype);
            buf.push(0x04);
        }
        ElementContent::Children(children) => {
            buf.push(0x02);
            for child in *children {
                encode_xml_node(buf, chunk_base, child);
            }
            buf.push(0x04);
        }
    }

    let data_size = (buf.len() - after_data_size) as u32;
    buf[data_size_pos..data_size_pos + 4].copy_from_slice(&data_size.to_le_bytes());
}

struct EvtxEventSpec<'a> {
    provider: &'a str,
    channel: &'a str,
    event_id: u16,
    data_fields: Vec<(&'a str, SubValue)>,
}

fn build_event_record(chunk_offset: usize, record_id: u64, spec: &EvtxEventSpec<'_>) -> Vec<u8> {
    let mut subs: Vec<SubValue> = vec![
        SubValue::Guid(provider_guid(spec.provider)),
        SubValue::UInt16(spec.event_id),
        SubValue::UInt8(0),
        SubValue::UInt8(0x04),
        SubValue::UInt16(0),
        SubValue::UInt8(0),
        SubValue::HexInt64(0x8020_0000_0000_0000),
        SubValue::FileTime(FIXED_FILETIME),
        SubValue::UInt64(record_id),
        SubValue::UInt32(4200),
        SubValue::UInt32(4204),
        SubValue::String(spec.channel.to_string()),
        SubValue::String("GUAP-WKSTN01.example.local".to_string()),
        SubValue::Sid(system_sid_bytes()),
    ];
    for (_, val) in &spec.data_fields {
        subs.push(val.clone());
    }

    let mut rec = Vec::with_capacity(1024);
    rec.extend_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.extend_from_slice(&record_id.to_le_bytes());
    rec.extend_from_slice(&FIXED_FILETIME.to_le_bytes());

    rec.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
    rec.push(0x0C);
    rec.push(0x01);
    rec.extend_from_slice(&(spec.event_id as u32).to_le_bytes());
    let tpl_def_offset = (chunk_offset + rec.len() + 4) as u32;
    rec.extend_from_slice(&tpl_def_offset.to_le_bytes());

    rec.extend_from_slice(&0u32.to_le_bytes());
    let mut guid = [0u8; 16];
    guid[0..2].copy_from_slice(&spec.event_id.to_le_bytes());
    guid[2..10].copy_from_slice(&record_id.to_le_bytes());
    rec.extend_from_slice(&guid);
    let tpl_size_pos = rec.len();
    rec.extend_from_slice(&0u32.to_le_bytes());

    let tpl_inner_start = rec.len();
    rec.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);

    let prov_attrs = [
        XmlAttr { name: "Name", val: XmlAttrVal::Literal(spec.provider) },
        XmlAttr { name: "Guid", val: XmlAttrVal::OptSub(0, 0x0F) },
    ];
    let time_attrs = [XmlAttr { name: "SystemTime", val: XmlAttrVal::OptSub(7, 0x11) }];
    let exec_attrs = [
        XmlAttr { name: "ProcessID", val: XmlAttrVal::OptSub(9, 0x08) },
        XmlAttr { name: "ThreadID", val: XmlAttrVal::OptSub(10, 0x08) },
    ];
    let sec_attrs = [XmlAttr { name: "UserID", val: XmlAttrVal::OptSub(13, 0x13) }];

    let sys_children = [
        XmlNode { name: "Provider", attrs: &prov_attrs, content: ElementContent::Empty },
        XmlNode { name: "EventID", attrs: &[], content: ElementContent::TextSub(1, 0x06) },
        XmlNode { name: "Version", attrs: &[], content: ElementContent::TextSub(2, 0x04) },
        XmlNode { name: "Level", attrs: &[], content: ElementContent::TextSub(3, 0x04) },
        XmlNode { name: "Task", attrs: &[], content: ElementContent::TextSub(4, 0x06) },
        XmlNode { name: "Opcode", attrs: &[], content: ElementContent::TextSub(5, 0x04) },
        XmlNode { name: "Keywords", attrs: &[], content: ElementContent::TextSub(6, 0x15) },
        XmlNode { name: "TimeCreated", attrs: &time_attrs, content: ElementContent::Empty },
        XmlNode { name: "EventRecordID", attrs: &[], content: ElementContent::TextSub(8, 0x0A) },
        XmlNode { name: "Correlation", attrs: &[], content: ElementContent::Empty },
        XmlNode { name: "Execution", attrs: &exec_attrs, content: ElementContent::Empty },
        XmlNode { name: "Channel", attrs: &[], content: ElementContent::TextSub(11, 0x01) },
        XmlNode { name: "Computer", attrs: &[], content: ElementContent::TextSub(12, 0x01) },
        XmlNode { name: "Security", attrs: &sec_attrs, content: ElementContent::Empty },
    ];

    let mut data_attr_storage: Vec<[XmlAttr<'_>; 1]> = Vec::with_capacity(spec.data_fields.len());
    for (fname, _) in &spec.data_fields {
        data_attr_storage.push([XmlAttr { name: "Name", val: XmlAttrVal::Literal(fname) }]);
    }
    let mut data_nodes: Vec<XmlNode<'_>> = Vec::with_capacity(spec.data_fields.len());
    for (i, (_, val)) in spec.data_fields.iter().enumerate() {
        data_nodes.push(XmlNode {
            name: "Data",
            attrs: &data_attr_storage[i],
            content: ElementContent::TextSub((14 + i) as u16, val.val_type()),
        });
    }

    let event_attrs = [XmlAttr {
        name: "xmlns",
        val: XmlAttrVal::Literal("http://schemas.microsoft.com/win/2004/08/events/event"),
    }];
    let root_children = [
        XmlNode { name: "System", attrs: &[], content: ElementContent::Children(&sys_children) },
        XmlNode { name: "EventData", attrs: &[], content: ElementContent::Children(&data_nodes) },
    ];
    let root = XmlNode { name: "Event", attrs: &event_attrs, content: ElementContent::Children(&root_children) };

    encode_xml_node(&mut rec, chunk_offset, &root);
    rec.push(0x00);

    let tpl_data_size = (rec.len() - tpl_inner_start) as u32;
    rec[tpl_size_pos..tpl_size_pos + 4].copy_from_slice(&tpl_data_size.to_le_bytes());

    rec.extend_from_slice(&(subs.len() as u32).to_le_bytes());
    let mut raw_values = Vec::new();
    for s in &subs {
        let bytes = s.to_bytes();
        rec.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        rec.push(s.val_type());
        rec.push(0x00);
        raw_values.extend_from_slice(&bytes);
    }
    rec.extend_from_slice(&raw_values);
    rec.push(0x00);

    let total_size = (rec.len() + 4) as u32;
    rec[4..8].copy_from_slice(&total_size.to_le_bytes());
    rec.extend_from_slice(&total_size.to_le_bytes());
    rec
}

fn build_evtx_file(events: &[EvtxEventSpec<'_>]) -> Result<Vec<u8>> {
    let mut chunk = vec![0u8; EVTX_CHUNK_SIZE];
    chunk[0..8].copy_from_slice(b"ElfChnk\0");

    let n = events.len() as u64;
    ensure!(n > 0, "EVTX file requires at least 1 event");
    chunk[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x10..0x18].copy_from_slice(&n.to_le_bytes());
    chunk[0x18..0x20].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x20..0x28].copy_from_slice(&n.to_le_bytes());
    chunk[0x28..0x2C].copy_from_slice(&(128u32).to_le_bytes());

    let mut cursor = EVTX_CHUNK_HEADER_SIZE;
    let mut last_rec_off = EVTX_CHUNK_HEADER_SIZE;
    for (idx, ev) in events.iter().enumerate() {
        let rec_bytes = build_event_record(cursor, (idx + 1) as u64, ev);
        ensure!(cursor + rec_bytes.len() <= EVTX_CHUNK_SIZE, "EVTX chunk overflow");
        last_rec_off = cursor;
        chunk[cursor..cursor + rec_bytes.len()].copy_from_slice(&rec_bytes);
        cursor += rec_bytes.len();
    }

    chunk[0x2C..0x30].copy_from_slice(&(last_rec_off as u32).to_le_bytes());
    chunk[0x30..0x34].copy_from_slice(&(cursor as u32).to_le_bytes());
    let events_crc = crc32_ieee(&chunk[EVTX_CHUNK_HEADER_SIZE..cursor]);
    chunk[0x34..0x38].copy_from_slice(&events_crc.to_le_bytes());

    let mut hdr_crc_input = Vec::with_capacity(120 + 384);
    hdr_crc_input.extend_from_slice(&chunk[0..120]);
    hdr_crc_input.extend_from_slice(&chunk[128..512]);
    let chunk_hdr_crc = crc32_ieee(&hdr_crc_input);
    chunk[0x7C..0x80].copy_from_slice(&chunk_hdr_crc.to_le_bytes());

    let mut file_hdr = vec![0u8; EVTX_FILE_HEADER_SIZE];
    file_hdr[0..8].copy_from_slice(b"ElfFile\0");
    file_hdr[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());
    file_hdr[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
    file_hdr[0x18..0x20].copy_from_slice(&(n + 1).to_le_bytes());
    file_hdr[0x20..0x24].copy_from_slice(&128u32.to_le_bytes());
    file_hdr[0x24..0x26].copy_from_slice(&1u16.to_le_bytes());
    file_hdr[0x26..0x28].copy_from_slice(&3u16.to_le_bytes());
    file_hdr[0x28..0x2A].copy_from_slice(&(EVTX_FILE_HEADER_SIZE as u16).to_le_bytes());
    file_hdr[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes());
    let file_crc = crc32_ieee(&file_hdr[0..120]);
    file_hdr[0x7C..0x80].copy_from_slice(&file_crc.to_le_bytes());

    let mut full = Vec::with_capacity(EVTX_FILE_HEADER_SIZE + EVTX_CHUNK_SIZE);
    full.extend_from_slice(&file_hdr);
    full.extend_from_slice(&chunk);
    Ok(full)
}

pub fn generate_evtx_dir(evtx_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(evtx_dir)?;

    let sec_events = vec![
        EvtxEventSpec {
            provider: "Microsoft-Windows-Security-Auditing",
            channel: "Security",
            event_id: 4624,
            data_fields: vec![
                ("TargetUserName", SubValue::String("alice".into())),
                ("TargetDomainName", SubValue::String("GUAP".into())),
                ("TargetLogonId", SubValue::HexInt64(0x0000_0000_003A_F410)),
                ("LogonType", SubValue::UInt32(10)),
                ("IpAddress", SubValue::String("192.168.10.50".into())),
                ("WorkstationName", SubValue::String("GUAP-CLIENT".into())),
            ],
        },
        EvtxEventSpec {
            provider: "Microsoft-Windows-Security-Auditing",
            channel: "Security",
            event_id: 4634,
            data_fields: vec![
                ("TargetUserName", SubValue::String("alice".into())),
                ("TargetDomainName", SubValue::String("GUAP".into())),
                ("TargetLogonId", SubValue::HexInt64(0x0000_0000_003A_F410)),
                ("LogonType", SubValue::UInt32(10)),
            ],
        },
        EvtxEventSpec {
            provider: "Microsoft-Windows-Security-Auditing",
            channel: "Security",
            event_id: 4688,
            data_fields: vec![
                ("NewProcessId", SubValue::HexInt32(0x14A0)),
                ("NewProcessName", SubValue::String(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into())),
                ("CommandLine", SubValue::String("powershell.exe -NoProfile -File C:\\Scripts\\audit.ps1".into())),
                ("ParentProcessName", SubValue::String(r"C:\Windows\explorer.exe".into())),
                ("ProcessId", SubValue::HexInt32(0x08B0)),
                ("SubjectUserName", SubValue::String("alice".into())),
                ("TokenElevationType", SubValue::String("%%1936".into())),
            ],
        },
    ];
    write_file_deterministic(&evtx_dir.join("Security.evtx"), &build_evtx_file(&sec_events)?)?;

    let sys_events = vec![
        EvtxEventSpec { provider: "EventLog", channel: "System", event_id: 6005, data_fields: vec![("Binary", SubValue::String("EventLogStarted".into()))] },
        EvtxEventSpec { provider: "EventLog", channel: "System", event_id: 6006, data_fields: vec![("Binary", SubValue::String("EventLogStopped".into()))] },
        EvtxEventSpec {
            provider: "User32",
            channel: "System",
            event_id: 1074,
            data_fields: vec![
                ("param1", SubValue::String("svchost.exe".into())),
                ("param2", SubValue::String("GUAP-WKSTN01".into())),
                ("param3", SubValue::String("Operating System: Upgrade".into())),
                ("param4", SubValue::String("0x80020010".into())),
                ("param5", SubValue::String("restart".into())),
            ],
        },
    ];
    write_file_deterministic(&evtx_dir.join("System.evtx"), &build_evtx_file(&sys_events)?)?;

    let wlan_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-WLAN-AutoConfig",
        channel: "Microsoft-Windows-WLAN-AutoConfig/Operational",
        event_id: 8001,
        data_fields: vec![
            ("InterfaceGuid", SubValue::String("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".into())),
            ("InterfaceDescription", SubValue::String("GUAP Virtual Wi-Fi Adapter".into())),
            ("ConnectionMode", SubValue::String("Automatic connection with a profile".into())),
            ("ProfileName", SubValue::String("GUAP-Lab-5G".into())),
            ("SSID", SubValue::String("GUAP-Lab-5G".into())),
            ("BSSID", SubValue::String("AA:BB:CC:11:22:33".into())),
            ("AuthenticationAlgorithm", SubValue::String("RSNA_PSK".into())),
            ("CipherAlgorithm", SubValue::String("CCMP".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx"), &build_evtx_file(&wlan_events)?)?;

    let def_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-Windows Defender",
        channel: "Microsoft-Windows-Windows Defender/Operational",
        event_id: 1116,
        data_fields: vec![
            ("Threat Name", SubValue::String("Trojan:Win32/EICAR_Test_File".into())),
            ("Severity Name", SubValue::String("Severe".into())),
            ("Category Name", SubValue::String("Trojan".into())),
            ("Path", SubValue::String("file:_C:\\Temp\\eicar.bin".into())),
            ("Process Name", SubValue::String(r"C:\Tools\test.exe".into())),
            ("Action Name", SubValue::String("Quarantine".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-Windows Defender%4Operational.evtx"), &build_evtx_file(&def_events)?)?;

    let lsm_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-TerminalServices-LocalSessionManager",
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        event_id: 21,
        data_fields: vec![
            ("User", SubValue::String("GUAP\\alice".into())),
            ("SessionID", SubValue::UInt32(2)),
            ("Address", SubValue::String("192.168.10.50".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"), &build_evtx_file(&lsm_events)?)?;

    let rcm_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
        channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        event_id: 1149,
        data_fields: vec![
            ("Param1", SubValue::String("alice".into())),
            ("Param2", SubValue::String("GUAP".into())),
            ("Param3", SubValue::String("192.168.10.50".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"), &build_evtx_file(&rcm_events)?)?;

    let ps_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-PowerShell",
        channel: "Microsoft-Windows-PowerShell/Operational",
        event_id: 4104,
        data_fields: vec![
            ("MessageNumber", SubValue::UInt32(1)),
            ("MessageTotal", SubValue::UInt32(1)),
            ("ScriptBlockText", SubValue::String("Get-Process | Select-Object -First 5".into())),
            ("ScriptBlockId", SubValue::String("11111111-2222-3333-4444-555555555555".into())),
            ("Path", SubValue::String(r"C:\Scripts\audit.ps1".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-PowerShell%4Operational.evtx"), &build_evtx_file(&ps_events)?)?;

    let task_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-TaskScheduler",
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        event_id: 106,
        data_fields: vec![
            ("TaskName", SubValue::String(r"\GUAP\NightlyAudit".into())),
            ("UserContext", SubValue::String(r"NT AUTHORITY\SYSTEM".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-TaskScheduler%4Operational.evtx"), &build_evtx_file(&task_events)?)?;

    let pnp_events = vec![EvtxEventSpec {
        provider: "Microsoft-Windows-Kernel-PnP",
        channel: "Microsoft-Windows-Kernel-PnP/Configuration",
        event_id: 400,
        data_fields: vec![
            ("DeviceInstanceId", SubValue::String(r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001231020118273&0".into())),
            ("DriverName", SubValue::String("disk.inf".into())),
            ("ClassGuid", SubValue::String("{4d36e967-e325-11ce-bfc1-08002be10318}".into())),
            ("ServiceName", SubValue::String("disk".into())),
        ],
    }];
    write_file_deterministic(&evtx_dir.join("Microsoft-Windows-Kernel-PnP%4Configuration.evtx"), &build_evtx_file(&pnp_events)?)?;

    Ok(())
}

pub fn verify_evtx_dir(evtx_dir: &Path) -> Result<(usize, Vec<String>)> {
    let expected_files = [
        "Security.evtx",
        "System.evtx",
        "Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
        "Microsoft-Windows-Windows Defender%4Operational.evtx",
        "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
        "Microsoft-Windows-PowerShell%4Operational.evtx",
        "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
    ];
    let mut found_event_ids = BTreeSet::new();
    let mut details = Vec::new();

    for name in &expected_files {
        let buf = std::fs::read(evtx_dir.join(name))?;
        ensure!(buf.len() == EVTX_FILE_HEADER_SIZE + EVTX_CHUNK_SIZE, "{}: bad size", name);
        ensure!(&buf[0..8] == b"ElfFile\0", "{}: bad ElfFile magic", name);
        ensure!(read_u32_le(&buf, 32)? == 128, "{}: bad header_size", name);
        ensure!(read_u16_le(&buf, 36)? == 1, "{}: bad minor_version", name);
        ensure!(read_u16_le(&buf, 38)? == 3, "{}: bad major_version", name);
        ensure!(read_u16_le(&buf, 40)? == 4096, "{}: bad block_size", name);
        ensure!(read_u32_le(&buf, 124)? == crc32_ieee(&buf[0..120]), "{}: file header CRC32 mismatch", name);

        let chunk = &buf[EVTX_FILE_HEADER_SIZE..];
        ensure!(&chunk[0..8] == b"ElfChnk\0", "{}: bad ElfChnk magic", name);
        let free_off = read_u32_le(chunk, 48)? as usize;
        ensure!(free_off > EVTX_CHUNK_HEADER_SIZE && free_off <= EVTX_CHUNK_SIZE, "{}: invalid free_space_offset", name);
        ensure!(read_u32_le(chunk, 52)? == crc32_ieee(&chunk[EVTX_CHUNK_HEADER_SIZE..free_off]), "{}: events CRC32 mismatch", name);
        let mut hdr_crc_in = Vec::with_capacity(120 + 384);
        hdr_crc_in.extend_from_slice(&chunk[0..120]);
        hdr_crc_in.extend_from_slice(&chunk[128..512]);
        ensure!(read_u32_le(chunk, 124)? == crc32_ieee(&hdr_crc_in), "{}: chunk header CRC32 mismatch", name);

        let mut pos = EVTX_CHUNK_HEADER_SIZE;
        let mut rec_count = 0usize;
        while pos < free_off {
            ensure!(&chunk[pos..pos + 4] == b"\x2a\x2a\x00\x00", "{}: bad record magic", name);
            let sz = read_u32_le(chunk, pos + 4)? as usize;
            ensure!(sz >= 32 && pos + sz <= free_off, "{}: invalid record size", name);
            ensure!(sz == read_u32_le(chunk, pos + sz - 4)? as usize, "{}: record size tail mismatch", name);
            let _rec_id = read_u64_le(chunk, pos + 8)?;
            ensure!(chunk[pos + 0x18..pos + 0x1C] == [0x0F, 0x01, 0x01, 0x00], "{}: bad BinXML FragmentHeader", name);
            ensure!(chunk[pos + 0x1C] == 0x0C, "{}: missing TemplateInstance 0x0C", name);
            let tpl_id = read_u32_le(chunk, pos + 0x1E)?;
            found_event_ids.insert(tpl_id);
            pos += sz;
            rec_count += 1;
        }
        details.push(format!("evtx/{}: {} events verified", name, rec_count));
    }

    for required in [4624u32, 4634, 4688, 6005, 6006, 1074, 8001, 1116, 21, 1149, 4104, 106, 400] {
        ensure!(found_event_ids.contains(&required), "EVTX missing required EventID {}", required);
    }

    Ok((expected_files.len(), details))
}