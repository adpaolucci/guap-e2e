use std::path::Path;
use anyhow::{ensure, Result};
use crate::util::{
    read_u32_le, utf16le_bytes, utf16le_nul, write_file_deterministic, FIXED_FILETIME,
    FIXED_UNIX_SECS,
};

fn push_minidump_string(buf: &mut Vec<u8>, s: &str) -> u32 {
    let rva = buf.len() as u32;
    let raw = utf16le_bytes(s);
    buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    buf.extend_from_slice(&raw);
    buf.extend_from_slice(&[0u8, 0u8]);
    rva
}

fn build_memory_dmp() -> Vec<u8> {
    let mut buf = vec![0u8; 32 + 4 * 12]; // header + 4 directory entries
    buf[0x00..0x04].copy_from_slice(&0x504D_444Du32.to_le_bytes()); // MDMP
    buf[0x04..0x08].copy_from_slice(&0x0000_A793u32.to_le_bytes());
    buf[0x08..0x0C].copy_from_slice(&4u32.to_le_bytes());
    buf[0x0C..0x10].copy_from_slice(&32u32.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&(FIXED_UNIX_SECS as u32).to_le_bytes());

    let csd_rva = push_minidump_string(&mut buf, "Service Pack 0");
    let mod1_rva = push_minidump_string(&mut buf, r"C:\Windows\System32\ntoskrnl.exe");
    let mod2_rva = push_minidump_string(&mut buf, r"C:\Windows\System32\drivers\guap_test.sys");

    // Thread context (1232B AMD64 CONTEXT)
    let ctx_rva = buf.len() as u32;
    let mut ctx = vec![0u8; 1232];
    ctx[0x30..0x34].copy_from_slice(&0x0010_000Fu32.to_le_bytes()); // ContextFlags
    ctx[0xF8..0x100].copy_from_slice(&0xFFFF_F800_1234_5678u64.to_le_bytes()); // Rip
    buf.extend_from_slice(&ctx);

    // 1. SystemInfoStream (7, 56B)
    let sys_rva = buf.len() as u32;
    let mut sys = vec![0u8; 56];
    sys[0..2].copy_from_slice(&9u16.to_le_bytes()); // AMD64
    sys[2..4].copy_from_slice(&6u16.to_le_bytes());
    sys[4..6].copy_from_slice(&0x9E0Au16.to_le_bytes());
    sys[6] = 4; // NumberOfProcessors
    sys[7] = 1; // Workstation
    sys[8..12].copy_from_slice(&10u32.to_le_bytes());
    sys[12..16].copy_from_slice(&0u32.to_le_bytes());
    sys[16..20].copy_from_slice(&22631u32.to_le_bytes());
    sys[20..24].copy_from_slice(&2u32.to_le_bytes());
    sys[24..28].copy_from_slice(&csd_rva.to_le_bytes());
    sys[28..30].copy_from_slice(&0x0100u16.to_le_bytes());
    buf.extend_from_slice(&sys);

    // 2. ExceptionStream (6, 168B)
    let exc_rva = buf.len() as u32;
    let mut exc = vec![0u8; 168];
    exc[0..4].copy_from_slice(&1004u32.to_le_bytes());
    exc[8..12].copy_from_slice(&0xC000_0005u32.to_le_bytes());
    exc[24..32].copy_from_slice(&0xFFFF_F800_1234_5678u64.to_le_bytes());
    exc[32..36].copy_from_slice(&2u32.to_le_bytes());
    exc[160..164].copy_from_slice(&1232u32.to_le_bytes());
    exc[164..168].copy_from_slice(&ctx_rva.to_le_bytes());
    buf.extend_from_slice(&exc);

    // 3. ModuleListStream (4, 4 + 108*2 = 220B)
    let mod_rva = buf.len() as u32;
    let mut mods = Vec::with_capacity(220);
    mods.extend_from_slice(&2u32.to_le_bytes());
    for (base, size, name_rva) in [
        (0xFFFF_F800_1000_0000u64, 0x0100_0000u32, mod1_rva),
        (0xFFFF_F800_1234_0000u64, 0x0002_0000u32, mod2_rva),
    ] {
        let mut m = vec![0u8; 108];
        m[0..8].copy_from_slice(&base.to_le_bytes());
        m[8..12].copy_from_slice(&size.to_le_bytes());
        m[16..20].copy_from_slice(&(FIXED_UNIX_SECS as u32).to_le_bytes());
        m[20..24].copy_from_slice(&name_rva.to_le_bytes());
        // VS_FIXEDFILEINFO (52B at offset 24)
        m[24..28].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
        m[28..32].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        m[32..36].copy_from_slice(&0x000A_0000u32.to_le_bytes()); // 10.0
        m[36..40].copy_from_slice(&0x5867_0001u32.to_le_bytes()); // 22631.1
        mods.extend_from_slice(&m);
    }
    buf.extend_from_slice(&mods);

    // 4. ThreadListStream (3, 4 + 48 = 52B)
    let thr_rva = buf.len() as u32;
    let mut thr = vec![0u8; 52];
    thr[0..4].copy_from_slice(&1u32.to_le_bytes());
    thr[4..8].copy_from_slice(&1004u32.to_le_bytes());
    thr[16..20].copy_from_slice(&8u32.to_le_bytes());
    thr[44..48].copy_from_slice(&1232u32.to_le_bytes());
    thr[48..52].copy_from_slice(&ctx_rva.to_le_bytes());
    buf.extend_from_slice(&thr);

    let dir_entries = [
        (7u32, 56u32, sys_rva),
        (6u32, 168u32, exc_rva),
        (4u32, 220u32, mod_rva),
        (3u32, 52u32, thr_rva),
    ];
    for (idx, (stype, dsz, drva)) in dir_entries.iter().enumerate() {
        let off = 32 + idx * 12;
        buf[off..off + 4].copy_from_slice(&stype.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&dsz.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&drva.to_le_bytes());
    }
    buf
}

fn build_report_wer() -> Vec<u8> {
    let text = format!(
        "Version=1\r\n\
         EventType=APPCRASH\r\n\
         EventTime={}\r\n\
         ReportType=2\r\n\
         ReportIdentifier=11112222-3333-4444-5555-666677778888\r\n\
         AppName=forensics_sample.exe\r\n\
         AppPath=C:\\Tools\\forensics_sample.exe\r\n\
         Sig[0].Name=Application Name\r\n\
         Sig[0].Value=forensics_sample.exe\r\n\
         Sig[1].Name=Application Version\r\n\
         Sig[1].Value=1.2.3.4\r\n\
         Sig[3].Name=Fault Module Name\r\n\
         Sig[3].Value=guap_test.dll\r\n\
         Sig[4].Name=Fault Module Version\r\n\
         Sig[4].Value=1.0.0.1\r\n\
         Sig[6].Name=Exception Code\r\n\
         Sig[6].Value=c0000005\r\n\
         Sig[7].Name=Exception Offset\r\n\
         Sig[7].Value=0000000000005678\r\n\
         OSVersion=10.0.22631.2.0.0.256.48\r\n",
        FIXED_FILETIME
    );
    let mut out = vec![0xFFu8, 0xFEu8];
    out.extend_from_slice(&utf16le_bytes(&text));
    // Ensure clean NUL not appended unless needed; Report.wer is plain UTF-16LE text
    let _ = utf16le_nul("");
    out
}

pub fn generate_crash_dir(crash_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(crash_dir)?;

    write_file_deterministic(&crash_dir.join("memory.dmp"), &build_memory_dmp())?;
    write_file_deterministic(&crash_dir.join("Report.wer"), &build_report_wer())?;

    let cbs_log = "\
2026-11-22 14:20:01, Info                  CBS    Session: 31100001_1001 initialized by client WindowsUpdateAgent.
2026-11-22 14:21:15, Info                  CBS    Appl: Package: Package_for_RollupFix~31bf3856ad364e35~amd64~~22631.4460.1.12 (KB5048685) installed [HRESULT = 0x00000000 - S_OK]
2026-11-22 14:22:30, Info                  CBS    Appl: Package: Package_for_DotNetRollup~31bf3856ad364e35~amd64~~10.0.9277.3 (KB5049981) installed [HRESULT = 0x00000000 - S_OK]
";
    write_file_deterministic(&crash_dir.join("CBS.log"), cbs_log.as_bytes())?;

    let wmi_json = serde_json::json!({
        "schema_version": 1,
        "generated_at": "2026-11-22T14:30:00Z",
        "defender_status": {
            "AMServiceEnabled": true,
            "AntivirusEnabled": true,
            "RealTimeProtectionEnabled": true,
            "AntispywareSignatureVersion": "1.421.150.0",
            "SignatureUpdated": "2026-11-22T12:00:00Z",
            "QuickScanAge": 1,
            "FullScanAge": 5,
            "ExclusionPaths": ["C:\\Cases\\Quarantine"]
        },
        "security_center2": {
            "AntiVirusProduct": [
                {
                    "displayName": "Windows Defender",
                    "instanceGuid": "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}",
                    "pathToSignedProductExe": "windowsdefender://",
                    "productState": 397312
                }
            ],
            "FirewallProduct": [
                {
                    "displayName": "Windows Firewall",
                    "instanceGuid": "{A1B2C3D4-0001-0002-0003-000000000001}",
                    "pathToSignedProductExe": "windowsfirewall://",
                    "productState": 397312
                }
            ],
            "AntiSpywareProduct": [
                {
                    "displayName": "GUAP Test Endpoint Monitor",
                    "instanceGuid": "{A1B2C3D4-0001-0002-0003-000000000002}",
                    "pathToSignedProductExe": "C:\\Program Files\\GUAP\\epmon.exe",
                    "productState": 393472
                }
            ]
        }
    });
    write_file_deterministic(
        &crash_dir.join("wmi_posture.json"),
        serde_json::to_string_pretty(&wmi_json)?.as_bytes(),
    )?;

    Ok(())
}

pub fn verify_crash_dir(crash_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    let dmp = std::fs::read(crash_dir.join("memory.dmp"))?;
    ensure!(read_u32_le(&dmp, 0)? == 0x504D_444D, "bad MDMP magic");
    let num_streams = read_u32_le(&dmp, 8)? as usize;
    ensure!(num_streams == 4, "MDMP unexpected stream count {}", num_streams);
    let dir_rva = read_u32_le(&dmp, 12)? as usize;
    let mut found_types = Vec::new();
    for i in 0..num_streams {
        let off = dir_rva + i * 12;
        let stype = read_u32_le(&dmp, off)?;
        let dsz = read_u32_le(&dmp, off + 4)? as usize;
        let drva = read_u32_le(&dmp, off + 8)? as usize;
        ensure!(drva + dsz <= dmp.len(), "MDMP stream {} out of bounds", stype);
        found_types.push(stype);
    }
    ensure!(found_types == [7, 6, 4, 3], "MDMP unexpected stream types {:?}", found_types);
    details.push("crash/memory.dmp: MDMP 4 streams verified".into());

    let wer = std::fs::read(crash_dir.join("Report.wer"))?;
    ensure!(wer.starts_with(&[0xFF, 0xFE]) && wer.len() % 2 == 0, "Report.wer bad UTF-16LE BOM");
    let units: Vec<u16> = wer[2..]
        .as_chunks::<2>().0.iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let decoded = String::from_utf16(&units)?;
    ensure!(decoded.contains("EventType=APPCRASH") && decoded.contains("c0000005"), "Report.wer missing fields");
    details.push("crash/Report.wer: UTF-16LE APPCRASH verified".into());

    let cbs = std::fs::read_to_string(crash_dir.join("CBS.log"))?;
    ensure!(cbs.contains("KB5048685") && cbs.contains("KB5049981"), "CBS.log missing KBs");
    details.push("crash/CBS.log: verified".into());

    let wmi: serde_json::Value = serde_json::from_slice(&std::fs::read(crash_dir.join("wmi_posture.json"))?)?;
    ensure!(wmi["defender_status"]["AntivirusEnabled"] == true, "wmi_posture.json invalid");
    details.push("crash/wmi_posture.json: verified".into());

    Ok((4, details))
}