use std::path::Path;
use anyhow::{ensure, Result};
use crate::util::write_file_deterministic;

pub fn build_valid_edid_256() -> Vec<u8> {
    let mut b0 = [0u8; 128];
    b0[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    b0[8..10].copy_from_slice(&[0x1E, 0xB0]); // "GUP"
    b0[10..12].copy_from_slice(&0x0001u16.to_le_bytes());
    b0[12..16].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    b0[16] = 47;
    b0[17] = 36; // 1990 + 36 = 2026
    b0[18] = 0x01;
    b0[19] = 0x04; // EDID 1.4
    b0[20] = 0xA5;
    b0[21] = 60;
    b0[22] = 34;
    b0[23] = 0x78;
    b0[24] = 0x22;
    b0[25..35].copy_from_slice(&[0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54]);
    b0[35..38].copy_from_slice(&[0x20, 0x00, 0x00]);
    b0[38..40].copy_from_slice(&[0xD1, 0xC0]);
    for i in 0..7 {
        b0[40 + i * 2] = 0x01;
        b0[40 + i * 2 + 1] = 0x01;
    }
    b0[54..72].copy_from_slice(&[
        0x02, 0x3A, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40, 0x58, 0x2C, 0x45, 0x00, 0x58, 0x54, 0x21,
        0x00, 0x00, 0x1E,
    ]);
    b0[72..77].copy_from_slice(&[0x00, 0x00, 0x00, 0xFC, 0x00]);
    b0[77..90].copy_from_slice(b"GUAP-27UHD\n  ");
    b0[90..95].copy_from_slice(&[0x00, 0x00, 0x00, 0xFF, 0x00]);
    b0[95..108].copy_from_slice(b"SN-GUAP-0001\n");
    b0[108..126].copy_from_slice(&[
        0x00, 0x00, 0x00, 0xFD, 0x00, 0x30, 0x90, 0x1E, 0xA0, 0x1E, 0x00, 0x0A, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20,
    ]);
    b0[126] = 0x01;
    let sum0: u32 = b0[0..127].iter().map(|&x| x as u32).sum();
    b0[127] = ((256 - (sum0 % 256)) % 256) as u8;

    let mut b1 = [0u8; 128];
    b1[0] = 0x02;
    b1[1] = 0x03;
    b1[2] = 0x0C;
    b1[3] = 0x71;
    b1[4..8].copy_from_slice(&[0x43, 0x90, 0x04, 0x03]);
    b1[8..12].copy_from_slice(&[0x23, 0x09, 0x07, 0x07]);
    let sum1: u32 = b1[0..127].iter().map(|&x| x as u32).sum();
    b1[127] = ((256 - (sum1 % 256)) % 256) as u8;

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&b0);
    out.extend_from_slice(&b1);
    out
}

pub fn generate_winctl_dir(winctl_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(winctl_dir)?;

    write_file_deterministic(&winctl_dir.join("monitor_edid.bin"), &build_valid_edid_256())?;

    let ncl = "\
; GUAP winctl2rust-cmd Script DSL fixture (offline dry-run safe)
speak text \"System audit complete\"
clipboard set \"GUAP-CLIPBOARD-TEST\"
mutesysvolume 0
setvolume 0 32768 32768
monitor off
screensaver
wait 500
beep 440 200
win min class \"Notepad\"
";
    write_file_deterministic(&winctl_dir.join("cmd_script.gcl"), ncl.as_bytes())?;

    let adv = serde_json::json!({
        "schema_version": 1,
        "profiles": [{
            "profile_name": "GuapOfflineToolCheck",
            "exe_path": "C:\\Windows\\System32\\cmd.exe",
            "args": "/c echo GUAP_OK",
            "work_dir": "C:\\Windows\\Temp",
            "run_as_mode": "CurrentUser",
            "priority_class": "Normal",
            "affinity_mask": "0x0000000F",
            "window_state": "Hidden",
            "env_overrides": { "GUAP_TEST_MODE": "1" },
            "compatibility_layer": ""
        }]
    });
    write_file_deterministic(
        &winctl_dir.join("advanced_run_profile.json"),
        serde_json::to_string_pretty(&adv)?.as_bytes(),
    )?;

    let audio_mccs = serde_json::json!({
        "schema_version": 1,
        "audio_endpoints": [{
            "id": "{0.0.0.00000000}.{11111111-2222-3333-4444-555555555555}",
            "name": "Speakers (GUAP Virtual Audio)",
            "direction": "Render",
            "default_type": "Console",
            "muted": false,
            "volume_percent": 65.0,
            "volume_db": -6.2,
            "channels": 2,
            "sessions": [{
                "pid": 4242,
                "app_name": "demo_player.exe",
                "volume_percent": 80.0,
                "muted": false
            }]
        }],
        "mccs_monitors": [{
            "monitor_name": "GUAP-27UHD",
            "device_name": "\\\\.\\DISPLAY1\\Monitor0",
            "capabilities": "(prot(monitor)type(lcd)model(GUAP-27UHD)vcp(10 12 60(0F 11 12) D6(01 04 05)))",
            "vcp_features": [
                { "code": "0x10", "name": "Luminance (Brightness)", "current": 75, "max": 100, "possible": [], "read_only": false },
                { "code": "0x12", "name": "Contrast", "current": 50, "max": 100, "possible": [], "read_only": false },
                { "code": "0x60", "name": "Input Source", "current": 15, "max": 18, "possible": [15, 17, 18], "read_only": false },
                { "code": "0xD6", "name": "Power Mode", "current": 1, "max": 5, "possible": [1, 4, 5], "read_only": false }
            ]
        }]
    });
    write_file_deterministic(
        &winctl_dir.join("audio_mccs_mock.json"),
        serde_json::to_string_pretty(&audio_mccs)?.as_bytes(),
    )?;

    Ok(())
}

pub fn verify_winctl_dir(winctl_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    let edid = std::fs::read(winctl_dir.join("monitor_edid.bin"))?;
    ensure!(edid.len() == 256, "bad EDID length {}", edid.len());
    ensure!(edid[0..8] == [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00], "bad EDID header");
    ensure!(edid[18] == 1 && edid[19] == 4 && edid[126] == 1, "bad EDID 1.4 version/ext");
    let sum0: u32 = edid[0..128].iter().map(|&x| x as u32).sum();
    let sum1: u32 = edid[128..256].iter().map(|&x| x as u32).sum();
    ensure!(sum0.is_multiple_of(256), "EDID block 0 checksum failed");
    ensure!(edid[128] == 0x02 && sum1.is_multiple_of(256), "CEA-861 block 1 checksum failed");
    details.push("winctl/monitor_edid.bin: 256B EDID 1.4 + CEA-861 checksums verified".into());

    let ncl = std::fs::read_to_string(winctl_dir.join("cmd_script.gcl"))?;
    ensure!(ncl.contains("mutesysvolume") && !ncl.contains("RunAsDate"), "bad cmd_script.gcl");
    details.push("winctl/cmd_script.gcl: verified".into());

    let adv: serde_json::Value = serde_json::from_slice(&std::fs::read(winctl_dir.join("advanced_run_profile.json"))?)?;
    ensure!(adv["profiles"][0]["profile_name"] == "GuapOfflineToolCheck", "bad advanced_run_profile.json");
    details.push("winctl/advanced_run_profile.json: verified".into());

    let am: serde_json::Value = serde_json::from_slice(&std::fs::read(winctl_dir.join("audio_mccs_mock.json"))?)?;
    ensure!(am["audio_endpoints"][0]["channels"] == 2 && am["mccs_monitors"][0]["vcp_features"].as_array().map(|a| a.len()) == Some(4), "bad audio_mccs_mock.json");
    details.push("winctl/audio_mccs_mock.json: verified".into());

    Ok((4, details))
}