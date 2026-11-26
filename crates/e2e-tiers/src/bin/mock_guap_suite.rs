use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use e2e_tiers::catalog::feature_groups;
use e2e_tiers::export_verify::{
    compute_merkle_root_sha256, compute_merkle_root_sha512, neutralize_spreadsheet_cell, sha256_hex,
    sha512_hex,
};
use e2e_tiers::{CliExportStyle, FeatureGroupDef, McpArgsKind, MutatingArgsKind, TargetWorkspace};
use serde_json::{Value, json};

fn detect_workspace() -> TargetWorkspace {
    if let Ok(ws) = std::env::var("MOCK_GUAP_WORKSPACE") {
        match ws.as_str() {
            "forensics2rust" => return TargetWorkspace::Forensics2Rust,
            "chrome2rust" => return TargetWorkspace::Chrome2Rust,
            "mail2rust" => return TargetWorkspace::Mail2Rust,
            "android2rust" => return TargetWorkspace::Android2Rust,
            "winctl2rust" => return TargetWorkspace::Winctl2Rust,
            "net2rust" => return TargetWorkspace::Net2Rust,
            "sys2rust" => return TargetWorkspace::Sys2Rust,
            "fs2rust" => return TargetWorkspace::Fs2Rust,
            _ => {}
        }
    }
    let stem = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default();
    match stem.as_str() {
        "forensics2rust" => TargetWorkspace::Forensics2Rust,
        "chrome2rust" => TargetWorkspace::Chrome2Rust,
        "mail2rust" => TargetWorkspace::Mail2Rust,
        "android2rust" => TargetWorkspace::Android2Rust,
        "winctl2rust" => TargetWorkspace::Winctl2Rust,
        "net2rust" => TargetWorkspace::Net2Rust,
        "sys2rust" => TargetWorkspace::Sys2Rust,
        "fs2rust" => TargetWorkspace::Fs2Rust,
        _ => TargetWorkspace::Forensics2Rust,
    }
}

fn mock_mode() -> String {
    std::env::var("MOCK_GUAP_MODE").unwrap_or_else(|_| "ok".to_string())
}

fn ws_groups(ws: TargetWorkspace) -> Vec<&'static FeatureGroupDef> {
    feature_groups().iter().filter(|fg| fg.workspace == ws).collect()
}

fn legacy_tools_for(ws: TargetWorkspace) -> &'static [&'static str] {
    match ws {
        TargetWorkspace::Chrome2Rust => &[
            "chrome2rust_profiles",
            "chrome2rust_sniff",
            "chrome2rust_cache_list",
            "chrome2rust_cache_inspect",
            "chrome2rust_cache_extract",
            "chrome2rust_analyze",
            "chrome2rust_report",
            "chrome2rust_custody",
        ],
        TargetWorkspace::Android2Rust => &[
            "android2rust_environment",
            "android2rust_presets",
            "android2rust_build_command",
            "android2rust_parse_command",
            "android2rust_decode_status",
            "android2rust_profiles",
            "android2rust_inspect_artifact",
            "android2rust_dry_run",
            "android2rust_run",
            "android2rust_report",
        ],
        _ => &[],
    }
}

fn print_help(ws: TargetWorkspace, args: &[String]) {
    let groups = ws_groups(ws);
    if args.iter().any(|a| a == "--help" || a == "-h") && args.len() == 1 {
        println!("{:?} mock suite CLI", ws);
        println!("Commands:");
        let mut seen = BTreeSet::new();
        for fg in &groups {
            for it in fg.items {
                if let Some(first) = it.cli_tokens.first() && seen.insert(*first) {
                    println!("  {first:<18} {} subcommands", fg.name);
                }
            }
        }
        if ws == TargetWorkspace::Chrome2Rust {
            println!("  cache              Cache analysis and deletion");
        }
        println!("  mcp                Start MCP JSON-RPC 2.0 server");
        return;
    }

    let prefix: Vec<&str> = args
        .iter()
        .take_while(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    println!("Usage: {:?} {} [OPTIONS]", ws, prefix.join(" "));
    println!("Commands:");
    let mut seen = BTreeSet::new();
    for fg in &groups {
        for it in fg.items {
            if it.cli_tokens.len() > prefix.len() && it.cli_tokens.starts_with(&prefix) {
                let next_tok = it.cli_tokens[prefix.len()];
                if seen.insert(next_tok) {
                    println!("  {next_tok:<20} {}", it.name);
                }
            }
        }
    }
}

fn build_schema(args_kind: McpArgsKind, mutating: bool) -> Value {
    let mut props = json!({});
    match args_kind {
        McpArgsKind::EmptyObject => {
            props = json!({
                "filter": { "type": "string" },
                "sort": { "type": "string" },
                "limit": { "type": "integer" }
            });
            if mutating {
                props["confirm_destructive"] = json!({ "type": "boolean" });
            }
            return json!({
                "type": "object",
                "properties": props,
                "additionalProperties": false
            });
        }
        McpArgsKind::Path => props["path"] = json!({ "type": "string" }),
        McpArgsKind::Source => props["source"] = json!({ "type": "string" }),
        McpArgsKind::SourcePath => props["source_path"] = json!({ "type": "string" }),
        McpArgsKind::ForensicsDiff => {
            props["source_path"] = json!({ "type": "string" });
            props["right_path"] = json!({ "type": "string" });
        }
        McpArgsKind::HiveList => props["hives"] = json!({ "type": "array", "items": { "type": "string" } }),
        McpArgsKind::SourceDirParent => props["source_dir"] = json!({ "type": "string" }),
    }
    json!({
        "type": "object",
        "properties": props
    })
}

fn build_mutating_schema(args_kind: MutatingArgsKind) -> Value {
    let mut props = json!({
        "confirm_destructive": { "type": "boolean" },
        "dry_run": { "type": "boolean" }
    });
    match args_kind {
        MutatingArgsKind::NetOsintSetDns => {
            props["interface"] = json!({ "type": "string" });
            props["servers"] = json!({ "type": "array", "items": { "type": "string" } });
            props["ipv6"] = json!({ "type": "boolean" });
            return json!({
                "type": "object",
                "properties": props,
                "required": ["interface"]
            });
        }
        MutatingArgsKind::NetRadioWifiSetOrder => {
            props["profile_name"] = json!({ "type": "string" });
            props["position"] = json!({ "type": "integer", "minimum": 0 });
            return json!({
                "type": "object",
                "properties": props,
                "required": ["profile_name", "position"]
            });
        }
        MutatingArgsKind::NetSocketsClose => {
            props["local_addr"] = json!({ "type": "string" });
            props["local_port"] = json!({ "type": "integer", "minimum": 1, "maximum": 65535 });
            props["remote_addr"] = json!({ "type": "string" });
            props["remote_port"] = json!({ "type": "integer", "minimum": 0, "maximum": 65535 });
            return json!({
                "type": "object",
                "properties": props,
                "required": ["local_addr", "local_port", "remote_addr", "remote_port"],
                "additionalProperties": false
            });
        }
        MutatingArgsKind::NetLanWol => {
            props["mac"] = json!({ "type": "string" });
            props["broadcast_ip"] = json!({ "type": "string" });
            props["port"] = json!({ "type": "integer", "minimum": 1, "maximum": 65535 });
            props["repeat_count"] = json!({ "type": "integer", "minimum": 1, "maximum": 10 });
            return json!({
                "type": "object",
                "properties": props,
                "required": ["mac"],
                "additionalProperties": false
            });
        }
        _ => {}
    }
    json!({
        "type": "object",
        "properties": props
    })
}

fn build_mcp_tools_json(ws: TargetWorkspace) -> Vec<Value> {
    let mut tools = Vec::new();
    let mut seen = BTreeSet::new();
    for fg in ws_groups(ws) {
        for it in fg.items {
            if !seen.insert(it.mcp_tool) {
                continue;
            }
            let ro = !it.mutating_capable;
            tools.push(json!({
                "name": it.mcp_tool,
                "description": format!("{} ({})", it.name, fg.name),
                "inputSchema": build_schema(it.mcp_args, it.mutating_capable),
                "annotations": {
                    "readOnlyHint": ro,
                    "destructiveHint": !ro
                }
            }));
        }
        if let Some(spec) = fg.mutating_action
            && seen.insert(spec.tool_id)
        {
            tools.push(json!({
                "name": spec.tool_id,
                "description": format!("Mutating action for {}", fg.name),
                "inputSchema": build_mutating_schema(spec.args_kind),
                "annotations": {
                    "readOnlyHint": false,
                    "destructiveHint": true
                }
            }));
        }
    }
    for &legacy in legacy_tools_for(ws) {
        if seen.insert(legacy) {
            tools.push(json!({
                "name": legacy,
                "description": format!("Legacy compatibility tool {legacy}"),
                "inputSchema": { "type": "object", "properties": {} }
            }));
        }
    }
    tools
}

fn make_row_payload(ws: TargetWorkspace, tool_id: &str, mode: &str) -> Value {
    if mode == "silent_empty" {
        return json!({});
    }
    let psk_val = match mode {
        "leak_r4_secret" => "GuapTestWpa2Key!2026",
        "leak_r4_keymaterial_mcp" => "<keyMaterial>SecretWifiPass99</keyMaterial>",
        "leak_r4_plaintext_flag_mcp" => "WLAN_PROFILE_GET_PLAINTEXT_KEY",
        _ => "[REDACTED]",
    };
    if ws == TargetWorkspace::Android2Rust {
        return json!({
            "status": "ok",
            "matched_count": 1,
            "entries": [{
                "object_id": "obj-1",
                "name": "IMG_0001.jpg",
                "size": 1024,
                "tool_id": tool_id
            }]
        });
    }
    if ws == TargetWorkspace::Net2Rust && matches!(tool_id, "radio.wifi-info" | "radio.wifi-profiles") {
        return json!({
            "tool_id": tool_id,
            "title": "WiFi Profiles",
            "columns": [
                {"id": "ssid", "label": "SSID", "col_type": "Text"},
                {"id": "psk", "label": "PSK", "col_type": "Text"}
            ],
            "rows": [{
                "row_id": 1,
                "ssid": "GUAP_TEST_NET",
                "psk": psk_val
            }],
            "total_rows": 1,
            "returned_rows": 1
        });
    }
    json!({
        "tool_id": tool_id,
        "title": format!("Mock {tool_id}"),
        "columns": [
            {"id": "name", "label": "Name", "col_type": "Text"},
            {"id": "value", "label": "Value", "col_type": "Text"}
        ],
        "rows": [{
            "row_id": 1,
            "name": tool_id,
            "value": "ok"
        }],
        "total_rows": 1,
        "returned_rows": 1
    })
}

fn run_mcp_server(ws: TargetWorkspace, args: &[String]) {
    let mut read_only = true;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--policy" && i + 1 < args.len() {
            read_only = args[i + 1] != "allow-mutating";
            i += 2;
        } else {
            i += 1;
        }
    }
    let mode = mock_mode();
    let tools = build_mcp_tools_json(ws);
    let groups = ws_groups(ws);

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                let code = if mode == "bad_parse_error" { -32600 } else { -32700 };
                let err = json!({"jsonrpc":"2.0","id":null,"error":{"code":code,"message":"parse error"}});
                let _ = writeln!(stdout, "{err}");
                let _ = stdout.flush();
                continue;
            }
        };
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let id = req.get("id").cloned();
        if id.is_none() || method.starts_with("notifications/") {
            continue;
        }
        let id = id.unwrap();
        let resp = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": format!("{ws:?}").to_ascii_lowercase(), "version": "0.1.0" }
                }
            }),
            "ping" => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            "tools/list" => json!({"jsonrpc":"2.0","id":id,"result":{"tools": tools}}),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                if !arguments.is_object() && !arguments.is_null() {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": "tool arguments must be a JSON object or null"}
                    })
                } else {
                    let is_mutating_spec = groups.iter().any(|fg| {
                        fg.mutating_action.is_some_and(|s| s.tool_id == tool_name)
                    });
                    let item_opt = groups.iter().flat_map(|fg| fg.items.iter()).find(|it| it.mcp_tool == tool_name);
                    let is_mutating_item = item_opt.is_some_and(|it| it.mutating_capable);
                    let is_legacy = legacy_tools_for(ws).contains(&tool_name);

                    if is_mutating_spec || is_mutating_item {
                        if read_only && mode != "allow_mutating_readonly" {
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32003,
                                    "message": format!("SAFETY REFUSAL: tool '{tool_name}' is mutating and blocked under ReadOnlyOnly policy")
                                }
                            })
                        } else {
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{"type": "text", "text": "{\"status\":\"mutated\"}"}],
                                    "isError": false
                                }
                            })
                        }
                    } else if item_opt.is_some() || is_legacy {
                        if mode == "non_json_mcp_radio"
                            && ws == TargetWorkspace::Net2Rust
                            && matches!(tool_name, "radio.wifi-info" | "radio.wifi-profiles")
                        {
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{"type": "text", "text": "ok"}],
                                    "isError": false
                                }
                            })
                        } else {
                            let payload = if let Some(it) = item_opt {
                                if !it.expects_nonempty_rows
                                    && ws == TargetWorkspace::Sys2Rust
                                    && matches!(tool_name, "pe_exports" | "pe_icons" | "pe_dotnet")
                                {
                                    json!({"tool_id": tool_name, "title": tool_name, "columns": [{"id":"n","label":"N"}], "rows": []})
                                } else {
                                    make_row_payload(ws, tool_name, &mode)
                                }
                            } else {
                                make_row_payload(ws, tool_name, &mode)
                            };
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{"type": "text", "text": serde_json::to_string(&payload).unwrap()}],
                                    "isError": false
                                }
                            })
                        }
                    } else if mode == "bad_32601_iserror" {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": format!("unknown tool '{tool_name}'")}],
                                "isError": true
                            }
                        })
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {"code": -32601, "message": format!("unknown tool '{tool_name}'")}
                        })
                    }
                }
            }
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("method not found: {other}")}
            }),
        };
        let _ = writeln!(stdout, "{resp}");
        let _ = stdout.flush();
    }
}
fn write_export_artifacts(
    ws: TargetWorkspace,
    tool_id: &str,
    export_style: CliExportStyle,
    csv_path: &Path,
    explicit_custody: Option<&Path>,
    mode: &str,
) -> io::Result<Value> {
    if let Some(parent) = csv_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let dangerous = "=cmd|' /C calc'!A0";
    let cell = if mode == "unneutralized_csv" {
        dangerous.to_string()
    } else {
        neutralize_spreadsheet_cell(dangerous)
    };
    let psk = if ws == TargetWorkspace::Net2Rust && matches!(tool_id, "radio.wifi-info" | "radio.wifi-profiles") {
        match mode {
            "leak_r4_secret" => "GuapTestWpa2Key!2026",
            "leak_r4_keymaterial_csv" => "<keyMaterial>SecretWifiPass99</keyMaterial>",
            "leak_r4_plaintext_flag_csv" => "WLAN_PROFILE_GET_PLAINTEXT_KEY",
            _ => "[REDACTED]",
        }
    } else {
        "ok"
    };
    let csv_body = if mode == "csv_header_only" {
        "tool_id,formula,detail\r\n".to_string()
    } else {
        format!("tool_id,formula,detail\r\n{tool_id},\"{cell}\",{psk}\r\n")
    };
    std::fs::write(csv_path, csv_body.as_bytes())?;

    let manifest = if mode == "custody_0leaves" {
        let empty: Vec<String> = Vec::new();
        json!({
            "generated_at": "2026-11-23T08:00:00Z",
            "tool_id": tool_id,
            "tool_version": "0.1.0",
            "artifact_count": 0,
            "total_bytes": 0,
            "merkle_root_sha256": compute_merkle_root_sha256(&empty),
            "merkle_root_sha512": compute_merkle_root_sha512(&empty),
            "leaves": []
        })
    } else {
        let s256 = sha256_hex(csv_body.as_bytes());
        let s512 = sha512_hex(csv_body.as_bytes());
        let merkle256 = if mode == "bad_merkle" {
            "0".repeat(64)
        } else {
            compute_merkle_root_sha256(std::slice::from_ref(&s256))
        };
        let merkle512 = compute_merkle_root_sha512(std::slice::from_ref(&s512));
        json!({
            "generated_at": "2026-11-23T08:00:00Z",
            "tool_id": tool_id,
            "tool_version": "0.1.0",
            "artifact_count": 1,
            "total_bytes": csv_body.len() as u64,
            "merkle_root_sha256": merkle256,
            "merkle_root_sha512": merkle512,
            "leaves": [{
                "index": 0,
                "path": csv_path.display().to_string(),
                "size_bytes": csv_body.len() as u64,
                "sha256": s256,
                "sha512": s512
            }]
        })
    };
    let dest = match export_style {
        CliExportStyle::Mail => PathBuf::from(format!("{}.custody.json", csv_path.display())),
        _ => explicit_custody
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(format!("{}.custody.json", csv_path.display()))),
    };
    let on_disk_val = if export_style == CliExportStyle::Winctl {
        json!({
            "suite_name": "winctl2rust",
            "suite_version": "0.1.0",
            "operator": "mock",
            "case_id": "mock-case",
            "host_name": "mock-host",
            "dry_run": false,
            "custody": manifest,
            "artifact_paths": [csv_path.display().to_string()],
            "sidecar_path": dest.display().to_string()
        })
    } else {
        manifest.clone()
    };
    let manifest_bytes = serde_json::to_vec_pretty(&on_disk_val).unwrap();
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&dest, &manifest_bytes)?;
    Ok(manifest)
}

fn is_corrupt_or_zero(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return true;
    };
    if meta.is_file() {
        if meta.len() == 0 {
            return true;
        }
        let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        return name.starts_with("bad_") || name.starts_with("corrupt_") || name.starts_with("truncated_") || name.starts_with("truncated.") || name.starts_with("zero");
    }
    false
}

fn main() {
    let ws = detect_workspace();
    let mode = mock_mode();
    if (mode == "broken_chrome" && ws == TargetWorkspace::Chrome2Rust)
        || (mode == "broken_fs" && ws == TargetWorkspace::Fs2Rust)
    {
        eprintln!("broken foreign binary");
        std::process::exit(1);
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() >= 2 && args[0] == "--log-level" {
        args.drain(0..2);
    }

    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help(ws, &args);
        return;
    }

    if args.iter().any(|a| a == "--nonexistent-flag-e2e") {
        eprintln!("error: unexpected argument '--nonexistent-flag-e2e' found\n\nUsage: mock");
        std::process::exit(2);
    }

    if args[0] == "mcp" || (args.len() >= 2 && args[0] == "--offline" && args[1] == "mcp") {
        let mcp_tail = if args[0] == "--offline" { &args[2..] } else { &args[1..] };
        if mcp_tail.first().is_some_and(|s| s == "--tools") {
            println!("{}", serde_json::to_string_pretty(&build_mcp_tools_json(ws)).unwrap());
            return;
        }
        run_mcp_server(ws, mcp_tail);
        return;
    }

    if ws == TargetWorkspace::Chrome2Rust
        && args.len() >= 2
        && args[0] == "cache"
        && args[1] == "delete"
    {
        if !args.iter().any(|a| a == "--yes") {
            println!("Dry-run preview: 0 files deleted");
        }
        return;
    }

    let groups = ws_groups(ws);
    let mut matched: Option<(&FeatureGroupDef, &e2e_tiers::ItemSpec)> = None;
    let mut best_len = 0usize;
    for fg in &groups {
        for it in fg.items {
            if args.len() >= it.cli_tokens.len()
                && args[..it.cli_tokens.len()]
                    .iter()
                    .zip(it.cli_tokens.iter())
                    .all(|(a, b)| a == b)
                && it.cli_tokens.len() > best_len
            {
                best_len = it.cli_tokens.len();
                matched = Some((fg, it));
            }
        }
    }

    let Some((fg, item)) = matched else {
        eprintln!("error: unrecognized subcommand '{}'", args.first().map(String::as_str).unwrap_or(""));
        std::process::exit(2);
    };

    let mut input_path: Option<PathBuf> = None;
    let mut source_dir: Option<PathBuf> = None;
    let mut export_path: Option<PathBuf> = None;
    let mut custody_path: Option<PathBuf> = None;
    let mut filter_expr: Option<String> = None;
    let mut sort_col: Option<String> = None;
    let mut pattern_expr: Option<String> = None;
    let mut regex_flag = false;
    let mut live_flag = false;
    let mut offline_flag = false;
    let mut json_flag = false;

    let mut i = best_len;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "--path" | "--gac-root" | "--hive" | "--source" | "--pcap" | "--root"
            | "--target" | "--left" | "--csv" | "--file" | "--lnk"
                if i + 1 < args.len() =>
            {
                input_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--right" if i + 1 < args.len() => {
                i += 2;
            }
            "--source-dir" if i + 1 < args.len() => {
                source_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--export" | "--export-csv" | "-o" | "--out" if i + 1 < args.len() => {
                export_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--output" if i + 1 < args.len() => {
                if ws == TargetWorkspace::Android2Rust {
                    export_path = Some(PathBuf::from(&args[i + 1]));
                }
                i += 2;
            }
            "--custody-manifest" | "--custody" | "--custody-out" | "--manifest"
                if i + 1 < args.len() =>
            {
                custody_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--filter" if i + 1 < args.len() => {
                filter_expr = Some(args[i + 1].clone());
                i += 2;
            }
            "--sort" if i + 1 < args.len() => {
                sort_col = Some(args[i + 1].clone());
                i += 2;
            }
            "--pattern" if i + 1 < args.len() => {
                pattern_expr = Some(args[i + 1].clone());
                i += 2;
            }
            "--format" | "-f" | "--limit" | "--log-level" if i + 1 < args.len() => {
                if (args[i] == "--format" || args[i] == "-f") && args[i + 1] == "json" {
                    json_flag = true;
                }
                i += 2;
            }
            "--regex" => {
                regex_flag = true;
                i += 1;
            }
            "--live" => {
                live_flag = true;
                i += 1;
            }
            "--offline" => {
                offline_flag = true;
                i += 1;
            }
            "--json" => {
                json_flag = true;
                i += 1;
            }
            v if !v.starts_with('-') && input_path.is_none() => {
                input_path = Some(PathBuf::from(v));
                i += 1;
            }
            other => {
                eprintln!("error: unexpected argument '{other}' found");
                std::process::exit(2);
            }
        }
    }

    let bad_query = filter_expr.as_deref() == Some("[unclosed")
        || sort_col.as_deref() == Some("nonexistent_col_e2e")
        || (regex_flag && pattern_expr.as_deref() == Some("[unclosed"));

    let missing_or_bad_input = if let Some(sd) = &source_dir {
        !sd.is_dir()
    } else if let Some(ip) = &input_path {
        !ip.exists() || is_corrupt_or_zero(ip)
    } else {
        false
    };

    if mode == "clap_exit2_on_negative" && (bad_query || missing_or_bad_input) {
        eprintln!("error: unexpected argument '--mock-bad' found\n\nUsage: mock");
        std::process::exit(2);
    }

    if bad_query {
        eprintln!("invalid query/filter/sort expression");
        std::process::exit(1);
    }

    if ws == TargetWorkspace::Android2Rust {
        if live_flag && source_dir.is_none() {
            println!("{}", json!({"status":"unavailable","error":"no WPD devices","entries":[]}));
            std::process::exit(1);
        }
        if let Some(sd) = &source_dir {
            if !sd.is_dir() {
                eprintln!("source_dir '{}' is not a directory", sd.display());
                std::process::exit(1);
            }
            let has_files = std::fs::read_dir(sd)
                .map(|mut rd| rd.next().is_some())
                .unwrap_or(false);
            if !has_files {
                println!("{}", json!({"status":"ok","matched_count":0,"entries":[]}));
                return;
            }
        }
    } else if ws == TargetWorkspace::Chrome2Rust {
        if missing_or_bad_input {
            println!("[]");
            return;
        }
    } else if missing_or_bad_input {
        eprintln!("failed to open input path cleanly");
        std::process::exit(1);
    }

    if mode == "silent_empty" {
        println!("{{}}");
        return;
    }
    if mode == "nonpriv_empty" {
        return;
    }

    if let Some(csv_p) = &export_path {
        let manifest = write_export_artifacts(
            ws,
            item.mcp_tool,
            fg.cli_export,
            csv_p,
            custody_path.as_deref(),
            &mode,
        )
        .expect("write export artifacts");
        if ws == TargetWorkspace::Android2Rust && json_flag {
            println!(
                "{}",
                json!({
                    "status": "ok",
                    "matched_count": 1,
                    "entries": [{"object_id": "obj-1", "name": "IMG_0001.jpg", "size": 1024}],
                    "custody_manifest": manifest
                })
            );
        } else if ws != TargetWorkspace::Sys2Rust {
            println!("[]");
        }
        return;
    }

    let _ = (offline_flag, item.cli_input);
    if ws == TargetWorkspace::Android2Rust {
        println!(
            "{}",
            json!({
                "status": "ok",
                "matched_count": 1,
                "entries": [{"object_id": "obj-1", "name": "IMG_0001.jpg", "size": 1024}]
            })
        );
    } else if ws == TargetWorkspace::Chrome2Rust && !item.expects_nonempty_rows {
        println!("[]");
    } else {
        let psk = if ws == TargetWorkspace::Net2Rust && matches!(item.mcp_tool, "radio.wifi-info" | "radio.wifi-profiles") {
            match mode.as_str() {
                "leak_r4_secret" => "GuapTestWpa2Key!2026",
                "leak_r4_keymaterial_cli" => "<keyMaterial>SecretWifiPass99</keyMaterial>",
                "leak_r4_plaintext_flag_cli" => "WLAN_PROFILE_GET_PLAINTEXT_KEY",
                _ => "[REDACTED]",
            }
        } else {
            "ok"
        };
        println!(
            "{}",
            json!([{
                "row_id": 1,
                "tool_id": item.mcp_tool,
                "name": item.name,
                "psk": psk
            }])
        );
    }
}