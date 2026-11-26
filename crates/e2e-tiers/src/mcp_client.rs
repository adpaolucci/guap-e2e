use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};

use crate::workspace::truncate_preview;

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const POLICY_DENIED_CODE: i64 = -32003;
pub const MCP_IO_TIMEOUT: Duration = Duration::from_secs(15);

pub struct McpSession {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout_rx: Receiver<Result<String, String>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<String>>,
    next_id: i64,
}

impl McpSession {
    pub fn spawn(bin_path: &Path, args: &[&str], env_overrides: &[(&str, &str)]) -> anyhow::Result<Self> {
        let mut cmd = Command::new(bin_path);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for &(k, v) in env_overrides {
            cmd.env(k, v);
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed spawning MCP server {}", bin_path.display()))?;

        let stdin = child.stdin.take().context("missing child stdin")?;
        let stdout = child.stdout.take().context("missing child stdout")?;
        let mut stderr = child.stderr.take().context("missing child stderr")?;

        let (tx, rx) = mpsc::channel();
        let stdout_thread = std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line_res in reader.lines() {
                match line_res {
                    Ok(line) => {
                        if tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string()));
                        break;
                    }
                }
            }
        });

        let stderr_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout_rx: rx,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            next_id: 1,
        })
    }

    fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        let stdin = self.stdin.as_mut().context("MCP stdin already closed")?;
        writeln!(stdin, "{line}")?;
        stdin.flush()?;
        Ok(())
    }

    fn read_json_line(&mut self, timeout: Duration) -> anyhow::Result<Value> {
        let start = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                bail!("timed out waiting for MCP JSON-RPC response after {:?}", timeout);
            }
            let raw = match self.stdout_rx.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                Ok(Err(err)) => bail!("MCP stdout read error: {err}"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    bail!("timed out waiting for MCP stdout line after {:?}", timeout);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let exit_code = self.child.wait().ok().and_then(|s| s.code());
                    let stderr = if let Some(h) = self.stderr_thread.take() {
                        h.join().unwrap_or_default()
                    } else {
                        String::new()
                    };
                    bail!(
                        "MCP server closed stdout unexpectedly (exit={:?}, stderr={})",
                        exit_code,
                        truncate_preview(&stderr, 300)
                    );
                }
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: Value = serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "MCP server emitted non-JSON stdout line (expected NDJSON): {:?}",
                    truncate_preview(trimmed, 240)
                )
            })?;
            return Ok(val);
        }
    }

    pub fn send_request(&mut self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        let encoded = serde_json::to_string(&req)?;
        self.write_line(&encoded)?;
        let resp = self.read_json_line(MCP_IO_TIMEOUT)?;
        let resp_id = resp.get("id");
        ensure!(
            resp_id == Some(&json!(id)),
            "MCP JSON-RPC response id mismatch for '{method}': expected {id}, got {:?}",
            resp_id
        );
        Ok(resp)
    }

    pub fn send_notification(&mut self, method: &str, params: Value) -> anyhow::Result<()> {
        let req = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        let encoded = serde_json::to_string(&req)?;
        self.write_line(&encoded)?;
        Ok(())
    }

    pub fn send_raw_line_and_read(&mut self, raw: &str) -> anyhow::Result<Value> {
        self.write_line(raw)?;
        self.read_json_line(MCP_IO_TIMEOUT)
    }

    pub fn initialize(&mut self) -> anyhow::Result<Value> {
        let resp = self.send_request(
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "guap-e2e", "version": "0.1.0" }
            }),
        )?;
        ensure!(
            resp.get("error").is_none(),
            "MCP initialize returned error: {}",
            resp
        );
        let result = resp
            .get("result")
            .context("MCP initialize missing 'result'")?;
        let proto = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .context("MCP initialize missing result.protocolVersion")?;
        ensure!(
            proto == MCP_PROTOCOL_VERSION,
            "MCP initialize protocolVersion {:?} != expected {:?}",
            proto,
            MCP_PROTOCOL_VERSION
        );
        ensure!(
            result.get("capabilities").and_then(|c| c.get("tools")).is_some(),
            "MCP initialize missing result.capabilities.tools: {}",
            result
        );

        self.send_notification("notifications/initialized", json!({}))?;
        std::thread::sleep(Duration::from_millis(25));
        if let Ok(spurious) = self.stdout_rx.try_recv() {
            bail!(
                "MCP server emitted unexpected response to notifications/initialized: {:?}",
                spurious
            );
        }
        Ok(resp)
    }

    pub fn ping(&mut self) -> anyhow::Result<()> {
        let resp = self.send_request("ping", json!({}))?;
        ensure!(resp.get("error").is_none(), "MCP ping error: {}", resp);
        ensure!(resp.get("result").is_some(), "MCP ping missing result");
        Ok(())
    }

    pub fn tools_list(&mut self) -> anyhow::Result<Vec<Value>> {
        let resp = self.send_request("tools/list", json!({}))?;
        ensure!(
            resp.get("error").is_none(),
            "MCP tools/list returned error: {}",
            resp
        );
        let tools = resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(Value::as_array)
            .cloned()
            .with_context(|| format!("MCP tools/list missing result.tools array: {}", resp))?;
        for tool in &tools {
            ensure!(
                tool.get("name").and_then(Value::as_str).is_some(),
                "MCP tool missing string 'name': {}",
                tool
            );
            ensure!(
                tool.get("description").and_then(Value::as_str).is_some(),
                "MCP tool missing string 'description': {}",
                tool
            );
            ensure!(
                tool.get("inputSchema").and_then(Value::as_object).is_some(),
                "MCP tool missing object 'inputSchema': {}",
                tool
            );
        }
        Ok(tools)
    }

    pub fn tools_call(&mut self, name: &str, arguments: Value) -> anyhow::Result<Value> {
        self.send_request(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments
            }),
        )
    }

    pub fn close(mut self) -> anyhow::Result<String> {
        drop(self.stdin.take());
        let start = Instant::now();
        let exit_code = loop {
            match self.child.try_wait() {
                Ok(Some(st)) => break st.code(),
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(3) {
                        let _ = self.child.kill();
                        let st = self.child.wait().ok();
                        break st.and_then(|s| s.code());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    let _ = self.child.kill();
                    break None;
                }
            }
        };
        if let Some(h) = self.stdout_thread.take() {
            let _ = h.join();
        }
        let stderr = if let Some(h) = self.stderr_thread.take() {
            h.join().unwrap_or_default()
        } else {
            String::new()
        };
        ensure!(
            !stderr.contains("panicked at"),
            "MCP server panicked (stderr): {}",
            truncate_preview(&stderr, 300)
        );
        ensure!(
            exit_code != Some(101),
            "MCP server exited with panic code 101; stderr={}",
            truncate_preview(&stderr, 300)
        );
        Ok(stderr)
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.stdout_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.stderr_thread.take() {
            let _ = h.join();
        }
    }
}

pub fn assert_tool_call_ok(resp: &Value, tool_name: &str) -> anyhow::Result<String> {
    if let Some(err) = resp.get("error") {
        bail!("MCP tools/call '{tool_name}' returned JSON-RPC error: {err}");
    }
    let result = resp
        .get("result")
        .with_context(|| format!("MCP tools/call '{tool_name}' missing result: {resp}"))?;
    let is_err = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    ensure!(
        !is_err,
        "MCP tools/call '{tool_name}' returned result.isError=true: {result}"
    );
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    ensure!(
        !text.trim().is_empty(),
        "MCP tools/call '{tool_name}' returned empty content text"
    );
    Ok(text)
}

pub fn assert_policy_denied(
    resp: &Value,
    tool_name: &str,
    strict_guap_mcp: bool,
) -> anyhow::Result<()> {
    if let Some(code) = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
    {
        ensure!(
            code == POLICY_DENIED_CODE,
            "mutating tool '{tool_name}' returned JSON-RPC error code {code}, expected -32003 (PolicyDenied): {resp}"
        );
        return Ok(());
    }
    if !strict_guap_mcp
        && resp
            .get("result")
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
    {
        let txt = resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("");
        if txt.contains("SAFETY REFUSAL") || txt.contains("confirm_destructive") || txt.contains("policy") {
            return Ok(());
        }
    }
    bail!(
        "POLICY GATE FAILURE: mutating tool '{tool_name}' was NOT rejected with -32003: {resp}"
    );
}