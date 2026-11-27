use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, bail, ensure};

use crate::model::TargetWorkspace;

pub const CLI_TIMEOUT: Duration = Duration::from_secs(15);
pub const CARGO_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

pub fn assert_no_panic(context: &str, out: &CommandOutput) -> anyhow::Result<()> {
    ensure!(
        !out.stdout.contains("panicked at"),
        "{context}: stdout contains Rust panic: {}",
        truncate_preview(&out.stdout, 300)
    );
    ensure!(
        !out.stderr.contains("panicked at"),
        "{context}: stderr contains Rust panic: {}",
        truncate_preview(&out.stderr, 300)
    );
    ensure!(
        out.exit_code != Some(101),
        "{context}: process exited with Rust panic code 101; stderr={}",
        truncate_preview(&out.stderr, 300)
    );
    Ok(())
}

pub fn truncate_preview(s: &str, max_chars: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let mut out: String = trimmed.chars().take(max_chars).collect();
        out.push_str("...");
        out
    }
}

pub fn run_command_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> anyhow::Result<CommandOutput> {
    let start = Instant::now();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command {:?}", cmd.get_program()))?;

    let mut stdout_pipe = child.stdout.take().context("missing stdout pipe")?;
    let mut stderr_pipe = child.stderr.take().context("missing stderr pipe")?;

    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    bail!(
                        "command {:?} timed out after {:?}",
                        cmd.get_program(),
                        timeout
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = out_handle.join();
                let _ = err_handle.join();
                return Err(e).context("error waiting for child process");
            }
        }
    };

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    Ok(CommandOutput {
        exit_code: status.code(),
        stdout,
        stderr,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

pub struct WorkspaceSession {
    pub guap_root: PathBuf,
    pub skip_cargo_build: bool,
    binary_cache: HashMap<TargetWorkspace, Option<PathBuf>>,
    cargo_build_attempted: HashMap<TargetWorkspace, Result<(), String>>,
    help_cache: HashMap<TargetWorkspace, Result<String, String>>,
    help_prefix_cache: HashMap<(TargetWorkspace, Vec<String>), Result<String, String>>,
    tools_cache: HashMap<TargetWorkspace, Result<Vec<serde_json::Value>, String>>,
    cargo_cmd_cache: HashMap<(PathBuf, Vec<String>), CommandOutput>,
}

impl WorkspaceSession {
    pub fn new(guap_root: PathBuf, skip_cargo_build: bool) -> Self {
        Self {
            guap_root,
            skip_cargo_build,
            binary_cache: HashMap::new(),
            cargo_build_attempted: HashMap::new(),
            help_cache: HashMap::new(),
            help_prefix_cache: HashMap::new(),
            tools_cache: HashMap::new(),
            cargo_cmd_cache: HashMap::new(),
        }
    }

    pub fn workspace_dir(&self, ws: TargetWorkspace) -> PathBuf {
        self.guap_root.join(ws.dir_name())
    }

    pub fn is_workspace_present(&self, ws: TargetWorkspace) -> bool {
        if ws == TargetWorkspace::All {
            return true;
        }
        self.workspace_dir(ws).join("Cargo.toml").is_file()
    }

    pub fn debug_binary_path(&self, ws: TargetWorkspace) -> Option<PathBuf> {
        let bin_name = ws.binary_name()?;
        let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
        Some(
            self.workspace_dir(ws)
                .join("target")
                .join("debug")
                .join(format!("{bin_name}{exe_suffix}")),
        )
    }

    pub fn find_existing_binary(&self, ws: TargetWorkspace) -> Option<PathBuf> {
        let bin_name = ws.binary_name()?;
        let ws_dir = self.workspace_dir(ws);
        let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
        let candidates = [
            ws_dir
                .join("target")
                .join("debug")
                .join(format!("{bin_name}{exe_suffix}")),
            ws_dir
                .join("target")
                .join("release")
                .join(format!("{bin_name}{exe_suffix}")),
        ];

        let mut best: Option<(SystemTime, PathBuf)> = None;
        for cand in candidates {
            if cand.is_file() {
                let mtime = std::fs::metadata(&cand)
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                match &best {
                    Some((prev_mtime, _)) if *prev_mtime >= mtime => {}
                    _ => best = Some((mtime, cand)),
                }
            }
        }
        best.map(|(_, p)| p)
    }

    pub fn resolve_binary(&mut self, ws: TargetWorkspace) -> anyhow::Result<Option<PathBuf>> {
        if let Some(cached) = self.binary_cache.get(&ws) {
            return Ok(cached.clone());
        }
        if !self.is_workspace_present(ws) {
            self.binary_cache.insert(ws, None);
            return Ok(None);
        }

        if !self.skip_cargo_build {
            if let Some(prev) = self.cargo_build_attempted.get(&ws) {
                if let Err(err) = prev {
                    bail!("{err}");
                }
            } else {
                let ws_dir = self.workspace_dir(ws);
                let Some(bin_name) = ws.binary_name() else {
                    self.binary_cache.insert(ws, None);
                    return Ok(None);
                };
                let cli_pkg = format!("{bin_name}-cli");
                let build_res = if ws_dir
                    .join("crates")
                    .join(&cli_pkg)
                    .join("Cargo.toml")
                    .is_file()
                {
                    let mut cmd = Command::new("cargo");
                    cmd.current_dir(&ws_dir)
                        .args(["build", "--offline", "-p", &cli_pkg]);
                    let out = run_command_with_timeout(&mut cmd, CARGO_TIMEOUT);
                    match out {
                        Ok(o) if o.success() => Ok(()),
                        Ok(o) => Err(format!(
                            "cargo build --offline -p {cli_pkg} failed in {}: {}",
                            ws_dir.display(),
                            truncate_preview(&o.stderr, 400)
                        )),
                        Err(e) => Err(e.to_string()),
                    }
                } else if self.find_existing_binary(ws).is_some() {
                    Ok(())
                } else {
                    let mut fb = Command::new("cargo");
                    fb.current_dir(&ws_dir)
                        .args(["build", "--offline", "--workspace"]);
                    let fb_out = run_command_with_timeout(&mut fb, CARGO_TIMEOUT)?;
                    if fb_out.success() {
                        Ok(())
                    } else {
                        Err(format!(
                            "cargo build --offline failed in {}: {}",
                            ws_dir.display(),
                            truncate_preview(&fb_out.stderr, 400)
                        ))
                    }
                };
                self.cargo_build_attempted.insert(ws, build_res.clone());
                if let Err(err) = build_res {
                    bail!("{err}");
                }
            }
        }

        let resolved = if !self.skip_cargo_build {
            self.debug_binary_path(ws)
                .filter(|p| p.is_file())
                .or_else(|| self.find_existing_binary(ws))
        } else {
            self.find_existing_binary(ws)
        };
        self.binary_cache.insert(ws, resolved.clone());
        Ok(resolved)
    }

    pub fn run_cli(
        &mut self,
        ws: TargetWorkspace,
        args: &[&str],
    ) -> anyhow::Result<Option<CommandOutput>> {
        self.run_cli_with_env(ws, args, &[])
    }

    pub fn run_cli_with_env(
        &mut self,
        ws: TargetWorkspace,
        args: &[&str],
        env_overrides: &[(&str, &str)],
    ) -> anyhow::Result<Option<CommandOutput>> {
        let Some(bin) = self.resolve_binary(ws)? else {
            return Ok(None);
        };
        let mut cmd = Command::new(&bin);
        cmd.args(args);
        for &(k, v) in env_overrides {
            cmd.env(k, v);
        }
        let out = run_command_with_timeout(&mut cmd, CLI_TIMEOUT)?;
        assert_no_panic(&format!("{} {}", ws.dir_name(), args.join(" ")), &out)?;
        Ok(Some(out))
    }

    pub fn run_cli_raw(
        &mut self,
        ws: TargetWorkspace,
        args: &[&str],
    ) -> anyhow::Result<Option<CommandOutput>> {
        let Some(bin) = self.resolve_binary(ws)? else {
            return Ok(None);
        };
        let mut cmd = Command::new(&bin);
        cmd.args(args);
        let out = run_command_with_timeout(&mut cmd, CLI_TIMEOUT)?;
        Ok(Some(out))
    }

    pub fn cached_help(&mut self, ws: TargetWorkspace) -> anyhow::Result<Option<String>> {
        if let Some(cached) = self.help_cache.get(&ws) {
            return match cached {
                Ok(text) => Ok(Some(text.clone())),
                Err(msg) => bail!("{msg}"),
            };
        }
        let Some(out) = self.run_cli(ws, &["--help"])? else {
            return Ok(None);
        };
        if !out.success() {
            let msg = format!(
                "{} --help exited with {:?}: {}",
                ws.dir_name(),
                out.exit_code,
                truncate_preview(&out.stderr, 300)
            );
            self.help_cache.insert(ws, Err(msg.clone()));
            bail!("{msg}");
        }
        self.help_cache.insert(ws, Ok(out.stdout.clone()));
        Ok(Some(out.stdout))
    }

    pub fn cached_help_for_prefix(
        &mut self,
        ws: TargetWorkspace,
        prefix: &[&str],
    ) -> anyhow::Result<Option<String>> {
        if prefix.is_empty() {
            return self.cached_help(ws);
        }
        let key: (TargetWorkspace, Vec<String>) =
            (ws, prefix.iter().map(|s| (*s).to_string()).collect());
        if let Some(cached) = self.help_prefix_cache.get(&key) {
            return match cached {
                Ok(text) => Ok(Some(text.clone())),
                Err(msg) => bail!("{msg}"),
            };
        }
        let mut args: Vec<&str> = prefix.to_vec();
        args.push("--help");
        let Some(out) = self.run_cli(ws, &args)? else {
            return Ok(None);
        };
        if !out.success() {
            let msg = format!(
                "{} {} --help exited with {:?}: {}",
                ws.dir_name(),
                prefix.join(" "),
                out.exit_code,
                truncate_preview(&out.stderr, 300)
            );
            self.help_prefix_cache.insert(key, Err(msg.clone()));
            bail!("{msg}");
        }
        self.help_prefix_cache.insert(key, Ok(out.stdout.clone()));
        Ok(Some(out.stdout))
    }

    pub fn cached_mcp_tools(
        &mut self,
        ws: TargetWorkspace,
    ) -> anyhow::Result<Option<Vec<serde_json::Value>>> {
        if let Some(cached) = self.tools_cache.get(&ws) {
            return match cached {
                Ok(v) => Ok(Some(v.clone())),
                Err(msg) => bail!("{msg}"),
            };
        }
        let Some(out) = self.run_cli(ws, &["mcp", "--tools"])? else {
            return Ok(None);
        };
        if !out.success() {
            let msg = format!(
                "{} mcp --tools exited with {:?}: {}",
                ws.dir_name(),
                out.exit_code,
                truncate_preview(&out.stderr, 300)
            );
            self.tools_cache.insert(ws, Err(msg.clone()));
            bail!("{msg}");
        }
        let parsed: serde_json::Value =
            serde_json::from_str(out.stdout.trim()).with_context(|| {
                format!(
                    "{} mcp --tools did not emit valid JSON: {}",
                    ws.dir_name(),
                    truncate_preview(&out.stdout, 300)
                )
            })?;
        let arr = parsed
            .as_array()
            .cloned()
            .or_else(|| parsed.get("tools").and_then(|t| t.as_array()).cloned())
            .with_context(|| {
                format!(
                    "{} mcp --tools JSON must be an array or {{tools:[...]}}",
                    ws.dir_name()
                )
            })?;
        self.tools_cache.insert(ws, Ok(arr.clone()));
        Ok(Some(arr))
    }

    pub fn run_cargo_in(&self, dir: &Path, args: &[&str]) -> anyhow::Result<CommandOutput> {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(dir).args(args);
        let out = run_command_with_timeout(&mut cmd, CARGO_TIMEOUT)?;
        assert_no_panic(
            &format!("cargo {} in {}", args.join(" "), dir.display()),
            &out,
        )?;
        Ok(out)
    }

    pub fn run_cargo_cached(&mut self, dir: &Path, args: &[&str]) -> anyhow::Result<CommandOutput> {
        let key = (
            dir.to_path_buf(),
            args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        );
        if let Some(prev) = self.cargo_cmd_cache.get(&key) {
            return Ok(prev.clone());
        }
        let out = self.run_cargo_in(dir, args)?;
        self.cargo_cmd_cache.insert(key, out.clone());
        Ok(out)
    }
}
