use std::{collections::HashMap, io::Read, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use bollard::{
    Docker, body_full,
    container::LogOutput,
    models::{
        ChangeType, ContainerCreateBody, HealthConfig, HostConfig, HostConfigCgroupnsModeEnum,
        HostConfigLogConfig, ResourcesUlimits,
    },
    query_parameters::{
        AttachContainerOptionsBuilder, DownloadFromContainerOptionsBuilder,
        KillContainerOptionsBuilder, RemoveContainerOptionsBuilder,
        UploadToContainerOptionsBuilder,
    },
};
use futures_util::StreamExt;
use tokio::{
    io::AsyncWriteExt,
    time::{Instant, timeout},
};

use crate::{
    RunArgs,
    report::{FileChange, Outcome, Report},
    trace,
};

pub const TRACE_LIMIT: usize = 8 * 1024 * 1024;
const OUTPUT_LIMIT: usize = 1024 * 1024;
const API_TIMEOUT: Duration = Duration::from_secs(15);
const TRACE_PATH: &str = "/trace/events.log";
const LABEL: &str = "io.docktell.managed";

pub async fn run(args: &RunArgs, stdin: Vec<u8>, sample: Option<Vec<u8>>) -> Result<Report> {
    // Register before creating anything, so an interrupt during setup is not lost.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let docker = connect(args.docker_host.as_deref())?
        .negotiate_version()
        .await
        .context("connect to Docker; start a Linux Docker daemon or set --docker-host")?;
    validate_daemon(
        &docker
            .info()
            .await
            .context("inspect daemon isolation support")?,
    )?;
    let image = docker.inspect_image(&args.image).await.context(
        "analysis image unavailable; build it with: docker build -t docktell-analysis:0.1 .",
    )?;
    ensure!(
        image.os.as_deref() == Some("linux"),
        "analysis requires a Linux image"
    );
    let config = image.config.context("image has no configuration")?;
    ensure!(
        config.volumes.as_ref().is_none_or(|v| v.is_empty()),
        "analysis images must not declare VOLUME mounts"
    );
    ensure!(
        config
            .labels
            .as_ref()
            .and_then(|l| l.get("io.docktell.analysis-image"))
            .is_some_and(|v| v == "1"),
        "use a trusted image built from the Docktell Dockerfile"
    );
    let image_id = image.id.context("image has no ID")?;
    let created = docker
        .create_container(
            None::<bollard::query_parameters::CreateContainerOptions>,
            container_config(args, &image_id),
        )
        .await
        .context("create analysis container")?;
    let id = &created.id;
    eprintln!("Analysis container: {id}");
    let mut report = Report {
        schema_version: 1,
        container_id: id.clone(),
        image: args.image.clone(),
        image_id,
        command: args.command.clone(),
        network_enabled: args.network,
        outcome: Outcome::Exited,
        exit_code: None,
        duration_ms: 0,
        oom_killed: false,
        container_removed: false,
        stdout: String::new(),
        stderr: String::new(),
        output_truncated: false,
        raw_trace: String::new(),
        trace: trace::Trace::default(),
        filesystem_changes: Vec::new(),
        warnings: created.warnings,
    };
    let started = Instant::now();
    let mut captured = Captured::default();
    let result = tokio::select! {
        result = timeout(Duration::from_secs(args.timeout), execute(&docker, id, stdin, sample, &mut captured)) => {
            match result {
                Ok(result) => result,
                Err(_) => { report.outcome = Outcome::TimedOut; Ok(()) }
            }
        }
        _ = sigint.recv() => { report.outcome = Outcome::Interrupted; Ok(()) }
        _ = sigterm.recv() => { report.outcome = Outcome::Interrupted; Ok(()) }
    };
    if let Err(error) = result {
        report.outcome = Outcome::Failed;
        report
            .warnings
            .push(format!("Execution/collection failed: {error:#}"));
    }
    report.duration_ms = started.elapsed().as_millis();
    report.stdout = String::from_utf8_lossy(&captured.stdout).into_owned();
    report.stderr = String::from_utf8_lossy(&captured.stderr).into_owned();
    report.output_truncated = captured.truncated;
    if captured.truncated {
        report
            .warnings
            .push("Guest output exceeded the combined 1 MiB capture limit.".into());
    }

    // Quiesce before inspecting files, including when the tracee outlives its tracer.
    let stopped = quiesce(&docker, id).await;
    match stopped {
        Ok(state) => {
            report.exit_code = state.exit_code;
            report.oom_killed = state.oom_killed.unwrap_or(false);
            collect(&docker, id, &mut report).await;
        }
        Err(error) => {
            report.outcome = Outcome::Failed;
            report
                .warnings
                .push(format!("Could not confirm container stopped: {error:#}"));
        }
    }
    match timeout(
        API_TIMEOUT,
        docker.remove_container(
            id,
            Some(
                RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .v(true)
                    .build(),
            ),
        ),
    )
    .await
    {
        Ok(Ok(())) => report.container_removed = true,
        result => report.warnings.push(format!(
            "Container cleanup failed: {result:?}. Remove container {id} manually."
        )),
    }
    report.warnings.push("In-container tracing is tamperable and detectable; this is not a hardened malware sandbox.".into());
    Ok(report)
}

fn validate_daemon(info: &bollard::models::SystemInfo) -> Result<()> {
    ensure!(
        info.memory_limit == Some(true)
            && info.swap_limit == Some(true)
            && info.pids_limit == Some(true)
            && info.cpu_cfs_quota == Some(true),
        "Docker must support memory, swap, PID and CPU quota limits; refusing an unbounded run"
    );
    ensure!(
        info.security_options.as_ref().is_some_and(|options| options
            .iter()
            .any(|option| option.starts_with("name=seccomp,")
                && !option.contains("profile=unconfined"))),
        "Docker must have a default seccomp profile; refusing to disable syscall filtering"
    );
    Ok(())
}

fn connect(endpoint: Option<&str>) -> Result<Docker> {
    let endpoint = endpoint
        .map(str::to_owned)
        .or_else(|| std::env::var("DOCKER_HOST").ok())
        .unwrap_or_else(|| {
            if Path::new("/var/run/docker.sock").exists() {
                "unix:///var/run/docker.sock".into()
            } else {
                let home = std::env::var("HOME").unwrap_or_default();
                format!("unix://{home}/.docker/run/docker.sock")
            }
        });
    ensure!(
        endpoint.starts_with("unix:///"),
        "only local unix:/// Docker endpoints are supported; Docker CLI contexts are not loaded"
    );
    Ok(Docker::connect_with_socket(
        &endpoint,
        API_TIMEOUT.as_secs(),
        bollard::API_DEFAULT_VERSION,
    )?)
}

fn container_config(args: &RunArgs, image_id: &str) -> ContainerCreateBody {
    let entrypoint = [
        "/usr/bin/strace",
        "-Tt",
        "-f",
        "-qq",
        "-yy",
        "-s",
        "128",
        "-e",
        "trace=%file,%process,%network,write,writev,pwrite64",
        "-o",
        TRACE_PATH,
        "--",
    ];
    ContainerCreateBody {
        image: Some(image_id.into()),
        user: Some("65532:65532".into()),
        working_dir: Some("/work".into()),
        env: Some(vec!["HOME=/work".into(), "LC_ALL=C".into()]),
        entrypoint: Some(entrypoint.into_iter().map(str::to_owned).collect()),
        cmd: Some(args.command.clone()),
        healthcheck: Some(HealthConfig {
            test: Some(vec!["NONE".into()]),
            ..Default::default()
        }),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        open_stdin: Some(true),
        stdin_once: Some(true),
        tty: Some(false),
        labels: Some(HashMap::from([(LABEL.into(), "true".into())])),
        host_config: Some(HostConfig {
            cap_drop: Some(vec!["ALL".into()]),
            security_opt: Some(vec!["no-new-privileges:true".into()]),
            privileged: Some(false),
            init: Some(true),
            network_mode: Some(if args.network { "bridge" } else { "none" }.into()),
            ipc_mode: Some("private".into()),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            publish_all_ports: Some(false),
            memory: Some(256 * 1024 * 1024),
            memory_swap: Some(256 * 1024 * 1024),
            nano_cpus: Some(1_000_000_000),
            pids_limit: Some(64),
            ulimits: Some(vec![
                ulimit("fsize", TRACE_LIMIT as i64),
                ulimit("nofile", 256),
                ulimit("core", 0),
            ]),
            log_config: Some(HostConfigLogConfig {
                typ: Some("none".into()),
                config: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn ulimit(name: &str, limit: i64) -> ResourcesUlimits {
    ResourcesUlimits {
        name: Some(name.into()),
        soft: Some(limit),
        hard: Some(limit),
    }
}

async fn execute(
    docker: &Docker,
    id: &str,
    stdin: Vec<u8>,
    sample: Option<Vec<u8>>,
    captured: &mut Captured,
) -> Result<()> {
    if let Some(sample) = sample {
        docker
            .upload_to_container(
                id,
                Some(
                    UploadToContainerOptionsBuilder::default()
                        .path("/sample")
                        .build(),
                ),
                body_full(sample.into()),
            )
            .await
            .context("copy sample")?;
    }
    let attached = docker
        .attach_container(
            id,
            Some(
                AttachContainerOptionsBuilder::default()
                    .stdin(true)
                    .stdout(true)
                    .stderr(true)
                    .stream(true)
                    .build(),
            ),
        )
        .await
        .context("attach to container")?;
    docker
        .start_container(id, None::<bollard::query_parameters::StartContainerOptions>)
        .await
        .context("start container (default seccomp must permit tracing a child process)")?;
    let mut output = attached.output;
    let mut input = attached.input;
    let writer = async {
        match input.write_all(&stdin).await {
            Ok(()) => {
                let _ = input.shutdown().await;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) => {}
            Err(error) => return Err(anyhow::Error::new(error).context("forward stdin")),
        }
        Ok(())
    };
    let reader = async {
        while let Some(message) = output.next().await {
            match message.context("read container output")? {
                LogOutput::StdOut { message } => captured.append(false, &message),
                LogOutput::StdErr { message } => captured.append(true, &message),
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(writer, reader)?;
    loop {
        let info = docker
            .inspect_container(
                id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await?;
        if info.state.is_some_and(|s| s.running == Some(false)) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn quiesce(docker: &Docker, id: &str) -> Result<bollard::models::ContainerState> {
    timeout(API_TIMEOUT, async {
        let state = docker
            .inspect_container(
                id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await?
            .state
            .context("missing container state")?;
        if state.running == Some(true) {
            match docker
                .kill_container(
                    id,
                    Some(
                        KillContainerOptionsBuilder::default()
                            .signal("SIGKILL")
                            .build(),
                    ),
                )
                .await
            {
                Ok(()) => {}
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 409, ..
                }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        loop {
            let state = docker
                .inspect_container(
                    id,
                    None::<bollard::query_parameters::InspectContainerOptions>,
                )
                .await?
                .state
                .context("missing container state")?;
            if state.running == Some(false) {
                return Ok(state);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("timed out stopping container")?
}

async fn collect(docker: &Docker, id: &str, report: &mut Report) {
    match timeout(API_TIMEOUT, read_trace(docker, id)).await {
        Ok(Ok(bytes)) => {
            if bytes.len() >= TRACE_LIMIT {
                report
                    .warnings
                    .push("Trace reached the 8 MiB file limit and may be truncated.".into());
            }
            if std::str::from_utf8(&bytes).is_err() {
                report.warnings.push(
                    "Trace contained invalid UTF-8; replacement characters were used.".into(),
                );
            }
            report.raw_trace = String::from_utf8_lossy(&bytes).into_owned();
            report.trace = trace::parse(&report.raw_trace);
            if report.trace.actions.is_empty() {
                if report.outcome == Outcome::Exited {
                    report.outcome = Outcome::Failed;
                }
                report.warnings.push(
                    "No syscall records collected: tracing failed or evidence was removed.".into(),
                );
            }
            if report.trace.unparsed_lines > 0
                || report.trace.unfinished_calls > 0
                || report.trace.actions_truncated
            {
                report.warnings.push(format!("Incomplete trace: {} unparsed lines, {} unfinished calls, action limit reached: {}.",
                    report.trace.unparsed_lines, report.trace.unfinished_calls, report.trace.actions_truncated));
            }
        }
        result => {
            report
                .warnings
                .push(format!("Trace collection failed: {result:?}"));
            if report.outcome == Outcome::Exited {
                report.outcome = Outcome::Failed;
            }
        }
    }
    match timeout(API_TIMEOUT, docker.container_changes(id)).await {
        Ok(Ok(changes)) => {
            report.filesystem_changes = changes
                .unwrap_or_default()
                .into_iter()
                .filter(|c| !instrumentation_path(&c.path))
                .map(|c| FileChange {
                    path: c.path,
                    kind: match c.kind {
                        ChangeType::_0 => "modified",
                        ChangeType::_1 => "added",
                        ChangeType::_2 => "deleted",
                    }
                    .into(),
                })
                .collect();
            report
                .filesystem_changes
                .sort_by(|a, b| a.path.cmp(&b.path));
        }
        result => report
            .warnings
            .push(format!("Filesystem diff unavailable: {result:?}")),
    }
}

fn instrumentation_path(path: &str) -> bool {
    path == "/trace"
        || path.starts_with("/trace/")
        || path == "/sample"
        || path.starts_with("/sample/")
}

async fn read_trace(docker: &Docker, id: &str) -> Result<Vec<u8>> {
    let mut stream = docker.download_from_container(
        id,
        Some(
            DownloadFromContainerOptionsBuilder::default()
                .path(TRACE_PATH)
                .build(),
        ),
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len() + chunk.len() <= TRACE_LIMIT + 64 * 1024,
            "trace archive exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    trace_from_archive(&bytes)
}

fn trace_from_archive(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive = tar::Archive::new(bytes);
    if let Some(entry) = archive.entries()?.next() {
        let entry = entry?;
        ensure!(
            entry.path()?.as_ref() == Path::new("events.log"),
            "unexpected trace archive path"
        );
        ensure!(
            entry.header().entry_type().is_file(),
            "trace is not a regular file"
        );
        ensure!(entry.size() <= TRACE_LIMIT as u64, "trace exceeds limit");
        let mut output = Vec::new();
        entry
            .take(TRACE_LIMIT as u64 + 1)
            .read_to_end(&mut output)?;
        return Ok(output);
    }
    bail!("trace archive is empty")
}

#[derive(Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl Captured {
    fn append(&mut self, stderr: bool, bytes: &[u8]) {
        let available = OUTPUT_LIMIT.saturating_sub(self.stdout.len() + self.stderr.len());
        self.truncated |= bytes.len() > available;
        let output = if stderr {
            &mut self.stderr
        } else {
            &mut self.stdout
        };
        output.extend_from_slice(&bytes[..bytes.len().min(available)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn security_defaults_and_network_toggle() {
        for network in [false, true] {
            let mut cli = vec!["docktell", "run"];
            if network {
                cli.push("--network");
            }
            cli.extend(["--", "true"]);
            let crate::Command::Run(args) = crate::Cli::parse_from(cli).command;
            let config = container_config(&args, "sha256:test");
            assert_eq!(config.user.as_deref(), Some("65532:65532"));
            assert!(
                config
                    .entrypoint
                    .as_ref()
                    .unwrap()
                    .iter()
                    .any(|arg| arg == "-Tt")
            );
            let host = config.host_config.unwrap();
            assert_eq!(
                host.network_mode.as_deref(),
                Some(if network { "bridge" } else { "none" })
            );
            assert_eq!(host.cap_drop, Some(vec!["ALL".into()]));
            assert_eq!(
                host.security_opt,
                Some(vec!["no-new-privileges:true".into()])
            );
            assert_eq!(host.privileged, Some(false));
            assert!(host.binds.is_none() && host.mounts.is_none() && host.devices.is_none());
            assert!(host.cap_add.is_none() && host.pid_mode.is_none());
            assert_eq!(host.memory, host.memory_swap);
            assert_eq!(host.pids_limit, Some(64));
        }
    }

    #[test]
    fn refuses_daemons_without_required_limits_or_seccomp() {
        let mut info = bollard::models::SystemInfo {
            memory_limit: Some(true),
            swap_limit: Some(true),
            pids_limit: Some(true),
            cpu_cfs_quota: Some(true),
            security_options: Some(vec!["name=seccomp,profile=builtin".into()]),
            ..Default::default()
        };
        assert!(validate_daemon(&info).is_ok());
        info.swap_limit = Some(false);
        assert!(validate_daemon(&info).is_err());
        info.swap_limit = Some(true);
        info.security_options = Some(vec!["name=seccomp,profile=unconfined".into()]);
        assert!(validate_daemon(&info).is_err());
        assert!(validate_daemon(&Default::default()).is_err());
    }

    #[test]
    fn caps_combined_output() {
        let mut captured = Captured::default();
        captured.append(false, &vec![b'x'; OUTPUT_LIMIT - 1]);
        captured.append(true, b"abc");
        assert_eq!(captured.stderr, b"a");
        assert!(captured.truncated);
    }

    #[test]
    fn refuses_nonlocal_docker_endpoints() {
        assert!(connect(Some("tcp://example.com:2375")).is_err());
    }

    #[test]
    fn reads_archive_without_extracting_paths() {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, "events.log", &b"abc"[..])
            .unwrap();
        assert_eq!(
            trace_from_archive(&archive.into_inner().unwrap()).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn rejects_trace_symlinks() {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        archive
            .append_link(&mut header, "events.log", "/etc/passwd")
            .unwrap();
        assert!(trace_from_archive(&archive.into_inner().unwrap()).is_err());
    }
}
