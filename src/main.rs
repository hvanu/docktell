mod docker;
mod report;
mod trace;

use std::{
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};

const INPUT_LIMIT: usize = 1024 * 1024;
const SAMPLE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "docktell",
    version,
    about = "Inspect command behavior in a disposable Docker container"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute inside a non-root Linux container; not a hardened malware sandbox
    Run(RunArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Enable bridge networking (may reach the host, LAN, and internet)
    #[arg(long)]
    network: bool,

    /// Copy a regular local file to /sample/<filename> (maximum 16 MiB)
    #[arg(long)]
    file: Option<PathBuf>,

    /// Trusted, locally built analysis image; images are never pulled implicitly
    #[arg(long, default_value = "docktell-analysis:0.1")]
    image: String,

    /// Execution deadline in seconds, including upload and attach
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout: u64,

    /// New JSON report file; defaults to a unique file in the current directory
    #[arg(long)]
    report: Option<PathBuf>,

    /// Local unix:/// Docker endpoint (otherwise DOCKER_HOST or local defaults)
    #[arg(long)]
    docker_host: Option<String>,

    /// Guest executable and arguments, after --; no implicit shell expansion
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match application().await {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("Error: {:?}", format!("{error:#}"));
            ExitCode::from(125)
        }
    }
}

async fn application() -> Result<u8> {
    let Command::Run(args) = Cli::parse().command;
    let sample = args.file.as_deref().map(sample_archive).transpose()?;
    let stdin = if std::io::stdin().is_terminal() {
        Vec::new()
    } else {
        read_limited(std::io::stdin().lock(), INPUT_LIMIT)
            .context("read piped stdin (maximum 1 MiB; must reach EOF before execution)")?
    };
    let report_path = args.report.clone().unwrap_or_else(|| {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        PathBuf::from(format!("docktell-report-{stamp}.json"))
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&report_path)
        .with_context(|| format!("create new report file {}", report_path.display()))?;
    eprintln!("Experimental observer: use a dedicated disposable VM for untrusted samples.");
    if args.network {
        eprintln!(
            "Warning: bridge networking permits access to external services and potentially the host/LAN."
        );
    }
    match docker::run(&args, stdin, sample).await {
        Ok(report) => {
            serde_json::to_writer_pretty(&mut file, &report)?;
            writeln!(file)?;
            file.sync_all()?;
            report.print();
            println!("\nFull JSON report: {:?}", report_path);
            Ok(report.status())
        }
        Err(error) => {
            serde_json::to_writer_pretty(
                &mut file,
                &serde_json::json!({"error": format!("{error:#}")}),
            )?;
            file.sync_all()?;
            Err(error)
        }
    }
}

fn read_limited(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds {limit} bytes");
    Ok(bytes)
}

fn sample_archive(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.symlink_metadata()?.file_type().is_file(),
        "sample must be a regular file, not a symlink or device"
    );
    let bytes = read_limited(File::open(path)?, SAMPLE_LIMIT).context("read sample")?;
    let name = path.file_name().context("sample needs a filename")?;
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o555);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    archive.append_data(&mut header, Path::new(name), bytes.as_slice())?;
    Ok(archive.into_inner()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_arguments_are_not_reinterpreted() {
        let Command::Run(args) =
            Cli::parse_from(["docktell", "run", "--", "sh", "-c", "printf '%s' '$HOME'"]).command;
        assert_eq!(args.command, ["sh", "-c", "printf '%s' '$HOME'"]);
        assert!(!args.network);
        assert_eq!(args.timeout, 30);
    }

    #[test]
    fn requires_command_and_positive_timeout() {
        assert!(Cli::try_parse_from(["docktell", "run"]).is_err());
        assert!(Cli::try_parse_from(["docktell", "run", "--timeout", "0", "--", "true"]).is_err());
    }

    #[test]
    fn copies_binary_bytes_with_fixed_guest_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample");
        std::fs::write(&file, b"\x7fELF\0\xff").unwrap();
        let bytes = sample_archive(&file).unwrap();
        let mut archive = tar::Archive::new(bytes.as_slice());
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().as_ref(), Path::new("sample"));
        assert_eq!(entry.header().mode().unwrap(), 0o555);
        assert_eq!(entry.header().uid().unwrap(), 0);
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"\x7fELF\0\xff");
        assert!(entries.next().is_none());
    }

    #[test]
    fn rejects_sample_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample");
        std::os::unix::fs::symlink("/dev/null", &file).unwrap();
        assert!(sample_archive(&file).is_err());
    }

    #[test]
    fn rejects_oversized_input() {
        assert_eq!(read_limited(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(read_limited(&b"abcd"[..], 3).is_err());
    }
}
