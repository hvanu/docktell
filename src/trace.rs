use std::collections::HashMap;

use serde::Serialize;

const MAX_ACTIONS: usize = 10_000;

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Filesystem,
    Io,
    Network,
    Process,
    Other,
}

#[derive(Debug, Serialize)]
pub struct Action {
    pub pid: Option<u32>,
    pub timestamp: Option<String>,
    pub duration_seconds: Option<f64>,
    pub category: Category,
    pub syscall: String,
    pub arguments: String,
    pub result: String,
    pub success: Option<bool>,
}

#[derive(Debug, Default, Serialize)]
pub struct Trace {
    pub actions: Vec<Action>,
    pub unparsed_lines: usize,
    pub unfinished_calls: usize,
    pub actions_truncated: bool,
}

pub fn parse(text: &str) -> Trace {
    let mut trace = Trace::default();
    let mut pending = HashMap::new();
    for line in text.lines() {
        let (pid, body) = split_pid(line.trim());
        let (mut timestamp, body) = split_timestamp(body);
        if body.is_empty() || body.starts_with("--- ") || body.starts_with("+++ ") {
            continue;
        }
        if let Some(prefix) = body.strip_suffix(" <unfinished ...>") {
            if pending.insert(pid, (timestamp, prefix.to_owned())).is_some() {
                trace.unfinished_calls += 1;
            }
            continue;
        }
        let joined;
        let body = if let Some(resumed) = body.strip_prefix("<... ") {
            let Some((syscall, suffix)) = resumed.split_once(" resumed>") else {
                trace.unparsed_lines += 1;
                continue;
            };
            let Some((started_at, prefix)) = pending.remove(&pid) else {
                trace.unparsed_lines += 1;
                continue;
            };
            if prefix.split_once('(').map(|(name, _)| name) != Some(syscall) {
                trace.unparsed_lines += 1;
                continue;
            }
            timestamp = started_at;
            joined = format!("{prefix}{suffix}");
            &joined
        } else {
            body
        };
        match parse_action(pid, timestamp, body) {
            Some(action) if trace.actions.len() < MAX_ACTIONS => trace.actions.push(action),
            Some(_) => trace.actions_truncated = true,
            None => trace.unparsed_lines += 1,
        }
    }
    trace.unfinished_calls += pending.len();
    trace
}

fn split_pid(line: &str) -> (Option<u32>, &str) {
    if let Some(rest) = line.strip_prefix("[pid ")
        && let Some((pid, body)) = rest.split_once(']')
        && let Ok(pid) = pid.trim().parse()
    {
        return (Some(pid), body.trim_start());
    }
    if let Some((pid, body)) = line.split_once(char::is_whitespace)
        && let Ok(pid) = pid.parse()
    {
        return (Some(pid), body.trim_start());
    }
    (None, line)
}

fn split_timestamp(line: &str) -> (Option<&str>, &str) {
    if let Some((timestamp, body)) = line.split_once(char::is_whitespace) {
        let bytes = timestamp.as_bytes();
        if bytes.len() == 8
            && bytes.iter().enumerate().all(|(i, c)| match i {
                2 | 5 => *c == b':',
                _ => c.is_ascii_digit(),
            })
            && &timestamp[..2] <= "23"
            && &timestamp[3..5] <= "59"
            && &timestamp[6..] <= "60"
        {
            return (Some(timestamp), body.trim_start());
        }
    }
    (None, line)
}

fn parse_action(pid: Option<u32>, timestamp: Option<&str>, line: &str) -> Option<Action> {
    let (call, result) = line.rsplit_once(" = ")?;
    let (result, duration_seconds) = if let Some((prefix, suffix)) = result.rsplit_once(" <")
        && let Some(duration) = suffix
            .strip_suffix('>')
            .and_then(|duration| duration.parse::<f64>().ok())
            .filter(|duration| duration.is_finite() && *duration >= 0.0)
    {
        (prefix, Some(duration))
    } else {
        (result, None)
    };
    let call = call.trim_end().strip_suffix(')')?;
    let (syscall, arguments) = call.split_once('(')?;
    if syscall.is_empty()
        || !syscall
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return None;
    }
    let first = result.split_whitespace().next()?;
    let success = if first == "?" {
        None
    } else if first == "-1" {
        Some(false)
    } else if first.starts_with(|c: char| c.is_ascii_digit()) {
        Some(true)
    } else {
        return None;
    };
    let category = match syscall {
        "write" | "writev" | "pwrite64" => Category::Io,
        "socket" | "socketpair" | "connect" | "accept" | "accept4" | "bind" | "listen"
        | "sendto" | "sendmsg" | "sendmmsg" | "recvfrom" | "recvmsg" | "recvmmsg" | "shutdown"
        | "getsockname" | "getpeername" | "getsockopt" | "setsockopt" => Category::Network,
        "execve" | "execveat" | "fork" | "vfork" | "clone" | "clone3" | "wait4" | "waitid"
        | "exit" | "exit_group" | "kill" | "tgkill" | "tkill" => Category::Process,
        "open" | "openat" | "openat2" | "creat" | "stat" | "lstat" | "fstat" | "stat64"
        | "lstat64" | "fstat64" | "newfstatat" | "fstatat64" | "statx" | "access" | "faccessat"
        | "faccessat2" | "readlink" | "readlinkat" | "chdir" | "fchdir" | "getcwd" | "rename"
        | "renameat" | "renameat2" | "unlink" | "unlinkat" | "mkdir" | "mkdirat" | "rmdir"
        | "link" | "linkat" | "symlink" | "symlinkat" | "truncate" | "truncate64" | "ftruncate"
        | "chmod" | "fchmod" | "fchmodat" | "fchmodat2" | "chown" | "lchown" | "fchown"
        | "fchownat" | "utime" | "utimes" | "futimesat" | "utimensat" | "mknod" | "mknodat"
        | "statfs" | "statfs64" | "mount" | "umount2" | "getxattr" | "lgetxattr" | "setxattr"
        | "lsetxattr" | "listxattr" | "llistxattr" | "removexattr" | "lremovexattr" => {
            Category::Filesystem
        }
        _ => Category::Other,
    };
    Some(Action {
        pid,
        timestamp: timestamp.map(str::to_owned),
        duration_seconds,
        category,
        syscall: syscall.into(),
        arguments: arguments.into(),
        result: result.into(),
        success,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_arguments_and_distinguishes_failures() {
        let trace = parse(concat!(
            "12 openat(AT_FDCWD</work>, \"a\\\"b\", O_WRONLY|O_CREAT, 0666) = 3</work/a\"b>\n",
            "12 connect(3<TCP:[123]>, {sa_family=AF_INET, sin_port=htons(80)}, 16) = -1 ENETUNREACH (Network is unreachable)\n",
            "12 exit_group(7) = ?\n",
        ));
        assert_eq!(trace.actions.len(), 3);
        assert_eq!(trace.actions[0].success, Some(true));
        assert!(trace.actions[0].arguments.contains("O_WRONLY|O_CREAT"));
        assert_eq!(trace.actions[1].category, Category::Network);
        assert_eq!(trace.actions[1].success, Some(false));
        assert_eq!(trace.actions[2].success, None);
    }

    #[test]
    fn parses_timestamps_and_durations_without_changing_results() {
        let trace = parse(concat!(
            "12 14:17:54 openat(AT_FDCWD, \"/tmp/file\", O_RDONLY) = 3</tmp/file> <0.000042>\n",
            "[pid 12] 14:17:55 connect(3, {}, 16) = -1 ENETUNREACH (Network is unreachable) <0.001234>\n",
            "14:17:56 exit_group(0) = ?\n",
            "12 14:17:56 +++ exited with 0 +++\n",
            "14:17:56 --- SIGCHLD {si_signo=SIGCHLD} ---\n",
        ));
        assert_eq!(trace.unparsed_lines, 0);
        assert_eq!(trace.actions.len(), 3);
        assert_eq!(trace.actions[0].timestamp.as_deref(), Some("14:17:54"));
        assert_eq!(trace.actions[0].duration_seconds, Some(0.000042));
        assert_eq!(trace.actions[0].result, "3</tmp/file>");
        assert_eq!(trace.actions[1].success, Some(false));
        assert_eq!(trace.actions[1].duration_seconds, Some(0.001234));
        assert_eq!(trace.actions[2].pid, None);
        assert_eq!(trace.actions[2].timestamp.as_deref(), Some("14:17:56"));
        assert_eq!(trace.actions[2].duration_seconds, None);
    }

    #[test]
    fn timed_resumed_calls_keep_the_start_timestamp() {
        let trace = parse(concat!(
            "12 23:59:59 wait4(13,  <unfinished ...>\n",
            "13 00:00:00 exit_group(0) = ?\n",
            "12 00:00:01 <... wait4 resumed>NULL, 0, NULL) = 13 <2.000123>\n",
        ));
        assert_eq!(trace.unparsed_lines, 0);
        assert_eq!(trace.unfinished_calls, 0);
        assert_eq!(trace.actions.len(), 2);
        assert_eq!(trace.actions[1].timestamp.as_deref(), Some("23:59:59"));
        assert_eq!(trace.actions[1].duration_seconds, Some(2.000123));
        assert_eq!(trace.actions[1].arguments, "13, NULL, 0, NULL");
        assert_eq!(trace.actions[1].result, "13");
    }

    #[test]
    fn untimed_records_have_no_timing_and_preserve_descriptor_results() {
        let trace = parse("openat(AT_FDCWD, \"/tmp/a b\", O_RDONLY) = 3</tmp/a b>\n");
        assert_eq!(trace.actions[0].timestamp, None);
        assert_eq!(trace.actions[0].duration_seconds, None);
        assert_eq!(trace.actions[0].result, "3</tmp/a b>");
    }

    #[test]
    fn accepts_strace_column_alignment() {
        let trace = parse("10 exit_group(7)                       = ?\n");
        assert_eq!(trace.actions.len(), 1);
        assert_eq!(trace.actions[0].syscall, "exit_group");
        assert_eq!(trace.unparsed_lines, 0);
    }

    #[test]
    fn joins_interleaved_calls_by_pid() {
        let trace = parse(concat!(
            "[pid 12] clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n",
            "13 execve(\"/bin/true\", [\"true\"], 0x123) = 0\n",
            "[pid 12] <... clone resumed>) = 13\n",
        ));
        assert_eq!(trace.actions.len(), 2);
        assert_eq!(trace.actions[1].pid, Some(12));
        assert_eq!(
            trace.actions[1].arguments,
            "child_stack=NULL, flags=SIGCHLD"
        );
        assert_eq!(trace.unfinished_calls, 0);
    }

    #[test]
    fn discloses_missing_and_malformed_records() {
        let trace = parse(concat!(
            "1 openat( <unfinished ...>\n",
            "2 <... connect resumed>) = 0\n",
            "garbage\n",
            "+++ exited with 0 +++\n",
            "--- SIGCHLD {si_signo=SIGCHLD} ---\n",
        ));
        assert_eq!(trace.unparsed_lines, 2);
        assert_eq!(trace.unfinished_calls, 1);
        assert!(trace.actions.is_empty());
    }

    #[test]
    fn accepts_unprefixed_records_and_limits_actions() {
        let trace = parse(&"unlink(\"/tmp/file\") = 0\n".repeat(MAX_ACTIONS + 1));
        assert_eq!(trace.actions.len(), MAX_ACTIONS);
        assert!(trace.actions_truncated);
        assert_eq!(trace.actions[0].pid, None);
    }
}
