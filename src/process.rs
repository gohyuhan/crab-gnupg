use std::{
    collections::HashMap,
    io::{Error, Read},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use crate::utils::errors::GPGError;
use crate::utils::response::CmdResult;

/// generate a list of arguments to be passed to gpg process
fn generate_cmd_args(
    cmd_args: Option<Vec<String>>,
    passphrase: Option<String>,
    version: f32,
    homedir: String,
    use_agent: bool,
    options: Option<Vec<String>>,
) -> Vec<String> {
    // cmd_args: a list of arguments to be passed to gpg
    // passphrase: whether the next operation need a passphrase to be passed
    // version: version of gpg
    // homedir: the homedir of gpg
    // use_agent: whether to use gpg-agent
    // options: additional options to be passed to gpg, obtained in GPG object

    let mut args: Vec<String> = vec![
        "gpg".to_string(),
        "--status-fd".to_string(),
        "2".to_string(),
        "--no-tty".to_string(),
        "--no-verbose".to_string(),
        "--homedir".to_string(),
    ];
    if passphrase.is_some() && version >= 2.1 {
        args.insert(1, "--pinentry-mode".to_string());
        args.insert(2, "loopback".to_string());
    }
    args.push(homedir);
    // TODO: add keyring and secret keyring support
    if passphrase.is_some() {
        args.append(&mut vec!["--passphrase-fd".to_string(), "0".to_string()]);
    }
    if use_agent {
        args.push("--use-agent".to_string());
    }
    if options.is_some() {
        args.append(&mut options.unwrap());
    }
    args.append(&mut cmd_args.unwrap());
    return args;
}

/// start a process and return the child process
pub fn start_process(
    cmd_args: Option<Vec<String>>,
    passphrase: Option<String>,
    version: f32,
    homedir: String,
    use_agent: bool,
    options: Option<Vec<String>>,
    env: Option<HashMap<String, String>>,
) -> Result<Child, Error> {
    let cmd_args: Vec<String> = generate_cmd_args(
        cmd_args,
        passphrase,
        version,
        homedir.clone(),
        use_agent,
        options,
    );

    let mut command = Command::new(&cmd_args[0]); // The first element of the vector is the command

    // Pass the rest of the arguments to the command
    command.args(&cmd_args[1..]);

    if env.is_some() {
        for (key, value) in env.unwrap() {
            command.env(key, value);
        }
    };
    let cmd: Result<Child, Error> = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    return cmd;
}

/// to collect error / output from the Command process
pub fn collect_cmd_output_response(
    mut cmd_process: Child,
    result: Arc<Mutex<&mut CmdResult>>,
    writer: Option<JoinHandle<()>>,
    stdin: Option<ChildStdin>,
) {
    let stderr: ChildStderr = cmd_process.stderr.take().unwrap();
    let stdout: ChildStdout = cmd_process.stdout.take().unwrap();

    thread::scope(|s| {
        s.spawn(|| {
            read_cmd_response(stdout, Arc::clone(&result));
        });
        s.spawn(|| {
            read_cmd_error(stderr, Arc::clone(&result));
        });
    });
    if writer.is_some() {
        let _ = writer.unwrap().join();
    }
    let exit_status: Result<ExitStatus, Error> = cmd_process.wait();
    let exit_code = match exit_status {
        Ok(status) => status.code().unwrap_or(-1), // Get the exit code, defaulting to -1 if None
        Err(_) => {
            -1 // Return -1 in case of error
        }
    };
    if stdin.is_some() {
        drop(stdin.unwrap());
    }
    result.lock().unwrap().set_return_code(exit_code);
}

/// read output from stdout
fn read_cmd_response(mut stdout: ChildStdout, result: Arc<Mutex<&mut CmdResult>>) {
    let mut output_lines: Vec<String> = Vec::new();
    loop {
        let mut buffer = [0; 32];
        let line = stdout.read(&mut buffer);
        match line {
            Ok(n) => {
                if n <= 0 {
                    break;
                }
            }
            Err(_) => {
                break;
            }
        }
        let line_string = String::from_utf8_lossy(&buffer[..line.unwrap()]);
        output_lines.push(line_string.to_string());
    }
    result.lock().unwrap().set_raw_data(output_lines.join(""));
    drop(stdout);
}

/// read error from stderr
fn read_cmd_error(mut stderr: ChildStderr, result: Arc<Mutex<&mut CmdResult>>) {
    let mut error_lines: Vec<String> = Vec::new();
    loop {
        let mut buffer: Vec<u8> = Vec::new();
        let error_line = stderr.read_to_end(&mut buffer);
        match error_line {
            Ok(n) => {
                if n <= 0 {
                    break;
                }
            }
            Err(_) => {
                break;
            }
        }
        let error_line_string = String::from_utf8_lossy(&buffer);
        if error_line_string.len() >= 9 {
            if &error_line_string[0..9] == "[GNUPG:] " {
                // Split into at most 2 parts based on whitespace
                let parts = &error_line_string[9..].splitn(2, char::is_whitespace);

                let mut p = parts.clone();
                let keyword: String = p.next().unwrap_or("").to_string(); // First part, default to empty string if no part
                let value: String = p.next().unwrap_or("").to_string(); // Second part, default to empty string if no part

                result.lock().unwrap().handle_status(keyword, value);
            } else if &error_line_string[0..5] == "gpg: " {
                let parts = &error_line_string[5..].splitn(2, ": ");

                let mut p = parts.clone();
                let keyword: String = p.next().unwrap_or("").to_string(); // First part, default to empty string if no part
                let value: String = p.next().unwrap_or("").to_string(); // Second part, default to empty string if no part

                result.lock().unwrap().handle_status(keyword, value);
            }
        }
        error_lines.push(error_line_string.to_string());
    }
    result.lock().unwrap().set_raw_data(error_lines.join(""));
    drop(stderr);
}

/// start writing process
fn start_writing_process() -> Result<JoinHandle<()>, GPGError> {
    // TODO: implement write to stdin

    return Err(GPGError::WriterFailError(
        "Fail to start writing process".to_string(),
    ));
}

/// write to stdin
fn write_to_stdin() {
    // TODO: implement write to stdin
}