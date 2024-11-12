use std::{
    collections::HashMap,
    io::Error,
    process::{Child, ChildStdin},
    sync::{Arc, Mutex},
};

use crate::{process::{collect_cmd_output_response, start_process}, utils::utils::get_gpg_version};
use crate::utils::errors::GPGError;
use crate::utils::response::{CmdResult, Operation};
use crate::utils::utils::{check_is_dir, get_or_create_gpg_homedir, get_or_create_gpg_output_dir};

/// a struct to represent a GPG object
#[derive(Debug)]
pub struct GPG {
    /// a path to a directory where the local key were at
    homedir: String,
    /// a path to a directory where the output files from gpg will save to
    output_dir: String,
    /// a haspmap ( or dict (in python) ) of env variables that would be passed to process
    env: Option<HashMap<String, String>>,
    /// a list of name of keyring files to use. If provided, the default keyring will be ignored.
    keyrings: Option<Vec<String>>,
    /// a list of name of secret keyring files to use.
    secret_keyring: Option<Vec<String>>,
    /// the --use-agent parameter is passed to gpg is set to true
    use_agent: bool,
    /// additional arguments to be passed to gpg
    options: Option<Vec<String>>,
    /// the major minor version of gpg, should only be set by system, user should not set this ex) 2.4
    version: f32,
    /// the full version of gpg, should only be set by system, user should not set this ex) 2.4.6
    full_version: String,
}

impl GPG {
    /// create a new GPG object with default settinga
    pub fn new() -> Result<GPG, GPGError> {
        let homedir: String = get_or_create_gpg_homedir();
        let output_dir: String = get_or_create_gpg_output_dir();

        let cmd_process: Result<Child, Error> = start_process(
            Some(vec![
                "--list-config".to_string(),
                "--with-colons".to_string(),
            ]),
            None,
            0.0,
            homedir.clone(),
            false,
            None,
            None,
        );
        let mut cmd_process = match cmd_process {
            Ok(child) => child,
            Err(e) => return Err(GPGError::FailedToStartProcess(e.to_string())),
        };
        let child_stdin: ChildStdin = match cmd_process.stdin.take() {
            Some(stdin) => stdin,
            None => {
                return Err(GPGError::FailedToRetrieveChildProcess(
                    "Fail to retrieve child process".to_string(),
                ))
            }
        };
        let mut result: CmdResult = CmdResult::init(Operation::Verify);
        // create a shared result object to be pass into thread(s)
        let share_result: Arc<Mutex<&mut CmdResult>> = Arc::new(Mutex::new(&mut result));
        collect_cmd_output_response(cmd_process, share_result, None, Some(child_stdin));

        let version:(f32, String) = get_gpg_version(result);

        return Ok(GPG {
            homedir: homedir,
            output_dir: output_dir,
            env: None,
            keyrings: None,
            secret_keyring: None,
            use_agent: false,
            options: None,
            version: version.0,
            full_version: version.1,
        });
    }

    /// initialize a GPG object with a homedir and an output_dir
    pub fn init(homedir: String, output_dir: String) -> Result<GPG, GPGError> {
        if !check_is_dir(homedir.clone()) {
            return Err(GPGError::OutputDirError(format!(
                "{} is not a directory",
                homedir
            )));
        }
        if !check_is_dir(output_dir.clone()) {
            return Err(GPGError::OutputDirError(format!(
                "{} is not a directory",
                homedir
            )));
        }

        let cmd_process: Result<Child, Error> = start_process(
            Some(vec![
                "--list-config".to_string(),
                "--with-colons".to_string(),
            ]),
            None,
            0.0,
            homedir.clone(),
            false,
            None,
            None,
        );
        print!("{:?}", cmd_process);
        let mut cmd_process = match cmd_process {
            Ok(child) => child,
            Err(e) => return Err(GPGError::FailedToStartProcess(e.to_string())),
        };
        let child_stdin: ChildStdin = match cmd_process.stdin.take() {
            Some(stdin) => stdin,
            None => {
                return Err(GPGError::FailedToRetrieveChildProcess(
                    "Fail to retrieve child process".to_string(),
                ))
            }
        };
        let mut result: CmdResult = CmdResult::init(Operation::Verify);
        // create a shared result object to be pass into thread(s)
        let share_result: Arc<Mutex<&mut CmdResult>> = Arc::new(Mutex::new(&mut result));
        collect_cmd_output_response(cmd_process, share_result, None, Some(child_stdin));

        let version:(f32, String) = get_gpg_version(result);

        return Ok(GPG {
            homedir: homedir,
            output_dir: output_dir,
            env: None,
            keyrings: None,
            secret_keyring: None,
            use_agent: false,
            options: None,
            version: version.0,
            full_version: version.1,
        });
    }
}
