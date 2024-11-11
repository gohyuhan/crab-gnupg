use std::{
    collections::HashMap, 
    io::Error, 
    process::{ChildStdin, Child}
};

use crate::utils::errors::GPGError;
use crate::utils::utils::{
    check_is_dir, 
    get_or_create_gpg_output_dir,
    get_or_create_gpg_homedir
};
use crate::process::{
    collect_cmd_output_response, 
    start_process
};
use crate::utils::response::{
    CmdResult,
    Operation
};

#[derive(Debug)]
pub struct GPG{
    /// a path to a directory where the local key were at
    homedir: String,
    /// a path to a directory where the output files from gpg will save to
    output_dir: String,
    /// a haspmap ( or dict (in python) ) of env variables that would be passed to process 
    env:Option<HashMap<String, String>>,
    /// a list of name of keyring files to use. If provided, the default keyring will be ignored.
    keyrings: Option<Vec<String>>,
    /// a list of name of secret keyring files to use.
    secret_keyring: Option<Vec<String>>,
    /// the --use-agent parameter is passed to gpg is set to true
    use_agent: bool,
    /// additional arguments to be passed to gpg
    options: Option<Vec<String>>,
    /// the version of gpg, should only be set by system, user should not set this
    version: f32,
}

impl GPG{
    /// create a new GPG object with default settinga
    pub fn new()-> Result<GPG , GPGError>{
        let homedir: String = get_or_create_gpg_homedir();
        let output_dir: String = get_or_create_gpg_output_dir();
        let mut gpg_version:f32 = 0.0;

        let cmd_process:Result<Child, Error> = start_process(
            Some(vec!["--list_config".to_string(), "--with-colons".to_string()]),
            None,
            gpg_version,
            homedir.clone(),
            false,
            None,
            None
        );

        return Ok(
            GPG{
                homedir: homedir,
                output_dir: output_dir,
                env: None,
                keyrings: None,
                secret_keyring: None,
                use_agent: false,
                options: None,
                version:gpg_version
            }
        )
    }

    /// initialize a GPG object with a homedir and an output_dir
    pub fn init(homedir: String, output_dir: String)-> Result<GPG , GPGError>{
        if !check_is_dir(homedir.clone()){
            return Err(GPGError::OutputDirError(format!("{} is not a directory", homedir)));
        }
        if !check_is_dir(output_dir.clone()){
            return Err(GPGError::OutputDirError(format!("{} is not a directory", homedir)));
        }
        let mut gpg_version:f32 = 0.0;

        let cmd_process:Result<Child, Error> = start_process(
            Some(vec!["--list_config".to_string(), "--with-colons".to_string()]),
            None,
            gpg_version,
            homedir.clone(),
            false,
            None,
            None
        );
        let mut cmd_process = match cmd_process { 
            Ok(child) => child, 
            Err(e) => return Err(GPGError::FailedToStartProcess(e.to_string())), 
        };
        let child_stdin: ChildStdin = match cmd_process.stdin.take() { 
            Some(stdin) => stdin, 
            None => return Err(GPGError::FailedToRetrieveChildProcess("Fail to retrieve child process".to_string())), 
        };
        let result:CmdResult = CmdResult::init(Operation::Verify);
        let cmd_result:CmdResult = collect_cmd_output_response(
            cmd_process,
            result,
            None,
            Some(child_stdin),
        );

        let gpg_version:f32 = 2.1;
        return Ok(
            GPG{
                homedir: homedir,
                output_dir: output_dir,
                env: None,
                keyrings: None,
                secret_keyring: None,
                use_agent: false,
                options: None,
                version:gpg_version
            }
        )
    }

    
}