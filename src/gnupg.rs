use std::collections::HashMap;

use crate::utils::response::Operation;
use crate::utils::utils::get_gpg_version;
use crate::utils::utils::{check_is_dir, get_or_create_gpg_homedir, get_or_create_gpg_output_dir};
use crate::{process::handle_cmd_io, utils::errors::GPGError};

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
    /// initialize a GPG object with a homedir and an output_dir or none (system set homedir and output dir)
    pub fn init(homedir: Option<String>, output_dir: Option<String>) -> Result<GPG, GPGError> {
        let mut h_d: String = String::from("");
        let mut o_d: String = String::from("");

        if homedir.is_some() {
            h_d = homedir.unwrap();
        } else {
            h_d = get_or_create_gpg_homedir();
        }
        if output_dir.is_some() {
            o_d = output_dir.unwrap();
        } else {
            o_d = get_or_create_gpg_output_dir();
        }

        if !check_is_dir(h_d.clone()) {
            return Err(GPGError::OutputDirError(format!(
                "{} is not a directory",
                h_d
            )));
        }
        if !check_is_dir(o_d.clone()) {
            return Err(GPGError::OutputDirError(format!(
                "{} is not a directory",
                o_d
            )));
        }

        let result = handle_cmd_io(
            Some(vec![
                "--list-config".to_string(),
                "--with-colons".to_string(),
            ]),
            None,
            0.0,
            h_d.clone(),
            false,
            None,
            None,
            None,
            None,
            false,
            Operation::Verify,
        );

        match result {
            Ok(result) => {
                println!("{:?}", result);
                let version: (f32, String) = get_gpg_version(result);
                return Ok(GPG {
                    homedir: h_d,
                    output_dir: o_d,
                    env: None,
                    keyrings: None,
                    secret_keyring: None,
                    use_agent: false,
                    options: None,
                    version: version.0,
                    full_version: version.1,
                });
            }
            Err(e) => {
                return Err(GPGError::OutputDirError(format!("{}", e)));
            }
        }
    }
}
