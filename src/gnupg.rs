use std::collections::HashMap;
use std::env;

use crate::utils::response::{CmdResult, Operation};
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
    /// the --use-agent parameter is passed to gpg when set to true
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

    pub fn gen_key(
        &self,
        args: HashMap<String, String>,
        passphrase: Option<String>,
    ) -> Result<CmdResult, GPGError> {
        let input: String = self.gen_key_input(args, passphrase.clone());
        let args: Vec<String> = vec!["--gen-key".to_string()];
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            passphrase,
            self.version,
            self.homedir.clone(),
            self.use_agent,
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            Some(input.as_bytes().to_vec()),
            true,
            Operation::GenerateKey,
        );
        return result;
    }

    fn gen_key_input(&self, args: HashMap<String, String>, passphrase: Option<String>) -> String {
        // generate the input we need to pass to gpg to generate a key

        // Key-Type: DSA
        // Key-Length: 1024
        // Subkey-Type: ELG-E
        // Subkey-Length: 1024
        // Name-Real: Joe Tester
        // Name-Comment: with stupid passphrase
        // Name-Email: joe@foo.bar
        // Expire-Date: 0
        // %no-protection
        // %commit

        let mut params: HashMap<String, String> = HashMap::new();
        for (key, value) in args.iter() {
            params.insert(key.replace("_", "-").to_string(), value.trim().to_string());
        }
        params
            .entry("Key-Type".to_string())
            .or_insert("RSA".to_string());
        if !params.contains_key("Key-Curve") {
            params
                .entry("Key-Length".to_string())
                .or_insert("2048".to_string());
        }
        params
            .entry("Expire-Date".to_string())
            .or_insert("0".to_string());
        params
            .entry("Name-Real".to_string())
            .or_insert("AutoGenerated Key".to_string());
        let logname = env::var("LOGNAME")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "unspecified".to_string());
        let hostname = hostname::get().unwrap_or_else(|_| "unknown".into());
        params.entry("Name-Email".to_string()).or_insert(format!(
            "{}@{}",
            logname,
            hostname.to_string_lossy()
        ));
        let mut input: String = format!("Key-Type: {}\n", params.remove("Key-Type").unwrap());
        for (key, value) in params.iter() {
            input.push_str(&format!("{}: {}\n", key, value));
        }
        if passphrase.is_none() {
            input.push_str("%no-protection\n");
        }
        input.push_str("%commit\n");
        return input;
    }

    pub fn set_use_agent(&mut self) {
        self.use_agent = true;
    }

    pub fn set_not_use_agent(&mut self) {
        self.use_agent = true;
    }

    pub fn set_option(&mut self, options: Vec<String>) {
        self.options = Some(options);
    }

    pub fn clear_option(&mut self) {
        self.options = None;
    }
    pub fn set_env(&mut self, env: HashMap<String, String>) {
        self.env = Some(env);
    }

    pub fn clear_env(&mut self) {
        self.env = None;
    }
}
