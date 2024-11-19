use std::collections::HashMap;
use std::env;
use std::fs::File;

use chrono::Local;

use crate::process::handle_cmd_io;
use crate::utils::enums::Operation;
use crate::utils::{
    errors::{GPGError, GPGErrorType},
    response::{CmdResult, ListKeyResult},
    utils::{
        check_is_dir, decode_list_key_result, get_file_extension, get_gpg_version,
        get_or_create_gpg_homedir, get_or_create_gpg_output_dir, is_passphrase_valid,
        set_output_without_confirmation,
    },
};

/// a struct to represent a GPG object
//*******************************************************

//                 RELATED TO GPG

//*******************************************************
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
        // homedir: a path to a directory where the local key were at
        // output_dir: a path to a directory where the output files from gpg will save to

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
            return Err(GPGError::new(
                GPGErrorType::OutputDirError(format!("{} is not a directory", h_d)),
                None,
            ));
        }
        if !check_is_dir(o_d.clone()) {
            return Err(GPGError::new(
                GPGErrorType::OutputDirError(format!("{} is not a directory", o_d)),
                None,
            ));
        }
        let result = handle_cmd_io(
            Some(vec![
                "--list-config".to_string(),
                "--with-colons".to_string(),
            ]),
            None,
            0.0,
            h_d.clone(),
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            Operation::Verify,
        );

        match result {
            Ok(result) => {
                let version: (f32, String) = get_gpg_version(&result);
                return Ok(GPG {
                    homedir: h_d,
                    output_dir: o_d,
                    env: None,
                    keyrings: None,
                    secret_keyring: None,
                    options: None,
                    version: version.0,
                    full_version: version.1,
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    //*******************************************************

    //    FUNCTION BELOW RELATED TO GPG VARIOUS OPERATIONS

    //*******************************************************

    //*******************************************************

    //                   GENERATE KEY

    //*******************************************************
    pub fn gen_key(
        &self,
        args: Option<HashMap<String, String>>,
        key_passphrase: Option<String>,
    ) -> Result<CmdResult, GPGError> {
        // args: a hashmap of arguments to generate the type of key, if not provided, it will generate a default key of
        // passphrase: a passphrase for the key ( was used to protect the private key and will need during operation like decrypt )

        let k_p = key_passphrase.clone();
        if k_p.is_some() {
            if !is_passphrase_valid(k_p.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("key passphrase invalid".to_string()),
                    None,
                ));
            }
        }
        let input: String = self.gen_key_input(args, key_passphrase.clone());
        let args: Vec<String> = vec!["--gen-key".to_string()];
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            key_passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            Some(input.as_bytes().to_vec()),
            true,
            false,
            Operation::GenerateKey,
        );
        return result;
    }

    fn gen_key_input(
        &self,
        args: Option<HashMap<String, String>>,
        passphrase: Option<String>,
    ) -> String {
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
        if args.is_some() {
            for (key, value) in args.unwrap().iter() {
                params.insert(key.replace("_", "-").to_string(), value.trim().to_string());
            }
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

    //*******************************************************

    //                     LIST KEY

    //*******************************************************
    pub fn list_keys(
        &self,
        secret: bool,
        keys: Option<Vec<String>>,
        signature: bool,
    ) -> Result<Vec<ListKeyResult>, GPGError> {
        // secret: if true, list secret keys
        // keys: list of keyid(s) to match
        // sigs: if true, include signatures

        let mut mode: String = "keys".to_string();
        if secret {
            mode = "secret-keys".to_string();
        } else if signature {
            mode = "sigs".to_string();
        }

        let mut args: Vec<String> = vec![
            format!("--list-{}", mode),
            "--fingerprint".to_string(),
            "--fingerprint".to_string(),
        ]; // duplicate --fingerprint to get the subkeys FP as well

        if self.version >= 2.1 {
            args.push("--with-keygrip".to_string());
        }
        if keys.is_some() {
            args.append(&mut keys.unwrap());
        }
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            None,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            None,
            false,
            false,
            Operation::ListKey,
        );
        match result {
            Ok(result) => {
                return Ok(decode_list_key_result(result));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    //*******************************************************

    //                 FILE ENCRYPTION

    //*******************************************************
    pub fn encrypt(
        &self,
        file: Option<File>,
        file_path: Option<String>,
        recipients: Option<Vec<String>>,
        sign: bool,
        sign_key: Option<String>,
        symmetric: bool,
        symmetric_algo: Option<String>,
        always_trust: bool,
        passphrase: Option<String>,
        armor: bool,
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Result<CmdResult, GPGError> {
        // file: file object
        // file_path: path to file
        // receipients: list of receipients keyid
        // sign: whether to sign the file
        // sign_key: keyid to sign the file
        // symmetric: whether to encrypt symmetrically ( will not encrypt using keyid(s)) [passphrase must be provided if symmetric is true]
        //             the file will be both encrypted with the keyid(s) and symmetrically
        // symmetric_algo: symmetric algorithm to use [if not provided a highly ranked cipher willl be chosen]
        // always_trust: whether to always trust keys
        // passphrase: passphrase to use for symmetric encryption [required if symmetric is true]
        // armor: whether to ASCII-armor the output
        // output: path to write the encrypted output,
        //         will use the default output dir with file name as [encrypted_file_<datetime>.<extension>] set in GPG if not provided
        // extra_args: extra arguments to pass to gpg

        //*****************************************************************************************
        //    NOTE: If signing with a passphrase-protected key,
        //          an error will occur.
        //          Please sign separately after encryption.
        //
        //    Reason:
        //           We stream all input to GPG through STDIN.
        //           When signing with a passphrase-protected key,
        //           GPG expects the passphrase to be entered after the file content.
        //           However, since we are streaming input through STDIN,
        //           it's impossible to distinguish between file content and the passphrase input.
        //           As a result, the passphrase is mistakenly treated as part of the file data,
        //           causing the signing process to fail for passphrase protected key.
        //******************************************************************************************

        let p = passphrase.clone();

        if p.is_some() {
            if !is_passphrase_valid(p.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("passphrase invalid".to_string()),
                    None,
                ));
            }
        }

        // generate encrypt operation arguments for gpg
        let args: Result<Vec<String>, GPGError> = self.gen_encrypt_args(
            file_path.clone(),
            recipients,
            sign,
            sign_key,
            symmetric,
            symmetric_algo,
            always_trust,
            passphrase,
            armor,
            output,
            extra_args,
        );

        match args {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        }

        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args.unwrap()),
            p,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            file,
            file_path,
            None,
            true,
            true,
            Operation::Encrypt,
        );

        match result {
            Ok(result) => {
                return Ok(result);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    fn gen_encrypt_args(
        &self,
        file_path: Option<String>,
        recipients: Option<Vec<String>>,
        sign: bool,
        sign_key: Option<String>,
        symmetric: bool,
        symmetric_algo: Option<String>,
        always_trust: bool,
        passphrase: Option<String>,
        armor: bool,
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Result<Vec<String>, GPGError> {
        let mut args: Vec<String> = vec![];

        if symmetric {
            args.append(&mut vec![
                "--symmetric".to_string(),
                "--no-symkey-cache".to_string(),
            ]);
            if passphrase.is_none() {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError(
                        "passphrase is required if encrypting symmetrically ".to_string(),
                    ),
                    None,
                ));
            }
            if symmetric_algo.is_some() {
                args.append(&mut vec![
                    "--personal-cipher-preferences".to_string(),
                    symmetric_algo.unwrap(),
                ]);
            }
        }
        if recipients.is_some() {
            args.push("--encrypt".to_string());
            for recipient in recipients.unwrap() {
                args.append(&mut vec!["--recipient".to_string(), recipient]);
            }
        }

        if args.len() == 0 {
            return Err(GPGError::new(
                GPGErrorType::InvalidArgumentError(
                    "Please choose symmetric or keys to encrypt your file".to_string(),
                ),
                None,
            ));
        }

        if armor {
            args.push("--armor".to_string());
        }
        if output.is_some() {
            set_output_without_confirmation(&mut args, &output.unwrap());
        } else {
            // if the system is handling the output
            // the name wil be [<encryption_type>_encrypted_file_<YYYYMMDD_HH/MM/SS/NANO-SECOND>.<extension>]
            // the encryption type will either [key] for public key encryption or [pass] for symmetric encryption
            // the extension will be the same if file_path is provided,
            // if a rust File type is provided, the name will be extension will be default to gpg

            let ext: String = get_file_extension(file_path);
            let time_stamp: String = Local::now().format("%Y%m%d-%H:%M:%S:%9f").to_string();
            let out: String = format!(
                "{}{}_encrypted_file_{}.{}",
                self.output_dir.clone(),
                if symmetric {
                    "pass".to_string()
                } else {
                    "key".to_string()
                },
                time_stamp,
                ext
            );
            args.append(&mut vec!["--output".to_string(), out]);
        }

        if sign {
            if sign_key.is_some() {
                args.append(&mut vec![
                    "--sign".to_string(),
                    "--default-key".to_string(),
                    sign_key.unwrap(),
                ]);
            } else {
                args.push("--sign".to_string());
            }
        }

        if always_trust {
            args.append(&mut vec!["--trust-model".to_string(), "always".to_string()]);
        }

        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        }

        return Ok(args);
    }

    //*******************************************************

    //                   FILE DECRYPTION

    //*******************************************************
    pub fn decrypt(
        &self,
        file: Option<File>,
        file_path: Option<String>,
        recipients: Option<String>,
        always_trust: bool,
        passphrase: Option<String>,
        key_passphrase: Option<String>,
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Result<CmdResult, GPGError> {
        // file: file object
        // file_path: path to file
        // recipients: list of recipients keyid
        // always_trust: whether to always trust keys
        // passphrase: passphrase if file if symmetric encrypted [required if it was symmetric encrypted]
        // key_passphrase: passphrase if file is key encrypted and need passphrase protected private key to decrypt
        // output: path to write the decrypted output,
        //         will use the default output dir with file name as [decrypted_file_<datetime>.<extension>] set in GPG if not provided
        // extra_args: extra arguments to pass to gpg

        let k_p = key_passphrase.clone();
        let p = passphrase.clone();
        let mut pass: Option<String> = None;

        if k_p.is_some() {
            if !is_passphrase_valid(k_p.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("key passphrase invalid".to_string()),
                    None,
                ));
            }
            pass = k_p;
        } else if p.is_some() {
            if !is_passphrase_valid(p.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("passphrase invalid".to_string()),
                    None,
                ));
            }
            pass = p;
        }

        let args: Vec<String> = self.gen_decrypt_args(
            file_path.clone(),
            recipients,
            always_trust,
            output,
            extra_args,
        );

        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            if pass.is_some() { pass } else { None },
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            file,
            file_path,
            None,
            true,
            true,
            Operation::Decrypt,
        );

        match result {
            Ok(result) => {
                return Ok(result);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub fn gen_decrypt_args(
        &self,
        file_path: Option<String>,
        recipients: Option<String>,
        always_trust: bool,
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Vec<String> {
        let mut args: Vec<String> = vec!["--decrypt".to_string()];
        if recipients.is_some() {
            args.append(&mut vec!["--recipient".to_string(), recipients.unwrap()]);
        }
        if always_trust {
            args.append(&mut vec!["--trust-model".to_string(), "always".to_string()]);
        }
        if output.is_some() {
            set_output_without_confirmation(&mut args, &output.unwrap());
        } else {
            // if the system is handling the output
            // the name wil be [<encryption_type>_encrypted_file_<YYYYMMDD_HH/MM/SS/NANO-SECOND>.<extension>]
            // the encryption type will either [key] for public key encryption or [pass] for symmetric encryption
            // the extension will be the same if file_path is provided,
            // if a rust File type is provided, the name will be extension will be default to gpg

            let ext: String = get_file_extension(file_path);
            let time_stamp: String = Local::now().format("%Y%m%d-%H:%M:%S:%9f").to_string();
            let out: String = format!(
                "{}decrypted_file_{}.{}",
                self.output_dir.clone(),
                time_stamp,
                ext
            );
            args.append(&mut vec!["--output".to_string(), out]);
        }

        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        }
        return args;
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
