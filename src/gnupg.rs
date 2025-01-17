use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use chrono::Local;

use crate::process::handle_cmd_io;
use crate::utils::enums::{Operation, TrustLevel};
use crate::utils::utils::get_file_obj;
use crate::utils::{
    errors::{GPGError, GPGErrorType},
    response::{CmdResult, ListKeyResult},
    utils::{
        check_is_dir, decode_list_key_result, get_file_extension, get_gpg_version,
        get_or_create_gpg_homedir, get_or_create_gpg_output_dir, is_passphrase_valid,
        set_output_without_confirmation,
    },
};

// a struct to represent a GPG object
//*******************************************************

//                 RELATED TO GPG

//*******************************************************
#[derive(Debug, Clone)]
pub struct GPG {
    // a path to a directory where the local key were at
    pub homedir: String,
    // a path to a directory where the output files from gpg will save to
    pub output_dir: String,
    // a haspmap of env variables that would be passed to process
    pub env: Option<HashMap<String, String>>,
    // a list of name of keyring files to use. If provided, the default keyring will be ignored.
    pub keyrings: Option<Vec<String>>,
    // a list of name of secret keyring files to use.
    pub secret_keyring: Option<Vec<String>>,
    // additional arguments to be passed to gpg
    pub options: Option<Vec<String>>,
    // a boolean to indicate if the output should be armored
    pub armor: bool,
    // the major minor version of gpg, should only be set by system, user should not set this ex) 2.4
    pub version: f32,
    // the full version of gpg, should only be set by system, user should not set this ex) 2.4.6
    pub full_version: String,
}

impl GPG {
    // initialize a GPG object with a homedir and an output_dir or none (system set homedir and output dir)
    pub fn init(
        homedir: Option<String>,
        output_dir: Option<String>,
        armor: bool,
    ) -> Result<GPG, GPGError> {
        // homedir: a path to a directory where the local key were at
        // output_dir: a path to a directory where the output files from gpg will save to
        // a boolean to indicate if the output should be armored

        let h_d: String = get_or_create_gpg_homedir(homedir.unwrap_or(String::new()));
        let o_d: String = get_or_create_gpg_output_dir(output_dir.unwrap_or(String::new()));

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
                    armor: armor,
                    version: version.0,
                    full_version: version.1,
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    //#######################################################

    //    FUNCTION BELOW RELATED TO GPG VARIOUS OPERATIONS

    //#######################################################

    //*******************************************************

    //                   GENERATE KEY

    //*******************************************************
    pub fn gen_key(
        &self,
        key_passphrase: Option<String>,
        args: Option<HashMap<String, String>>,
    ) -> Result<CmdResult, GPGError> {
        // passphrase: a passphrase for the key ( was used to protect the private key and will be needed during operation like decrypt )
        // args: a hashmap of arguments to generate the type of key, if not provided, it will generate a default key of type RSA with key length of 2048

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

        //******************* EXAMPLE ************************
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
        //*****************************************************

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

    //                   DELETE KEY

    //*******************************************************
    pub fn delete_keys(
        &self,
        mut fingerprints: Vec<String>,
        is_secret: bool,
        is_subkey: bool,
        passphrase: Option<String>,
    ) -> Result<CmdResult, GPGError> {
        // fingerprints: list of fingerprints to delete
        // is_secret: if true, delete secret keys only 
        // is_subkey: if true, only delete subkeys
        // passphrase: passphrase for passphrase protected secret keys

        // NOTE: delete both public and secret key by default
        // NOTE: If the fingerprint is for subkeys, but is_subkey was not set to true, it will remove the parent key also

        let mut mode:String = "secret-and-public-key".to_string();
        if is_secret {
            mode = "secret-keys".to_string();
        }
        let mut args: Vec<String> = vec![
            "--yes".to_string(),
            format!("--delete-{}", mode),
        ];

        if is_subkey{
            let mut subkey_fingerprints: Vec<String> = Vec::new();
            for f_p in fingerprints{
                subkey_fingerprints.push(format!("{}!", f_p));
            }
            args.append(&mut subkey_fingerprints);
        } else {
            args.append(&mut fingerprints);
        }
        let result:Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            None,
            false,
            false,
            Operation::DeleteKey,
        );

        return result;
    }

    //*******************************************************

    //                   ADD SUBKEY

    //*******************************************************
    pub fn add_subkey(
        &self,
        fingerprint: String,
        passphrase: Option<String>,
        algo: String,
        usage: String,
        expire: String // ISO format YYYY-MM-DD or "-" for no expiration
    ) -> Result<CmdResult, GPGError> {
        if passphrase.is_some() {
            if !is_passphrase_valid(&mut passphrase.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("passphrase invalid".to_string()),
                    None,
                ));
            }
        }

        let args:Vec<String> =vec!["--quick-add-key".to_string(), fingerprint, algo, usage, expire]; 

        let result = handle_cmd_io(
            Some(args),
            passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            None,
            false,
            false,
            Operation::AddSubKey,
        );

        return result;

    }

    //*******************************************************

    //                   REVOKE KEY

    //*******************************************************
    pub fn revoke_key(
        &self,
        keyid: String,
        passphrase: Option<String>,
        reason_code:u8,
        revoke_desc: Option<String>,
        is_subkey: bool,
    ) -> Result<CmdResult, GPGError> {
        let mut args:Vec<String> = vec![];
        let mut desc:String = "".to_string();

        if revoke_desc.is_some() {
            desc = revoke_desc.unwrap();
        }

        if !(0..=3).contains(&reason_code){
            // 0 = No reason specified
            // 1 = Key has been compromised
            // 2 = Key is superseded
            // 3 = Key is no longer used
            return Err(GPGError::new(
                GPGErrorType::InvalidReasonCode("Please choose between 0~3 as a reason code for revoking a key".to_string()),
                None,
            ));
        }

        let mut byte_input:Vec<u8> = format!("revkey\ny\n{}\n{}\ny\nsave\n", reason_code, desc).as_bytes().to_vec();

        if is_subkey {
            let sequence: Result<u8, GPGError> = self.get_subkey_position(keyid.clone());
            match sequence {
                Ok(sequence) => {
                    let selected_key = format!("key {}", sequence);
                    byte_input = format!("{}\nrevkey\ny\n{}\n{}\ny\nsave\n", selected_key, reason_code, desc).as_bytes().to_vec();
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        args.append(&mut vec!["--command-fd".to_string(), "0".to_string(), "--edit-key".to_string(), keyid]);

        let result = handle_cmd_io(
            Some(args),
            passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            Some(byte_input),
            true,
            false,
            Operation::RevokeKey,
        );

        return result;
    }

    fn get_subkey_position(
        &self,
        keyid: String,
    ) -> Result<u8, GPGError> {
        let key_list: Result<Vec<ListKeyResult>, GPGError> = self.list_keys(false, Some(vec![keyid.clone()]), false);
        match key_list {
            Ok(key_list) => {
                if key_list[0].subkeys.len() > 0 {
                    let position: u8 = key_list[0].subkeys.iter().position(|x| x.keyid == keyid).unwrap() as u8;
                    return Ok(position+1);
                }
                return Err(GPGError::new(
                    GPGErrorType::KeyNotSubkey("keyid provided is not a subkey".to_string()),
                    None,
                ));
            },
            Err(e) => {
                return Err(e);
            }
        }
    }

    //*******************************************************

    //                   IMPORT KEY

    //*******************************************************
    pub fn import_key(
        &self,
        file: Option<File>,
        file_path: Option<String>,
        merge_only: bool,
        extra_args: Option<Vec<String>>,
    ) -> Result<CmdResult, GPGError> {
        let file: Result<File, GPGError> = get_file_obj(file, file_path);
        match file {
            Ok(mut file) => {
                let mut buffer: Vec<u8> = Vec::new();
                let _ = file.read_to_end(&mut buffer);
                let result: Result<CmdResult, GPGError> = self.import_key_file_buffer(
                    buffer, 
                    merge_only, 
                    extra_args);
                match result {
                    Ok(result) => {
                        return Ok(result);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Err(e)=>{
                return Err(e);
            }
        }
    }

    fn import_key_file_buffer(
        &self,
        key_buffer: Vec<u8>,
        merge_only: bool,
        extra_args: Option<Vec<String>>,
    ) -> Result<CmdResult, GPGError> {
        let mut args: Vec<String> = vec!["--import".to_string()];
        if merge_only {
            args.append(&mut vec![
                "--import-options".to_string(),
                "merge-only".to_string(),
            ]);
        };
        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        };
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            None,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            Some(key_buffer),
            true,
            false,
            Operation::ImportKey,
        );
        return result;
    }

    //*******************************************************

    //                   EXPORT KEY

    //*******************************************************
    pub fn export_public_key(
        &self,
        key_id: Option<Vec<String>>,
        output: Option<String>,
    ) -> Result<CmdResult, GPGError> {
        // key_id: list of keyid(s) to export, if not provided, all public keys will be exported
        // output: path that the exported key file will be saved to

        let mut args: Vec<String> = vec!["--export".to_string()];
        if output.is_some() {
            set_output_without_confirmation(&mut args, &output.unwrap());
        } else {
            // if output folder not specified, system will create a exported_public_key folder in the set output dir when initalizling the gpg
            // all exported public key will be saved to there with filename as public_key_<timestamp>.asc
            let gpg_p_key_output_dir = PathBuf::from(self.output_dir.clone())
                .join("exported_public_key")
                .to_string_lossy()
                .to_string();
            if !check_is_dir(gpg_p_key_output_dir.clone()) {
                std::fs::create_dir_all(gpg_p_key_output_dir.clone()).unwrap();
            }
            let time_stamp: String = Local::now().format("%Y%m%d-%H:%M:%S:%9f").to_string();
            let gpg_p_key_output = PathBuf::from(gpg_p_key_output_dir)
                .join(format!("public_key_{}.asc", time_stamp))
                .to_string_lossy()
                .to_string();
            set_output_without_confirmation(&mut args, &gpg_p_key_output);
        }
        if key_id.is_some() {
            args.append(&mut key_id.unwrap());
        }
        let result: Result<CmdResult, GPGError> =
            self.export_key(args, None, Operation::ExportPublicKey);
        return result;
    }

    pub fn export_secret_key(
        &self,
        key_id: Option<Vec<String>>,
        passphrase: Option<String>,
        output: Option<String>,
    ) -> Result<CmdResult, GPGError> {
        // key_id: list of keyid(s) to export, if not provided, all secret keys will be exported
        // passphrase: for gpg version > 2.1, passphrase for passphrase proctected secret keys are required
        // output: path that the exported key file will be saved to

        //*****************************************************************************
        //  NOTE: If there are 2 or more secret key that are
        //        passphrase proctected ( but different passphrase )
        //        are being exported, keys that are protected by the provided passphrase
        //        and keys that aren't passphrase protected will be exported
        //        ( as gpg can only read 1 passphrase at a time from STDIN)
        //*****************************************************************************

        if passphrase.is_some() {
            if !is_passphrase_valid(&mut passphrase.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("passphrase invalid".to_string()),
                    None,
                ));
            }
        }

        let mut args: Vec<String> = vec!["--export-secret-key".to_string()];
        if output.is_some() {
            set_output_without_confirmation(&mut args, &output.unwrap());
        } else {
            // if output folder not specified, system will create a exported_secret_key folder in the set output dir when initalizling the gpg
            // all exported secret key will be saved to there with filename as secret_key_<timestamp>.sec.asc
            let gpg_s_key_output_dir = PathBuf::from(self.output_dir.clone())
                .join("exported_secret_key")
                .to_string_lossy()
                .to_string();
            if !check_is_dir(gpg_s_key_output_dir.clone()) {
                std::fs::create_dir_all(gpg_s_key_output_dir.clone()).unwrap();
            }
            let time_stamp: String = Local::now().format("%Y%m%d-%H:%M:%S:%9f").to_string();
            let gpg_s_key_output = PathBuf::from(gpg_s_key_output_dir)
                .join(format!("secret_key_{}.sec.asc", time_stamp))
                .to_string_lossy()
                .to_string();
            set_output_without_confirmation(&mut args, &gpg_s_key_output);
        }
        if key_id.is_some() {
            args.append(&mut key_id.unwrap());
        }

        let result: Result<CmdResult, GPGError> =
            self.export_key(args, passphrase, Operation::ExportSecretKey);
        return result;
    }

    fn export_key(
        &self,
        args: Vec<String>,
        passphrase: Option<String>,
        ops: Operation,
    ) -> Result<CmdResult, GPGError> {
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            None,
            false,
            false,
            ops,
        );
        return result;
    }

    //*******************************************************

    //                   TRUST KEY

    //*******************************************************
    pub fn trust_key(
        &self,
        fingerprints: Vec<String>,
        trust_level: TrustLevel,
    ) -> Result<CmdResult, GPGError> {
        // fingerprints: list of fingerprint(s) to trust
        // trust_level: trust level to set for the key

        let args: Vec<String> = vec!["--import-ownertrust".to_string()];
        let mut input_list: String = String::new();
        for fingerprint in fingerprints {
            input_list.push_str(&format!("{}:{}:\n", fingerprint, trust_level.value()));
        }

        let result = handle_cmd_io(
            Some(args),
            None,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            Some(input_list.as_bytes().to_vec()),
            true,
            false,
            Operation::TrustKey,
        );

        return result;
    }

    //*******************************************************

    //                   SIGN KEY

    //*******************************************************
    pub fn sign_key(
        &self,
        signing_key_id: String,
        target_key_id: String,
        passphrase: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Result<CmdResult, GPGError> {
        if passphrase.is_some() {
            if !is_passphrase_valid(passphrase.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("passphrase invalid".to_string()),
                    None,
                ));
            }
        }

        let mut args: Vec<String> = vec![
            "--yes".to_string(),
            "--default-key".to_string(),
            signing_key_id,
            "--sign-key".to_string(),
            target_key_id,
        ];
        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        }

        let result = handle_cmd_io(
            Some(args),
            passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            None,
            None,
            None,
            false,
            false,
            Operation::SignKey,
        );

        return result;
    }

    //*******************************************************

    //                 FILE ENCRYPTION

    //*******************************************************
    // to encrypt file, use the EncryptionOption struct to create the encryption options
    pub fn encrypt(&self, encrypt_option: EncryptOption) -> Result<CmdResult, GPGError> {
        // encryption_option: struct that contains all the encryption options ( refer to the struct for more info )

        //*****************************************************************************************
        //    NOTE: If signing with a passphrase-protected key,
        //          an error will occur.
        //          Please sign separately after encryption if using
        //          passphrase-protected key.
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

        let p: Option<String> = encrypt_option.passphrase.clone();

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
            encrypt_option.file_path.clone(),
            encrypt_option.recipients,
            encrypt_option.sign,
            encrypt_option.sign_key,
            encrypt_option.symmetric,
            encrypt_option.symmetric_algo,
            encrypt_option.always_trust,
            encrypt_option.passphrase,
            encrypt_option.output,
            encrypt_option.extra_args,
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
            encrypt_option.file,
            encrypt_option.file_path,
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
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Result<Vec<String>, GPGError> {
        let mut args: Vec<String> = vec![];
        let mut encrypt_type: String = "".to_string();

        if symmetric {
            args.append(&mut vec![
                "--symmetric".to_string(),
            ]);
            if self.version>=2.1{
                args.push("--no-symkey-cache".to_string());
            }
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
            encrypt_type.push_str("pass_");
        }
        if recipients.is_some() {
            args.push("--encrypt".to_string());
            for recipient in recipients.unwrap() {
                args.append(&mut vec!["--recipient".to_string(), recipient]);
            }
            encrypt_type.push_str("keys_");
        }

        if args.len() == 0 {
            return Err(GPGError::new(
                GPGErrorType::InvalidArgumentError(
                    "Please choose symmetric or keys to encrypt your file".to_string(),
                ),
                None,
            ));
        }

        if self.armor {
            args.push("--armor".to_string());
        }
        if output.is_some() {
            set_output_without_confirmation(&mut args, &output.unwrap());
        } else {
            // if the system is handling the output
            // the name wil be [<encryption_type>_encrypted_file_<YYYYMMDD_HH/MM/SS/NANO-SECOND>.<extension>]
            // the encryption type will either [key] for public key encryption or [pass] for symmetric encryption or both
            // the extension will be the same if file_path is provided,
            // if a rust File type is provided, the file extension will be default to .gpg

            let ext: String = get_file_extension(file_path);
            let time_stamp: String = Local::now().format("%Y%m%d-%H:%M:%S:%9f").to_string();
            let out: String = PathBuf::from(self.output_dir.clone())
                .join(format!(
                    "{}_encrypted_file_{}.{}",
                    encrypt_type, time_stamp, ext
                ))
                .to_string_lossy()
                .to_string();
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
    // to encrypt file, use the DecryptionOption struct to create the decryption options
    pub fn decrypt(&self, decrypt_option: DecryptOption) -> Result<CmdResult, GPGError> {
        // decrypt_option: struct that contains all the decryption options ( refer to the struct for more info )

        let k_p: Option<String> = decrypt_option.key_passphrase.clone();
        let p: Option<String> = decrypt_option.passphrase.clone();
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
            decrypt_option.file_path.clone(),
            decrypt_option.recipient,
            decrypt_option.always_trust,
            decrypt_option.output,
            decrypt_option.extra_args,
        );
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            pass,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            decrypt_option.file,
            decrypt_option.file_path,
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

    fn gen_decrypt_args(
        &self,
        file_path: Option<String>,
        recipient: Option<String>,
        always_trust: bool,
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Vec<String> {
        let mut args: Vec<String> = vec!["--decrypt".to_string()];
        if recipient.is_some() {
            args.append(&mut vec!["--recipient".to_string(), recipient.unwrap()]);
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
            let out: String = PathBuf::from(self.output_dir.clone())
                .join(format!("decrypted_file_{}.{}", time_stamp, ext))
                .to_string_lossy()
                .to_string();
            args.append(&mut vec!["--output".to_string(), out]);
        }

        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        }
        return args;
    }

    //*******************************************************

    //                   FILE SIGNING

    //*******************************************************
    pub fn sign(&self, sign_option: SignOption) -> Result<CmdResult, GPGError> {
        // sign_option: struct that contains all the signing options ( refer to the struct for more info )

        if sign_option.key_passphrase.is_some() {
            if !is_passphrase_valid(sign_option.key_passphrase.as_ref().unwrap()) {
                return Err(GPGError::new(
                    GPGErrorType::PassphraseError("passphrase invalid".to_string()),
                    None,
                ));
            }
        };
        let args: Vec<String> = self.gen_sign_args(
            sign_option.keyid.clone(),
            sign_option.clearsign,
            sign_option.detach,
            sign_option.output,
            sign_option.extra_args,
        );

        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            sign_option.key_passphrase,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            sign_option.file,
            sign_option.file_path,
            None,
            true,
            true,
            Operation::Sign,
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

    fn gen_sign_args(
        &self,
        keyid: Option<String>,
        clearsign: bool,
        detach: bool,
        output: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Vec<String> {
        let mut args: Vec<String> = vec!["--sign".to_string()];
        let time_stamp: String = Local::now().format("%Y%m%d-%H:%M:%S:%9f").to_string();

        if clearsign {
            args.push("--clearsign".to_string());
        };
        if detach {
            args.push("--detach-sign".to_string());
            let extension = if self.armor { ".asc" } else { ".sig" };
            let file_path: String = output.unwrap_or(
                PathBuf::from(self.output_dir.clone())
                    .join(format!("detach_sign_{}{}", time_stamp, extension))
                    .to_string_lossy()
                    .to_string(),
            );
            set_output_without_confirmation(&mut args, &file_path);
        } else {
            let file_path: String = output.unwrap_or(
                PathBuf::from(self.output_dir.clone())
                    .join(format!("embedded_sign_{}.gpg", time_stamp))
                    .to_string_lossy()
                    .to_string(),
            );
            set_output_without_confirmation(&mut args, &file_path);
        }

        if keyid.is_some() {
            args.append(&mut vec!["--default-key".to_string(), keyid.unwrap()]);
        };

        if self.armor {
            args.push("--armor".to_string());
        }

        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        }

        return args;
    }

    //*******************************************************

    //                   FILE VERIFICATION

    //*******************************************************
    pub fn verify_file(
        &self,
        file: Option<File>,
        file_path: Option<String>,
        signature_file_path: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Result<CmdResult, GPGError> {
        // file: file object
        // file_path: path to file
        // signature_file_path: path to signature file
        // extra_args: extra arguments to pass to gpg

        //*****************************************************************************************
        //    NOTE: If only file or file_path is provided, it expected the file to include a
        //          complete signature.
        //          For detached signature, signature_file_path is required along
        //          with file or file_path
        //******************************************************************************************

        let args: Vec<String> = self.gen_verify_file_args(signature_file_path, extra_args);
        let result: Result<CmdResult, GPGError> = handle_cmd_io(
            Some(args),
            None,
            self.version,
            self.homedir.clone(),
            self.options.clone(),
            self.env.clone(),
            file,
            file_path.clone(),
            None,
            true,
            true,
            Operation::VerifyFile,
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

    fn gen_verify_file_args(
        &self,
        signature_file_path: Option<String>,
        extra_args: Option<Vec<String>>,
    ) -> Vec<String> {
        let mut args: Vec<String> = vec!["--verify".to_string()];
        if signature_file_path.is_some() {
            args.append(&mut vec![signature_file_path.unwrap(), "-".to_string()]);
        }
        if extra_args.is_some() {
            args.append(&mut extra_args.unwrap());
        }
        return args;
    }
}

// a struct to represent GPG Encryption Option
// use this to construct the options for GPG Encryption
// that will be pass to the encryption method
//*******************************************************

//         RELATED TO GPG ENCRYPTION OPTION

//*******************************************************
#[derive(Debug)]
pub struct EncryptOption {
    // file: file object
    pub file: Option<File>,
    // file_path: path to file
    pub file_path: Option<String>,
    // receipients: list of receipients keyid
    pub recipients: Option<Vec<String>>,
    // sign: whether to sign the file
    pub sign: bool,
    // sign_key: keyid to sign the file
    pub sign_key: Option<String>,
    // symmetric: whether to encrypt symmetrically ( will not encrypt using keyid(s)) [passphrase must be provided if symmetric is true]
    //            the file will be both encrypted with the keyid(s) and symmetrically
    pub symmetric: bool,
    // symmetric_algo: symmetric algorithm to use [if not provided a highly ranked cipher willl be chosen]
    pub symmetric_algo: Option<String>,
    // always_trust: whether to always trust keys
    pub always_trust: bool,
    // passphrase: passphrase to use for symmetric encryption [required if symmetric is true]
    pub passphrase: Option<String>,
    // output: path to write the encrypted output,
    //         will use the default output dir set in GPG if not provided and
    //         with file name as [<encryption_type>_encrypted_file_<datetime>.<extension>]
    pub output: Option<String>,
    // extra_args: extra arguments to pass to gpg
    pub extra_args: Option<Vec<String>>,
}

impl EncryptOption {
    // for default, it will be a encryption with just keys and always trust will be true
    pub fn default(
        file: Option<File>,
        file_path: Option<String>,
        recipients: Vec<String>,
        output: Option<String>,
    ) -> EncryptOption {
        return EncryptOption {
            file: file,
            file_path: file_path,
            recipients: Some(recipients),
            sign: false,
            sign_key: None,
            symmetric: false,
            symmetric_algo: None,
            always_trust: true,
            passphrase: None,
            output: output,
            extra_args: None,
        };
    }

    // for with_symmetric, it will be a encryption with passphrase instead of keys and always trust will be true
    pub fn with_symmetric(
        file: Option<File>,
        file_path: Option<String>,
        symmetric_algo: Option<String>,
        passphrase: String,
        output: Option<String>,
    ) -> EncryptOption {
        return EncryptOption {
            file: file,
            file_path: file_path,
            recipients: None,
            sign: false,
            sign_key: None,
            symmetric: true,
            symmetric_algo: symmetric_algo,
            always_trust: true,
            passphrase: Some(passphrase),
            output: output,
            extra_args: None,
        };
    }

    // for with_key_and_symmetric, it will be a encryption with both passphrase and keys and always trust will be true
    pub fn with_key_and_symmetric(
        file: Option<File>,
        file_path: Option<String>,
        recipients: Option<Vec<String>>,
        symmetric_algo: Option<String>,
        passphrase: String,
        output: Option<String>,
    ) -> EncryptOption {
        return EncryptOption {
            file: file,
            file_path: file_path,
            recipients: recipients,
            sign: false,
            sign_key: None,
            symmetric: true,
            symmetric_algo: symmetric_algo,
            always_trust: true,
            passphrase: Some(passphrase),
            output: output,
            extra_args: None,
        };
    }
}

// a struct to represent GPG Decryption Option
// use this to construct the options for GPG Decryption
// that will be pass to the decryption method
//*******************************************************

//         RELATED TO GPG DECRYPTION OPTION

//*******************************************************
#[derive(Debug)]
pub struct DecryptOption {
    // file: file object
    pub file: Option<File>,
    // file_path: path to file
    pub file_path: Option<String>,
    // recipients: recipients keyid
    pub recipient: Option<String>,
    // always_trust: whether to always trust keys
    pub always_trust: bool,
    // passphrase: passphrase if file if symmetric encrypted [required if it was symmetric encrypted]
    pub passphrase: Option<String>,
    // key_passphrase: passphrase if file is key encrypted and need passphrase protected private key to decrypt
    pub key_passphrase: Option<String>,
    // output: path to write the decrypted output,
    //         will use the default output dir with file name as [decrypted_file_<datetime>.<extension>] set in GPG if not provided
    pub output: Option<String>,
    // extra_args: extra arguments to pass to gpg
    pub extra_args: Option<Vec<String>>,
}

impl DecryptOption {
    // for default, it will be a decryption with secret key and always trust will be true
    // [key_passphrase is required for passphrase protected private key]
    pub fn default(
        file: Option<File>,
        file_path: Option<String>,
        recipient: String,
        key_passphrase: Option<String>,
        output: Option<String>,
    ) -> DecryptOption {
        return DecryptOption {
            file: file,
            file_path: file_path,
            recipient: Some(recipient),
            always_trust: true,
            passphrase: None,
            key_passphrase: key_passphrase,
            output: output,
            extra_args: None,
        };
    }

    // for with_symmetric, it will be a decryption with passphrase instead of secret keys and always trust will be true
    pub fn with_symmetric(
        file: Option<File>,
        file_path: Option<String>,
        passphrase: String,
        output: Option<String>,
    ) -> DecryptOption {
        return DecryptOption {
            file: file,
            file_path: file_path,
            recipient: None,
            always_trust: true,
            passphrase: Some(passphrase),
            key_passphrase: None,
            output: output,
            extra_args: None,
        };
    }
}

// a struct to represent GPG Signing Option
// use this to construct the options for GPG Signing
// that will be pass to the signing method
//*******************************************************

//         RELATED TO GPG SIGNING OPTION

//*******************************************************
#[derive(Debug)]
pub struct SignOption {
    // file: file object
    pub file: Option<File>,
    // file_path: path to file
    pub file_path: Option<String>,
    // keyid: keyid for signing
    pub keyid: Option<String>,
    // key_passphrase: required for passphrase protected private key
    pub key_passphrase: Option<String>,
    // clearsign: Whether to use clear signing
    pub clearsign: bool,
    // detach: Whether to produce a detached signature.
    pub detach: bool,
    // output: path to write the detached signature or embedded sign file
    //         if output not specified:
    //           will use the default output dir with file name as [<sign_type>_<datetime>.<sig or gpg>] set in GPG if
    //           file is provided instead of file_path or detached signature
    pub output: Option<String>,
    // extra_args: extra arguments to pass to gpg
    pub extra_args: Option<Vec<String>>,
}

impl SignOption {
    // for default, it will be an embedded signing with secret key with clearsign
    // [key_passphrase is required for passphrase protected private key]
    pub fn default(
        file: Option<File>,
        file_path: Option<String>,
        keyid: String,
        key_passphrase: Option<String>,
        output: Option<String>,
    ) -> SignOption {
        return SignOption {
            file: file,
            file_path: file_path,
            keyid: Some(keyid),
            key_passphrase: key_passphrase,
            clearsign: true,
            detach: false,
            output: output,
            extra_args: None,
        };
    }

    // for detached, it will be a detached signing with secret key without clearsign
    pub fn detached(
        file: Option<File>,
        file_path: Option<String>,
        keyid: String,
        key_passphrase: Option<String>,
        output: Option<String>,
    ) -> SignOption {
        return SignOption {
            file: file,
            file_path: file_path,
            keyid: Some(keyid),
            key_passphrase: key_passphrase,
            clearsign: false,
            detach: true,
            output: output,
            extra_args: None,
        };
    }
}
