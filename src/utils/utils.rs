use std::{
    fs::{metadata, File}, io::{Seek, Write}, path::{Path, PathBuf}, process::Command
};

#[cfg(unix)]
use std::{
    fs::set_permissions,
    os::unix::fs::PermissionsExt
};


use regex::Regex;

use crate::utils::response::ListKey;

use super::errors::{GPGError, GPGErrorType};
use super::response::{CmdResult, ListKeyResult};

const VERSION_REGEX: &str = r"^cfg:version:(\d+(\.\d+)*)";
const LIST_KEY_KEYWORDS: [&str; 8] = ["pub", "uid", "sec", "fpr", "sub", "ssb", "sig", "grp"];

// check if a path is a directory
pub fn check_is_dir(path: String) -> bool {
    let path = Path::new(&path);

    if !path.is_dir() {
        return false;
    }
    return true;
}

// retrieve home directory of the system
fn get_user_directory() -> PathBuf {
    let home_dir = if cfg!(unix) {
        std::env::var("HOME").unwrap()
    } else {
        std::env::var("USERPROFILE").unwrap()
    };

    return PathBuf::from(home_dir);
}

// retrieve home directory of the system
fn get_download_directory() -> PathBuf {
    let home_dir: PathBuf = get_user_directory();

    return PathBuf::from(home_dir).join("Downloads");
}

//  retrieve or generate the directory for gpg key
pub fn get_or_create_gpg_homedir(path:String) -> String {
    let home_dir = get_user_directory();
    let gpg_directory: &str = if cfg!(unix) { ".gnupg" } else { "gnupg" };
    let gpg_dir = if !path.is_empty() { path } else { home_dir.join(gpg_directory).to_string_lossy().to_string() };

    if !check_is_dir(gpg_dir.clone()) {
        std::fs::create_dir_all(gpg_dir.clone()).unwrap();
    }

    // set the permission of the directory to 700 in unix systems
    // else gpg will warn use with the following warning:
    // [ gpg: WARNING: unsafe permissions on homedir '/Users/< NAME >/.gnupg' ]
    let gpg_dir_path: &Path = Path::new(&gpg_dir);
    let metadata = metadata(gpg_dir_path);

    match metadata {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o700); // 700 in octal
                let _ = set_permissions(gpg_dir_path, permissions);
            }
        }
        Err(_) => {}
    }

    let conf_path = gpg_dir_path.join("gpg-agent.conf");
    if !Path::new(&conf_path).exists() {
        let mut file = File::create(conf_path).unwrap();

        // Write the configuration to disable passphrase caching
        let _ = file.write_all(b"default-cache-ttl 0\n");
        let _ = file.write_all(b"max-cache-ttl 0\n");

        let _ = Command::new("gpgconf")
            .arg("--reload")
            .arg("gpg-agent");
    }
    
    return gpg_dir;
}

//  retrieve or generate the directory for gpg output
pub fn get_or_create_gpg_output_dir(path:String) -> String {
    let download_dir = get_download_directory();
    let gpg_output_dir = if !path.is_empty() { path } else { download_dir.join("gnupg_output").to_string_lossy().to_string() };

    if !check_is_dir(gpg_output_dir.clone()) {
        std::fs::create_dir_all(gpg_output_dir.clone()).unwrap();
    }

    return gpg_output_dir;
}

// retrieve gpg version from result raw data
pub fn get_gpg_version(result: &CmdResult) -> (f32, String) {
    let data: Option<String> = result.get_raw_data();
    let re = Regex::new(VERSION_REGEX).unwrap();

    if data.is_some() {
        let data = data.as_ref().unwrap();
        let version = re.captures(data);

        if version.is_some() {
            let version_string = version.unwrap().get(1).unwrap().as_str().to_string();
            let version_clone: String = version_string.clone();
            let v: Vec<&str> = version_clone.split(".").collect();
            let major_minor_v = format!("{}.{}", v[0], v[1]);

            let version_float: f32 = major_minor_v.parse::<f32>().unwrap_or(0.0);

            return (version_float, version_string);
        }

        return (0.0, "0.0.0".to_string());
    }
    return (0.0, "0.0.0".to_string());
}

pub fn get_file_obj(file: Option<File>, file_path: Option<String>) -> Result<File, GPGError> {
    if file.is_some() {
        let mut file = file.unwrap();
        file.rewind().unwrap();
        return Ok(file);
    } else if file_path.is_some() {
        let file_path = file_path.unwrap();
        let file = File::open(file_path);

        if file.is_err() {
            return Err(GPGError::new(
                GPGErrorType::FileNotFoundError("File do not exist".to_string()),
                None,
            ));
        }
        let mut file = file.unwrap();
        file.rewind().unwrap();
        return Ok(file);
    }

    return Err(GPGError::new(
        GPGErrorType::FileNotProvidedError("File or file path not provided".to_string()),
        None,
    ));
}

pub fn decode_list_key_result(result: CmdResult) -> Vec<ListKeyResult> {
    let output_lines = result.get_raw_data().unwrap();
    let mut processed_keyword: Vec<String> = Vec::new();
    let mut r: ListKey = ListKey::init();
    for output in output_lines.split("\n") {
        let l = output.trim().to_string();
        if l.is_empty() {
            break;
        }

        // split the line into a list of strings [ the first will the the key word ]
        let l_key_pair: Vec<&str> = l.split(":").collect();
        let k_w = l_key_pair[0];

        // check if is was info for the next key
        if processed_keyword.contains(&k_w.to_string()) && (k_w == "pub" || k_w == "sec") {
            processed_keyword.clear();
            r.append_result()
        }

        // process if keyword found
        if LIST_KEY_KEYWORDS.to_vec().contains(&l_key_pair[0]) {
            r.call_method(&l_key_pair[0], l_key_pair);
            processed_keyword.push(k_w.to_string());
        }
    }
    r.append_result();
    return r.get_list_key_result();
}

pub fn is_passphrase_valid(passhrase: &str) -> bool {
    return !passhrase.contains("\n") && !passhrase.contains("\r") && !passhrase.contains("\x00");
}

pub fn set_output_without_confirmation(args: &mut Vec<String>, output: &str) {
    // prevent a confimation prompt when output provided exist
    if Path::new(output).exists() {
        args.push("--yes".to_string()); // assume yes on most question
    }
    args.append(&mut vec!["--output".to_string(), output.to_string()]);
}

pub fn get_file_extension(file_path: Option<String>) -> String {
    let mut ext: String = "gpg".to_string();

    if file_path.is_some() {
        let p = file_path.unwrap();
        let path = Path::new(p.as_str());
        ext = path
            .extension()
            .map(|ext| ext.to_string_lossy().into_owned())
            .unwrap_or("gpg".to_string());
    }
    return ext;
}
