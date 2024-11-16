use std::fs::{metadata, set_permissions, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use regex::Regex;

use crate::utils::response::ListKey;

use super::errors::GPGError;
use super::response::{CmdResult, ListKeyResult, Operation};

const VERSION_REGEX: &str = r"^cfg:version:(\d+(\.\d+)*)";

/// check if a path is a directory
pub fn check_is_dir(path: String) -> bool {
    let path = Path::new(&path);

    if !path.is_dir() {
        return false;
    }
    return true;
}

/// retrieve home directory of the system
fn get_user_directory() -> String {
    let home_dir = std::env::var("HOME").unwrap();

    return home_dir;
}

///  retrieve or generate the directory for gpg key
pub fn get_or_create_gpg_homedir() -> String {
    let home_dir = get_user_directory();
    let gpg_dir = format!("{}/{}", home_dir, ".gnupg");

    if !check_is_dir(gpg_dir.clone()) {
        std::fs::create_dir_all(gpg_dir.clone()).unwrap();
    }

    // set the permission of the directory to 700
    // else gpg will warn use with the following warning:
    // [ gpg: WARNING: unsafe permissions on homedir '/Users/< NAME >/.gnupg' ]
    let gpg_dir_path: &Path = Path::new(&gpg_dir);
    let metadata = metadata(gpg_dir_path);

    match metadata {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700); // 700 in octal
            let _ = set_permissions(gpg_dir_path, permissions);
        }
        Err(_) => {}
    }

    return gpg_dir;
}

///  retrieve or generate the directory for gpg output
pub fn get_or_create_gpg_output_dir() -> String {
    let home_dir = get_user_directory();
    let gpg_output_dir = format!("{}/{}", home_dir, "gnupg/output");

    if !check_is_dir(gpg_output_dir.clone()) {
        std::fs::create_dir_all(gpg_output_dir.clone()).unwrap();
    }

    return gpg_output_dir;
}

/// retrieve gpg version from result raw data
pub fn get_gpg_version(result: CmdResult) -> (f32, String) {
    let data: Option<String> = result.get_raw_data();
    let re = Regex::new(VERSION_REGEX).unwrap();

    if data.is_some() {
        let data = data.as_ref().unwrap();
        let version = re.captures(data);

        if version.is_some() {
            let version_string = version.unwrap().get(1).unwrap().as_str().to_string();
            let version_clone: String = version_string.clone();
            let mut version_float: f32 = 0.0;
            let v: Vec<&str> = version_clone.split(".").collect();
            let major_minor_v = format!("{}.{}", v[0], v[1]);

            version_float = major_minor_v.parse::<f32>().unwrap();

            return (version_float, version_string);
        }

        return (0.0, "0.0.0".to_string());
    }
    // if no version is found, return 0.0.0
    // should take into account also that the version
    // might not be in the same format for every version
    return (0.0, "0.0.0".to_string());
}

pub fn get_file_obj(file: Option<File>, file_path: Option<String>) -> Result<File, GPGError> {
    if file.is_some() {
        return Ok(file.unwrap());
    } else if file_path.is_some() {
        let file_path = file_path.unwrap();
        let file = File::open(file_path);

        if file.is_err() {
            return Err(GPGError::FileNotFoundError("Not do not exist".to_string()));
        }

        return Ok(file.unwrap());
    }

    return Err(GPGError::FileNotProvidedError(
        "File or file path not provided".to_string(),
    ));
}

pub fn decode_list_key_result(result: CmdResult) -> Vec<ListKeyResult>{
    println!("output: {:?}", result);
    let output_lines = result.get_raw_data().unwrap();
    let keywords = ["pub", "uid", "sec", "fpr", "sub", "ssb", "sig", "grp"];
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
        if processed_keyword.contains(&k_w.to_string()) {
            processed_keyword.clear();
            r.append_result()
        }

        // process if keyword found
        if keywords.contains(&l_key_pair[0]) {
            r.call_method(&l_key_pair[0], l_key_pair);
            processed_keyword.push(k_w.to_string());
        }
    }
    r.append_result();
    return r.get_list_key_result();
}
