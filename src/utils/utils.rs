use std::path::Path;
use std::fs::{metadata, set_permissions};
use std::os::unix::fs::PermissionsExt;
use regex::Regex;

use super::response::CmdResult;


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
    let gpg_dir_path:&Path = Path::new(&gpg_dir);
    let metadata = metadata(gpg_dir_path);
    match metadata {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);  // 700 in octal
            let _ = set_permissions(gpg_dir_path, permissions);
        }
        Err(_) => {
        }
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
pub fn get_gpg_version(result:CmdResult) -> (f32, String) {
    let data: &Option<String> = result.get_raw_data();
    let re = Regex::new(VERSION_REGEX).unwrap();
    if data.is_some(){
        let data = data.as_ref().unwrap();
        let version = re.captures(data);
        if version.is_some() {
            let version_string = version.unwrap().get(1).unwrap().as_str().to_string();
            let mut version_clone:String = version_string.clone();
            let mut version_float:f32 = 0.0;

            let mut v:Vec<&str> = version_clone.split(".").collect();
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
