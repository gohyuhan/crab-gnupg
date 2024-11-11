use std::path::Path;

/// check if a path is a directory
pub fn check_is_dir(path: String) -> bool {
    let path = Path::new(&path);
    if !path.is_dir() {
        return false;
    }
    return true;
}

/// retrieve the user's home directory
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