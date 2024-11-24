use std::{
    collections::HashMap,
    fs::remove_dir_all,
    path::{
        PathBuf,
        Path
    },
    io::Write
};

use tempfile::tempfile;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use crab_gnupg::{
    gnupg::GPG,
    utils::{
        errors::{GPGError, GPGErrorType},
        response::{CmdResult, ListKeyResult}
    },
};


#[cfg(test)]
mod tests {

    use std::string;

    use super::*;

    fn get_homedir(name:&str) -> String {
        let home_dir = std::env::var("HOME").unwrap();

        return PathBuf::from(home_dir).join(format!("gnupg_test_{}/test_home", name)).to_string_lossy().to_string();
    }
    
    fn get_output_dir(name:&str) -> String {
        let home_dir = std::env::var("HOME").unwrap();

        return PathBuf::from(home_dir).join(format!("gnupg_test_{}/test_output", name)).to_string_lossy().to_string();
    }

    fn generate_random_string() -> String {
        let rng = thread_rng(); // Use the thread's random number generator
        let random_string: String = rng.sample_iter(&Alphanumeric) // Alphanumeric is a distribution of letters and digits
            .take(16) // Take 'length' characters
            .map(char::from) // Convert from u8 to char
            .collect(); // Collect into a String
        return random_string;
    }

    fn get_key_passphrass() -> String {
        // only for test, please use a strong passphrase for your own use case
        return String::from("test_passphrase_1");
    }

    fn get_gpg_init(name:&str) -> GPG {
        let gpg: Result<GPG, GPGError> = GPG::init(Some(get_homedir(name)), Some(get_output_dir(name) ), true);
        let gpg_unwrap: GPG = gpg.unwrap();
        return gpg_unwrap;
    }

    fn gen_protected_key(gpg:GPG){
        let _ = gpg.gen_key(Some(get_key_passphrass()), None);
    }

    fn gen_unprotected_key(gpg:GPG){
        let _ = gpg.gen_key(None, None);
    }

    fn list_keys(gpg:GPG, secret:bool, sig:bool) -> Vec<ListKeyResult> {
        let list_key_result:Result<Vec<ListKeyResult>, GPGError> = gpg.list_keys(secret, None, sig);
        let list_key_result_unwrap: Vec<ListKeyResult> = list_key_result.unwrap();
        return list_key_result_unwrap;
    }

    fn cleanup_after_tests(name:&str) {
        let home_dir = std::env::var("HOME").unwrap();
        let test_dir = PathBuf::from(home_dir).join(format!("gnupg_test_{}", name)).to_string_lossy().to_string();
    
        // Perform cleanup here
        if let Err(e) = remove_dir_all(test_dir) {
            println!("Error cleaning up: {}", e);
        } else {
            println!("Cleanup test directory {} completed successfully.", name);
        }
    }
    
    #[test]
    fn test_gnupg_init() {
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        assert_eq!(gpg.homedir, get_homedir(name));
        assert_eq!(gpg.output_dir, get_output_dir(name));

        cleanup_after_tests(name);
    }

    #[test]
    fn test_gnupg_gen_key_with_passphrase() {
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(Some(get_key_passphrass()), None);
        assert_eq!(result.unwrap().is_success(), true);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_gnupg_gen_key_no_passphrase() {
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, None);
        assert_eq!(result.unwrap().is_success(), true);
        cleanup_after_tests(name);
    }

    #[test]
    fn test_gnupg_gen_key_error_invalid_args() {
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let mut args: HashMap<String, String> = HashMap::new();
        args.insert("some".to_string(), "random".to_string());
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, Some(args));
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));

        cleanup_after_tests(name);
    }

    #[test]
    fn test_list_keys(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        assert_eq!(result.unwrap().len(), 1);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_list_keys_no_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        assert_eq!(result.unwrap().len(), 0);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_export_public_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        let key_list: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        let key_id: String = key_list[0].keyid.clone();
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_public_key(Some(vec![key_id]), Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_export_secret_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        let key_list: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let key_id: String = key_list[0].keyid.clone();
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_secret_key.sec.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_secret_key(Some(vec![key_id]), Some(get_key_passphrass()), Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_export_secret_key_no_passphrase(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        let key_list: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let key_id: String = key_list[0].keyid.clone();
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_secret_key.sec.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_secret_key(Some(vec![key_id]), None, Some(output.clone()));
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(Path::new(&output).exists(), false);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_export_partial_secret_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        gen_protected_key(gpg.clone());
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_secret_key.sec.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_secret_key(None, None, Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        cleanup_after_tests(name);
    }

    #[test] 
    fn test_export_key_no_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_public_key(None,Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), false);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_import_public_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);

        // create key in another homedir and export the key
        let other_homedir: String = PathBuf::from(get_homedir(name)).join("other_homedir").to_string_lossy().to_string();
        let other_gpg: Result<GPG, GPGError> = GPG::init(Some(other_homedir), Some(get_output_dir(name) ), true);
        let other_gpg: GPG = other_gpg.unwrap();
        gen_unprotected_key(other_gpg.clone());
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let _ = other_gpg.export_public_key(None, Some(output.clone()));
        assert_eq!(Path::new(&output).exists(), true);

        let result: Result<CmdResult, GPGError> = gpg.import_key(None, Some(output), false, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, false).len(), 1);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_import_secret_key(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);

        // create key in another homedir and export the key
        let other_homedir: String = PathBuf::from(get_homedir(name)).join("other_homedir").to_string_lossy().to_string();
        let other_gpg: Result<GPG, GPGError> = GPG::init(Some(other_homedir), Some(get_output_dir(name) ), true);
        let other_gpg: GPG = other_gpg.unwrap();
        gen_protected_key(other_gpg.clone());
        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_secret_key.asc").to_string_lossy().to_string();
        let _ = other_gpg.export_secret_key(None, Some(get_key_passphrass()), Some(output.clone()));
        assert_eq!(Path::new(&output).exists(), true);

        let result: Result<CmdResult, GPGError> = gpg.import_key(None, Some(output),  false, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, true, false).len(), 1);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_import_key_non_key_file(){
        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);

        // create a non key file 
        let mut file = tempfile().unwrap();
        writeln!(file, "testing as a non key file").unwrap();

        let result: Result<CmdResult, GPGError> = gpg.import_key(Some(file), None,  false, None);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(list_keys(gpg, true, false).len(), 0);

        cleanup_after_tests(name);
    }
}