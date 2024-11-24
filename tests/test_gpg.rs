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

use crab_gnupg::{
    gnupg::GPG,
    utils::{
        errors::{GPGError, GPGErrorType},
        response::{CmdResult, ListKeyResult}
    },
};


#[cfg(test)]
mod tests {

    use super::*;

    fn get_homedir(num:u8) -> String {
        let home_dir = std::env::var("HOME").unwrap();

        return PathBuf::from(home_dir).join(format!("gnupg_test_{}/test_home", num)).to_string_lossy().to_string();
    }
    
    fn get_output_dir(num:u8) -> String {
        let home_dir = std::env::var("HOME").unwrap();

        return PathBuf::from(home_dir).join(format!("gnupg_test_{}/test_output", num)).to_string_lossy().to_string();
    }

    fn get_key_passphrass() -> String {
        // only for test, please use a strong passphrase for your own use case
        return String::from("test_passphrase_1");
    }

    fn get_gpg_init(num:u8) -> GPG {
        let gpg: Result<GPG, GPGError> = GPG::init(Some(get_homedir(num)), Some(get_output_dir(num) ), true);
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

    fn cleanup_after_tests(num:u8) {
        let home_dir = std::env::var("HOME").unwrap();
        let test_dir = PathBuf::from(home_dir).join(format!("gnupg_test_{}", num)).to_string_lossy().to_string();
    
        // Perform cleanup here
        if let Err(e) = remove_dir_all(test_dir) {
            println!("Error cleaning up: {}", e);
        } else {
            println!("Cleanup test directory {} completed successfully.", num);
        }
    }
    
    #[test]
    fn test_1_gnupg_init() {
        let gpg: GPG = get_gpg_init(1);
        assert_eq!(gpg.homedir, get_homedir(1));
        assert_eq!(gpg.output_dir, get_output_dir(1));

        cleanup_after_tests(1);
    }

    #[test]
    fn test_2_gnupg_gen_key_with_passphrase() {
        let gpg: GPG = get_gpg_init(2);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(Some(get_key_passphrass()), None);
        assert_eq!(result.unwrap().is_success(), true);

        cleanup_after_tests(2);
    }

    #[test]
    fn test_3_gnupg_gen_key_no_passphrase() {
        let gpg: GPG = get_gpg_init(3);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, None);
        assert_eq!(result.unwrap().is_success(), true);
        cleanup_after_tests(3);
    }

    #[test]
    fn test_4_gnupg_gen_key_error_invalid_args() {
        let gpg: GPG = get_gpg_init(4);
        let mut args: HashMap<String, String> = HashMap::new();
        args.insert("some".to_string(), "random".to_string());
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, Some(args));
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));

        cleanup_after_tests(4);
    }

    #[test]
    fn test_5_list_keys(){
        let gpg: GPG = get_gpg_init(5);
        gen_protected_key(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        assert_eq!(result.unwrap().len(), 1);

        cleanup_after_tests(5);
    }

    #[test]
    fn test_6_list_keys_no_key(){
        let gpg: GPG = get_gpg_init(6);
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        assert_eq!(result.unwrap().len(), 0);

        cleanup_after_tests(6);
    }

    #[test]
    fn test_7_export_public_key(){
        let gpg: GPG = get_gpg_init(7);
        gen_unprotected_key(gpg.clone());
        let key_list: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        let key_id: String = key_list[0].keyid.clone();
        let output: String = PathBuf::from(get_output_dir(7)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_public_key(Some(vec![key_id]), Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        cleanup_after_tests(7);
    }

    #[test]
    fn test_8_export_secret_key(){
        let gpg: GPG = get_gpg_init(8);
        gen_protected_key(gpg.clone());
        let key_list: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let key_id: String = key_list[0].keyid.clone();
        let output: String = PathBuf::from(get_output_dir(8)).join("test_export_secret_key.sec.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_secret_key(Some(vec![key_id]), Some(get_key_passphrass()), Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        cleanup_after_tests(8);
    }

    #[test]
    fn test_9_export_secret_key_no_passphrase(){
        let gpg: GPG = get_gpg_init(9);
        gen_protected_key(gpg.clone());
        let key_list: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let key_id: String = key_list[0].keyid.clone();
        let output: String = PathBuf::from(get_output_dir(9)).join("test_export_secret_key.sec.asc").to_string_lossy().to_string();
        let _: Result<CmdResult, GPGError> = gpg.export_secret_key(Some(vec![key_id]), None, Some(output.clone()));

        assert_eq!(Path::new(&output).exists(), false);

        cleanup_after_tests(9);
    }

    #[test] 
    fn test_10_export_key_no_key(){
        let gpg: GPG = get_gpg_init(10);
        let output: String = PathBuf::from(get_output_dir(10)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_public_key(None,Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), false);

        cleanup_after_tests(10);
    }

    #[test]
    fn test_11_import_public_key(){
        let gpg: GPG = get_gpg_init(11);

        // create key in another homedir and export the key
        let other_homedir: String = PathBuf::from(get_homedir(11)).join("other_homedir").to_string_lossy().to_string();
        let other_gpg: Result<GPG, GPGError> = GPG::init(Some(other_homedir), Some(get_output_dir(11) ), true);
        let other_gpg: GPG = other_gpg.unwrap();
        gen_unprotected_key(other_gpg.clone());
        let output: String = PathBuf::from(get_output_dir(11)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let _ = other_gpg.export_public_key(None, Some(output.clone()));
        assert_eq!(Path::new(&output).exists(), true);

        let result: Result<CmdResult, GPGError> = gpg.import_key(None, Some(output), false, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, false).len(), 1);

        cleanup_after_tests(11);
    }

    #[test]
    fn test_12_import_secret_key(){
        let gpg: GPG = get_gpg_init(12);

        // create key in another homedir and export the key
        let other_homedir: String = PathBuf::from(get_homedir(12)).join("other_homedir").to_string_lossy().to_string();
        let other_gpg: Result<GPG, GPGError> = GPG::init(Some(other_homedir), Some(get_output_dir(12) ), true);
        let other_gpg: GPG = other_gpg.unwrap();
        gen_protected_key(other_gpg.clone());
        let output: String = PathBuf::from(get_output_dir(12)).join("test_export_secret_key.asc").to_string_lossy().to_string();
        let _ = other_gpg.export_secret_key(None, Some(get_key_passphrass()), Some(output.clone()));
        assert_eq!(Path::new(&output).exists(), true);

        let result: Result<CmdResult, GPGError> = gpg.import_key(None, Some(output),  false, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, true, false).len(), 1);

        cleanup_after_tests(12);
    }

    #[test]
    fn test_13_import_key_non_key_file(){
        let gpg: GPG = get_gpg_init(13);

        // create a non key file 
        let mut file = tempfile().unwrap();
        writeln!(file, "testing as a non key file").unwrap();

        let result: Result<CmdResult, GPGError> = gpg.import_key(Some(file), None,  false, None);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(list_keys(gpg, true, false).len(), 0);

        cleanup_after_tests(13);
    }
}