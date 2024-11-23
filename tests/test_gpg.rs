use std::{
    collections::HashMap,
    fs::remove_dir_all,
    path::PathBuf
};

use crab_gnupg::{
    gnupg::GPG,
    utils::{
        errors::GPGError,
        response::CmdResult
    },
};


#[cfg(test)]
mod tests {


    use crab_gnupg::utils::errors::GPGErrorType;

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
        return String::from("test_passphrase_1".to_string());
    }

    fn get_gpg_init(num:u8) -> GPG {
        let gpg: Result<GPG, GPGError> = GPG::init(Some(get_homedir(num)), Some(get_output_dir(num) ), true);
        let gpg_unwrap: GPG = gpg.unwrap();
        return gpg_unwrap;
    }

    fn test_cleanup_after_tests(num:u8) {
        let home_dir = std::env::var("HOME").unwrap();
        let test_dir = PathBuf::from(home_dir).join(format!("gnupg_test_{}", num)).to_string_lossy().to_string();
    
        // Perform cleanup here
        if let Err(e) = remove_dir_all(test_dir) {
            println!("Error cleaning up: {}", e);
        } else {
            println!("Cleanup test directory completed successfully.");
        }
    }
    
    #[test]
    fn test_1_gnupg_init() {
        let gpg: GPG = get_gpg_init(1);
        assert_eq!(gpg.homedir, get_homedir(1));
        assert_eq!(gpg.output_dir, get_output_dir(1));
        test_cleanup_after_tests(1);
    }

    #[test]
    fn test_2_gnupg_gen_key_with_passphrase() {
        let gpg: GPG = get_gpg_init(2);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(Some(get_key_passphrass()), None);
        assert_eq!(result.unwrap().is_success(), true);
        test_cleanup_after_tests(2);
    }

    #[test]
    fn test_3_gnupg_gen_key_no_passphrase() {
        let gpg: GPG = get_gpg_init(3);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, None);
        assert_eq!(result.unwrap().is_success(), true);
        test_cleanup_after_tests(3);
    }

    #[test]
    fn test_4_gnupg_gen_key_error_invalid_args() {
        let gpg: GPG = get_gpg_init(4);
        let mut args: HashMap<String, String> = HashMap::new();
        args.insert("some".to_string(), "random".to_string());
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, Some(args));
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        test_cleanup_after_tests(4);
    }
}