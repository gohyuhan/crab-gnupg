use std::{
    collections::HashMap,
    fs::{
        remove_dir_all,
        File
    },
    path::{
        PathBuf,
        Path
    },
    io::{Read, Write},
};

use tempfile::tempfile;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use crab_gnupg::{
    gnupg::{
        GPG,
        EncryptOption,
        DecryptOption,
        SignOption
    },
    utils::{
        errors::{GPGError, GPGErrorType},
        response::{CmdResult, ListKeyResult},
        enums::TrustLevel
    },
};


#[cfg(test)]
mod tests {

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

    fn gen_unprotected_key_with_subkeys(gpg:GPG){
        let mut args: HashMap<String, String> = HashMap::new();
        args.insert("Subkey-Type".to_string(), "RSA".to_string());
        args.insert("Subkey-Length".to_string(), "2048".to_string());
        let _ = gpg.gen_key(None, Some(args));
    }

    fn gen_protected_key_with_subkeys(gpg:GPG){
        let mut args: HashMap<String, String> = HashMap::new();
        args.insert("Subkey-Type".to_string(), "RSA".to_string());
        args.insert("Subkey-Length".to_string(), "2048".to_string());
        let _ = gpg.gen_key(Some(get_key_passphrass()), Some(args));
    }

    fn list_keys(gpg:GPG, secret:bool, sig:bool) -> Vec<ListKeyResult> {
        let list_key_result:Result<Vec<ListKeyResult>, GPGError> = gpg.list_keys(secret, None, sig);
        let list_key_result_unwrap: Vec<ListKeyResult> = list_key_result.unwrap();
        return list_key_result_unwrap;
    }

    fn gen_encrypt_default_option(file:File, recipients:Vec<String>, output:Option<String>) -> EncryptOption{
        let options: EncryptOption = EncryptOption::default(Some(file), None, recipients, output);
        return options;
    }

    fn gen_encrypt_symmetric_option(file:File, symmetric_algo: Option<String>, passphrase: String, output:Option<String>) -> EncryptOption{
        let options: EncryptOption = EncryptOption::with_symmetric(Some(file), None, symmetric_algo, passphrase, output);
        return options;
    }

    fn gen_encrypt_key_and_symmetric_option(file:File, recipients:Vec<String>, symmetric_algo: Option<String>, passphrase: String, output:Option<String>) -> EncryptOption{
        let options: EncryptOption = EncryptOption::with_key_and_symmetric(Some(file), None, Some(recipients), symmetric_algo, passphrase, output);
        return options;
    }

    fn gen_decrypt_default_option(file_path:String, recipients:String, key_passphrase: Option<String>, output:Option<String>) -> DecryptOption{
        let options: DecryptOption = DecryptOption::default(None, Some(file_path), recipients, key_passphrase, output);
        return options;
    }

    fn gen_decrypt_passphrase_option(file_path:String, passphrase: String, output:Option<String>) -> DecryptOption{
        let options: DecryptOption = DecryptOption::with_symmetric(None, Some(file_path), passphrase, output);
        return options;
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
        // test the init function of GPG

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        assert_eq!(gpg.homedir, get_homedir(name));
        assert_eq!(gpg.output_dir, get_output_dir(name));

        cleanup_after_tests(name);
    }

    #[test]
    fn test_gnupg_gen_key_with_passphrase() {
        // test the generate key with passphrase

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(Some(get_key_passphrass()), None);
        assert_eq!(result.unwrap().is_success(), true);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_gnupg_gen_key_no_passphrase() {
        // test the generate key without passphrase

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let result: Result<CmdResult, GPGError> = gpg.gen_key(None, None);
        assert_eq!(result.unwrap().is_success(), true);
        cleanup_after_tests(name);
    }

    #[test]
    fn test_gnupg_gen_key_error_invalid_args() {
        // test the generate key with invalid arguments

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
        // test the listing keys

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
        // test the listing keys while there were no keys in local gpg home directory

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        assert_eq!(result.unwrap().len(), 0);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_delete_keys(){
        // test deleting keys

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        let fingerprint: String = result.unwrap()[0].fingerprint.clone();

        let result:Result<CmdResult, GPGError>  = gpg.delete_keys(vec![fingerprint], false, false, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(gpg.list_keys(false, None, false).unwrap().len(), 0);
        assert_eq!(gpg.list_keys(true, None, false).unwrap().len(), 0);


        cleanup_after_tests(name);
    }

    #[test]
    fn test_delete_keys_secret_keys_only(){
        // test deleting secret keys only 

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(true, None, false);
        let fingerprint: String = result.unwrap()[0].fingerprint.clone();

        let result:Result<CmdResult, GPGError>  = gpg.delete_keys(vec![fingerprint], true, false, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(gpg.list_keys(false, None, false).unwrap().len(), 1);
        assert_eq!(gpg.list_keys(true, None, false).unwrap().len(), 0);


        cleanup_after_tests(name);
    }

    #[test]
    fn test_delete_keys_passphrase_protected_secret_keys_only(){
        // test deleting secret keys only ( pasphrase proctected )

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(true, None, false);
        let fingerprint: String = result.unwrap()[0].fingerprint.clone();

        let result:Result<CmdResult, GPGError>  = gpg.delete_keys(vec![fingerprint], true, false, Some(get_key_passphrass()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(gpg.list_keys(false, None, false).unwrap().len(), 1);
        assert_eq!(gpg.list_keys(true, None, false).unwrap().len(), 0);


        cleanup_after_tests(name);
    }

    #[test]
    fn test_delete_subkeys(){
        // test deleting subkeys

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key_with_subkeys(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(false, None, false);
        let fingerprint: String = result.unwrap()[0].subkeys[0].fingerprint.clone();
        assert_eq!(gpg.list_keys(false, None, false).unwrap()[0].subkeys.len(), 1);
        assert_eq!(gpg.list_keys(true, None, false).unwrap()[0].subkeys.len(), 1);

        let result:Result<CmdResult, GPGError>  = gpg.delete_keys(vec![fingerprint], false, true, None);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(gpg.list_keys(false, None, false).unwrap()[0].subkeys.len(), 0);
        assert_eq!(gpg.list_keys(true, None, false).unwrap()[0].subkeys.len(), 0);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_delete_keys_not_found_fingerprint(){
        // test deleting with fingerprint not found in local

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        let result:Result<Vec<ListKeyResult>, GPGError>  = gpg.list_keys(true, None, false);
        let mut fingerprint: String = result.unwrap()[0].fingerprint.clone();

        if let Some(char) = fingerprint.pop(){
            if char == '1'{
                fingerprint.push('2');
            }else{
                fingerprint.push('1');
            }
        }

        let result:Result<CmdResult, GPGError>  = gpg.delete_keys(vec![fingerprint], false, false, None);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(gpg.list_keys(false, None, false).unwrap().len(), 1);
        assert_eq!(gpg.list_keys(true, None, false).unwrap().len(), 1);


        cleanup_after_tests(name);
    }

    
    #[test]
    fn test_export_public_key(){
        // test exporting the public key

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
        // test exporting the secretkey

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
        // test exporting passphrase protected seceret key without passphrase

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
        // test exporting passphrase protected seceret key without passphrase together with unprotected seceret key
        // this will still result in a success as the export will be done for the unprotected key

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
        // test exporting keys but there are no keys in local gpg home directory

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
    fn test_export_key_wrong_key_id(){
        // test exporting keys if all the keyid(s) provided were incorrect

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        let mut keyid: String = result[0].keyid.clone();

        if let Some(char) = keyid.pop() {
            if char as u8 == 1{
                keyid.push('0');
            } else {
                keyid.push('1');
            }
        }

        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_public_key(Some(vec![keyid]),Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), false);

        cleanup_after_tests(name);
    }

    #[test] 
    fn test_export_key_partial_wrong_key_id(){
        // test exporting keys if some of the keyid(s) provided were incorrect

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());
        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        let mut keyid: String = result[0].keyid.clone();

        if let Some(char) = keyid.pop() {
            if char as u8 == 1{
                keyid.push('0');
            } else {
                keyid.push('1');
            }
        }

        let output: String = PathBuf::from(get_output_dir(name)).join("test_export_public_key.asc").to_string_lossy().to_string();
        let result: Result<CmdResult, GPGError> = gpg.export_public_key(Some(vec![keyid, result[1].keyid.clone()]),Some(output.clone()));
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        cleanup_after_tests(name);
    }

    #[test]
    fn test_import_public_key(){
        // test importing public key

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
        // test importing secret key

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
        // test importing key with a non key file

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

    #[test]
    fn test_trust_key(){
        // test setting ownertrust for key

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        assert_eq!(result[0].ownertrust, "u".to_string());

        let result: Result<CmdResult, GPGError> = gpg.trust_key(vec![result[0].fingerprint.clone()], TrustLevel::Fully);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, false)[0].ownertrust, "f".to_string());

        cleanup_after_tests(name);
    }

    #[test]
    fn test_trust_key_invalid_fingerprint(){
        // test setting ownertrust for key with invalid fingerprint

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        assert_eq!(result[0].ownertrust, "u".to_string());

        let result: Result<CmdResult, GPGError> = gpg.trust_key(vec![format!("{}123", result[0].fingerprint)], TrustLevel::Fully);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(list_keys(gpg, false, false)[0].ownertrust, "u".to_string());

        cleanup_after_tests(name);
    }

    #[test]
    fn test_trust_key_not_found_fingerprint(){
        // test setting ownertrust for key with a valid fingerprint that doesn't exist in the local home directory

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), false, false);
        assert_eq!(result[0].ownertrust, "u".to_string());

        // change the fingerprint into another valid format of fingerprint that doesn't exist in the local
        let mut fingerprint: String = result[0].fingerprint.clone();

        if let Some(char) = fingerprint.pop() {
            if char as u8 == 1{
                fingerprint.push('0');
            } else {
                fingerprint.push('1');
            }
        }

        let result: Result<CmdResult, GPGError> = gpg.trust_key(vec![fingerprint], TrustLevel::Fully);
        // although the fingerprint is not found in local, the gpg process will still return success
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, false)[0].ownertrust, "u".to_string());

        cleanup_after_tests(name);
    }

    #[test]
    fn test_sign_key(){
        // test signing key

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);

        let result: Result<CmdResult, GPGError> = gpg.sign_key(
            result[0].keyid.clone(), 
            result[1].keyid.clone(), 
            None, 
            None
        );
        
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, true)[1].sigs.len(), 2);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_sign_default_key_wrong_keyid(){
        // test signing key ( signing default key with another key )

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let mut keyid: String = result[1].keyid.clone();

        if let Some(char) = keyid.pop() {
            if char as u8 == 1{
                keyid.push('0');
            } else {
                keyid.push('1');
            }
        }
        
        let result: Result<CmdResult, GPGError> = gpg.sign_key(
            keyid, 
            result[0].keyid.clone(), 
            None, 
            None
        );
        
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, true)[0].sigs.len(), 1);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_sign_key_wrong_keyid(){
        // test signing key
        // if the keyid is not found, it will default to use the first key gpg found

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_unprotected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let mut keyid: String = result[0].keyid.clone();

        if let Some(char) = keyid.pop() {
            if char as u8 == 1{
                keyid.push('0');
            } else {
                keyid.push('1');
            }
        }
        
        let result: Result<CmdResult, GPGError> = gpg.sign_key(
            keyid, 
            result[1].keyid.clone(), 
            None, 
            None
        );
        
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, true)[1].sigs.len(), 2);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_sign_key_with_passphrase_protected_key(){
        // test signing key with passphrase proctected key
        // gpg signing use private key

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        
        let result: Result<CmdResult, GPGError> = gpg.sign_key(
            result[0].keyid.clone(), 
            result[1].keyid.clone(), 
            Some(get_key_passphrass()), 
            None
        );
        
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(list_keys(gpg, false, true)[1].sigs.len(), 2);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_sign_key_with_passphrase_protected_key_wrong_passphrase(){
        // test signing key with passphrase proctected key with wrong passphrase
        // gpg signing use private key

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        
        let result: Result<CmdResult, GPGError> = gpg.sign_key(
            result[0].keyid.clone(), 
            result[1].keyid.clone(), 
            Some("wrong-passphrase".to_string()), 
            None
        );
        
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(list_keys(gpg, false, true)[1].sigs.len(), 1);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_sign_key_with_passphrase_protected_key_no_passphrase(){
        // test signing key with passphrase proctected key without providing passphrase
        // gpg signing use private key

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());
        gen_unprotected_key(gpg.clone());

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        
        let result: Result<CmdResult, GPGError> = gpg.sign_key(
            result[0].keyid.clone(), 
            result[1].keyid.clone(), 
            None, 
            None
        );
        
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(list_keys(gpg, false, true)[1].sigs.len(), 1);
    
        cleanup_after_tests(name);
    }

    
    #[test]
    fn test_encrypt_file(){
        // test encrypting file with just key (default)

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        writeln!(file, "testing encryption").unwrap();
        file.flush().unwrap();

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_default_option(file, vec![result[0].keyid.clone()], Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_encrypt_file_symmetric(){
        // test encrypting file with just passphrase (symmetric)

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        writeln!(file, "testing encryption").unwrap();
        file.flush().unwrap();

        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_symmetric_option(file, None, "1234".to_string(), Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_encrypt_file_key_and_symmetric(){
        // test encrypting file with both key and passphrase (key and symmetric)

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        writeln!(file, "testing encryption").unwrap();
        file.flush().unwrap();

        let result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_key_and_symmetric_option(file, vec![result[0].keyid.clone()], None, "1234".to_string(), Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_encrypt_file_default_fail_no_receipient(){
        // test encrypting file with just key (default) but without providing recipient (list of key id)

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        writeln!(file, "testing encryption").unwrap();
        file.flush().unwrap();

        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = EncryptOption{
            file: Some(file),
            file_path: None,
            recipients: None,
            sign: false,
            sign_key: None,
            symmetric: false,
            symmetric_algo: None,
            always_trust: true,
            passphrase: None,
            output: Some(output.clone()),
            extra_args: None,
        };

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::InvalidArgumentError(_)));
        assert_eq!(Path::new(&output).exists(), false);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_encrypt_file_symmetric_fail_no_passphrase(){
        // test encrypting file with just passphrase (symmetric) but without providing passphrase

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        writeln!(file, "testing encryption").unwrap();
        file.flush().unwrap();

        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = EncryptOption{
            file: Some(file),
            file_path: None,
            recipients: None,
            sign: false,
            sign_key: None,
            symmetric: false,
            symmetric_algo: None,
            always_trust: true,
            passphrase: None,
            output: Some(output.clone()),
            extra_args: None,
        };

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::InvalidArgumentError(_)));
        assert_eq!(Path::new(&output).exists(), false);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_encrypt_file_key_and_symmetric_fail_no_passphrase(){
        // test encrypting file with both key and passphrase (symmetric) but without providing both

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        writeln!(file, "testing encryption").unwrap();
        file.flush().unwrap();

        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = EncryptOption{
            file: Some(file),
            file_path: None,
            recipients: None,
            sign: false,
            sign_key: None,
            symmetric: false,
            symmetric_algo: None,
            always_trust: true,
            passphrase: None,
            output: Some(output.clone()),
            extra_args: None,
        };

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::InvalidArgumentError(_)));
        assert_eq!(Path::new(&output).exists(), false);
    
        cleanup_after_tests(name);
    }

    #[test]
    fn test_decrypt_file_with_key(){
        // test decrypting file with key

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        write!(file, "testing decryption").unwrap();
        file.flush().unwrap();

        let key_result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_default_option(file, vec![key_result[0].keyid.clone()], Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        let decrypt_output: String = PathBuf::from(get_output_dir(name)).join("test_decrypt.txt").to_string_lossy().to_string();
        let option = gen_decrypt_default_option(output, key_result[0].keyid.clone(), Some(get_key_passphrass()), Some(decrypt_output.clone()));
        let result = gpg.decrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&decrypt_output).exists(), true);

        let mut decrypt_file: File = File::open(&decrypt_output).unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        decrypt_file.read_to_end(&mut buffer).unwrap();
        assert_eq!(String::from_utf8_lossy(&buffer), "testing decryption");

        cleanup_after_tests(name);
    }

    #[test]
    fn test_decrypt_file_with_passphrase(){
        // test decrypting file with passphrase

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        write!(file, "testing decryption").unwrap();
        file.flush().unwrap();

        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_symmetric_option(file, None, "1234".to_string(), Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        let decrypt_output: String = PathBuf::from(get_output_dir(name)).join("test_decrypt.txt").to_string_lossy().to_string();
        let option = gen_decrypt_passphrase_option(output, "1234".to_string(), Some(decrypt_output.clone()));
        let result = gpg.decrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&decrypt_output).exists(), true);

        let mut decrypt_file: File = File::open(&decrypt_output).unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        decrypt_file.read_to_end(&mut buffer).unwrap();
        assert_eq!(String::from_utf8_lossy(&buffer), "testing decryption");

        cleanup_after_tests(name);
    }

    #[test]
    fn test_decrypt_file_with_passphrase_or_key(){
        // test decrypting file with passphrase

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        write!(file, "testing decryption").unwrap();
        file.flush().unwrap();

        let key_result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_key_and_symmetric_option(file, vec![key_result[0].keyid.clone()],None, "1234".to_string(), Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        let decrypt_output: String = PathBuf::from(get_output_dir(name)).join("test_decrypt.txt").to_string_lossy().to_string();
        // decrypt with key
        let option = gen_decrypt_default_option(output.clone(), key_result[0].keyid.clone(), Some(get_key_passphrass()), Some(decrypt_output.clone()));
        let result = gpg.decrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&decrypt_output).exists(), true);

        let mut decrypt_file: File = File::open(&decrypt_output).unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        decrypt_file.read_to_end(&mut buffer).unwrap();
        assert_eq!(String::from_utf8_lossy(&buffer), "testing decryption");

        // decrypt with passphrase
        let option = gen_decrypt_passphrase_option(output, "1234".to_string(), Some(decrypt_output.clone()));
        let result = gpg.decrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&decrypt_output).exists(), true);

        let mut decrypt_file: File = File::open(&decrypt_output).unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        decrypt_file.read_to_end(&mut buffer).unwrap();
        assert_eq!(String::from_utf8_lossy(&buffer), "testing decryption");

        cleanup_after_tests(name);
    }

    #[test]
    fn test_decrypt_file_with_passphrase_or_key_fail(){
        // test decrypting file with passphrase

        let name:String  = generate_random_string();
        let name: &str = name.as_str();

        let gpg: GPG = get_gpg_init(name);
        gen_protected_key(gpg.clone());

        let mut file = tempfile().unwrap();
        write!(file, "testing decryption").unwrap();
        file.flush().unwrap();

        let key_result: Vec<ListKeyResult> = list_keys(gpg.clone(), true, false);
        let output: String = PathBuf::from(get_output_dir(name)).join("test_encrypt.txt").to_string_lossy().to_string();
        let option = gen_encrypt_key_and_symmetric_option(file, vec![key_result[0].keyid.clone()],None, "1234".to_string(), Some(output.clone()));

        let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
        assert_eq!(result.unwrap().is_success(), true);
        assert_eq!(Path::new(&output).exists(), true);

        let decrypt_output: String = PathBuf::from(get_output_dir(name)).join("test_decrypt.txt").to_string_lossy().to_string();
        // decrypt with key, but didn't provide key passphrase
        let option = gen_decrypt_default_option(output.clone(), key_result[0].keyid.clone(), None, Some(decrypt_output.clone()));
        let result = gpg.decrypt(option);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(Path::new(&decrypt_output).exists(), false);

        // decrypt with passphrase, but wrong passphrase
        let option = gen_decrypt_passphrase_option(output, "123".to_string(), Some(decrypt_output.clone()));
        let result = gpg.decrypt(option);
        assert!(matches!(result.unwrap_err().error_type, GPGErrorType::GPGProcessError(_)));
        assert_eq!(Path::new(&decrypt_output).exists(), false);

        cleanup_after_tests(name);
    }
}