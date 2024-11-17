pub mod gnupg;
pub mod process;
pub mod utils;

fn main() {
    let gpg = match gnupg::GPG::init(None, None) {
        Ok(gpg) => gpg,
        Err(_) => {
            return;
        }
    };
    println!("{:?}", gpg);

    // NOTE:  GENERATE KEY

    // use std::collections::HashMap;
    // let passphrase = None;
    // let mut args: HashMap<String, String> = HashMap::new();
    // args.insert("Key-Typesssds".to_string(), "RweweSA".to_string());
    // args.insert("Subkey-Type".to_string(), "DSA".to_string());
    // args.insert("Subkey-Length".to_string(), "DSA".to_string());
    // let result = gpg.gen_key(args, passphrase);
    // println!("{:?}", result);

    // NOTE:  LIST KEYS

    // let result = gpg.list_keys(false, None, false);
    // println!("{:?}", result.unwrap());
    // println!("GPG:  {:?}", gpg);

    // NOTE:  ENCRYPT

    let result = gpg.encrypt(
        None,
        Some("/Users/gohyuhan/crab-gnupg/test.txt".to_string()),
        Some(vec![
            "D6DD040DBA05F474".to_string(),
            "E6FC15EB4B28E6B6".to_string(),
        ]),
        false,
        // Some("D6DD040DBA05F474".to_string()),
        None,
        false,
        None,
        true,
        None,
        false,
        None,
        None,
    );
    println!("{:?}", result);
}
