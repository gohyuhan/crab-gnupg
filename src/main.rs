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

    let result = gpg.list_keys(true, None, false);
    println!("GPG:  {:?}", gpg);

    let key_id: String = result.unwrap()[0].keyid.clone();
    // NOTE:  ENCRYPT

    let result = gpg.encrypt(
        None,
        Some("/Users/gohyuhan/gnupg/output/test.txt".to_string()),
        Some(vec![key_id.clone()]),
        true,
        Some(key_id.clone()),
        true,
        None,
        true,
        Some("1234".to_string()),
        true,
        Some("/Users/gohyuhan/gnupg/output/encrypted.txt".to_string()),
        None,
    );
    println!("{:?}", result);

    // NOTE:  DECRYPT

    let result = gpg.decrypt(
        None,
        Some("/Users/gohyuhan/gnupg/output/encrypted.txt".to_string()),
        Some(key_id),
        false,
        Some("1234".to_string()),
        Some("/Users/gohyuhan/gnupg/output/decrypted.txt".to_string()),
        None,
    );
    println!("{:?}", result);
}
