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
    // args.insert("Key-Type".to_string(), "DSA".to_string());
    // let result = gpg.gen_key(args, passphrase);
    // println!("{:?}", result);


    // NOTE:  LIST KEYS

    let result = gpg.list_keys(false, None, false);
    println!("{:?}", result);
}
