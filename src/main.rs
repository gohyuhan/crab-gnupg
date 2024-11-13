use std::env;

pub mod gnupg;
pub mod process;
pub mod utils;

fn main() {
    let gpg = match gnupg::GPG::new() {
        Ok(gpg) => gpg,
        Err(_) => {
            return;
        }
    };
    println!("{:?}", utils::utils::get_system_encoding().unwrap());
    println!("{:?}", gpg);
}
