pub mod gnupg;
pub mod utils;
pub mod process;


fn main() {
    let gpg = gnupg::GPG::new().unwrap();
    println!("{:?}", gpg);
}
