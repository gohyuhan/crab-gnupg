pub mod gnupg;
pub mod process;
pub mod utils;

fn main(){

    let gpg = gnupg::GPG::init(None, None, true).unwrap();
    let keylist = gpg.list_keys(false, None, false);
    println!("{:?}", keylist);
}