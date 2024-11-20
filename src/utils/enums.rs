use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub enum Operation {
    NotSet,
    Verify, // this means verify if gpg was installed and is working, gpg operation verify file was under another naming
    GenerateKey,
    ListKey,
    SearchKey,
    Encrypt,
    Decrypt,
    Sign
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::NotSet => write!(f, "NotSet"),
            Operation::Verify => write!(f, "Verify"),
            Operation::GenerateKey => write!(f, "GenerateKey"),
            Operation::ListKey => write!(f, "ListKey"),
            Operation::SearchKey => write!(f, "SearchKey"),
            Operation::Encrypt => write!(f, "Encrypt"),
            Operation::Decrypt => write!(f, "Decrypt"),
            Operation::Sign => write!(f, "Sign"),
        }
    }
}
