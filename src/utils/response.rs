use std::fmt::{Display, Formatter};

/// a result handler for command process output/error result
pub struct CmdResult{
    raw_data: Option<String>,
    return_code: Option<u8>,
    status: Option<String>,
    status_message:Option<String>,
    operation:Operation
}

impl CmdResult {
    pub fn init(ops:Operation) -> CmdResult{
        CmdResult{
            raw_data: None,
            return_code: None,
            status: None,
            status_message: None,
            operation: ops
        }
    }
}

#[derive(Debug)]
pub enum Operation{
    Verify,
}

impl Display for Operation{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Verify => write!(f, "Verify"),
        }
    }
}

#[derive(Debug)]
pub enum ResultError{
    NotFoundError,
}

impl Display for ResultError{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultError::NotFoundError => write!(f, "Not Found"),
        }
    }
}