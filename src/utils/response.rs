use std::fmt::{Display, Formatter};

/// a result handler for command process output/error result
#[derive(Debug)]
pub struct CmdResult {
    raw_data: Option<String>,
    return_code: Option<i32>,
    status: Option<String>,
    status_message: Option<String>,
    operation: Operation,
}

impl CmdResult {
    pub fn init(ops: Operation) -> CmdResult {
        CmdResult {
            raw_data: None,
            return_code: None,
            status: None,
            status_message: None,
            operation: ops,
        }
    }

    pub fn set_raw_data(&mut self, raw_data: String) {
        self.raw_data = Some(raw_data);
    }

    pub fn get_raw_data(&self) -> &Option<String> {
        return &self.raw_data;
    }

    pub fn handle_status(&mut self, keyword: String, value: String) {
        self.status = Some(keyword);
        self.status_message = Some(value);
    }

    pub fn set_return_code(&mut self, return_code: i32) {
        self.return_code = Some(return_code);
    }
}

#[derive(Debug)]
pub enum Operation {
    Verify,
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Verify => write!(f, "Verify"),
        }
    }
}

#[derive(Debug)]
pub enum ResultError {
    NotFoundError,
}

impl Display for ResultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultError::NotFoundError => write!(f, "Not Found"),
        }
    }
}
