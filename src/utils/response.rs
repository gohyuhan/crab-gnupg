use std::fmt::{Display, Formatter};

/// a result handler for command process output/error result
#[derive(Debug)]
pub struct CmdResult {
    raw_data: Option<String>,
    return_code: Option<i32>,
    status: Option<String>,
    status_message: Option<String>,
    operation: Operation,
    debug_log: Option<Vec<String>>,
    problem: Option<Vec<String>>,
}

impl CmdResult {
    pub fn init(ops: Operation) -> CmdResult {
        CmdResult {
            raw_data: None,
            return_code: None,
            status: None,
            status_message: None,
            operation: ops,
            debug_log: None,
            problem: None,
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

    pub fn capture_debug_log(&mut self, debug_log: String) {
        if self.debug_log.is_none() {
            self.debug_log = Some(vec![debug_log]);
        } else {
            self.debug_log.as_mut().unwrap().push(debug_log);
        }
    }
}

#[derive(Debug)]
pub enum Operation {
    Verify,
    GenerateKey,
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Verify => write!(f, "Verify"),
            Operation::GenerateKey => write!(f, "GenerateKey"),
        }
    }
}
