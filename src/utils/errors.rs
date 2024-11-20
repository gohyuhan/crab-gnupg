use std::fmt::{Display, Formatter};

use super::response::CmdResult;

#[derive(Debug)]
#[allow(dead_code)]
pub struct GPGError {
    // the type of error
    error_type: GPGErrorType,
    // provide more insight if error occured during the gpg cmd process
    cmd_result: Option<CmdResult>,
}

impl GPGError {
    pub fn new(error_type: GPGErrorType, cmd_result: Option<CmdResult>) -> GPGError {
        return GPGError {
            error_type,
            cmd_result,
        };
    }
}

#[derive(Debug)]
pub enum GPGErrorType {
    HomedirError(String),
    OutputDirError(String),
    GPGInitError(String),
    GPGNotFoundError(String),
    GPGProcessError(String),
    InvalidArgumentError(String),
    FailedToStartProcess(String),
    FailedToRetrieveChildProcess(String),
    WriteFailError(String),
    ReadFailError(String),
    PassphraseError(String),
    FileNotFoundError(String),
    FileNotProvidedError(String),
}

impl Display for GPGErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GPGErrorType::HomedirError(err) => write!(f, "[HomedirError] {}", err),
            GPGErrorType::OutputDirError(err) => write!(f, "[OutputDirError] {}", err),
            GPGErrorType::GPGInitError(err) => write!(f, "[GPGInitError] {}", err),
            GPGErrorType::GPGNotFoundError(err) => write!(f, "[GPGNotFoundError] {}", err),
            GPGErrorType::GPGProcessError(err) => write!(f, "[GPGProcessError] {}", err),
            GPGErrorType::InvalidArgumentError(err) => write!(f, "[InvalidArgumentError] {}", err),
            GPGErrorType::FailedToStartProcess(err) => write!(f, "[FailedToStartProcess] {}", err),
            GPGErrorType::FailedToRetrieveChildProcess(err) => {
                write!(f, "[FailedToRetrieveChildProcess] {}", err)
            }
            GPGErrorType::WriteFailError(err) => write!(f, "[WriteFailError] {}", err),
            GPGErrorType::ReadFailError(err) => write!(f, "[ReadFailError] {}", err),
            GPGErrorType::PassphraseError(err) => write!(f, "[PassphraseError] {}", err),
            GPGErrorType::FileNotFoundError(err) => write!(f, "[FileNotFoundError] {}", err),
            GPGErrorType::FileNotProvidedError(err) => write!(f, "[FileNotProvidedError] {}", err),
        }
    }
}
