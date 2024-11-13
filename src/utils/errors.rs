use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum GPGError {
    HomedirError(String),
    OutputDirError(String),
    GPGNotFoundError(String),
    FailedToStartProcess(String),
    FailedToRetrieveChildProcess(String),
    WriterFailError(String),
}

impl Display for GPGError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GPGError::HomedirError(err) => write!(f, "[HomedirError] {}", err),
            GPGError::OutputDirError(err) => write!(f, "[OutputDirError] {}", err),
            GPGError::GPGNotFoundError(err) => write!(f, "[GPGNotFoundError] {}", err),
            GPGError::FailedToStartProcess(err) => write!(f, "[FailedToStartProcess] {}", err),
            GPGError::FailedToRetrieveChildProcess(err) => {
                write!(f, "[FailedToRetrieveChildProcess] {}", err)
            }
            GPGError::WriterFailError(err) => write!(f, "[WriterFailError] {}", err),
        }
    }
}
