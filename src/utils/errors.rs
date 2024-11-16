use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum GPGError {
    HomedirError(String),
    OutputDirError(String),
    GPGInitError(String),
    GPGNotFoundError(String),
    GPGProcessError(String),
    FailedToStartProcess(String),
    FailedToRetrieveChildProcess(String),
    WriteFailError(String),
    ReadFailError(String),
    PassphraseError(String),
    FileNotFoundError(String),
    FileNotProvidedError(String),
}

impl Display for GPGError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GPGError::HomedirError(err) => write!(f, "[HomedirError] {}", err),
            GPGError::OutputDirError(err) => write!(f, "[OutputDirError] {}", err),
            GPGError::GPGInitError(err) => write!(f, "[GPGInitError] {}", err),
            GPGError::GPGNotFoundError(err) => write!(f, "[GPGNotFoundError] {}", err),
            GPGError::GPGProcessError(err) => write!(f, "[GPGProcessError] {}", err),
            GPGError::FailedToStartProcess(err) => write!(f, "[FailedToStartProcess] {}", err),
            GPGError::FailedToRetrieveChildProcess(err) => {
                write!(f, "[FailedToRetrieveChildProcess] {}", err)
            }
            GPGError::WriteFailError(err) => write!(f, "[WriteFailError] {}", err),
            GPGError::ReadFailError(err) => write!(f, "[ReadFailError] {}", err),
            GPGError::PassphraseError(err) => write!(f, "[PassphraseError] {}", err),
            GPGError::FileNotFoundError(err) => write!(f, "[FileNotFoundError] {}", err),
            GPGError::FileNotProvidedError(err) => write!(f, "[FileNotProvidedError] {}", err),
        }
    }
}
