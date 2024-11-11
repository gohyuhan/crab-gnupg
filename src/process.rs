use std::{collections::HashMap, io::Error, process::{Command, Stdio, Child, ChildStdin}};

use tokio::runtime::{Builder, Runtime};
use crate::utils::response::CmdResult;

/// generate a list of arguments to be passed to gpg process
fn generate_cmd_args(
    cmd_args:Option<Vec<String>>, 
    passphrase:Option<String>,
    version:f32,
    homedir:String,
    use_agent:bool,
    options:Option<Vec<String>>
) ->  Vec<String>{
    // cmd_args: a list of arguments to be passed to gpg
    // passphrase: whether the next operation need a passphrase to be passed
    // version: version of gpg
    // homedir: the homedir of gpg
    // use_agent: whether to use gpg-agent
    // options: additional options to be passed to gpg, obtained in GPG object

    let mut args:Vec<String> = vec![
        "gpg".to_string(), 
        "--status-fd".to_string(), 
        "2".to_string(), 
        "--no-tty".to_string(), 
        "--no-verbose".to_string(), 
        "--homedir".to_string()
    ];
    if passphrase.is_some() && version>=2.1{
        args.insert(1, "--pinentry-mode".to_string());
        args.insert(2, "loopback".to_string());
    }
    args.push(homedir);
    /// TODO: add keyring and secret keyring support
    
    if passphrase.is_some(){
        args.append(&mut vec!["--passphrase-fd".to_string(), "0".to_string()]);
    }
    if use_agent{
        args.push("--use-agent".to_string());
    }
    if options.is_some(){
        args.append(&mut options.unwrap());
    }
    args.append(&mut cmd_args.unwrap());
    return args;
}

pub fn start_process(
    cmd_args:Option<Vec<String>>, 
    passphrase:Option<String>,
    version:f32,
    homedir:String,
    use_agent:bool,
    options:Option<Vec<String>>,
    env:Option<HashMap<String, String>>,
) -> Result<Child, Error> {
    let cmd_args:Vec<String> = generate_cmd_args(
        cmd_args,
        passphrase,
        version,
        homedir.clone(),
        use_agent,
        options,
    );

    let mut command = Command::new(&cmd_args[0]); // The first element of the vector is the command

    // Pass the rest of the arguments to the command
    command.args(&cmd_args[1..]);

    if env.is_some(){
        for (key, value) in env.unwrap(){
            command.env(key, value);
        };
    };
    let cmd: Result<Child, Error> = command
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn();

    return cmd;
}

/// to collect error / output from the Command process
pub fn collect_cmd_output_response(
    cmd_process:Child,
    result: CmdResult,
    writer: Option<Runtime>,
    stdin:Option<ChildStdin>
) -> CmdResult{
    let tokio_read_error_runtime:Runtime= Builder::new_current_thread().enable_all().build().unwrap();
    let tokio_read_output_runtime:Runtime= Builder::new_current_thread().enable_all().build().unwrap();

    return result;
}

// pub fn read_cmd_response(){

// }

// pub fn read_cmd_error(){

// }