use std::collections::HashMap;

use super::enums::{DeleteProblem, Operation};

//*******************************************************

//            RELATED TO RESPONSE HANDLING

//*******************************************************

// a result handler for command process output/error result
#[derive(Debug, Clone)]
pub struct CmdResult {
    pub raw_data: Option<String>,
    pub return_code: Option<i32>,
    pub status: Option<String>,
    pub status_message: Option<String>,
    pub operation: Operation,
    pub debug_log: Option<Vec<String>>,
    pub problem: Option<Vec<HashMap<String, String>>>,
    pub success: bool,
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
            success: true,
        }
    }

    pub fn set_raw_data(&mut self, raw_data: String) {
        if self.raw_data.is_none() {
            self.raw_data = Some(raw_data);
        } else {
            self.raw_data.as_mut().unwrap().push_str(&raw_data);
        }
    }

    pub fn get_raw_data(&self) -> Option<String> {
        return self.raw_data.clone();
    }

    pub fn handle_status(&mut self, keyword: &str, value: String) {
        self.status = Some(keyword.to_string());
        self.status_message = Some(value.to_string());

        if keyword == "FAILURE" {
            // for export secret key, there can be failure at the end if there are 1 or more key no exported due to passphrase
            // in this case if there are any key that exported even just partially, we should still consider it as success
            // for it to not export anything, there will be gpg: WARNING: nothing exported in the output
            if self.operation == Operation::ExportSecretKey {
                if self.raw_data.as_ref().unwrap().contains("WARNING: nothing exported") {
                    self.success = false;
                } else {
                    self.success = true;
                }
            } else{
                self.success = false;
            }
        } else if keyword == "BADSIG" {
            self.success = false;
            self.status = Some("bad signature".to_string());
            let values = value.splitn(2, char::is_whitespace).collect::<Vec<&str>>();
            let mut problem: HashMap<String, String> = HashMap::new();
            problem.insert("status".to_string(), self.status.as_ref().unwrap().clone());
            problem.insert("key_id".to_string(), values[0].to_string());
            problem.insert("username".to_string(), values[1].to_string());
            if self.problem.is_none() {
                self.problem = Some(vec![problem]);
            } else {
                self.problem.as_mut().unwrap().push(problem);
            }
        } else if keyword == "NODATA" {
            if self.raw_data.as_ref().unwrap().contains("no valid OpenPGP data found") {
                self.success = false;
            }
        } else if keyword == "DELETE_PROBLEM" {
            let mut problem: HashMap<String, String> = HashMap::new();
            problem.insert("delete_problem".to_string(), DeleteProblem::from_str(value.as_str()));
            if self.problem.is_none() {
                self.problem = Some(vec![problem]);
            } else {
                self.problem.as_mut().unwrap().push(problem);
            }
            self.success = false;
        } else if keyword == "UNKNOWN_KEYWORD" {
            self.success = false;
            let mut problem: HashMap<String, String> = HashMap::new();
            problem.insert("unknown_keyword".to_string(), value);
            if self.problem.is_none() {
                self.problem = Some(vec![problem]);
            } else {
                self.problem.as_mut().unwrap().push(problem);
            }
        } else if keyword == "NO_PASSPHRASE" {
            self.success = false;
            let mut problem: HashMap<String, String> = HashMap::new();
            problem.insert("passphrase".to_string(), value);
            if self.problem.is_none() {
                self.problem = Some(vec![problem]);
            } else {
                self.problem.as_mut().unwrap().push(problem);
            }
        } else if keyword == "INVALID_FINGERPRINT" {
            self.success = false;
            let mut problem: HashMap<String, String> = HashMap::new();
            problem.insert("fingerprint".to_string(), value);
            if self.problem.is_none() {
                self.problem = Some(vec![problem]);
            } else {
                self.problem.as_mut().unwrap().push(problem);
            }
        } else if keyword == "BAD_PASSPHRASE" {
            self.success = false;
            let mut problem: HashMap<String, String> = HashMap::new();
            problem.insert("passphrase".to_string(), value);
            if self.problem.is_none() {
                self.problem = Some(vec![problem]);
            } else {
                self.problem.as_mut().unwrap().push(problem);
            }
        }
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

    pub fn is_success(&self) -> bool {
        return self.success;
    }

    pub fn get_error_message(&mut self) -> String {
        return self
            .status_message
            .as_mut()
            .unwrap_or(&mut "Undefined Error".to_string())
            .clone();
    }

    pub fn clone_cmd_info(&mut self, cmd_result: &CmdResult) {
        self.raw_data = cmd_result.raw_data.clone();
        self.return_code = cmd_result.return_code.clone();
        self.status = cmd_result.status.clone();
        self.status_message = cmd_result.status_message.clone();
        self.operation = cmd_result.operation.clone();
        self.debug_log = cmd_result.debug_log.clone();
        self.problem = cmd_result.problem.clone();
        self.success = cmd_result.success;
    }
}

//*******************************************************

//            RELATED TO LIST KEY RESULT

//*******************************************************
#[derive(Debug, Clone)]
pub struct ListKeyResult {
    // https://github.com/gpg/gnupg/blob/master/doc/DETAILS
    pub r#type: String,
    pub validity: String,
    pub length: String,
    pub algo: String,
    pub keyid: String,
    pub date: String,
    pub expires: String,
    pub dummy: String,
    pub ownertrust: String,
    pub uid: String,
    pub sig: String,
    pub cap: String,
    pub issuer: String,
    pub flag: String,
    pub token: String,
    pub hash: String,
    pub curve: String,
    pub compliance: String,
    pub updated: String,
    pub origin: String,
    pub comment: String,
    pub keygrip: String,
    pub uids: Vec<String>,
    pub sigs: Vec<Vec<String>>,
    pub subkeys: Vec<Subkey>,
    pub fingerprint: String,
}

impl ListKeyResult {
    fn new(args: Vec<&str>) -> Self {
        let mut result: ListKeyResult = ListKeyResult {
            r#type: String::from("Unavailable"),
            validity: String::from("Unavailable"),
            length: String::from("Unavailable"),
            algo: String::from("Unavailable"),
            keyid: String::from("Unavailable"),
            date: String::from("Unavailable"),
            expires: String::from("Unavailable"),
            dummy: String::from("Unavailable"),
            ownertrust: String::from("Unavailable"),
            uid: String::from("Unavailable"),
            sig: String::from("Unavailable"),
            cap: String::from("Unavailable"),
            issuer: String::from("Unavailable"),
            flag: String::from("Unavailable"),
            token: String::from("Unavailable"),
            hash: String::from("Unavailable"),
            curve: String::from("Unavailable"),
            compliance: String::from("Unavailable"),
            updated: String::from("Unavailable"),
            origin: String::from("Unavailable"),
            comment: String::from("Unavailable"),
            keygrip: String::from("Unavailable"),
            uids: vec![],
            sigs: vec![],
            subkeys: vec![],
            fingerprint: String::from(""),
        };
        let mut idx: usize = 0;
        if idx < args.len() {
            result.r#type = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.validity = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.length = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.algo = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.keyid = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.date = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.expires = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.dummy = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.ownertrust = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.uid = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.sig = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.cap = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.issuer = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.flag = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.token = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.hash = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.curve = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.compliance = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.updated = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.comment = String::from(args[idx]);
        }
        return result;
    }
}

#[derive(Debug, Clone)]
pub struct Subkey {
    pub r#type: String,
    pub validity: String,
    pub length: String,
    pub algo: String,
    pub keyid: String,
    pub date: String,
    pub expires: String,
    pub dummy: String,
    pub ownertrust: String,
    pub uid: String,
    pub sig: String,
    pub cap: String,
    pub issuer: String,
    pub flag: String,
    pub token: String,
    pub hash: String,
    pub curve: String,
    pub compliance: String,
    pub updated: String,
    pub keygrip: String,
    pub fingerprint: String,
}
impl Subkey {
    fn new(args: Vec<&str>) -> Self {
        let mut result: Subkey = Subkey {
            r#type: String::from("Unavailable"),
            validity: String::from("Unavailable"),
            length: String::from("Unavailable"),
            algo: String::from("Unavailable"),
            keyid: String::from("Unavailable"),
            date: String::from("Unavailable"),
            expires: String::from("Unavailable"),
            dummy: String::from("Unavailable"),
            ownertrust: String::from("Unavailable"),
            uid: String::from("Unavailable"),
            sig: String::from("Unavailable"),
            cap: String::from("Unavailable"),
            issuer: String::from("Unavailable"),
            flag: String::from("Unavailable"),
            token: String::from("Unavailable"),
            hash: String::from("Unavailable"),
            curve: String::from("Unavailable"),
            compliance: String::from("Unavailable"),
            updated: String::from("Unavailable"),
            keygrip: String::from(""),
            fingerprint: String::from(""),
        };
        let mut idx: usize = 0;
        if idx < args.len() {
            result.r#type = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.validity = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.length = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.algo = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.keyid = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.date = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.expires = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.dummy = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.ownertrust = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.uid = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.sig = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.cap = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.issuer = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.flag = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.token = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.hash = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.curve = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.compliance = String::from(args[idx]);
            idx += 1;
        }
        if idx < args.len() {
            result.updated = String::from(args[idx]);
        }
        return result
    }
}

//  a result handler for handling the result of keys action ( mainly of retrieve key list related action )
pub struct ListKey {
    // in_subkey: include subkeys
    // key list: a list of key
    // curkey: current processing key
    // fingerprints: a list of fingerprints
    in_subkey: bool,
    key_list: Option<Vec<ListKeyResult>>,
    curkey: Option<ListKeyResult>,
    fingerprints: Option<Vec<String>>,
}

impl ListKey {
    pub fn init() -> ListKey {
        ListKey {
            in_subkey: false,
            key_list: Some(Vec::new()),
            curkey: None,
            fingerprints: Some(Vec::new()),
        }
    }

    pub fn call_method(&mut self, keyword: &str, args: Vec<&str>) {
        match keyword {
            "pub" => self.pub_t(args),
            "uid" => self.uid(args),
            "sec" => self.pub_t(args),
            "fpr" => self.fpr(args),
            "sub" => self.sub(args),
            "ssb" => self.ssb(args),
            "sig" => self.sig(args),
            "grp" => self.grp(args),
            _ => return,
        }
    }

    fn pub_t(&mut self, args: Vec<&str>) {
        self.curkey = Some(ListKeyResult::new(args));
        // remove uid from curkey hashmap and push to uids array
        let uid = self.curkey.as_ref().unwrap().uid.clone();
        if !uid.is_empty() {
            self.curkey.as_mut().unwrap().uids.push(uid);
        }
        self.in_subkey = false;
    }

    fn uid(&mut self, args: Vec<&str>) {
        let uid_index: usize = 9;
        self.curkey
            .as_mut()
            .unwrap()
            .uids
            .push(args[uid_index].to_string());
    }

    fn fpr(&mut self, args: Vec<&str>) {
        let fingerprint = args[9].to_string();
        if !self.in_subkey {
            self.curkey.as_mut().unwrap().fingerprint = fingerprint.clone();
            self.fingerprints.as_mut().unwrap().push(fingerprint);
        } else {
            let len: usize = self.curkey.as_ref().unwrap().subkeys.len();
            self.curkey.as_mut().unwrap().subkeys[len - 1].fingerprint = fingerprint;
        }
    }

    fn sub(&mut self, args: Vec<&str>) {
        let subkey: Subkey = Subkey::new(args);
        self.curkey.as_mut().unwrap().subkeys.push(subkey);
        self.in_subkey = true;
    }

    fn ssb(&mut self, args: Vec<&str>) {
        let subkey: Subkey = Subkey::new(args);
        self.curkey.as_mut().unwrap().subkeys.push(subkey);
        self.in_subkey = true;
    }

    fn sig(&mut self, args: Vec<&str>) {
        self.curkey.as_mut().unwrap().sigs.push(vec![
            args[4].to_string(),
            args[9].to_string(),
            args[10].to_string(),
        ]);
    }

    fn grp(&mut self, args: Vec<&str>) {
        let grp: String = args[9].to_string();
        if !self.in_subkey {
            self.curkey.as_mut().unwrap().keygrip = grp;
        } else {
            let len: usize = self.curkey.as_ref().unwrap().subkeys.len();
            self.curkey.as_mut().unwrap().subkeys[len - 1].keygrip = grp;
        }
    }

    pub fn get_list_key_result(&mut self) -> Vec<ListKeyResult> {
        if self.curkey.is_none() {
            return vec![];
        }
        return self.key_list.as_ref().unwrap().clone();
    }

    pub fn append_result(&mut self) {
        if !self.curkey.is_none() {
            let curkey = self.curkey.as_ref().unwrap().clone();
            self.key_list.as_mut().unwrap().push(curkey);
        }
    }
}
