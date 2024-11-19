use super::enums::Operation;

//*******************************************************

//            RELATED TO RESPONSE HANDLING

//*******************************************************

/// a result handler for command process output/error result
#[derive(Debug, Clone)]
pub struct CmdResult {
    raw_data: Option<String>,
    return_code: Option<i32>,
    status: Option<String>,
    status_message: Option<String>,
    operation: Operation,
    debug_log: Option<Vec<String>>,
    problem: Option<Vec<String>>,
    success: bool,
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
            self.success = false;
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
    pub r#type: String,
    pub trust: String,
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
    pub keygrip: String,
    pub uids: Vec<String>,
    pub sigs: Vec<String>,
    pub subkeys: Vec<Subkey>,
    pub fingerprint: String,
}

impl ListKeyResult {
    fn new(args: Vec<&str>) -> Self {
        return ListKeyResult {
            r#type: String::from(args[0]),
            trust: String::from(args[1]),
            length: String::from(args[2]),
            algo: String::from(args[3]),
            keyid: String::from(args[4]),
            date: String::from(args[5]),
            expires: String::from(args[6]),
            dummy: String::from(args[7]),
            ownertrust: String::from(args[8]),
            uid: String::from(args[9]),
            sig: String::from(args[10]),
            cap: String::from(args[11]),
            issuer: String::from(args[12]),
            flag: String::from(args[13]),
            token: String::from(args[14]),
            hash: String::from(args[15]),
            curve: String::from(args[16]),
            compliance: String::from(args[17]),
            updated: String::from(args[18]),
            origin: String::from(args[19]),
            keygrip: String::from(args[20]),
            uids: vec![],
            sigs: vec![],
            subkeys: vec![],
            fingerprint: String::from(""),
        };
    }
}

#[derive(Debug, Clone)]
pub struct Subkey {
    pub r#type: String,
    pub trust: String,
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
        return Subkey {
            r#type: String::from(args[0]),
            trust: String::from(args[1]),
            length: String::from(args[2]),
            algo: String::from(args[3]),
            keyid: String::from(args[4]),
            date: String::from(args[5]),
            expires: String::from(args[6]),
            dummy: String::from(args[7]),
            ownertrust: String::from(args[8]),
            uid: String::from(args[9]),
            sig: String::from(args[10]),
            cap: String::from(args[11]),
            issuer: String::from(args[12]),
            flag: String::from(args[13]),
            token: String::from(args[14]),
            hash: String::from(args[15]),
            curve: String::from(args[16]),
            compliance: String::from(args[17]),
            updated: String::from(args[18]),
            keygrip: String::from(""),
            fingerprint: String::from(""),
        };
    }
}

///  a result handler for handling the result of keys action ( mainly of retrieve key list related action )
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
        self.curkey.as_mut().unwrap().sigs.append(&mut vec![
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
        let curkey = self.curkey.as_ref().unwrap().clone();
        self.key_list.as_mut().unwrap().push(curkey);
    }
}
