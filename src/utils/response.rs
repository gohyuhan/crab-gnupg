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
        if self.raw_data.is_none() {
            self.raw_data = Some(raw_data);
        } else {
            self.raw_data.as_mut().unwrap().push_str(&raw_data);
        }
    }

    pub fn get_raw_data(&self) -> Option<String> {
        return self.raw_data.clone();
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

#[derive(Debug, Clone)]
pub struct ListKeyResult {
    r#type: Option<String>,
    trust: Option<String>,
    length: Option<String>,
    algo: Option<String>,
    keyid: Option<String>,
    date: Option<String>,
    expires: Option<String>,
    dummy: Option<String>,
    ownertrust: Option<String>,
    uid: Option<String>,
    sig: Option<String>,
    cap: Option<String>,
    issuer: Option<String>,
    flag: Option<String>,
    token: Option<String>,
    hash: Option<String>,
    curve: Option<String>,
    compliance: Option<String>,
    updated: Option<String>,
    origin: Option<String>,
    keygrip: Option<String>,
    uids: Option<Vec<String>>,
    sigs: Option<Vec<String>>,
    subkeys: Option<Vec<String>>,
}

impl ListKeyResult {
    fn new() -> Self {
        return ListKeyResult {
            r#type: None,
            trust: None,
            length: None,
            algo: None,
            keyid: None,
            date: None,
            expires: None,
            dummy: None,
            ownertrust: None,
            uid: None,
            sig: None,
            cap: None,
            issuer: None,
            flag: None,
            token: None,
            hash: None,
            curve: None,
            compliance: None,
            updated: None,
            origin: None,
            keygrip: None,
            uids: None,
            sigs: None,
            subkeys: None,
        };
    }
}

///  a result handler for handling the result of keys action ( mainly of retrieve key list related action )
pub struct ListKey {
    // in_subkey: include subkeys
    // key list: a list of key
    // curkey: current processing key
    //
    //
    //
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
            "sec" => {}
            "fpr" => {}
            "sub" => {}
            "ssb" => {}
            "sig" => {}
            "grp" => {}
            _ => return,
        }
    }

    fn get_fields(&self, args: Vec<&str>) -> ListKeyResult {
        let mut result: ListKeyResult = ListKeyResult::new();
        result.r#type = Some(String::from(args[0]));
        result.trust = Some(String::from(args[1]));
        result.length = Some(String::from(args[2]));
        result.algo = Some(String::from(args[3]));
        result.keyid = Some(String::from(args[4]));
        result.date = Some(String::from(args[5]));
        result.expires = Some(String::from(args[6]));
        result.dummy = Some(String::from(args[7]));
        result.ownertrust = Some(String::from(args[8]));
        result.uid = Some(String::from(args[9]));
        result.sig = Some(String::from(args[10]));
        result.cap = Some(String::from(args[11]));
        result.issuer = Some(String::from(args[12]));
        result.flag = Some(String::from(args[13]));
        result.token = Some(String::from(args[14]));
        result.hash = Some(String::from(args[15]));
        result.curve = Some(String::from(args[16]));
        result.compliance = Some(String::from(args[17]));
        result.updated = Some(String::from(args[18]));
        result.origin = Some(String::from(args[19]));
        result.keygrip = Some(String::from(args[20]));
        result.uids = Some(vec![]);
        result.sigs = Some(vec![]);
        result.subkeys = Some(vec![]);
        return result;
    }

    fn pub_t(&mut self, args: Vec<&str>) {
        self.curkey = Some(self.get_fields(args));
        // remove uid from curkey hashmap and push to uids array
        let uid = self.curkey.as_ref().unwrap().uid.as_ref().unwrap().clone();
        if !uid.is_empty() {
            self.curkey
                .as_mut()
                .unwrap()
                .uids
                .as_mut()
                .unwrap()
                .push(uid);
        }
        self.in_subkey = false;
    }

    fn uid(&mut self, args: Vec<&str>) {
        let uid_index: usize = 9;
        self.curkey
            .as_mut()
            .unwrap()
            .uids
            .as_mut()
            .unwrap()
            .push(args[uid_index].to_string());
    }

    pub fn get_list_key_result(&mut self) -> Vec<ListKeyResult> {
        if self.curkey.is_none() {
            return vec![ListKeyResult::new()];
        }
        return self.key_list.as_ref().unwrap().clone();
    }

    pub fn append_result(&mut self) {
        let curkey = self.curkey.as_ref().unwrap().clone();
        self.key_list.as_mut().unwrap().push(curkey);
    }
}

#[derive(Debug, Clone)]
pub enum Operation {
    Verify,
    GenerateKey,
    ListKey,
    SearchKey,
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Verify => write!(f, "Verify"),
            Operation::GenerateKey => write!(f, "GenerateKey"),
            Operation::ListKey => write!(f, "ListKey"),
            Operation::SearchKey => write!(f, "SearchKey"),
        }
    }
}
