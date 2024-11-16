use std::{any::Any, collections::HashMap, fmt::{Display, Formatter}, iter::Enumerate};

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


/// a value enum 
#[derive(Debug)] 
enum Value { 
    Str(String), 
    Vec(Vec<String>), 
}

///  a result handler for handling the result of listing keys
pub struct ListKey {
    in_subkey: bool,
    key_map: HashMap<String, String>,
    key_list: Option<Vec<HashMap<String, Value>>>,
    curkey: Option<HashMap<String, Value>>,
    fingerprints: Option<Vec<String>>,
    uids: Option<Vec<String>>,
    operation: Operation,
}

impl ListKey {
    const LIST_FIELDS:[&str; 21] = [
        "type",
        "trust",
        "length",
        "algo",
        "keyid",
        "date",
        "expires",
        "dummy",
        "ownertrust",
        "uid",
        "sig",
        "cap",
        "issuer",
        "flag",
        "token",
        "hash",
        "curve",
        "compliance",
        "updated",
        "origin",
        "keygrip"
    ];

    pub fn init(ops:Operation) -> ListKey {
        ListKey {
            in_subkey:false,
            key_map: HashMap::new(),
            key_list:None,
            curkey: None,
            fingerprints: None,
            uids: None,
            operation: ops,
        }
    }

    pub fn call_method(&mut self, keyword:&str, args:Vec<String>){
        ["pub", "uid", "sec", "fpr", "sub", "ssb", "sig", "grp"];
        match keyword {
            "pub" => self.pub_t(args),
            "uid" => {},
            "sec" => {},
            "fpr" => {},
            "sub" => {},
            "ssb" => {},
            "sig" => {},
            "grp" => {},
            _ => return
        }
    }

    fn get_fields(&self, args:Vec<String>) -> HashMap<String, Value> {
        let mut result: HashMap<String, Value>= HashMap::new();
        match self.operation{
            Operation::ListKey => {
                for (i, fields) in ListKey::LIST_FIELDS.iter().enumerate() {
                    if i < args.len() {
                        result.insert(fields.to_string(), Value::Str(args[i].to_string()));
                    }else{
                        result.insert(fields.to_string(), Value::Str("unavailable".to_string()));
                    }

                }
            }
            _ => {}
        }
        result.entry("uids".to_string()).or_insert(Value::Vec(Vec::<String>::new()));
        result.entry("sigs".to_string()).or_insert(Value::Vec(Vec::<String>::new()));
        return result;
    }

    fn pub_t(&mut self, args:Vec<String>){
        self.curkey = Some(self.get_fields(args));
    }

    fn uid(&mut self, args:Vec<String>){
        let uid_index:u8 = 9 if self.operation == Operation::ListKey else if self.operation == Operation:: 1;

    }
    
}

#[derive(Debug)]
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
