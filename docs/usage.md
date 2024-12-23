<p style="font-size: 36px;">🚧 Under Constuction 🚧</p>

# ⚙️ Usage
- [Initialize gpg](#initialize-gpg)
- [Generate key](#generate-key)
- [List keys](#list-keys)
- [Delete keys](#delete-keys)
- [Import keys](#import-keys)
- [Export public keys](#export-public-keys)
- [Export secret keys](#export-secret-keys)
- [Trust key](#trust-key)
- [Sign key](#sign-key)
- [Encrypt file](#encrypt-file)
- [Decrypt file](#decrypt-file)
- [Sign file](#sign-file)
- [Verify file](#verify-file)

&nbsp;
# 🔠 Type
- [GPG](#gpg)
- [CmdResult](#cmdresult)
- [GPGError](#gpgerror)
- [ListKeyResult](#listkeyresult)
- [EncryptOption](#encrypt-option)
- [DecryptOption](#decrypt-option)
- [SignOption](#sign-option)

&nbsp;
# #️⃣ Enum
- [TrustLevel](#trustlevel)

&nbsp;
## Initialize gpg
Before any operation of gpg, a gpg object need to be initialized to get access to other gpg function.  
`GPG::init()` takes in 3 parameter in the following sequence
| parameter  | type             | description                                                                                |
|------------|------------------|--------------------------------------------------------------------------------------------|
| homedir    | `Option<String>` | Path where gpg store key, if `None` default to `~/.gnupg` for unix or `~/gnupg` for window |
| output_dir | `Option<String>` | Path where gpg will save output files to, if `None` default to `~/Downloads/gnupg_output`  |
| armor      | `bool`           | If output should be ASCII armoured                                                         |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
```

&nbsp;
## Generate key
To generate gpg key, you can use the function of `gen_key()` provided by `GPG`.  
`gen_key()` takes in 2 parameters in the following sequence
| parameter        | type                              | description                                                                                                   |
|------------------|-----------------------------------|---------------------------------------------------------------------------------------------------------------|
| key_passphrase   | `Option<String>`                  | Passphrase for passphrase protected key, if not provided, the key generated will not be passphrase protected  |
| args             | `Option<HashMap<String, String>>` | Additional args provided for key generation, check GnuPG official documentation for detail available arguments|

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result:Result<CmdResult, GPGError> = gpg.gen_key("example-passphrase".to_string(), None)
```

&nbsp;
## List keys
To list gpg key, you can use the function of `list_keys()` provided by `GPG`.  
`list_keys()` takes in 3 parameters in the following sequence
| parameter| type                  | description                                                                                                  |
|----------|-----------------------|--------------------------------------------------------------------------------------------------------------|
| secret   | `bool`                | If `true` list secret keys instead of public keys                                                            |
| keys     | `Option<Vec<String>>` | If provided, only list keys that matches the provided keyid(s) instead of all the keys in gpg home directory |
| signature| `bool`                | If `true`, also include signature to the listing of keys                                                     |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result:Result<Vec<ListKeyResult>, GPGError> = gpg.list_keys()
```

&nbsp;
## Delete keys
To delete gpg key, you can use the function of `delete_keys()` provided by `GPG`.  
`delete_keys()` takes in 4 parameters in the following sequence
| parameter    | type               | description                                       |
|--------------|--------------------|---------------------------------------------------|
| fingerprints | `Vec<String>`      | List of fingerprints of keys to delete            |
| is_secret    | `bool`             | If `true`, delete secret keys only                |
| is_subkey    | `bool`             | If `true`, delete subkeys instead                 |
| passphrase   | `Option<String>`   | Passphrase for passphrase protected secret keys   |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result:Result<Vec<ListKeyResult>, GPGError> = gpg.delete_keys(vec!["< FINGERPRINT >"], false, false, None);
```

&nbsp;
## Import keys
To import gpg key, you can use the function of `import_key()` provided by `GPG`.  
`import_key()` takes in 4 parameters in the following sequence
| parameter  | type                  | description                                                                                            |
|------------|-----------------------|--------------------------------------------------------------------------------------------------------|
| file       | `Option<File>`        | File for importing keys ( will be priotize if provided )                                               |
| file_path  | `Option<String>`      | File for importing keys, will be ignored if file is provided                                           |
| merge_only | `bool`                | If `true`, does not insert new keys but does only the merging of new signatures, user-IDs, subkeys etc |
| extra_args | `Option<Vec<String>>` | Additional args provided for importing keys                                                            |

Example:
```rust
use crab_gnupg::gnupg::GPG;
use std::fs::File;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)

// using file
let file:File = File::open("< FILE_PATH >".to_string()).unwrap();
let result:Result<Vec<ListKeyResult>, GPGError> = gpg.import_key(Some(), None, false, None);

// using file path
let result:Result<Vec<ListKeyResult>, GPGError> = gpg.import_key(None, Some("< FILE_PATH >".to_string()), false, None);
```

&nbsp;
## Export public keys
To export public gpg key, you can use the function of `export_public_key()` provided by `GPG`.  
`export_public_key()` takes in 2 parameters in the following sequence
| parameter | type                  | description                                                                                                                                       |
|-----------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| key_id    | `Option<Vec<String>>` | List of keyid(s) to export, if `None`, all public keys will be exported                                                                           |
| output    | `Option<String>`      | Path that the exported key file will be saved to, if `None` default to `~/Downloads/gnupg_output/exported_public_key/public_key_< TIMESTAMP >.asc`|

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result:Result<Vec<ListKeyResult>, GPGError> = gpg.export_public_key(None, None);
```

&nbsp;
## Export secret keys
To export secret gpg key, you can use the function of `export_secret_key()` provided by `GPG`.  
`export_secret_key()` takes in 3 parameters in the following sequence
| parameter | type                  | description                                                                                                                                       |
|-----------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| key_id    | `Option<Vec<String>>` | List of keyid(s) to export, if `None`, all secret keys will be exported                                                                           |
| passphrase| `Option<String>`      | Passphrase for passphrase protected secret keys. For gpg version > 2.1, this is required for passphrase proctected secret keys                    |
| output    | `Option<String>`      | Path that the exported key file will be saved to, if `None` default to `~/Downloads/gnupg_output/exported_secret_key/secret_key_< TIMESTAMP >.asc`|

> [!NOTE] 
> If there are 2 or more secret key that are passphrase proctected ( but different passphrase ) are being exported, only keys that are protected by the provided passphrase and keys that aren't passphrase protected will be exported. ( as GPG can only read 1 passphrase at a time from STDIN)

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result:Result<Vec<ListKeyResult>, GPGError> = gpg.export_secret_key(None, None, None);
```

&nbsp;
## Trust key
To trust gpg key, you can use the function of `trust_key()` provided by `GPG`.  
`trust_key()` takes in 2 parameters in the following sequence
| parameter    | type          | description                                                                                 |
|--------------|---------------|---------------------------------------------------------------------------------------------|
| fingerprints | `Vec<String>` | List of keyid(s) to trust                                                                   |
| trust_level  | `TrustLevel`  | Trust level to set for the keys, see [TrustLevel](#trustlevel) for all available option     |

Example:
```rust
use crab_gnupg::{
    gnupg::GPG,
    utils::enums::TrustLevel
};

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result: Result<CmdResult, GPGError> = gpg.trust_key(vec!["< FINGERPRINT >".to_string()], TrustLevel::Fully);
```

&nbsp;
## Sign key
To sign gpg key, you can use the function of `sign_key()` provided by `GPG`.  
`sign_key()` takes in 4 parameters in the following sequence
| parameter      | type                   | description                                                             |
|----------------|------------------------|-------------------------------------------------------------------------|
| signing_key_id | `String`               | Keyid of the key that was used for signing                              |
| target_key_id  | `String`               | Keyid of the key that will be signed                                    |
| passphrase     | `Option<String>`       | Passphrase for passphrase protected secret keys (signing key)           |
| extra_args     | `Option<Vec<String>>`  | Additional args provided for signing keys                               |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result: Result<CmdResult, GPGError> = gpg.sign_key(
    "< SIGNING_KEY_ID >".to_string(), 
    "< TARGET_KEY_ID >".to_string(), 
    None, 
    None
);
```

&nbsp;
## Encrypt file
To encrypt file, you can use the function of `encrypt()` provided by `GPG`.  
`encrypt()` takes in 1 parameters in the following sequence
| parameter         | type                   | description                                                                                          |
|-------------------|------------------------|------------------------------------------------------------------------------------------------------|
| encryption_option | `EncryptOption`        | a struct to represent GPG encryption option. Refer [EncryptOption](#encrypt-option) for more detail  |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let options: EncryptOption = EncryptOption::default(Some(file), None, vec![" <receipient> ".to_string()], " <OUTPUT> ".to_string());
let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
```

&nbsp;
## Decrypt file
To decrypt file, you can use the function of `decrypt()` provided by `GPG`.  
`decrypt()` takes in 1 parameters in the following sequence
| parameter      | type                   | description                                                                                          |
|----------------|------------------------|------------------------------------------------------------------------------------------------------|
| decrypt_option | `DecryptOption`        | a struct to represent GPG decrypt option. Refer [DecryptOption](#decrypt-option) for more detail  |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let options: DecryptOption = DecryptOption::default(Some(file), None, " <receipient> ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), " <OUTPUT> ".to_string());
let result: Result<CmdResult, GPGError> = gpg.decrypt(option);
```

&nbsp;
## Sign file
To sign file, you can use the function of `sign()` provided by `GPG`.  
`sign()` takes in 1 parameters in the following sequence
| parameter   | type                | description                                                                              |
|-------------|---------------------|------------------------------------------------------------------------------------------|
| sign_option | `SignOption`        | a struct to represent GPG sign option. Refer [SignOption](#sign-option) for more detail  |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let options: SignOption = SignOption::default(Some(file), None, " <keyid> ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), " <OUTPUT> ".to_string());
let result: Result<CmdResult, GPGError> = gpg.sign(option);
```

&nbsp;
## Verify file
To verify file, you can use the function of `verify_file()` provided by `GPG`.  
`verify_file()` takes in 4 parameters in the following sequence
| parameter           | type                  | description                                                |
|---------------------|-----------------------|------------------------------------------------------------|
| file                | `Option<File>`        | File object                                                |
| file_path           | `Option<String>`      | Path for the file, will be ignored if file is provided     |
| signature_file_path | `Option<String>`      | Path to the signature file ( if signature is detached )    |
| extra_args          | `Option<Vec<String>>` | Additional args provided for verifying file                |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let result: Result<CmdResult, GPGError> = gpg.verify_file(Some(file), None, None, None);
```

---
&nbsp;
## TrustLevel
An enum to represent the level of trust for trusting a gpg key. The options are:

- Expired
- Undefined
- Never
- Marginal
- Fully
- Ultimate