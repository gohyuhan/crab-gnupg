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
- [EncryptOption](#encryptoption)
- [DecryptOption](#decryptoption)
- [SignOption](#signoption)

&nbsp;
# #️⃣ Enum
- [TrustLevel](#trustlevel)

&nbsp;
## Initialize gpg
Before any operation of gpg, a gpg object need to be initialized to get access to other gpg function.  
`GPG::init()` takes in 3 parameter in the following sequence.
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
`gen_key()` takes in 2 parameters in the following sequence.
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
`list_keys()` takes in 3 parameters in the following sequence.
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
`delete_keys()` takes in 4 parameters in the following sequence.
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
`import_key()` takes in 4 parameters in the following sequence.
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
`export_public_key()` takes in 2 parameters in the following sequence.
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
`export_secret_key()` takes in 3 parameters in the following sequence.
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
`trust_key()` takes in 2 parameters in the following sequence.
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
`sign_key()` takes in 4 parameters in the following sequence.
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
`encrypt()` takes in 1 parameters in the following sequence.
| parameter         | type                   | description                                                                                          |
|-------------------|------------------------|------------------------------------------------------------------------------------------------------|
| encryption_option | `EncryptOption`        | a struct to represent GPG encryption option. Refer [EncryptOption](#encryptoption) for more detail  |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let options: EncryptOption = EncryptOption::default(Some(file), None, vec![" <receipient> ".to_string()], Some(" <OUTPUT> ".to_string()));
let result: Result<CmdResult, GPGError> = gpg.encrypt(option);
```

&nbsp;
## Decrypt file
To decrypt file, you can use the function of `decrypt()` provided by `GPG`.  
`decrypt()` takes in 1 parameters in the following sequence.
| parameter      | type                   | description                                                                                          |
|----------------|------------------------|------------------------------------------------------------------------------------------------------|
| decrypt_option | `DecryptOption`        | a struct to represent GPG decrypt option. Refer [DecryptOption](#decryptoption) for more detail  |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let options: DecryptOption = DecryptOption::default(Some(file), None, " <receipient> ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), Some(" <OUTPUT> ".to_string()));
let result: Result<CmdResult, GPGError> = gpg.decrypt(option);
```

&nbsp;
## Sign file
To sign file, you can use the function of `sign()` provided by `GPG`.  
`sign()` takes in 1 parameters in the following sequence.
| parameter   | type                | description                                                                              |
|-------------|---------------------|------------------------------------------------------------------------------------------|
| sign_option | `SignOption`        | a struct to represent GPG sign option. Refer [SignOption](#signoption) for more detail  |

Example:
```rust
use crab_gnupg::gnupg::GPG;

let gpg:Result<GPG, GPGError> = GPG::init(None, None, true)
let options: SignOption = SignOption::default(Some(file), None, " <keyid> ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), Some(" <OUTPUT> ".to_string()));
let result: Result<CmdResult, GPGError> = gpg.sign(option);
```

&nbsp;
## Verify file
To verify file, you can use the function of `verify_file()` provided by `GPG`.  
`verify_file()` takes in 4 parameters in the following sequence.
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
## GPG
| parameter           | type                              | description                                                                                                        |
|---------------------|-----------------------------------|--------------------------------------------------------------------------------------------------------------------|
| homedir             | `String`                          | A path to a directory where the local key were at.                                                                 |
| output_dir          | `String`                          | A path to a directory where the output files from gpg will save to.                                                |
| env                 | `Option<HashMap<String, String>>` | A haspmap of env variables that would be passed to process.                                                        |
| keyrings            | `Option<Vec<String>>`             | A list of name of keyring files to use. If provided, the default keyring will be ignored.  (Currently not in used) |
| secret_keyring      | `Option<Vec<String>>`             | A list of name of secret keyring files to use. (Currently not in used)                                             |
| options             | `Option<Vec<String>>`             | Additional arguments to be passed to gpg                                                                           |
| armour              | `bool`                            | A boolean to indicate if the output should be armored                                                              |
| version             | `f32`                             | The major minor version of gpg, should only be set by system, user should not set this ex. 2.4                     |
| full_version        | `String`                          | The full version of gpg, should only be set by system, user should not set this ex. 2.4.6                          |


&nbsp;
## CmdResult
| parameter           | type                                   | description                                                                                                        |
|---------------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| raw_data            | `Option<String>`                       | Raw data of gpg command response and output                                                                        |
| return_code         | `Option<i32>`                          | Return status code of gpg operation                                                                                |
| status              | `Option<String>`                       | Status of the current Command Result                                                                               |
| status_message      | `Option<String>`                       | Description about status                                                                                           |
| operation           | `Operation`                            | The current gpg operation                                                                                          |
| debug_log           | `Option<Vec<String>>`                  | Log for debug purpose                                                                                              |
| problem             | `Option<Vec<HashMap<String, String>>>` | Description for more insight about the problem if gpg operation fail                                               |
| success             | `bool`                                 | If the operation is a success                                                                                      |

&nbsp;
## GPGError
| parameter           | type                                   | description                                                                                                        |
|---------------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| error_type          | `GPGErrorType`                         | The type of error                                                                                                  |
| cmd_result          | `Option<CmdResult>`                    | Provide more insight if error occured during the gpg cmd process                                                   |

&nbsp;
## ListKeyResult
Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS for full description of each corresponding parameter
| parameter           | type                                   | description                                                                                                        |
|---------------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| type                | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-1---type-of-record                                |
| validity            | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-2---validity                                      |
| length              | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-3---key-length                                    |
| algo                | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-4---public-key-algorithm                          |
| keyid               | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-5---keyid                                         |
| date                | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-6---creation-date                                 |
| expire              | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-7---expiration-date                               |
| dummy               | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-8---certificate-sn-uid-hash-trust-signature-info  |
| ownertrust          | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-9----ownertrust                                   |
| uid                 | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-10---user-id                                      |
| sig                 | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-11---signature-class                              |
| cap                 | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-12---key-capabilities                             |
| issuer              | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-13---issuer-certificate-fingerprint-or-other-info |
| flag                | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-14---flag-field                                   |
| token               | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-15---sn-of-a-token                                |
| hash                | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-16---hash-algorithm                               |
| curve               | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-17---curve-name                                   |
| compliance          | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-18---compliance-flags                             |
| updated             | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-19---last-update                                  |
| origin              | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-20---origin                                       |
| comment             | `String`                               | Check https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-21---comment                                      |
| keygrip             | `String`                               | Keygrip                                                                                                            |
| uids                | `Vec<String>`                          | List of uid(s)                                                                                                     |
| sigs                | `Vec<Vec<String>>`                     | List of sig(s)                                                                                                     |
| subkeys             | `Vec<Subkey>`                          | List of subkey(s)                                                                                                  |
| fingerprint         | `String`                               | Fingerprint of the key                                                                                             |

&nbsp;
## EncryptOption
EncryptOption was taken in by `encrypt()` function provided by `GPG`.
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| recipients          | `Option<Vec<String>>`                  | List of receipients keyid                                                                                                                                                     |
| sign                | `bool`                                 | Whether to sign the file                                                                                                                                                      |
| sign_key            | `Option<String>`                       | Keyid to sign the file                                                                                                                                                        |
| symmetric           | `bool`                                 | Whether to encrypt symmetrically  [passphrase must be provided if symmetric is true]                                                                                          |
| symmetric_algo      | `Option<String>`                       | Symmetric algorithm to use [if not provided a highly ranked cipher willl be chosen]                                                                                           |
| always_trust        | `bool`                                 | Whether to always trust keys                                                                                                                                                  |
| passphrase          | `Option<String>`                       | Passphrase to use for symmetric encryption [required if symmetric is true]                                                                                                    |
| output              | `Option<String>`                       | Path to write the encrypted output, will use the default output dir set in GPG if not provided and with file name as [<encryption_type>_encrypted_file_<datetime>.< extension >]|
| extra_args          | `Option<Vec<String>>`                  | Extra arguments to pass to gpg                                                                                                                                                |

It provided three options to generate the structure type based on your needs:

### `default()`
Encryption with just keys and always trust will be true.  
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| recipients          | `Vec<String>`                          | List of receipients keyid                                                                                                                                                     |
| output              | `Option<String>`                       | Path to write the encrypted output, will use the default output dir set in GPG if not provided and with file name as [<encryption_type>_encrypted_file_<datetime>.< extension >]|

Example:
```rust
use crab_gnupg::gnupg::EncryptOption;

let options: EncryptOption = EncryptOption::default(Some(file), None, vec![" <receipient> ".to_string()], Some(" <OUTPUT> ".to_string()));
```

### `with_symmetric()`
Encryption with passphrase instead of keys and always trust will be true.  
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| symmetric_algo      | `Option<String>`                       | Symmetric algorithm to use [if not provided a highly ranked cipher willl be chosen]                                                                                           |
| passphrase          | `String`                               | Passphrase to use for symmetric encryption [required if symmetric is true]                                                                                                    |
| output              | `Option<String>`                       | Path to write the encrypted output, will use the default output dir set in GPG if not provided and with file name as [<encryption_type>_encrypted_file_<datetime>.< extension >]|

Example:
```rust
use crab_gnupg::gnupg::EncryptOption;

let options: EncryptOption = EncryptOption::with_symmetric(Some(file), None, None, " <PASSPHRASE> ".to_string(), Some(" <OUTPUT> ".to_string()));
```

### `with_key_and_symmetric()`
Encryption with both passphrase and keys and always trust will be true.  
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| recipients          | `Option<Vec<String>>`                  | List of receipients keyid                                                                                                                                                     |
| symmetric_algo      | `Option<String>`                       | Symmetric algorithm to use [if not provided a highly ranked cipher willl be chosen]                                                                                           |
| passphrase          | `String`                               | Passphrase to use for symmetric encryption [required if symmetric is true]                                                                                                    |
| output              | `Option<String>`                       | Path to write the encrypted output, will use the default output dir set in GPG if not provided and with file name as [<encryption_type>_encrypted_file_<datetime>.< extension >]|

Example:
```rust
use crab_gnupg::gnupg::EncryptOption;

let options: EncryptOption = EncryptOption::with_key_and_symmetric(Some(file), None, Some(vec![" <receipient> ".to_string()]), None, " <PASSPHRASE> ".to_string(), Some(" <OUTPUT> ".to_string()));
```

&nbsp;
## DecryptOption
DecryptOption was taken in by `decrypt()` function provided by `GPG`.
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| recipient           | `Option<String>`                       | Receipient keyid                                                                                                                                                              |
| always_trust        | `bool`                                 | Whether to always trust keys                                                                                                                                                  |
| passphrase          | `Option<String>`                       | Passphrase for symmetric encrypted file                                                                                                                                       |
| key_passphrase      | `Option<String>`                       | Passphrase for file that is encrypted using a passphrase protected private key                                                                                                |
| output              | `Option<String>`                       | Path to write the decrypted output, will use the default output dir set in GPG if not provided and with file name as [decrypted_file_<datetime>.< extension >]                  |
| extra_args          | `Option<Vec<String>>`                  | Extra arguments to pass to gpg                                                                                                                                                |

It provided two options to generate the structure type based on your needs:

### `default()`
Decryption with secret key and always trust will be true.  
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| recipient           | `String`                               | Receipient keyid                                                                                                                                                              |
| key_passphrase      | `Option<String>`                       | Passphrase for file that is encrypted using a passphrase protected private key                                                                                                |
| output              | `Option<String>`                       | Path to write the decrypted output, will use the default output dir set in GPG if not provided and with file name as [decrypted_file_<datetime>.< extension >]                  |

Example:
```rust
use crab_gnupg::gnupg::DecryptOption;

let options: DecryptOption = DecryptOption::default(Some(file), None, " <receipient> ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), Some(" <OUTPUT> ".to_string()));
```

### `with_symmetric()`
Decryption with passphrase instead of secret keys and always trust will be true.  
| parameter           | type                                   | description                                                                                                                                                                   |
|---------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                   |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                  |
| passphrase          | `String`                               | Passphrase for symmetric encrypted file                                                                                                                                       |
| output              | `Option<String>`                       | Path to write the decrypted output, will use the default output dir set in GPG if not provided and with file name as [decrypted_file_<datetime>.< extension >]                  |

Example:
```rust
use crab_gnupg::gnupg::DecryptOption;

let options: DecryptOption = DecryptOption::with_symmetric(Some(file), None, " <PASSPHRASE> ".to_string(), Some(" <OUTPUT> ".to_string()));
```

&nbsp;
## SignOption
SignOption was taken in by `sign()` function provided by `GPG`.
| parameter           | type                                   | description                                                                                                                                                                        |
|---------------------|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                        |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                       |
| keyid               | `Option<String>`                       | Keyid for signing                                                                                                                                                                  |
| key_passphrase      | `Option<String>`                       | Passphrase for passphrase protected private key                                                                                                                                    |
| clearsign           | `bool`                                 | Whether to use clear signing                                                                                                                                                       |
| detached            | `bool`                                 | Whether to produce a detached signature                                                                                                                                            |
| output              | `Option<String>`                       | Path to write the detached signature or embedded sign file, will use the default output dir set in GPG if not provided and with file name as [<sign_type>_<datetime>.< sig or gpg >] |
| extra_args          | `Option<Vec<String>>`                  | Extra arguments to pass to gpg                                                                                                                                                     |

It provided two options to generate the structure type based on your needs:

### `default()`
Embedded signing with secret key with clearsign.  
| parameter           | type                                   | description                                                                                                                                                                        |
|---------------------|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                        |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                       |
| keyid               | `String`                               | Keyid for signing                                                                                                                                                                  |
| key_passphrase      | `Option<String>`                       | Passphrase for passphrase protected private key                                                                                                                                    |
| output              | `Option<String>`                       | Path to write the detached signature or embedded sign file, will use the default output dir set in GPG if not provided and with file name as [<sign_type>_<datetime>.< sig or gpg >] |

Example:
```rust
use crab_gnupg::gnupg::SignOption;

let options: SignOption = SignOption::default(Some(file), None, " < KEYID > ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), Some(" <OUTPUT> ".to_string()));
```

### `detached()`
Detached signing with secret key without clearsign.  
| parameter           | type                                   | description                                                                                                                                                                        |
|---------------------|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file                | `Option<File>`                         | File object                                                                                                                                                                        |
| file_path           | `Option<String>`                       | Path to file                                                                                                                                                                       |
| keyid               | `String`                               | Keyid for signing                                                                                                                                                                  |
| key_passphrase      | `Option<String>`                       | Passphrase for passphrase protected private key                                                                                                                                    |
| output              | `Option<String>`                       | Path to write the detached signature or embedded sign file, will use the default output dir set in GPG if not provided and with file name as [<sign_type>_<datetime>.< sig or gpg >] |

Example:
```rust
use crab_gnupg::gnupg::SignOption;

let options: SignOption = SignOption::detached(Some(file), None, " < KEYID > ".to_string(), Some(" <KEY_PASSPHRASE> ".to_string()), Some(" <OUTPUT> ".to_string()));
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