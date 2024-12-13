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
- [Sign key](#aign-key)
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

&nbsp;
## Initialize gpg
Before any operation of gpg, a gpg object need to be initialized to get access to other gpg function.  
`GPG::init()` takes in 3 parameter in the following sequence
| parameter  | type             | description                                                                                |
|------------|------------------|--------------------------------------------------------------------------------------------|
| homedir    | `Option<String>` | Path where gpg store key, if `None` default to `~/.gnupg` for unix or `~/gnupg` for window |
| output_dir | `Option<String>` | Path where gpg will save output files to, if `None` default to `~/Downloads/gnupg_output`  |
| armor      | `bool`           | if output should be ASCII armoured                                                         |

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
| args             | `Option<HashMap<String, String>>` | additional args provided for key generation, check GnuPG official documentation for detail available arguments|

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
