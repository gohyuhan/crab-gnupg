# crab-gnupg

crab-gnupg was a wrapper for the gnupg command line tool written in rust. 
It was design to make it easier to interact with gnupg command line tool for program that was written in rust.

![badge](https://img.shields.io/badge/License-MIT-blue.svg)
![GnuPG Version](https://img.shields.io/badge/gnupg-2.4.x-green)
![GnuPG Version](https://img.shields.io/badge/gnupg-1.4.x-green)
![Rust Version](https://img.shields.io/badge/rust-1.82.0-blue)


## Table of Contents (Optional)
1. [Description](#description)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Change Logs](#change-logs)

## Description
This project ``crab-gnupg`` allows you to easily interact with the gnupg command line tool with rust. It provides a simple and easy-to-use interface for performing various gnupg operations, such as encrypting, decrypting, signing, and verifying file as well as generating and managing keys. This project was build and tested using gnupg version 2.4.x. More modification and changes will be done to support gnupg version 1.4.x. in the future.
> [!NOTE] 
> You will still need to install gnupg on your system.

## Installation
To install gnupg, you can use the following command:

for macOS:
```bash
brew install gnupg
```

for linux (ubuntu) [this might not get the latest version]:
```bash
sudo apt update
sudo apt install gnupg
```
To get the latest version of GnuPG, download it from the official GnuPG website and follow the instruction

for window:
```bash
choco install gnupg
```

To add ``crab-gnupg`` to be use in a rust program
```bash
cargo add crab-gnupg
```

## Usage
To check out how to use ``crab-gnupg``, check the [docs](docs/usage.md) here

## Change Logs
### v0.1.1
Initial crate Publish. This includes GnuPG key managment and file operation like:

- generate key
- list keys
- delete keys
- import keys
- export public keys
- export secret keys
- trust key
- sign key
- encrypt file
- decrypt file
- sign file
- verify file
