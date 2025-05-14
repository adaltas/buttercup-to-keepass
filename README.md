# Buttercup to KeePass exporter

The script reads a KeePass vault and export its entries as CSV in a KeePass format.

The export CSV structure is:

- `Group`
- `Title`
- `Username`
- `Password`
- `URL`
- `Notes`
- `TOTP`

## Installation

Node.js must be present on the system. The script has been tested with version 16 up to 24.

```bash

```

## Usage

```bash
node index.js \
  --source ~/Downloads/buttercup.bcup \
  --password my-secret \
  --target ~/Downloads/buttercup.csv \
  --info
```

## Options

- `-i` `--columns`  
  Print column names in the first line.
- `-h` `--help`  
  Display help information
- `-i` `--info`  
  Print the vault structure to stdout.
- `-p` `--password`  
  Buttercup vault password Required.
- `-s` `--source`  
  Buttercup vault location Required.
- `-t` `--target`  
  CSV exported file location Required.
