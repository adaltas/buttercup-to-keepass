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
npx buttercup-to-keepass --help
```

Alternatively, the project is cloned and initialised locally.

```bash
git clone https://github.com/adaltas/buttercup-to-keepass.git
cd buttercup-to-keepass
npm install
node index.js --help
```

## Usage

```bash
npx buttercup-to-keepass \
  --source ~/Downloads/buttercup.bcup \
  --password my-secret \
  --target ~/Downloads/buttercup.csv
```

## Options

- `-c` `--columns`  
  Print column names in the first line.
- `-h` `--help`  
  Display help information
- `-i` `--info`  
  Print the vault structure to stdout.
- `-o` `--otp`  
  List of attributes interpreted as OTP code.
- `-p` `--password`  
  Buttercup vault password Required.
- `-s` `--source`  
  Buttercup vault location Required.
- `-t` `--target`  
  CSV exported file location Required.
