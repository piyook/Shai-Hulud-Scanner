# Shai-Hulud NPM Supply Chain Attack Scanner

The **Shai-Hulud Scanner** is a tool designed to detect malicious packages in your `package-lock.json` file. It identifies compromised packages associated with the Shai-Hulud npm supply chain attack, based on a comprehensive list of known malicious versions.

## Features

- Scans `package-lock.json` files for malicious packages.
- Scans globally installed npm packages for malicious versions.
- Supports both Node.js and Bash environments.
- Can scan individual files or all package-lock.json files in a directory.
- Provides detailed logs and actionable recommendations.
- Optionally outputs results to a file.
- Generates a list of malicious packages for reference.

## Usage

### Node.js Script (`shai_hulud_scanner.js`)

#### Prerequisites

- Node.js installed on your system.

#### Running the Script

```bash
node shai_hulud_scanner.js [OPTIONS]
```

#### Options

- `-f, --file FILE`  
  Specify the path to the `package-lock.json` file (default: `./package-lock.json`).
- `-d, --dir DIR`  
  Directory to scan for all package-lock.json files recursively.
- `-g, --global`  
  Scan globally installed npm packages.
- `-v, --verbose`  
  Enable verbose output.
- `-o, --output FILE`  
  Save the results to a specified file.
- `-h, --help`  
  Show the help message.
- `--create-list`  
  Generate a text file (`malicious_packages.txt`) listing all known malicious packages.

#### Examples

```bash
# Scan default package-lock.json in current directory
node shai_hulud_scanner.js

# Scan a specific package-lock.json file with verbose output
node shai_hulud_scanner.js -f /path/to/package-lock.json -v

# Scan a specific file and save results
node shai_hulud_scanner.js --file ./project/package-lock.json --output scan_results.txt

# Scan all package-lock.json files in a directory
node shai_hulud_scanner.js --dir /path/to/projects --output scan_results.txt

# Scan all files in directory with verbose output
node shai_hulud_scanner.js -d ./projects -v

# Scan globally installed npm packages
node shai_hulud_scanner.js --global --output global_scan.txt
```

---

### Bash Script (`shai_hulud_scanner.sh`)

#### Prerequisites

- Bash shell (Linux/MacOS/WSL).
- `jq` installed for JSON parsing.

#### Running the Script

```bash
bash shai_hulud_scanner.sh [OPTIONS]
```

#### Options

- `-f, --file FILE`  
  Specify the path to the `package-lock.json` file (default: `./package-lock.json`).
- `-d, --dir DIR`  
  Directory to scan for all package-lock.json files recursively.
- `-g, --global`  
  Scan globally installed npm packages.
- `-v, --verbose`  
  Enable verbose output.
- `-o, --output FILE`  
  Save the results to a specified file.
- `-h, --help`  
  Show the help message.
- `--create-list`  
  Generate a text file (`malicious_packages.txt`) listing all known malicious packages.

#### Examples

```bash
# Scan default package-lock.json in current directory
bash shai_hulud_scanner.sh

# Scan a specific package-lock.json file with verbose output
bash shai_hulud_scanner.sh -f /path/to/package-lock.json -v

# Scan a specific file and save results
bash shai_hulud_scanner.sh --file ./project/package-lock.json --output scan_results.txt

# Scan all package-lock.json files in a directory
bash shai_hulud_scanner.sh --dir /path/to/projects --output scan_results.txt

# Scan all files in directory with verbose output
bash shai_hulud_scanner.sh -d ./projects -v

# Scan globally installed npm packages
bash shai_hulud_scanner.sh --global --output global_scan.txt
```

---

## Output

- **Console Logs**: Displays scan results, including any detected malicious packages.
- **Directory Scanning**: When using `--dir`, shows progress for each file and provides a summary of total files scanned and files with threats.
- **Global Package Scanning**: When using `--global`, scans all globally installed npm packages and reports any malicious versions found.
- **Output File (Optional)**: Saves detailed results to a specified file.
- **Malicious Package List**: Use the `--create-list` option to generate a `malicious_packages.txt` file for reference.

---

## Security Recommendations

If malicious packages are detected:

1. Remove the malicious packages immediately.
2. Rotate all access tokens for GitHub, NPM, AWS, GCP, and Azure.
3. Check for unauthorized GitHub repositories named "Shai-Hulud."
4. Scan your system with tools like [TruffleHog](https://github.com/trufflesecurity/trufflehog) to detect leaked secrets.
5. Review recent npm publish activities on your account.

---

## References

- [JFrog Blog: Shai-Hulud NPM Supply Chain Attack](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- [TruffleHog: Secret Scanning Tool](https://github.com/trufflesecurity/trufflehog)

---

## License

This project is provided as-is for educational and security purposes. Use at your own risk.
