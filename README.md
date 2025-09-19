# Shai-Hulud NPM Supply Chain Attack Scanner

The **Shai-Hulud Scanner** is a tool designed to detect malicious packages in your `package-lock.json` file. It identifies compromised packages associated with the Shai-Hulud npm supply chain attack, based on a comprehensive list of known malicious versions.

## Features

- Scans `package-lock.json` files for malicious packages.
- Supports both Node.js and Bash environments.
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
node shai_hulud_scanner.js
node shai_hulud_scanner.js -f /path/to/package-lock.json -v
node shai_hulud_scanner.js --file ./project/package-lock.json --output scan_results.txt
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
bash shai_hulud_scanner.sh
bash shai_hulud_scanner.sh -f /path/to/package-lock.json -v
bash shai_hulud_scanner.sh --file ./project/package-lock.json --output scan_results.txt
```

---

## Output

- **Console Logs**: Displays scan results, including any detected malicious packages.
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
