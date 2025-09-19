#!/bin/bash

# Shai-Hulud NPM Supply Chain Attack Scanner
# Scans package-lock.json files for malicious package versions
# Based on JFrog's comprehensive list of compromised packages

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PACKAGE_LOCK_FILE="package-lock.json"
VERBOSE=false
OUTPUT_FILE=""
SCAN_DIR=""

# Function to display help
show_help() {
    cat << EOF
Shai-Hulud NPM Supply Chain Attack Scanner

This script scans package-lock.json files for malicious package versions
associated with the Shai-Hulud npm supply chain attack.

Usage: $0 [OPTIONS]

OPTIONS:
    -f, --file FILE         Specify package-lock.json file path (default: ./package-lock.json)
    -d, --dir DIR           Directory to scan for all package-lock.json files
    -v, --verbose          Enable verbose output
    -o, --output FILE      Output results to file
    -h, --help             Show this help message

Examples:
    $0                     # Scan ./package-lock.json
    $0 -f /path/to/package-lock.json -v
    $0 --file ./project/package-lock.json --output scan_results.txt
    $0 --dir /path/to/projects --output scan_results.txt
    $0 -d ./projects -v

EOF
}

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "VERBOSE")
            if [ "$VERBOSE" = true ]; then
                echo -e "${BLUE}[VERBOSE]${NC} $message"
            fi
            ;;
    esac
    
    # Log to output file if specified
    if [ -n "$OUTPUT_FILE" ]; then
        echo "[$timestamp] [$level] $message" >> "$OUTPUT_FILE"
    fi
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                PACKAGE_LOCK_FILE="$2"
                shift 2
                ;;
            -d|--dir)
                SCAN_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Malicious package versions (based on JFrog's comprehensive list)
declare -A MALICIOUS_PACKAGES=(
    ["@ahmedhfarag/ngx-perfect-scrollbar"]="20.0.20"
    ["@ahmedhfarag/ngx-virtual-scroller"]="4.0.4"
    ["@art-ws/common"]="2.0.28"
    ["@art-ws/config-eslint"]="2.0.4,2.0.5"
    ["@art-ws/config-ts"]="2.0.7,2.0.8"
    ["@art-ws/db-context"]="2.0.24"
    ["@art-ws/di-node"]="2.0.13"
    ["@art-ws/di"]="2.0.28,2.0.32"
    ["@art-ws/eslint"]="1.0.5,1.0.6"
    ["@art-ws/fastify-http-server"]="2.0.24,2.0.27"
    ["@art-ws/http-server"]="2.0.21,2.0.25"
    ["@art-ws/openapi"]="0.1.9,0.1.12"
    ["@art-ws/package-base"]="1.0.5,1.0.6"
    ["@art-ws/prettier"]="1.0.5,1.0.6"
    ["@art-ws/slf"]="2.0.15,2.0.22"
    ["@art-ws/ssl-info"]="1.0.9,1.0.10"
    ["@art-ws/web-app"]="1.0.3,1.0.4"
    ["@crowdstrike/commitlint"]="8.1.1,8.1.2"
    ["@crowdstrike/falcon-shoelace"]="0.4.1,0.4.2"
    ["@crowdstrike/foundry-js"]="0.19.1,0.19.2"
    ["@crowdstrike/glide-core"]="0.34.2,0.34.3"
    ["@crowdstrike/logscale-dashboard"]="1.205.1,1.205.2"
    ["@crowdstrike/logscale-file-editor"]="1.205.1,1.205.2"
    ["@crowdstrike/logscale-parser-edit"]="1.205.1,1.205.2"
    ["@crowdstrike/logscale-search"]="1.205.1,1.205.2"
    ["@crowdstrike/tailwind-toucan-base"]="5.0.1,5.0.2"
    ["@ctrl/deluge"]="7.2.1,7.2.2"
    ["@ctrl/golang-template"]="1.4.2,1.4.3"
    ["@ctrl/magnet-link"]="4.0.3,4.0.4"
    ["@ctrl/ngx-codemirror"]="7.0.1,7.0.2"
    ["@ctrl/ngx-csv"]="6.0.1,6.0.2"
    ["@ctrl/ngx-emoji-mart"]="9.2.1,9.2.2"
    ["@ctrl/ngx-rightclick"]="4.0.1,4.0.2"
    ["@ctrl/qbittorrent"]="9.7.1,9.7.2"
    ["@ctrl/react-adsense"]="2.0.1,2.0.2"
    ["@ctrl/shared-torrent"]="6.3.1,6.3.2"
    ["@ctrl/tinycolor"]="4.1.1,4.1.2"
    ["@ctrl/torrent-file"]="4.1.1,4.1.2"
    ["@ctrl/transmission"]="7.3.1"
    ["@ctrl/ts-base32"]="4.0.1,4.0.2"
    ["@hestjs/core"]="0.2.1"
    ["@hestjs/cqrs"]="0.1.6"
    ["@hestjs/demo"]="0.1.2"
    ["@hestjs/eslint-config"]="0.1.2"
    ["@hestjs/logger"]="0.1.6"
    ["@hestjs/scalar"]="0.1.7"
    ["@hestjs/validation"]="0.1.6"
    ["@nativescript-community/arraybuffers"]="1.1.6,1.1.7,1.1.8"
    ["@nativescript-community/gesturehandler"]="2.0.35"
    ["@nativescript-community/perms"]="3.0.5,3.0.6,3.0.7,3.0.8,3.0.9"
    ["@nativescript-community/sentry"]="4.6.43"
    ["@nativescript-community/sqlite"]="3.5.2,3.5.3,3.5.4,3.5.5"
    ["@nativescript-community/text"]="1.6.9,1.6.10,1.6.11,1.6.12,1.6.13"
    ["@nativescript-community/typeorm"]="0.2.30,0.2.31,0.2.32,0.2.33"
    ["@nativescript-community/ui-collectionview"]="6.0.6"
    ["@nativescript-community/ui-document-picker"]="1.1.27,1.1.28,13.0.32"
    ["@nativescript-community/ui-drawer"]="0.1.30"
    ["@nativescript-community/ui-image"]="4.5.6"
    ["@nativescript-community/ui-label"]="1.3.35,1.3.36,1.3.37"
    ["@nativescript-community/ui-material-bottom-navigation"]="7.2.72,7.2.73,7.2.74,7.2.75"
    ["@nativescript-community/ui-material-bottomsheet"]="7.2.72"
    ["@nativescript-community/ui-material-core-tabs"]="7.2.72,7.2.73,7.2.74,7.2.75,7.2.76"
    ["@nativescript-community/ui-material-core"]="7.2.72,7.2.73,7.2.74,7.2.75,7.2.76"
    ["@nativescript-community/ui-material-ripple"]="7.2.72,7.2.73,7.2.74,7.2.75"
    ["@nativescript-community/ui-material-tabs"]="7.2.72,7.2.73,7.2.74,7.2.75"
    ["@nativescript-community/ui-pager"]="14.1.36,14.1.37,14.1.38"
    ["@nativescript-community/ui-pulltorefresh"]="2.5.4,2.5.5,2.5.6,2.5.7"
    ["@nexe/config-manager"]="0.1.1"
    ["@nexe/eslint-config"]="0.1.1"
    ["@nexe/logger"]="0.1.3"
    ["@nstudio/angular"]="20.0.4,20.0.5,20.0.6"
    ["@nstudio/focus"]="20.0.4,20.0.5,20.0.6"
    ["@nstudio/nativescript-checkbox"]="2.0.6,2.0.7,2.0.8,2.0.9"
    ["@nstudio/nativescript-loading-indicator"]="5.0.1,5.0.2,5.0.3,5.0.4"
    ["@nstudio/ui-collectionview"]="5.1.11,5.1.12,5.1.13,5.1.14"
    ["@nstudio/web-angular"]="20.0.4"
    ["@nstudio/web"]="20.0.4"
    ["@nstudio/xplat-utils"]="20.0.5,20.0.6,20.0.7"
    ["@nstudio/xplat"]="20.0.5,20.0.6,20.0.7"
    ["@operato/board"]="9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46"
    ["@operato/data-grist"]="9.0.29,9.0.35,9.0.36,9.0.37"
    ["@operato/graphql"]="9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46"
    ["@operato/headroom"]="9.0.2,9.0.35,9.0.36,9.0.37"
    ["@operato/help"]="9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46"
    ["@operato/i18n"]="9.0.35,9.0.36,9.0.37"
    ["@operato/input"]="9.0.27,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.47,9.0.48"
    ["@operato/layout"]="9.0.35,9.0.36,9.0.37"
    ["@operato/popup"]="9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.49"
    ["@operato/pull-to-refresh"]="9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42"
    ["@operato/shell"]="9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39"
    ["@operato/styles"]="9.0.2,9.0.35,9.0.36,9.0.37"
    ["@operato/utils"]="9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.49"
    ["@teselagen/bio-parsers"]="0.4.29,0.4.30"
    ["@teselagen/bounce-loader"]="0.3.16,0.3.17"
    ["@teselagen/file-utils"]="0.3.21,0.3.22"
    ["@teselagen/liquibase-tools"]="0.4.1"
    ["@teselagen/ove"]="0.7.39,0.7.40"
    ["@teselagen/range-utils"]="0.3.14,0.3.15"
    ["@teselagen/react-list"]="0.8.19,0.8.20"
    ["@teselagen/react-table"]="6.10.19,6.10.20,6.10.21,6.10.22"
    ["@teselagen/sequence-utils"]="0.3.33,0.3.34"
    ["@teselagen/ui"]="0.9.9,0.9.10"
    ["@thangved/callback-window"]="1.1.4"
    ["@things-factory/attachment-base"]="9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.47,9.0.48,9.0.49,9.0.50,9.0.51,9.0.52,9.0.53,9.0.54,9.0.55"
    ["@things-factory/auth-base"]="9.0.42,9.0.43,9.0.44,9.0.45"
    ["@things-factory/email-base"]="9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.47,9.0.48,9.0.49,9.0.50,9.0.51,9.0.52,9.0.53,9.0.54,9.0.55,9.0.56,9.0.57,9.0.58,9.0.59"
    ["@things-factory/env"]="9.0.42,9.0.43,9.0.44,9.0.45"
    ["@things-factory/integration-base"]="9.0.42,9.0.43,9.0.44,9.0.45"
    ["@things-factory/integration-marketplace"]="9.0.42,9.0.43,9.0.44,9.0.45"
    ["@things-factory/shell"]="9.0.42,9.0.43,9.0.44,9.0.45"
    ["@tnf-dev/api"]="1.0.8"
    ["@tnf-dev/core"]="1.0.8"
    ["@tnf-dev/js"]="1.0.8"
    ["@tnf-dev/mui"]="1.0.8"
    ["@tnf-dev/react"]="1.0.8"
    ["@ui-ux-gang/devextreme-angular-rpk"]="24.1.7"
    ["@yoobic/design-system"]="6.5.17"
    ["@yoobic/jpeg-camera-es6"]="1.0.13"
    ["@yoobic/yobi"]="8.7.53"
    ["airchief"]="0.3.1"
    ["airpilot"]="0.8.8"
    ["angulartics2"]="14.1.1,14.1.2"
    ["browser-webdriver-downloader"]="3.0.8"
    ["capacitor-notificationhandler"]="0.0.2,0.0.3"
    ["capacitor-plugin-healthapp"]="0.0.2,0.0.3"
    ["capacitor-plugin-ihealth"]="1.1.8,1.1.9"
    ["capacitor-plugin-vonage"]="1.0.2,1.0.3"
    ["capacitorandroidpermissions"]="0.0.4,0.0.5"
    ["config-cordova"]="0.8.5"
    ["cordova-plugin-voxeet2"]="1.0.24"
    ["cordova-voxeet"]="1.0.32"
    ["create-hest-app"]="0.1.9"
    ["db-evo"]="1.1.4,1.1.5"
    ["devextreme-angular-rpk"]="21.2.8"
    ["ember-browser-services"]="5.0.2,5.0.3"
    ["ember-headless-form-yup"]="1.0.1"
    ["ember-headless-form"]="1.1.2,1.1.3"
    ["ember-headless-table"]="2.1.5,2.1.6"
    ["ember-url-hash-polyfill"]="1.0.12,1.0.13"
    ["ember-velcro"]="2.2.1,2.2.2"
    ["encounter-playground"]="0.0.2,0.0.3,0.0.4,0.0.5"
    ["eslint-config-crowdstrike-node"]="4.0.3,4.0.4"
    ["eslint-config-crowdstrike"]="11.0.2,11.0.3"
    ["eslint-config-teselagen"]="6.1.7,6.1.8"
    ["globalize-rpk"]="1.7.4"
    ["graphql-sequelize-teselagen"]="5.3.8,5.3.9"
    ["html-to-base64-image"]="1.0.2"
    ["json-rules-engine-simplified"]="0.2.1,0.2.3,0.2.4"
    ["jumpgate"]="0.0.2"
    ["koa2-swagger-ui"]="5.11.1,5.11.2"
    ["mcfly-semantic-release"]="1.3.1"
    ["mcp-knowledge-base"]="0.0.2"
    ["mcp-knowledge-graph"]="1.2.1"
    ["mobioffice-cli"]="1.0.3"
    ["monorepo-next"]="13.0.1,13.0.2"
    ["mstate-angular"]="0.4.4"
    ["mstate-cli"]="0.4.7"
    ["mstate-dev-react"]="1.1.1"
    ["mstate-react"]="1.6.5"
    ["ng2-file-upload"]="7.0.2,7.0.3,8.0.1,8.0.2,8.0.3,9.0.1"
    ["ngx-bootstrap"]="18.1.4,19.0.3,19.0.4,20.0.3,20.0.4,20.0.5,20.0.6"
    ["ngx-color"]="10.0.1,10.0.2"
    ["ngx-toastr"]="19.0.1,19.0.2"
    ["ngx-trend"]="8.0.1"
    ["ngx-ws"]="1.1.5,1.1.6"
    ["oradm-to-gql"]="35.0.14,35.0.15"
    ["oradm-to-sqlz"]="1.1.2,1.1.4"
    ["ove-auto-annotate"]="0.0.9,0.0.10"
    ["pm2-gelf-json"]="1.0.4,1.0.5"
    ["printjs-rpk"]="1.6.1"
    ["react-complaint-image"]="0.0.32,0.0.34,0.0.35"
    ["react-jsonschema-form-conditionals"]="0.3.18,0.3.20,0.3.21"
    ["react-jsonschema-form-extras"]="1.0.3,1.0.4"
    ["react-jsonschema-rxnt-extras"]="0.4.8,0.4.9"
    ["remark-preset-lint-crowdstrike"]="4.0.1,4.0.2"
    ["rxnt-authentication"]="0.0.3,0.0.4,0.0.5,0.0.6"
    ["rxnt-healthchecks-nestjs"]="1.0.2,1.0.3,1.0.4,1.0.5"
    ["rxnt-kue"]="1.0.4,1.0.5,1.0.6,1.0.7"
    ["swc-plugin-component-annotate"]="1.9.1,1.9.2"
    ["tbssnch"]="1.0.2"
    ["teselagen-interval-tree"]="1.1.2"
    ["tg-client-query-builder"]="2.14.4,2.14.5"
    ["tg-redbird"]="1.3.1,1.3.2"
    ["tg-seq-gen"]="1.0.9,1.0.10"
    ["thangved-react-grid"]="1.0.3"
    ["ts-gaussian"]="3.0.5,3.0.6"
    ["ts-imports"]="1.0.1,1.0.2"
    ["tvi-cli"]="0.1.5"
    ["ve-bamreader"]="0.2.6,0.2.7"
    ["ve-editor"]="1.0.1,1.0.2"
    ["verror-extra"]="6.0.1"
    ["voip-callkit"]="1.0.2,1.0.3"
    ["wdio-web-reporter"]="0.1.3"
    ["yargs-help-output"]="5.0.3"
    ["yoo-styles"]="6.0.326"
    ["devextreme-rpk"]="21.2.8"
    ["@basic-ui-components-stc/basic-ui-components"]="1.0.5"
)

# Function to find all package-lock.json files in a directory recursively
find_package_lock_files() {
    local dir_path="$1"
    local files=()
    
    if [ ! -d "$dir_path" ]; then
        log_message "ERROR" "Directory not found: $dir_path"
        return 1
    fi
    
    # Use find command to locate all package-lock.json files, excluding node_modules
    while IFS= read -r -d '' file; do
        files+=("$file")
    done < <(find "$dir_path" -name "package-lock.json" -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    printf '%s\n' "${files[@]}"
}

# Function to check if version is malicious
is_version_malicious() {
    local package_name=$1
    local version=$2
    
    if [[ -n "${MALICIOUS_PACKAGES[$package_name]}" ]]; then
        local malicious_versions="${MALICIOUS_PACKAGES[$package_name]}"
        IFS=',' read -ra VERSIONS <<< "$malicious_versions"
        for v in "${VERSIONS[@]}"; do
            if [[ "$version" == "$v" ]]; then
                return 0
            fi
        done
    fi
    return 1
}

# Function to extract package info from package-lock.json
extract_packages() {
    local file=$1
    
    if ! command -v jq >&2 >/dev/null; then
        log_message "ERROR" "jq is required but not installed. Please install jq to run this script."
        return 1
    fi
    
    # Extract packages from both root level and node_modules
    jq -r '
        (.packages // {}) as $packages |
        (.dependencies // {}) as $deps |
        
        # Process packages from lockfileVersion 2/3 format
        ($packages | to_entries[] | select(.key != "") | 
         {name: (.key | ltrimstr("node_modules/")), version: .value.version}) |
         
        # Process dependencies from lockfileVersion 1 format  
        if .name and .version then
            "\(.name)@\(.version)"
        else
            empty
        end,
        
        # Also handle lockfileVersion 1 format
        ($deps | to_entries[] | 
         {name: .key, version: .value.version} |
         if .name and .version then
            "\(.name)@\(.version)"
         else
            empty
         end)
    ' "$file" 2>/dev/null | sort -u
}

# Function to scan for malicious packages
scan_packages() {
    local file=$1
    local found_malicious=false
    local total_packages=0
    local malicious_count=0
    
    log_message "INFO" "Scanning $file for malicious packages..."
    log_message "INFO" "This scan checks for packages compromised in the Shai-Hulud npm supply chain attack"
    
    if [ ! -f "$file" ]; then
        log_message "ERROR" "File not found: $file"
        return 1
    fi
    
    # Check if file is valid JSON
    if ! jq . "$file" >/dev/null 2>&1; then
        log_message "ERROR" "Invalid JSON file: $file"
        return 1
    fi
    
    log_message "VERBOSE" "Extracting package information from $file"
    
    while IFS= read -r package_line; do
        if [[ -n "$package_line" ]]; then
            total_packages=$((total_packages + 1))
            
            # Extract package name and version
            if [[ "$package_line" =~ ^(.+)@([^@]+)$ ]]; then
                package_name="${BASH_REMATCH[1]}"
                version="${BASH_REMATCH[2]}"
                
                log_message "VERBOSE" "Checking $package_name@$version"
                
                if is_version_malicious "$package_name" "$version"; then
                    log_message "WARNING" "🚨 MALICIOUS PACKAGE DETECTED: $package_name@$version"
                    found_malicious=true
                    malicious_count=$((malicious_count + 1))
                fi
            fi
        fi
    done < <(extract_packages "$file")
    
    log_message "INFO" "Scan completed. Total packages checked: $total_packages"
    
    if [ "$found_malicious" = true ]; then
        log_message "ERROR" "⚠️  SECURITY ALERT: Found $malicious_count malicious package(s)!"
        log_message "ERROR" "These packages are part of the Shai-Hulud npm supply chain attack."
        log_message "ERROR" "IMMEDIATE ACTIONS REQUIRED:"
        log_message "ERROR" "1. Remove the malicious packages immediately"
        log_message "ERROR" "2. Rotate all access tokens for GitHub, NPM, AWS, GCP, and Azure"
        log_message "ERROR" "3. Check for unauthorized GitHub repositories named 'Shai-Hulud'"
        log_message "ERROR" "4. Scan your system with TruffleHog to detect any leaked secrets"
        log_message "ERROR" "5. Review recent npm publish activities on your account"
        return 1
    else
        log_message "SUCCESS" "✅ No malicious packages detected. Your project appears to be safe."
        return 0
    fi
}

# Function to scan all package-lock.json files in a directory
scan_all_packages() {
    local dir_path="$1"
    local total_files=0
    local files_with_threats=0
    local overall_result=0
    
    log_message "INFO" "Scanning all package-lock.json files in directory: $dir_path"
    
    # Get list of package-lock.json files
    local package_lock_files
    package_lock_files=$(find_package_lock_files "$dir_path")
    
    if [ -z "$package_lock_files" ]; then
        log_message "WARNING" "No package-lock.json files found in $dir_path"
        return 0
    fi
    
    # Count files
    local file_count
    file_count=$(echo "$package_lock_files" | wc -l)
    log_message "INFO" "Found $file_count package-lock.json file(s) to scan"
    
    # Process each file
    while IFS= read -r file_path; do
        if [ -n "$file_path" ]; then
            total_files=$((total_files + 1))
            log_message "INFO" ""
            log_message "INFO" "--- Scanning file $total_files/$file_count: $file_path ---"
            
            local result
            result=$(scan_packages "$file_path")
            if [ "$result" -ne 0 ]; then
                files_with_threats=$((files_with_threats + 1))
                overall_result=1  # At least one file has threats
            fi
        fi
    done <<< "$package_lock_files"
    
    log_message "INFO" ""
    log_message "INFO" "--- Scan Summary ---"
    log_message "INFO" "Total files scanned: $total_files"
    log_message "INFO" "Files with security threats: $files_with_threats"
    
    if [ $overall_result -eq 0 ]; then
        log_message "SUCCESS" "✅ All $total_files file(s) are clean - no malicious packages detected."
    else
        log_message "ERROR" "⚠️  SECURITY ALERT: $files_with_threats out of $total_files file(s) contain malicious packages!"
    fi
    
    return $overall_result
}

# Main function
main() {
    echo "================================================================"
    echo "  Shai-Hulud NPM Supply Chain Attack Scanner"
    echo "  Detecting malicious packages in npm dependencies"
    echo "================================================================"
    echo
    
    parse_arguments "$@"
    
    # Clear output file if specified
    if [ -n "$OUTPUT_FILE" ]; then
        > "$OUTPUT_FILE"
        log_message "INFO" "Results will be saved to: $OUTPUT_FILE"
    fi
    
    # Choose scanning mode
    if [ -n "$SCAN_DIR" ]; then
        scan_all_packages "$SCAN_DIR"
        scan_result=$?
    else
        log_message "INFO" "Scanning file: $PACKAGE_LOCK_FILE"
        scan_packages "$PACKAGE_LOCK_FILE"
        scan_result=$?
    fi
    
    echo
    echo "================================================================"
    echo "  Scan Summary"
    echo "================================================================"
    
    if [ $scan_result -eq 0 ]; then
        log_message "SUCCESS" "No security threats detected."
    else
        log_message "ERROR" "Security threats found! Please take immediate action."
        log_message "INFO" "For more information about this attack, visit:"
        log_message "INFO" "- https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/"
        log_message "INFO" "- https://github.com/trufflesecurity/trufflehog (for secret scanning)"
    fi
    
    if [ -n "$OUTPUT_FILE" ]; then
        log_message "INFO" "Detailed results saved to: $OUTPUT_FILE"
    fi
    
    exit $scan_result
}

# Function to create a simple package list checker (alternative method)
create_package_list() {
    local output_file="malicious_packages.txt"
    
    echo "Creating list of malicious packages..."
    
    cat > "$output_file" << 'EOF'
# Shai-Hulud NPM Supply Chain Attack - Malicious Package List
# Generated by shai-hulud scanner script
# Source: JFrog Security Research

@ahmedhfarag/ngx-perfect-scrollbar@20.0.20
@ahmedhfarag/ngx-virtual-scroller@4.0.4
@art-ws/common@2.0.28
@art-ws/config-eslint@2.0.4
@art-ws/config-eslint@2.0.5
@art-ws/config-ts@2.0.7
@art-ws/config-ts@2.0.8
@art-ws/db-context@2.0.24
@art-ws/di-node@2.0.13
@art-ws/di@2.0.28
@art-ws/di@2.0.32
@art-ws/eslint@1.0.5
@art-ws/eslint@1.0.6
@art-ws/fastify-http-server@2.0.24
@art-ws/fastify-http-server@2.0.27
@art-ws/http-server@2.0.21
@art-ws/http-server@2.0.25
@art-ws/openapi@0.1.9
@art-ws/openapi@0.1.12
@art-ws/package-base@1.0.5
@art-ws/package-base@1.0.6
@art-ws/prettier@1.0.5
@art-ws/prettier@1.0.6
@art-ws/slf@2.0.15
@art-ws/slf@2.0.22
@art-ws/ssl-info@1.0.9
@art-ws/ssl-info@1.0.10
@art-ws/web-app@1.0.3
@art-ws/web-app@1.0.4
@crowdstrike/commitlint@8.1.1
@crowdstrike/commitlint@8.1.2
@crowdstrike/falcon-shoelace@0.4.1
@crowdstrike/falcon-shoelace@0.4.2
@crowdstrike/foundry-js@0.19.1
@crowdstrike/foundry-js@0.19.2
@crowdstrike/glide-core@0.34.2
@crowdstrike/glide-core@0.34.3
@crowdstrike/logscale-dashboard@1.205.1
@crowdstrike/logscale-dashboard@1.205.2
@crowdstrike/logscale-file-editor@1.205.1
@crowdstrike/logscale-file-editor@1.205.2
@crowdstrike/logscale-parser-edit@1.205.1
@crowdstrike/logscale-parser-edit@1.205.2
@crowdstrike/logscale-search@1.205.1
@crowdstrike/logscale-search@1.205.2
@crowdstrike/tailwind-toucan-base@5.0.1
@crowdstrike/tailwind-toucan-base@5.0.2
@ctrl/deluge@7.2.1
@ctrl/deluge@7.2.2
@ctrl/golang-template@1.4.2
@ctrl/golang-template@1.4.3
@ctrl/magnet-link@4.0.3
@ctrl/magnet-link@4.0.4
@ctrl/ngx-codemirror@7.0.1
@ctrl/ngx-codemirror@7.0.2
@ctrl/ngx-csv@6.0.1
@ctrl/ngx-csv@6.0.2
@ctrl/ngx-emoji-mart@9.2.1
@ctrl/ngx-emoji-mart@9.2.2
@ctrl/ngx-rightclick@4.0.1
@ctrl/ngx-rightclick@4.0.2
@ctrl/qbittorrent@9.7.1
@ctrl/qbittorrent@9.7.2
@ctrl/react-adsense@2.0.1
@ctrl/react-adsense@2.0.2
@ctrl/shared-torrent@6.3.1
@ctrl/shared-torrent@6.3.2
@ctrl/tinycolor@4.1.1
@ctrl/tinycolor@4.1.2
@ctrl/torrent-file@4.1.1
@ctrl/torrent-file@4.1.2
@ctrl/transmission@7.3.1
@ctrl/ts-base32@4.0.1
@ctrl/ts-base32@4.0.2
angulartics2@14.1.1
angulartics2@14.1.2
encounter-playground@0.0.2
encounter-playground@0.0.3
encounter-playground@0.0.4
encounter-playground@0.0.5
json-rules-engine-simplified@0.2.1
json-rules-engine-simplified@0.2.3
json-rules-engine-simplified@0.2.4
koa2-swagger-ui@5.11.1
koa2-swagger-ui@5.11.2
@nativescript-community/gesturehandler@2.0.35
@nativescript-community/sentry@4.6.43
@nativescript-community/text@1.6.9
@nativescript-community/text@1.6.10
@nativescript-community/text@1.6.11
@nativescript-community/text@1.6.12
@nativescript-community/text@1.6.13
@nativescript-community/ui-collectionview@6.0.6
@nativescript-community/ui-drawer@0.1.30
@nativescript-community/ui-image@4.5.6
@nativescript-community/ui-material-bottomsheet@7.2.72
@nativescript-community/ui-material-core@7.2.72
@nativescript-community/ui-material-core@7.2.73
@nativescript-community/ui-material-core@7.2.74
@nativescript-community/ui-material-core@7.2.75
@nativescript-community/ui-material-core@7.2.76
@nativescript-community/ui-material-core-tabs@7.2.72
@nativescript-community/ui-material-core-tabs@7.2.73
@nativescript-community/ui-material-core-tabs@7.2.74
@nativescript-community/ui-material-core-tabs@7.2.75
@nativescript-community/ui-material-core-tabs@7.2.76
ngx-color@10.0.1
ngx-color@10.0.2
ngx-toastr@19.0.1
ngx-toastr@19.0.2
ngx-trend@8.0.1
react-complaint-image@0.0.32
react-complaint-image@0.0.34
react-complaint-image@0.0.35
react-jsonschema-form-conditionals@0.3.18
react-jsonschema-form-conditionals@0.3.20
react-jsonschema-form-conditionals@0.3.21
react-jsonschema-form-extras@1.0.3
react-jsonschema-form-extras@1.0.4
rxnt-authentication@0.0.3
rxnt-authentication@0.0.4
rxnt-authentication@0.0.5
rxnt-authentication@0.0.6
rxnt-healthchecks-nestjs@1.0.2
rxnt-healthchecks-nestjs@1.0.3
rxnt-healthchecks-nestjs@1.0.4
rxnt-healthchecks-nestjs@1.0.5
rxnt-kue@1.0.4
rxnt-kue@1.0.5
rxnt-kue@1.0.6
rxnt-kue@1.0.7
swc-plugin-component-annotate@1.9.1
swc-plugin-component-annotate@1.9.2
ts-gaussian@3.0.5
ts-gaussian@3.0.6
EOF

    echo "Malicious package list created: $output_file"
}

# Check for special arguments
if [[ "$1" == "--create-list" ]]; then
    create_package_list
    exit 0
fi

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi