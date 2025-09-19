#!/usr/bin/env node
/**
 * shai-hulud.js
 * Shai-Hulud NPM Supply Chain Attack Scanner (Node.js port)
 *
 * Usage:
 *   node shai-hulud.js
 *   node shai-hulud.js -f /path/to/package-lock.json -v -o results.txt
 *   node shai-hulud.js --create-list
 */

import fs from "fs";
import process from "process";
import { fileURLToPath } from "url";

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const NC = "\x1b[0m";

let PACKAGE_LOCK_FILE = "package-lock.json";
let VERBOSE = false;
let OUTPUT_FILE = "";

function nowTimestamp() {
  return new Date().toISOString().replace("T", " ").replace("Z", "");
}

function logToConsole(level, message) {
  switch (level) {
    case "ERROR":
      console.error(`${RED}[ERROR]${NC} ${message}`);
      break;
    case "WARNING":
      console.warn(`${YELLOW}[WARNING]${NC} ${message}`);
      break;
    case "SUCCESS":
      console.log(`${GREEN}[SUCCESS]${NC} ${message}`);
      break;
    case "INFO":
      console.log(`${BLUE}[INFO]${NC} ${message}`);
      break;
    case "VERBOSE":
      if (VERBOSE) console.log(`${BLUE}[VERBOSE]${NC} ${message}`);
      break;
    default:
      console.log(`${message}`);
  }
}

function log_message(level, message) {
  logToConsole(level, message);
  if (OUTPUT_FILE) {
    try {
      fs.appendFileSync(
        OUTPUT_FILE,
        `[${nowTimestamp()}] [${level}] ${message}\n`
      );
    } catch (err) {
      // If logging fails, just print an error to stderr but keep running.
      console.error(
        `${RED}[ERROR]${NC} Failed to write to output file ${OUTPUT_FILE}: ${err.message}`
      );
    }
  }
}

function show_help() {
  console.log(`
Shai-Hulud NPM Supply Chain Attack Scanner

This script scans package-lock.json files for malicious package versions
associated with the Shai-Hulud npm supply chain attack.

Usage: node shai-hulud.js [OPTIONS]

OPTIONS:
    -f, --file FILE         Specify package-lock.json file path (default: ./package-lock.json)
    -v, --verbose           Enable verbose output
    -o, --output FILE       Output results to file
    -h, --help              Show this help message
    --create-list           Create a text file listing malicious packages

Examples:
    node shai-hulud.js
    node shai-hulud.js -f /path/to/package-lock.json -v
    node shai-hulud.js --file ./project/package-lock.json --output scan_results.txt
`);
}

/**
 * Malicious package versions map (package -> comma-separated versions)
 * Copied from the bash script. Values are strings with comma separated versions.
 */
const MALICIOUS_PACKAGES = {
  "@ahmedhfarag/ngx-perfect-scrollbar": "20.0.20",
  "@ahmedhfarag/ngx-virtual-scroller": "4.0.4",
  "@art-ws/common": "2.0.28",
  "@art-ws/config-eslint": "2.0.4,2.0.5",
  "@art-ws/config-ts": "2.0.7,2.0.8",
  "@art-ws/db-context": "2.0.24",
  "@art-ws/di-node": "2.0.13",
  "@art-ws/di": "2.0.28,2.0.32",
  "@art-ws/eslint": "1.0.5,1.0.6",
  "@art-ws/fastify-http-server": "2.0.24,2.0.27",
  "@art-ws/http-server": "2.0.21,2.0.25",
  "@art-ws/openapi": "0.1.9,0.1.12",
  "@art-ws/package-base": "1.0.5,1.0.6",
  "@art-ws/prettier": "1.0.5,1.0.6",
  "@art-ws/slf": "2.0.15,2.0.22",
  "@art-ws/ssl-info": "1.0.9,1.0.10",
  "@art-ws/web-app": "1.0.3,1.0.4",
  "@crowdstrike/commitlint": "8.1.1,8.1.2",
  "@crowdstrike/falcon-shoelace": "0.4.1,0.4.2",
  "@crowdstrike/foundry-js": "0.19.1,0.19.2",
  "@crowdstrike/glide-core": "0.34.2,0.34.3",
  "@crowdstrike/logscale-dashboard": "1.205.1,1.205.2",
  "@crowdstrike/logscale-file-editor": "1.205.1,1.205.2",
  "@crowdstrike/logscale-parser-edit": "1.205.1,1.205.2",
  "@crowdstrike/logscale-search": "1.205.1,1.205.2",
  "@crowdstrike/tailwind-toucan-base": "5.0.1,5.0.2",
  "@ctrl/deluge": "7.2.1,7.2.2",
  "@ctrl/golang-template": "1.4.2,1.4.3",
  "@ctrl/magnet-link": "4.0.3,4.0.4",
  "@ctrl/ngx-codemirror": "7.0.1,7.0.2",
  "@ctrl/ngx-csv": "6.0.1,6.0.2",
  "@ctrl/ngx-emoji-mart": "9.2.1,9.2.2",
  "@ctrl/ngx-rightclick": "4.0.1,4.0.2",
  "@ctrl/qbittorrent": "9.7.1,9.7.2",
  "@ctrl/react-adsense": "2.0.1,2.0.2",
  "@ctrl/shared-torrent": "6.3.1,6.3.2",
  "@ctrl/tinycolor": "4.1.1,4.1.2",
  "@ctrl/torrent-file": "4.1.1,4.1.2",
  "@ctrl/transmission": "7.3.1",
  "@ctrl/ts-base32": "4.0.1,4.0.2",
  "@hestjs/core": "0.2.1",
  "@hestjs/cqrs": "0.1.6",
  "@hestjs/demo": "0.1.2",
  "@hestjs/eslint-config": "0.1.2",
  "@hestjs/logger": "0.1.6",
  "@hestjs/scalar": "0.1.7",
  "@hestjs/validation": "0.1.6",
  "@nativescript-community/arraybuffers": "1.1.6,1.1.7,1.1.8",
  "@nativescript-community/gesturehandler": "2.0.35",
  "@nativescript-community/perms": "3.0.5,3.0.6,3.0.7,3.0.8,3.0.9",
  "@nativescript-community/sentry": "4.6.43",
  "@nativescript-community/sqlite": "3.5.2,3.5.3,3.5.4,3.5.5",
  "@nativescript-community/text": "1.6.9,1.6.10,1.6.11,1.6.12,1.6.13",
  "@nativescript-community/typeorm": "0.2.30,0.2.31,0.2.32,0.2.33",
  "@nativescript-community/ui-collectionview": "6.0.6",
  "@nativescript-community/ui-document-picker": "1.1.27,1.1.28,13.0.32",
  "@nativescript-community/ui-drawer": "0.1.30",
  "@nativescript-community/ui-image": "4.5.6",
  "@nativescript-community/ui-label": "1.3.35,1.3.36,1.3.37",
  "@nativescript-community/ui-material-bottom-navigation":
    "7.2.72,7.2.73,7.2.74,7.2.75",
  "@nativescript-community/ui-material-bottomsheet": "7.2.72",
  "@nativescript-community/ui-material-core-tabs":
    "7.2.72,7.2.73,7.2.74,7.2.75,7.2.76",
  "@nativescript-community/ui-material-core":
    "7.2.72,7.2.73,7.2.74,7.2.75,7.2.76",
  "@nativescript-community/ui-material-ripple": "7.2.72,7.2.73,7.2.74,7.2.75",
  "@nativescript-community/ui-material-tabs": "7.2.72,7.2.73,7.2.74,7.2.75",
  "@nativescript-community/ui-pager": "14.1.36,14.1.37,14.1.38",
  "@nativescript-community/ui-pulltorefresh": "2.5.4,2.5.5,2.5.6,2.5.7",
  "@nexe/config-manager": "0.1.1",
  "@nexe/eslint-config": "0.1.1",
  "@nexe/logger": "0.1.3",
  "@nstudio/angular": "20.0.4,20.0.5,20.0.6",
  "@nstudio/focus": "20.0.4,20.0.5,20.0.6",
  "@nstudio/nativescript-checkbox": "2.0.6,2.0.7,2.0.8,2.0.9",
  "@nstudio/nativescript-loading-indicator": "5.0.1,5.0.2,5.0.3,5.0.4",
  "@nstudio/ui-collectionview": "5.1.11,5.1.12,5.1.13,5.1.14",
  "@nstudio/web-angular": "20.0.4",
  "@nstudio/web": "20.0.4",
  "@nstudio/xplat-utils": "20.0.5,20.0.6,20.0.7",
  "@nstudio/xplat": "20.0.5,20.0.6,20.0.7",
  "@operato/board":
    "9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46",
  "@operato/data-grist": "9.0.29,9.0.35,9.0.36,9.0.37",
  "@operato/graphql":
    "9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46",
  "@operato/headroom": "9.0.2,9.0.35,9.0.36,9.0.37",
  "@operato/help":
    "9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46",
  "@operato/i18n": "9.0.35,9.0.36,9.0.37",
  "@operato/input":
    "9.0.27,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.47,9.0.48",
  "@operato/layout": "9.0.35,9.0.36,9.0.37",
  "@operato/popup":
    "9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.49",
  "@operato/pull-to-refresh":
    "9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42",
  "@operato/shell": "9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39",
  "@operato/styles": "9.0.2,9.0.35,9.0.36,9.0.37",
  "@operato/utils":
    "9.0.22,9.0.35,9.0.36,9.0.37,9.0.38,9.0.39,9.0.40,9.0.41,9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.49",
  "@teselagen/bio-parsers": "0.4.29,0.4.30",
  "@teselagen/bounce-loader": "0.3.16,0.3.17",
  "@teselagen/file-utils": "0.3.21,0.3.22",
  "@teselagen/liquibase-tools": "0.4.1",
  "@teselagen/ove": "0.7.39,0.7.40",
  "@teselagen/range-utils": "0.3.14,0.3.15",
  "@teselagen/react-list": "0.8.19,0.8.20",
  "@teselagen/react-table": "6.10.19,6.10.20,6.10.21,6.10.22",
  "@teselagen/sequence-utils": "0.3.33,0.3.34",
  "@teselagen/ui": "0.9.9,0.9.10",
  "@thangved/callback-window": "1.1.4",
  "@things-factory/attachment-base":
    "9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.47,9.0.48,9.0.49,9.0.50,9.0.51,9.0.52,9.0.53,9.0.54,9.0.55",
  "@things-factory/auth-base": "9.0.42,9.0.43,9.0.44,9.0.45",
  "@things-factory/email-base":
    "9.0.42,9.0.43,9.0.44,9.0.45,9.0.46,9.0.47,9.0.48,9.0.49,9.0.50,9.0.51,9.0.52,9.0.53,9.0.54,9.0.55,9.0.56,9.0.57,9.0.58,9.0.59",
  "@things-factory/env": "9.0.42,9.0.43,9.0.44,9.0.45",
  "@things-factory/integration-base": "9.0.42,9.0.43,9.0.44,9.0.45",
  "@things-factory/integration-marketplace": "9.0.42,9.0.43,9.0.44,9.0.45",
  "@things-factory/shell": "9.0.42,9.0.43,9.0.44,9.0.45",
  "@tnf-dev/api": "1.0.8",
  "@tnf-dev/core": "1.0.8",
  "@tnf-dev/js": "1.0.8",
  "@tnf-dev/mui": "1.0.8",
  "@tnf-dev/react": "1.0.8",
  "@ui-ux-gang/devextreme-angular-rpk": "24.1.7",
  "@yoobic/design-system": "6.5.17",
  "@yoobic/jpeg-camera-es6": "1.0.13",
  "@yoobic/yobi": "8.7.53",
  airchief: "0.3.1",
  airpilot: "0.8.8",
  angulartics2: "14.1.1,14.1.2",
  "browser-webdriver-downloader": "3.0.8",
  "capacitor-notificationhandler": "0.0.2,0.0.3",
  "capacitor-plugin-healthapp": "0.0.2,0.0.3",
  "capacitor-plugin-ihealth": "1.1.8,1.1.9",
  "capacitor-plugin-vonage": "1.0.2,1.0.3",
  capacitorandroidpermissions: "0.0.4,0.0.5",
  "config-cordova": "0.8.5",
  "cordova-plugin-voxeet2": "1.0.24",
  "cordova-voxeet": "1.0.32",
  "create-hest-app": "0.1.9",
  "db-evo": "1.1.4,1.1.5",
  "devextreme-angular-rpk": "21.2.8",
  "ember-browser-services": "5.0.2,5.0.3",
  "ember-headless-form-yup": "1.0.1",
  "ember-headless-form": "1.1.2,1.1.3",
  "ember-headless-table": "2.1.5,2.1.6",
  "ember-url-hash-polyfill": "1.0.12,1.0.13",
  "ember-velcro": "2.2.1,2.2.2",
  "encounter-playground": "0.0.2,0.0.3,0.0.4,0.0.5",
  "eslint-config-crowdstrike-node": "4.0.3,4.0.4",
  "eslint-config-crowdstrike": "11.0.2,11.0.3",
  "eslint-config-teselagen": "6.1.7,6.1.8",
  "globalize-rpk": "1.7.4",
  "graphql-sequelize-teselagen": "5.3.8,5.3.9",
  "html-to-base64-image": "1.0.2",
  "json-rules-engine-simplified": "0.2.1,0.2.3,0.2.4",
  jumpgate: "0.0.2",
  "koa2-swagger-ui": "5.11.1,5.11.2",
  "mcfly-semantic-release": "1.3.1",
  "mcp-knowledge-base": "0.0.2",
  "mcp-knowledge-graph": "1.2.1",
  "mobioffice-cli": "1.0.3",
  "monorepo-next": "13.0.1,13.0.2",
  "mstate-angular": "0.4.4",
  "mstate-cli": "0.4.7",
  "mstate-dev-react": "1.1.1",
  "mstate-react": "1.6.5",
  "ng2-file-upload": "7.0.2,7.0.3,8.0.1,8.0.2,8.0.3,9.0.1",
  "ngx-bootstrap": "18.1.4,19.0.3,19.0.4,20.0.3,20.0.4,20.0.5,20.0.6",
  "ngx-color": "10.0.1,10.0.2",
  "ngx-toastr": "19.0.1,19.0.2",
  "ngx-trend": "8.0.1",
  "ngx-ws": "1.1.5,1.1.6",
  "oradm-to-gql": "35.0.14,35.0.15",
  "oradm-to-sqlz": "1.1.2,1.1.4",
  "ove-auto-annotate": "0.0.9,0.0.10",
  "pm2-gelf-json": "1.0.4,1.0.5",
  "printjs-rpk": "1.6.1",
  "react-complaint-image": "0.0.32,0.0.34,0.0.35",
  "react-jsonschema-form-conditionals": "0.3.18,0.3.20,0.3.21",
  "react-jsonschema-form-extras": "1.0.3,1.0.4",
  "react-jsonschema-rxnt-extras": "0.4.8,0.4.9",
  "remark-preset-lint-crowdstrike": "4.0.1,4.0.2",
  "rxnt-authentication": "0.0.3,0.0.4,0.0.5,0.0.6",
  "rxnt-healthchecks-nestjs": "1.0.2,1.0.3,1.0.4,1.0.5",
  "rxnt-kue": "1.0.4,1.0.5,1.0.6,1.0.7",
  "swc-plugin-component-annotate": "1.9.1,1.9.2",
  tbssnch: "1.0.2",
  "teselagen-interval-tree": "1.1.2",
  "tg-client-query-builder": "2.14.4,2.14.5",
  "tg-redbird": "1.3.1,1.3.2",
  "tg-seq-gen": "1.0.9,1.0.10",
  "thangved-react-grid": "1.0.3",
  "ts-gaussian": "3.0.5,3.0.6",
  "ts-imports": "1.0.1,1.0.2",
  "tvi-cli": "0.1.5",
  "ve-bamreader": "0.2.6,0.2.7",
  "ve-editor": "1.0.1,1.0.2",
  "verror-extra": "6.0.1",
  "voip-callkit": "1.0.2,1.0.3",
  "wdio-web-reporter": "0.1.3",
  "yargs-help-output": "5.0.3",
  "yoo-styles": "6.0.326",
  "devextreme-rpk": "21.2.8",
  "@basic-ui-components-stc/basic-ui-components": "1.0.5",
};

/**
 * Check if given packageName@version matches malicious list
 */
function is_version_malicious(packageName, version) {
  if (!packageName || !version) return false;
  const versions = MALICIOUS_PACKAGES[packageName];
  if (!versions) return false;
  const allowed = versions.split(",").map((v) => v.trim());
  return allowed.includes(version);
}

/**
 * Extract packages from package-lock.json
 * Handles lockfile v2/v3 (packages object) and v1 (dependencies tree).
 * Returns Set of strings "name@version"
 */
function extract_packages(lockJson) {
  const results = new Set();

  try {
    // v2/v3: "packages" object mapping "" and "node_modules/..." -> { version: "x.y.z", ... }
    if (
      lockJson &&
      typeof lockJson === "object" &&
      lockJson.packages &&
      typeof lockJson.packages === "object"
    ) {
      Object.entries(lockJson.packages).forEach(([key, val]) => {
        // skip root entry without version
        if (!val || !val.version) return;
        let name = key;
        if (name.startsWith("node_modules/")) {
          name = name.substring("node_modules/".length);
        } else if (name === "") {
          // root package; no package name in lockfile "packages['']" — skip
          return;
        }
        results.add(`${name}@${val.version}`);
      });
    }

    // v1: "dependencies" tree — recursively traverse
    if (
      lockJson &&
      lockJson.dependencies &&
      typeof lockJson.dependencies === "object"
    ) {
      function recurseDeps(deps) {
        Object.entries(deps).forEach(([depName, depVal]) => {
          if (!depVal) return;
          if (depVal.version) {
            results.add(`${depName}@${depVal.version}`);
          }
          // some entries may contain a 'requires' object but nested dependencies are under 'dependencies'
          if (depVal.dependencies && typeof depVal.dependencies === "object") {
            recurseDeps(depVal.dependencies, depName);
          }
        });
      }
      recurseDeps(lockJson.dependencies, null);
    }

    // Also try top-level "packages" alternative: some lockfiles might have "packages" as array (rare). We do not handle arrays specially.
  } catch (err) {
    // Return whatever we collected; caller will detect issues if needed
    log_message("VERBOSE", `Error while extracting packages: ${err.message}`);
  }

  return results;
}

/**
 * Scan packages and report malicious ones
 */
function scan_packages(filePath) {
  log_message("INFO", `Scanning ${filePath} for malicious packages...`);
  log_message(
    "INFO",
    `This scan checks for packages compromised in the Shai-Hulud npm supply chain attack`
  );

  if (!fs.existsSync(filePath)) {
    log_message("ERROR", `File not found: ${filePath}`);
    return 1;
  }

  let raw;
  try {
    raw = fs.readFileSync(filePath, { encoding: "utf8" });
  } catch (err) {
    log_message("ERROR", `Failed to read file: ${err.message}`);
    return 1;
  }

  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    log_message("ERROR", `Invalid JSON file: ${filePath}`);
    return 1;
  }

  log_message("VERBOSE", `Extracting package information from ${filePath}`);
  const pkgSet = extract_packages(json);
  let total_packages = 0;
  let malicious_count = 0;
  let found_malicious = false;

  for (const pkg of Array.from(pkgSet).sort()) {
    if (!pkg) continue;
    total_packages++;
    const match = pkg.match(/^(.+)@([^@]+)$/);
    if (!match) continue;
    const package_name = match[1];
    const version = match[2];
    log_message("VERBOSE", `Checking ${package_name}@${version}`);
    if (is_version_malicious(package_name, version)) {
      log_message(
        "WARNING",
        `🚨 MALICIOUS PACKAGE DETECTED: ${package_name}@${version}`
      );
      found_malicious = true;
      malicious_count++;
    }
  }

  log_message(
    "INFO",
    `Scan completed. Total packages checked: ${total_packages}`
  );

  if (found_malicious) {
    log_message(
      "ERROR",
      `⚠️  SECURITY ALERT: Found ${malicious_count} malicious package(s)!`
    );
    log_message(
      "ERROR",
      `These packages are part of the Shai-Hulud npm supply chain attack.`
    );
    log_message("ERROR", `IMMEDIATE ACTIONS REQUIRED:`);
    log_message("ERROR", `1. Remove the malicious packages immediately`);
    log_message(
      "ERROR",
      `2. Rotate all access tokens for GitHub, NPM, AWS, GCP, and Azure`
    );
    log_message(
      "ERROR",
      `3. Check for unauthorized GitHub repositories named 'Shai-Hulud'`
    );
    log_message(
      "ERROR",
      `4. Scan your system with TruffleHog to detect any leaked secrets`
    );
    log_message(
      "ERROR",
      `5. Review recent npm publish activities on your account`
    );
    return 1;
  } else {
    log_message(
      "SUCCESS",
      `✅ No malicious packages detected. Your project appears to be safe.`
    );
    return 0;
  }
}

/**
 * Create a simple malicious package list file (malicious_packages.txt)
 */
function create_package_list() {
  const output_file = "malicious_packages.txt";
  const header = `# Shai-Hulud NPM Supply Chain Attack - Malicious Package List
# Generated by shai-hulud scanner script
# Source: JFrog Security Research

`;
  try {
    const lines = [header];
    // Expand each package -> create individual package@version lines for each version in the CSV
    for (const [pkg, versionsCsv] of Object.entries(MALICIOUS_PACKAGES)) {
      const versions = versionsCsv
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);
      for (const v of versions) {
        lines.push(`${pkg}@${v}`);
      }
    }
    fs.writeFileSync(output_file, lines.join("\n") + "\n", {
      encoding: "utf8",
    });
    console.log(`Malicious package list created: ${output_file}`);
    return 0;
  } catch (err) {
    console.error(`${RED}[ERROR]${NC} Failed to create list: ${err.message}`);
    return 1;
  }
}

/**
 * Parse CLI arguments
 */
function parse_arguments(argv) {
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case "-f":
      case "--file":
        i++;
        if (i >= args.length) {
          console.error(`${RED}[ERROR]${NC} Missing argument for ${a}`);
          process.exit(1);
        }
        PACKAGE_LOCK_FILE = args[i];
        break;
      case "-v":
      case "--verbose":
        VERBOSE = true;
        break;
      case "-o":
      case "--output":
        i++;
        if (i >= args.length) {
          console.error(`${RED}[ERROR]${NC} Missing argument for ${a}`);
          process.exit(1);
        }
        OUTPUT_FILE = args[i];
        // initially clear file
        try {
          fs.writeFileSync(OUTPUT_FILE, "", { encoding: "utf8" });
        } catch (err) {
          console.error(
            `${RED}[ERROR]${NC} Could not write to output file ${OUTPUT_FILE}: ${err.message}`
          );
          process.exit(1);
        }
        break;
      case "-h":
      case "--help":
        show_help();
        process.exit(0);
      case "--create-list":
        const rc = create_package_list();
        process.exit(rc);
      default:
        console.error(`${RED}[ERROR]${NC} Unknown option: ${a}`);
        show_help();
        process.exit(1);
    }
  }
}

/**
 * Main
 */
function main() {
  console.log(
    "================================================================"
  );
  console.log("  Shai-Hulud NPM Supply Chain Attack Scanner");
  console.log("  Detecting malicious packages in npm dependencies");
  console.log(
    "================================================================\n"
  );

  parse_arguments(process.argv);

  if (OUTPUT_FILE) {
    log_message("INFO", `Results will be saved to: ${OUTPUT_FILE}`);
  }

  const result = scan_packages(PACKAGE_LOCK_FILE);

  console.log(
    "\n================================================================"
  );
  console.log("  Scan Summary");
  console.log(
    "================================================================"
  );

  if (result === 0) {
    log_message("SUCCESS", "No security threats detected.");
  } else {
    log_message(
      "ERROR",
      "Security threats found! Please take immediate action."
    );
    log_message("INFO", "For more information about this attack, visit:");
    log_message(
      "INFO",
      "- https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/"
    );
    log_message(
      "INFO",
      "- https://github.com/trufflesecurity/trufflehog (for secret scanning)"
    );
  }

  if (OUTPUT_FILE) {
    log_message("INFO", `Detailed results saved to: ${OUTPUT_FILE}`);
  }

  process.exit(result);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
