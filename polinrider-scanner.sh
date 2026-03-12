#!/bin/bash
#
# PolinRider Malware Scanner v1.0
# https://opensourcemalware.com
#
# Scans local git repositories for evidence of PolinRider malware infection.
# PolinRider appends obfuscated JS payloads to config files and uses
# temp_auto_push.bat to amend commits and force-push to GitHub.
#
# Usage:
#   ./polinrider-scanner.sh                        # Scan current directory
#   ./polinrider-scanner.sh /path/to/projects      # Scan specific directory
#   ./polinrider-scanner.sh --verbose /path         # Verbose output
#
# Exit codes:
#   0 - No infections found
#   1 - Infections found
#   2 - Error (invalid path, etc.)

set -u

VERSION="1.0"
VERBOSE=0
JS_ALL=0
SCAN_DIR=""

# PolinRider signatures
PRIMARY_SIG='("rmcej%otb%",2857687)'
SECONDARY_SIG="global['!']='8-270-2';var _\$_1e42="

# Config files targeted by PolinRider
CONFIG_FILES="postcss.config.mjs postcss.config.js tailwind.config.js eslint.config.mjs next.config.mjs next.config.ts babel.config.js"

# Colors (disabled if not a terminal)
RED=""
GREEN=""
YELLOW=""
CYAN=""
BOLD=""
RESET=""

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
fi

# Counters
TOTAL_REPOS=0
INFECTED_REPOS=0
INFECTED_REPO_PATHS=""

print_banner() {
    printf "\n"
    printf "${BOLD}========================================${RESET}\n"
    printf "${BOLD}  PolinRider Malware Scanner v%s${RESET}\n" "$VERSION"
    printf "${BOLD}  https://opensourcemalware.com${RESET}\n"
    printf "${BOLD}========================================${RESET}\n"
    printf "\n"
}

print_usage() {
    printf "Usage: %s [--verbose] [--js-all] [directory]\n" "$0"
    printf "\n"
    printf "Scans git repositories for PolinRider malware artifacts.\n"
    printf "\n"
    printf "Options:\n"
    printf "  --verbose    Show detailed output for each repository\n"
    printf "  --js-all     Scan all .js files (not just known config files)\n"
    printf "  --help       Show this help message\n"
    printf "\n"
    printf "Examples:\n"
    printf "  %s                          # Scan current directory\n" "$0"
    printf "  %s /path/to/projects        # Scan specific directory\n" "$0"
    printf "  %s --verbose ~/projects     # Verbose scan\n" "$0"
    printf "  %s --js-all ~/projects      # Scan all .js files\n" "$0"
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        printf "  ${CYAN}[verbose]${RESET} %s\n" "$1"
    fi
}

scan_repo() {
    local repo_dir="$1"
    local findings=""
    local finding_count=0

    log_verbose "Scanning repo: $repo_dir"

    # Check config files for PolinRider payload
    # Save/restore IFS since caller may have changed it
    local old_ifs="$IFS"
    IFS=' '
    for config_file in $CONFIG_FILES; do
        local filepath="${repo_dir}/${config_file}"
        if [ -f "$filepath" ]; then
            log_verbose "Checking $config_file"
            if grep -qF "$PRIMARY_SIG" "$filepath" 2>/dev/null; then
                findings="${findings}  ${RED}-${RESET} ${BOLD}${config_file}${RESET}: PolinRider payload detected (primary signature)\n"
                finding_count=$((finding_count + 1))
            elif grep -qF "$SECONDARY_SIG" "$filepath" 2>/dev/null; then
                findings="${findings}  ${RED}-${RESET} ${BOLD}${config_file}${RESET}: PolinRider payload detected (secondary signature)\n"
                finding_count=$((finding_count + 1))
            fi
        fi
    done
    IFS="$old_ifs"

    # If --js-all, scan all .js files in the repo for signatures
    if [ "$JS_ALL" -eq 1 ]; then
        while IFS= read -r jsfile; do
            if [ -f "$jsfile" ]; then
                local relpath="${jsfile#${repo_dir}/}"
                # Skip node_modules and .git
                case "$relpath" in
                    node_modules/*|.git/*) continue ;;
                esac
                log_verbose "Checking $relpath"
                if grep -qF "$PRIMARY_SIG" "$jsfile" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: PolinRider payload detected (primary signature)\n"
                    finding_count=$((finding_count + 1))
                elif grep -qF "$SECONDARY_SIG" "$jsfile" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: PolinRider payload detected (secondary signature)\n"
                    finding_count=$((finding_count + 1))
                fi
            fi
        done <<JSEOF
$(find "$repo_dir" -name "*.js" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
JSEOF
    fi

    # Check for temp_auto_push.bat
    if [ -f "${repo_dir}/temp_auto_push.bat" ]; then
        findings="${findings}  ${RED}-${RESET} ${BOLD}temp_auto_push.bat${RESET}: Propagation script found\n"
        finding_count=$((finding_count + 1))
    fi

    # Check for config.bat
    if [ -f "${repo_dir}/config.bat" ]; then
        findings="${findings}  ${RED}-${RESET} ${BOLD}config.bat${RESET}: Hidden orchestrator found\n"
        finding_count=$((finding_count + 1))
    fi

    # Check .gitignore for config.bat entry
    if [ -f "${repo_dir}/.gitignore" ]; then
        if grep -qxF "config.bat" "${repo_dir}/.gitignore" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}.gitignore${RESET}: config.bat entry injected\n"
            finding_count=$((finding_count + 1))
        fi
    fi

    # Check git reflog for suspicious patterns
    local reflog_findings=0
    if [ -d "${repo_dir}/.git" ]; then
        # Check for --no-verify usage
        if git -C "$repo_dir" reflog 2>/dev/null | grep -q "amend"; then
            log_verbose "Found amend entries in reflog"
            # Only flag if combined with other findings
            if [ "$finding_count" -gt 0 ]; then
                findings="${findings}  ${YELLOW}-${RESET} ${BOLD}git reflog${RESET}: Amended commits found (consistent with PolinRider behavior)\n"
                reflog_findings=1
            fi
        fi
    fi

    # Report findings
    if [ "$finding_count" -gt 0 ]; then
        printf "\n${RED}${BOLD}[INFECTED]${RESET} %s\n" "$repo_dir"
        printf "$findings"
        INFECTED_REPOS=$((INFECTED_REPOS + 1))
        INFECTED_REPO_PATHS="${INFECTED_REPO_PATHS}${repo_dir}\n"
        return 1
    else
        log_verbose "Clean: $repo_dir"
        return 0
    fi
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --verbose)
            VERBOSE=1
            shift
            ;;
        --js-all)
            JS_ALL=1
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        -*)
            printf "Error: Unknown option '%s'\n" "$1" >&2
            print_usage >&2
            exit 2
            ;;
        *)
            if [ -n "$SCAN_DIR" ]; then
                printf "Error: Multiple directories specified\n" >&2
                print_usage >&2
                exit 2
            fi
            SCAN_DIR="$1"
            shift
            ;;
    esac
done

# Default to current directory
if [ -z "$SCAN_DIR" ]; then
    SCAN_DIR="."
fi

# Resolve to absolute path
SCAN_DIR="$(cd "$SCAN_DIR" 2>/dev/null && pwd)"
if [ $? -ne 0 ] || [ ! -d "$SCAN_DIR" ]; then
    printf "Error: Directory not found or not accessible: %s\n" "$SCAN_DIR" >&2
    exit 2
fi

print_banner

printf "Scanning: ${BOLD}%s${RESET}\n" "$SCAN_DIR"

# Find all git repositories
REPO_LIST=""
while IFS= read -r git_dir; do
    repo_dir="$(dirname "$git_dir")"
    REPO_LIST="${REPO_LIST}${repo_dir}
"
    TOTAL_REPOS=$((TOTAL_REPOS + 1))
done <<EOF
$(find "$SCAN_DIR" -name .git -type d 2>/dev/null | sort)
EOF

# Remove trailing newline
REPO_LIST="${REPO_LIST%
}"

if [ "$TOTAL_REPOS" -eq 0 ]; then
    printf "No git repositories found under %s\n" "$SCAN_DIR"
    exit 0
fi

printf "Found ${BOLD}%d${RESET} git repositories...\n" "$TOTAL_REPOS"

# Scan each repo
while IFS= read -r repo; do
    if [ -n "$repo" ]; then
        scan_repo "$repo"
    fi
done <<REPOEOF
$REPO_LIST
REPOEOF

# Print summary
CLEAN_REPOS=$((TOTAL_REPOS - INFECTED_REPOS))
printf "\n"

if [ "$CLEAN_REPOS" -gt 0 ]; then
    printf "${GREEN}${BOLD}[CLEAN]${RESET} %d repositories scanned clean\n" "$CLEAN_REPOS"
fi

printf "\n${BOLD}========================================${RESET}\n"
if [ "$INFECTED_REPOS" -gt 0 ]; then
    printf "  ${RED}${BOLD}RESULTS: %d infected repo(s) found${RESET}\n" "$INFECTED_REPOS"
else
    printf "  ${GREEN}${BOLD}RESULTS: No infections found${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n"

if [ "$INFECTED_REPOS" -gt 0 ]; then
    printf "\n${BOLD}REMEDIATION STEPS:${RESET}\n"
    printf "1. Remove the obfuscated payload from the end of infected config files\n"
    printf "   (everything after the legitimate config, starting with \"global['!']\")\n"
    printf "2. Delete temp_auto_push.bat and config.bat if present\n"
    printf "3. Remove \"config.bat\" from .gitignore\n"
    printf "4. Check your npm global packages and VS Code extensions for the initial dropper\n"
    printf "5. Force-push clean versions to GitHub\n"
    printf "6. Report to https://opensourcemalware.com\n"
    printf "\n"
    exit 1
fi

printf "\n"
exit 0
