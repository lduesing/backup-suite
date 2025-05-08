#!/bin/bash

# ==============================================================================
# Restic Repository Maintenance Script
# ==============================================================================
# Description:
# Performs maintenance tasks (forget --prune, check) on Restic repositories
# managed by the backup_server.sh script. Reads configuration from the
# central backup config file to locate repositories and password file.
# Uses file locking to prevent concurrent runs. Supports dry-run for forget.
# Adheres to Google Shell Style Guide. Root privileges required.
#
# Installation Path: /opt/backup/bin/restic_maintenance.sh
#
# License: AGPL-3.0-or-later
# Copyright (c) Lars Duesing <lars.duesing@camelotsweb.de>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Author: Lars Duesing <lars.duesing@camelotsweb.de>
# Date: 2025-05-02
# Version: 0.1
# ==============================================================================

# --- Script Metadata and Constants ---
readonly SCRIPT_VERSION="0.1"
readonly SCRIPT_NAME=$(basename "$0")
# Path to the *server's* main backup configuration file
readonly CENTRAL_CONFIG_FILE="/etc/backup/server_config.yml" # Use server config
# Path to common config for tool paths etc.
readonly COMMON_CONFIG_FILE="/etc/backup/common_config"
# Lock file location (different from the main backup script's lock)
readonly LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
readonly LOCK_FD_NUM=201 # Use a different FD number

# Default Restic forget policy (can be overridden in server_config.yml)
readonly DEFAULT_RESTIC_FORGET_POLICY="--keep-daily 7 --keep-weekly 4 --keep-monthly 12 --keep-yearly 3"

# --- Script Flags and State Variables ---
verbose=0; show_help=0; show_version=0; dry_run=0
# Config variables
RESTIC_REPO_ROOT=""; RESTIC_PW_FILE=""; RESTIC_CMD=""
RESTIC_FORGET_POLICY=""; RESTIC_PRUNE="true"; RESTIC_CHECK="true"; RESTIC_CHECK_OPTIONS=""
YQ_CMD=""
# Runtime state
tmp_log_file=""
declare -a HOSTS_CONFIG_MAINT=() # Array to hold host JSON chunks
declare -a FAILED_REPOS=() # Track repos that failed maintenance

# --- Shell Options ---
set -eo pipefail

# --- Source Common Functions (Minimal logging if not found) ---
COMMON_FUNCTIONS_SCRIPT_PATH="/opt/backup/lib/plugins/common_functions.sh" # Assuming installed path
if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
else
    echo "WARNING: common_functions.sh not found at '$COMMON_FUNCTIONS_SCRIPT_PATH', using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [Maint] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }
fi

# --- Function Definitions ---

# Display Help Message
show_help() {
  cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Performs Restic maintenance (forget --prune, check) on repositories defined
in '${CENTRAL_CONFIG_FILE}'. Uses file locking '${LOCK_FILE}'.

Options:
  -d, --dry-run    Enable dry-run mode for 'restic forget --prune'. Shows what
                   would be removed without actually removing anything. 'restic check'
                   will still run as it doesn't modify data.
  -v, --verbose    Enable verbose output (shows DEBUG messages and restic verbose output).
  -h, --help       Display this help message and exit.
  -V, --version    Display script version (${SCRIPT_VERSION}) and exit.

Configuration:
  Reads Restic settings and the hosts list from '${CENTRAL_CONFIG_FILE}'.
  Reads tool paths from '${COMMON_CONFIG_FILE}'.

Prerequisites:
  restic, yq (v4+), flock, standard coreutils. Root privileges required.

Example:
  sudo ${SCRIPT_NAME} -v        # Run maintenance with verbose output.
  sudo ${SCRIPT_NAME} --dry-run  # Simulate forget/prune actions.
EOF
}

# Display Version
show_version() { echo "${SCRIPT_NAME} Version ${SCRIPT_VERSION}"; }

# Check File Permissions (Sourced or minimal definition)
if ! command -v check_perms &> /dev/null; then
  check_perms() { log_detail "Permissions check skipped (common_functions.sh not found)."; return 0; }
fi

# --- Trap Functions ---

# ERR Trap Handler: Captures context on command failure
trap_err_handler() { error_lineno=${BASH_LINENO[0]}; error_command=${BASH_COMMAND}; local i; error_funcstack=(); for ((i=0; i < ${#FUNCNAME[@]}; i++)); do error_funcstack+=("${FUNCNAME[$i]:-main}:${BASH_LINENO[$i+1]}"); done; log_detail "Error context captured: Line ${error_lineno}, Command '${error_command}'"; }

# EXIT Trap Handler: Cleanup log file
trap_exit_handler() {
  local exit_code=$?; set +e
  log_detail "--- Running Maintenance EXIT trap (Exit code: ${exit_code}) ---"

  if [[ "$exit_code" -ne 0 ]]; then
      log_error "Restic maintenance script finished with ERROR (Exit Code: ${exit_code})."
      if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then echo "Log file kept for analysis: ${tmp_log_file}" >&2; fi
      # Consider sending an email on failure here too, using ADMIN_EMAIL_GLOBAL if loaded
  else
      log_info "Restic maintenance script finished successfully."
      if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then rm -f "$tmp_log_file"; fi
  fi

  # --- Release Lock and Exit ---
  log_detail "Exiting maintenance script. Lock will be released (FD ${LOCK_FD_NUM})."
  exit "${exit_code}"
}

# --- Main Function Definition ---
main() {
  # --- Setup Logging & Traps ---
  tmp_log_file=$(mktemp /tmp/local_backup_log."$SCRIPT_NAME".XXXXXX); chmod 600 "$tmp_log_file"
  exec > >(tee -a "$tmp_log_file") 2>&1 # Redirect stdout/stderr
  trap trap_err_handler ERR
  trap trap_exit_handler EXIT # Handles log cleanup and lock release on exit

  # --- Start Process ---
  log_info "============================================================"
  log_info "Starting Restic Maintenance Script (Version ${SCRIPT_VERSION}) - Locked (PID $$)"
  if [[ "${dry_run}" -eq 1 ]]; then log_info "*** DRY-RUN MODE ACTIVATED (Applies to forget --prune) ***"; fi

  # --- Load Common Config ---
  log_info "Loading common configuration from ${COMMON_CONFIG_FILE}..."
  if [[ ! -f "$COMMON_CONFIG_FILE" ]]; then log_error "Common config file '${COMMON_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${COMMON_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${COMMON_CONFIG_FILE}'. Requires 600 owned by root."; exit 1; fi
  local source_exit_code; set +e; source "${COMMON_CONFIG_FILE}"; source_exit_code=$?; set -e
  if [[ ${source_exit_code} -ne 0 ]]; then log_error "Failed to source common config file '${COMMON_CONFIG_FILE}'. Syntax error?"; exit 1; fi
  log_detail "Common configuration sourced."

  # --- Load Server Config (YAML) ---
  log_info "Loading server configuration from ${SERVER_CONFIG_FILE}..."
  if [[ ! -f "$SERVER_CONFIG_FILE" ]]; then log_error "Server config file '${SERVER_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${SERVER_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${SERVER_CONFIG_FILE}'. Requires 600 owned by root."; exit 1; fi
  # Set defaults for tool paths before reading overrides
  YQ_CMD="${YQ_CMD:-yq}"; RESTIC_CMD="${RESTIC_CMD:-restic}"
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('$YQ_CMD') not found. Cannot parse server config."; exit 1; fi
  if ! command -v "$RESTIC_CMD" &>/dev/null; then log_error "restic command ('$RESTIC_CMD') not found."; exit 1; fi

  # Read Restic settings from YAML, overriding common defaults if present
  local repo_root_yml; repo_root_yml=$("$YQ_CMD" e '.restic.repository_root // ""' "$SERVER_CONFIG_FILE"); [[ -n "$repo_root_yml" ]] && RESTIC_REPO_ROOT="$repo_root_yml"
  local pw_file_yml; pw_file_yml=$("$YQ_CMD" e '.restic."password_file" // ""' "$SERVER_CONFIG_FILE"); [[ -n "$pw_file_yml" ]] && RESTIC_PW_FILE="$pw_file_yml"
  local restic_cmd_yml; restic_cmd_yml=$("$YQ_CMD" e '.restic.restic_cmd // ""' "$SERVER_CONFIG_FILE"); [[ -n "$restic_cmd_yml" ]] && RESTIC_CMD="$restic_cmd_yml"
  # Read maintenance specific settings
  RESTIC_FORGET_POLICY=$("$YQ_CMD" e '.restic.maintenance.forget_policy // ""' "$SERVER_CONFIG_FILE")
  RESTIC_PRUNE=$("$YQ_CMD" e '.restic.maintenance.prune // "true"' "$SERVER_CONFIG_FILE") # Default to true
  RESTIC_CHECK=$("$YQ_CMD" e '.restic.maintenance.check // "true"' "$SERVER_CONFIG_FILE") # Default to true
  RESTIC_CHECK_OPTIONS=$("$YQ_CMD" e '.restic.maintenance.check_options // ""' "$SERVER_CONFIG_FILE")

  # --- Validate Restic Config ---
  log_info "Validating Restic configuration..."
  local validation_ok=1 # Use local var
  if [[ -z "$RESTIC_REPO_ROOT" ]] || [[ ! -d "$RESTIC_REPO_ROOT" ]]; then log_error "Config Error: restic.repository_root ('$RESTIC_REPO_ROOT') is invalid or missing."; validation_ok=0; fi
  if [[ -z "$RESTIC_PW_FILE" ]]; then log_error "Config Error: restic.password_file is not set."; validation_ok=0; elif ! check_perms "$RESTIC_PW_FILE" "600" "root"; then log_error "Config Error: Restic password file '$RESTIC_PW_FILE' requires 600 root:root."; validation_ok=0; fi
  if [[ "$RESTIC_PRUNE" != "true" ]] && [[ "$RESTIC_PRUNE" != "false" ]]; then log_error "Config Error: restic.maintenance.prune must be true or false."; validation_ok=0; fi
  if [[ "$RESTIC_CHECK" != "true" ]] && [[ "$RESTIC_CHECK" != "false" ]]; then log_error "Config Error: restic.maintenance.check must be true or false."; validation_ok=0; fi
  if [[ -z "$RESTIC_FORGET_POLICY" ]]; then RESTIC_FORGET_POLICY="$DEFAULT_RESTIC_FORGET_POLICY"; log_detail "Using default Restic forget policy."; fi # Use default if empty

  if [[ "$validation_ok" -eq 0 ]]; then log_error "Restic configuration validation failed. Aborting."; exit 1; fi
  log_info "Restic configuration validated."

  # --- Read Host List ---
  log_info "Reading host list from ${SERVER_CONFIG_FILE}..."
  HOSTS_CONFIG_MAINT=() # Reset global array
  local host_yaml_list; host_yaml_list=$("$YQ_CMD" e '.hosts' -o=json "$SERVER_CONFIG_FILE")
  local host_count; host_count=$("$YQ_CMD" e '.hosts | length' "$SERVER_CONFIG_FILE")
  if [[ "$host_count" -eq 0 ]]; then log_error "No host configurations found in '.hosts[]'. Nothing to do."; exit 1; fi

  local i host_config_json host_valid hostname # Local loop vars
  for (( i=0; i<host_count; i++ )); do
      host_config_json=$("$YQ_CMD" e ".hosts[${i}]" -o=json "$SERVER_CONFIG_FILE")
      hostname=$("$YQ_CMD" e '.hostname // ""' - <<< "$host_config_json")
      if [[ -z "$hostname" ]]; then log_error "Host config ${i}: 'hostname' is missing. Skipping."; continue; fi
      # Store the valid JSON chunk for iteration
      HOSTS_CONFIG_MAINT+=("$host_config_json")
      log_detail "Host ${i} (${hostname}): Configuration found."
  done

  if [[ ${#HOSTS_CONFIG_MAINT[@]} -eq 0 ]]; then log_error "No valid host configurations loaded. Nothing to do."; exit 1; fi
  log_info "Found ${#HOSTS_CONFIG_MAINT[@]} host repositories to maintain."
  log_info "============================================================"

  # --- Main Host Processing Loop ---
  FAILED_REPOS=() # Reset failure tracker

  local host_config_json # Local loop var
  for host_config_json in "${HOSTS_CONFIG_MAINT[@]}"; do
    # Use a subshell to process each host repo, isolating potential errors
    (
        set -e # Exit subshell on error
        local hostname repo_path # Local vars for this host

        # Parse hostname again inside subshell
        hostname=$("$YQ_CMD" e '.hostname // ""' - <<< "$host_config_json")
        if [[ -z "$hostname" ]]; then log_error "Internal Error: Missing hostname in validated config chunk."; return 1; fi # Should not happen

        log_info ">>> Processing Maintenance for Host Repository: $hostname <<<"
        repo_path="${RESTIC_REPO_ROOT}/${hostname}"
        log_detail "Repository path: ${repo_path}"

        # Check if repository directory exists
        if [[ ! -d "$repo_path" ]]; then log_error "Restic repository directory not found for host '$hostname' at: ${repo_path}. Skipping."; return 1; fi

        # --- Restic Forget --prune ---
        log_info "  Running 'restic forget' for repository: ${repo_path}"
        # Build forget arguments safely
        local -a forget_args=(); read -r -a forget_args <<< "$RESTIC_FORGET_POLICY" # Split policy string into array
        if [[ "$RESTIC_PRUNE" == "true" ]]; then forget_args+=(--prune); fi
        if [[ "${dry_run}" -eq 1 ]]; then forget_args+=(--dry-run); log_info "    (Dry Run Enabled for forget/prune)"; fi
        if [[ "${verbose}" -eq 1 ]]; then forget_args+=(-v); fi

        log_detail "Executing: ${RESTIC_CMD} -r \"${repo_path}\" --password-file \"${RESTIC_PW_FILE}\" forget ${forget_args[*]}"
        if ! "$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" forget "${forget_args[@]}"; then
            log_error "Restic forget/prune failed for repository: ${repo_path}"
            return 1 # Exit subshell with error
        fi
        log_info "  -> Restic forget/prune completed."

        # --- Restic Check ---
        if [[ "$RESTIC_CHECK" == "true" ]]; then
            log_info "  Running 'restic check' for repository: ${repo_path}"
            local -a check_args=(); read -r -a check_args <<< "$RESTIC_CHECK_OPTIONS" # Split options string
            if [[ "${verbose}" -eq 1 ]]; then check_args+=(-v); fi
            # Note: Restic check does not have a native --dry-run that makes sense here. It's read-only.
            log_detail "Executing: ${RESTIC_CMD} -r \"${repo_path}\" --password-file \"${RESTIC_PW_FILE}\" check ${check_args[*]}"
            if ! "$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" check "${check_args[@]}"; then
                log_error "Restic check failed for repository: ${repo_path}"
                return 1 # Exit subshell with error
            fi
            log_info "  -> Restic check completed."
        else
            log_info "  Skipping 'restic check' as configured."
        fi

        log_info ">>> Finished Maintenance for Host Repository: $hostname SUCCESSFULLY <<<"
        echo # Blank line for separation

    # End of subshell for host processing
    # Catch errors from the subshell
    ) || {
        local host_fail_code=$? # Capture exit code
        # Re-parse hostname
        local failed_hostname; failed_hostname=$("$YQ_CMD" e '.hostname // "UNKNOWN"' - <<< "$host_config_json")
        log_error ">>> Maintenance FAILED for host repository ${failed_hostname} (Subshell Exit Code: ${host_fail_code}) <<<"
        # Use declare -g to modify global array from subshell error handler context
        declare -g -a FAILED_REPOS+=("$failed_hostname")
        # No email sending here, rely on main script summary or separate monitoring
        echo # Blank line for separation
    }
  done # End host loop

  # --- Final Summary ---
  log_info "============================================================"
  if [[ ${#FAILED_REPOS[@]} -gt 0 ]]; then
      log_error "Restic maintenance run finished with errors for ${#FAILED_REPOS[@]} repositories:"
      local failed_repo; for failed_repo in "${FAILED_REPOS[@]}"; do log_error "  - ${failed_repo}"; done
      exit 1 # Exit with error code
  else
      log_info "Restic maintenance run finished successfully for all repositories."
  fi
  log_info "============================================================"

  # Successful exit - EXIT trap will run
  exit 0

} # End of main function definition


# === Script Execution Starts Here ===

# --- Argument Parsing ---
SHORT_OPTS="vhVd"; LONG_OPTS="verbose,help,version,dry-run"
declare parsed_options=""; parsed_options=$(getopt -o "$SHORT_OPTS" --long "$LONG_OPTS" -n "$SCRIPT_NAME" -- "$@")
if [[ $? != 0 ]] ; then echo "ERROR: Invalid options provided. Use -h for help." >&2 ; exit 1 ; fi
eval set -- "$parsed_options";
while true ; do case "$1" in -d|--dry-run) dry_run=1 ; shift ;; -v|--verbose) verbose=1 ; shift ;; -h|--help) show_help=1 ; shift ;; -V|--version) show_version=1 ; shift ;; --) shift ; break ;; *) echo "Internal error!" >&2 ; exit 1 ;; esac; done

# --- Handle -h and -V Options ---
if [[ "$show_help" -eq 1 ]]; then show_help; exit 0; fi
if [[ "$show_version" -eq 1 ]]; then show_version; exit 0; fi

# --- Check Root Privileges ---
if [[ "$(id -u)" -ne 0 ]]; then echo "ERROR: This script must be run as root."; exit 1; fi


# --- Acquire Lock and Run Main Logic ---
exec 200>"$LOCK_FILE" # Use literal FD number
if ! flock -n 200; then echo "ERROR: [$SCRIPT_NAME] Another instance is already running (Lock file: '$LOCK_FILE'). Exiting." >&2; exit 1; fi
# Lock Acquired! Call the main function. EXIT trap handles cleanup & lock release.
main "$@"

# Exit code is determined by the 'exit' command within main() or trap_exit_handler()
