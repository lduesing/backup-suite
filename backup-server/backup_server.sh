#!/bin/bash

# ==============================================================================
# Backup Server Script
# ==============================================================================
# Description:
# Fetches client backup archives (.tar.gz) via SSH/SCP, unpacks them into a
# consistent per-host temporary directory (emptied before each use), and backs
# up the content using Restic into host-specific sub-repositories.
# Performs an SSH connection test before checking for client-side lock files.
# Checks if a newer snapshot already exists in Restic before backing up.
# Implements a check for a client-side lock file to avoid fetching incomplete
# archives, with retries. Manages the archive on the remote host upon
# successful Restic backup. Cleans up local temporary files. Sends email
# notifications and a final summary. Includes enhanced validation, file locking,
# YAML config, dry-run mode, signal handling, and granular logging.
# Adheres to Google Shell Style Guide. Root privileges are required.
#
# Installation Path: /opt/backup/bin/backup_server.sh
#
# License: AGPL-3.0-or-later
# Copyright (c) 2025 Lars Duesing <lars.duesing@camelotsweb.de>
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
# Date: 2025-05-22
# Version: 0.2
# ==============================================================================

# --- Script Metadata and Constants ---
readonly SCRIPT_VERSION="0.2"
readonly SCRIPT_NAME=$(basename "$0")
# Standardized configuration directory
readonly CONFIG_DIR="/etc/backup"
# Path to common config file (shell variables)
readonly COMMON_CONFIG_FILE="${CONFIG_DIR}/common_config"
# Path to server-specific config file (YAML)
readonly SERVER_CONFIG_FILE="${CONFIG_DIR}/server_config.yml"
# Default values for optional settings if not found anywhere
readonly MIN_FREE_SPACE_MB_DEFAULT=500
# Default path for plugins, primarily to locate common_functions.sh
readonly DEFAULT_PLUGIN_DIR="/opt/backup/lib/plugins"
# Instance lock file (for flock)
readonly SCRIPT_INSTANCE_LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
readonly SCRIPT_INSTANCE_LOCK_FD_NUM=200
# Shared directory lock (client-side TAR creation lock)
readonly CLIENT_TAR_LOCK_FILENAME=".backup_archive_in_progress.lock"
readonly SHARED_LOCK_CHECK_RETRY_COUNT=3
readonly SHARED_LOCK_CHECK_RETRY_DELAY_SECONDS=120 # Increased delay

# --- Script Flags and State Variables ---
# Command line flags (lowercase)
verbose=0
show_help=0
show_version=0
dry_run=0
# Config variables (UPPERCASE - loaded from config files)
LOG_LEVEL=2 # Default to INFO (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)
LOCAL_TEMP_BASE_DIR=""
ADMIN_EMAIL_GLOBAL=""
MSMTP_CMD=""
YQ_CMD=""
JQ_CMD="" # For parsing Restic JSON output
RESTIC_REPO_ROOT=""
RESTIC_PW_FILE=""
RESTIC_CMD=""
RESTIC_BACKUP_OPTIONS=""
TAR_CMD=""
GZIP_CMD=""
SSH_CMD=""
SCP_CMD=""
EMAIL_SUBJECT_PREFIX="" # Loaded from config
HOSTNAME=""             # Loaded from config
# Runtime state (lowercase)
tmp_log_file=""
# Arrays to track host status are populated *after* all subshells complete
declare -a succeeded_hosts_final=() # Track successful hosts for summary
declare -a failed_hosts_final=()   # Track failed hosts for summary and exit code
declare -a skipped_hosts_final=() # For hosts skipped due to client lock or newer backup
# Error context variables (lowercase, set by trap)
error_lineno=0
error_command=""
declare -a error_funcstack=()

# --- Shell Options ---
# 'set -e' and 'set -o pipefail' are set inside main_logic after traps.

# --- Source Common Functions ---
# Use default plugin dir initially to find common functions
COMMON_FUNCTIONS_SCRIPT_PATH="${DEFAULT_PLUGIN_DIR}/common_functions.sh"
if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
else
    # Minimal logging if common_functions.sh is not found
    echo "WARNING: common_functions.sh not found at '$COMMON_FUNCTIONS_SCRIPT_PATH', using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [Server] $1"; }
    log_info() { if [[ "${LOG_LEVEL:-2}" -ge 2 ]]; then _log_base "INFO:  $1"; fi; }
    log_error() { _log_base "ERROR: $1" >&2; }
    log_warn() { if [[ "${LOG_LEVEL:-2}" -ge 1 ]]; then _log_base "WARN:  $1" >&2; fi; }
    log_detail() { if [[ "${LOG_LEVEL:-2}" -ge 3 ]]; then _log_base "DEBUG: $1"; fi; }
    check_perms() { log_detail "Permissions check skipped (common_functions.sh not found)."; return 0; }
    check_disk() { log_detail "Disk space check skipped (common_functions.sh not found)."; return 0; }
    create_dir_secure() { local dir_path="$1"; mkdir -p "$dir_path" && chmod 700 "$dir_path" || { echo "ERROR: Failed to create dir: ${dir_path}" >&2; exit 1; }; }
    check_command_exists() { command -v "$1" &>/dev/null; }
    syntax_check_shell_script() { log_detail "Shell syntax check skipped."; return 0; }
    syntax_check_yaml_file() { log_detail "YAML syntax check skipped."; return 0; }
    get_yaml_value() { echo "${3:-}"; return 1; }
    send_email() { log_error "send_email function not available from common_functions.sh"; return 1; }
fi

# --- Function Definitions ---

# Function: show_help
# Description:
#   Displays the help message for the script, outlining usage, options,
#   configuration paths, and examples.
# Arguments:
#   None.
# Outputs:
#   Help text to stdout.
show_help() {
  cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Fetches backup archives from client hosts, unpacks them, and backs them up
using Restic. Checks for a client-side lock file before fetching.
Reads common defaults from '${COMMON_CONFIG_FILE}', server settings from
'${SERVER_CONFIG_FILE}'. Includes enhanced validation, summary email,
file locking, dry-run mode, and signal handling.

Options:
  -d, --dry-run    Enable dry-run mode. Simulates actions.
  -v, --verbose    Enable verbose output (sets LOG_LEVEL to DEBUG).
  -h, --help       Display this help message and exit.
  -V, --version    Display script version (${SCRIPT_VERSION}) and exit.

Configuration:
  See '${COMMON_CONFIG_FILE}', '${SERVER_CONFIG_FILE}', and README.md for details.

Prerequisites:
  ssh, scp, tar, gzip, restic, yq (v4+), jq, msmtp, flock, etc. Root privileges.
  Manual SSH host key verification. Restic repos initialized.

Example:
  sudo ${SCRIPT_NAME} -v --dry-run
EOF
}

# Function: show_version
# Description:
#   Displays the version of the script.
# Arguments:
#   None.
# Outputs:
#   Version string to stdout.
show_version() {
  echo "${SCRIPT_NAME} Version ${SCRIPT_VERSION}"
}

# --- Trap Functions ---

# Function: trap_err_handler
# Description:
#   ERR trap handler. Captures context (line number, command, function stack)
#   when a command fails (due to 'set -e'). Sets global error_* variables.
# Arguments:
#   None (implicitly receives error context from Bash).
trap_err_handler() {
  error_lineno=${BASH_LINENO[0]}
  error_command=${BASH_COMMAND}
  local i
  error_funcstack=()
  for ((i = 0; i < ${#FUNCNAME[@]}; i++)); do
    error_funcstack+=("${FUNCNAME[$i]:-main}:${BASH_LINENO[$i + 1]}")
  done
  log_detail "Error context captured: Line ${error_lineno}, Command '${error_command}'"
}

# Function: trap_sigterm_sigint_handler
# Description:
#   Handles SIGTERM and SIGINT signals for graceful shutdown.
#   Logs the signal and calls the main exit trap.
# Arguments:
#   $1: signal_name (implicitly passed by trap, e.g., "TERM", "INT")
# shellcheck disable=SC2317  # Don't warn about unreachable commands in this function
trap_sigterm_sigint_handler() {
  local signal_name="$1"
  log_error "Received signal ${signal_name}. Initiating graceful shutdown..."
  # Call the main exit handler with appropriate exit code
  if [[ "$signal_name" == "SIGINT" ]]; then
    # Exit code 130 for SIGINT (Ctrl+C)
    trap_exit_handler 130
  else # SIGTERM or other
    # Exit code 143 for SIGTERM
    trap_exit_handler 143
  fi
}


# Function: trap_exit_handler
# Description:
#   EXIT trap handler. Runs whenever the script exits.
#   Performs final cleanup (temporary log file) and sends a summary email.
# Arguments:
#   $1 (optional): Explicit exit code to use. Defaults to $?.
# shellcheck disable=SC2317  # Don't warn about unreachable commands in this function
trap_exit_handler() {
  local exit_code=${1:-$?}
  # Disable exit-on-error within this trap function to ensure all cleanup runs
  set +e
  log_detail "--- Running EXIT trap (Exit code: ${exit_code}) ---"

  # --- Send Summary Email ---
  # Send summary email if not in dry-run, OR if in dry-run and there were errors/skips.
  if [[ -n "$ADMIN_EMAIL_GLOBAL" ]]; then
    if [[ "${dry_run:-0}" -eq 0 ]] || \
       [[ "$exit_code" -ne 0 ]] || \
       [[ ${#failed_hosts_final[@]} -gt 0 ]] || \
       [[ ${#skipped_hosts_final[@]} -gt 0 ]]; then
      local summary_subject
      local summary_body
      local overall_status

      if [[ ${#failed_hosts_final[@]} -gt 0 ]] || [[ "$exit_code" -ne 0 ]]; then
        overall_status="COMPLETED WITH ERRORS"
      elif [[ ${#skipped_hosts_final[@]} -gt 0 ]]; then
        overall_status="COMPLETED WITH SKIPS"
      else
        overall_status="SUCCESSFUL"
      fi
      summary_subject="${EMAIL_SUBJECT_PREFIX:-[Backup Server]} ${HOSTNAME} - Backup Run ${overall_status}"

      if [[ "${dry_run:-0}" -eq 1 ]]; then
        summary_subject="[DRY-RUN] ${summary_subject}"
      fi

      # Use printf for body to correctly interpret \n
      summary_body=""
      printf -v summary_body "Backup server run finished.\nOverall Status: %s\n\n" "${overall_status}"

      printf -v succeeded_list "Successful Hosts (%s):\n" "${#succeeded_hosts_final[@]}"
      summary_body+="${succeeded_list}"
      if [[ ${#succeeded_hosts_final[@]} -gt 0 ]]; then
        local host # Local loop var
        for host in "${succeeded_hosts_final[@]}"; do
          printf -v host_line "  - %s\n" "${host}"
          summary_body+="${host_line}"
        done
      else
        printf -v none_line "  (None)\n"
        summary_body+="${none_line}"
      fi

      printf -v skipped_list "\nSkipped Hosts (%s):\n" "${#skipped_hosts_final[@]}"
      summary_body+="${skipped_list}"
      if [[ ${#skipped_hosts_final[@]} -gt 0 ]]; then
        local host # Local loop var
        for host in "${skipped_hosts_final[@]}"; do
          printf -v host_line "  - %s\n" "${host}" # Status reason already in the array element
          summary_body+="${host_line}"
        done
      else
        printf -v none_line "  (None)\n"
        summary_body+="${none_line}"
      fi
      printf -v failed_list "\nFailed Hosts (%s):\n" "${#failed_hosts_final[@]}"
      summary_body+="${failed_list}"
      if [[ ${#failed_hosts_final[@]} -gt 0 ]]; then
        local host # Local loop var
        for host in "${failed_hosts_final[@]}"; do
          printf -v host_line "  - %s (Failed)\n" "${host}"
          summary_body+="${host_line}"
        done
      else
        printf -v none_line "  (None)\n"
        summary_body+="${none_line}"
      fi
      printf -v log_path_line "\nFull log available on server at: %s" "${tmp_log_file:-N/A (if error was very early)}"
      summary_body+="${log_path_line}"

      # In dry-run, only log the email content, unless it's a real error summary
      if [[ "${dry_run:-0}" -eq 1 ]] && \
         [[ "$exit_code" -eq 0 ]] && \
         [[ ${#failed_hosts_final[@]} -eq 0 ]] && \
         [[ ${#skipped_hosts_final[@]} -eq 0 ]] ; then
        log_info "DRY-RUN: Would send summary email to ${ADMIN_EMAIL_GLOBAL}"
        log_detail "DRY-RUN: Summary Subject: ${summary_subject}"
        log_detail "DRY-RUN: Summary Body:\n${summary_body}"
      else
        # send_email is from common_functions.sh
        send_email "$ADMIN_EMAIL_GLOBAL" "$summary_subject" "$summary_body"
      fi
    fi
  elif [[ "$exit_code" -ne 0 ]]; then
    log_info "No global admin email configured for summary report."
  fi

  # --- Log File Handling ---
  if [[ "$exit_code" -ne 0 ]]; then
    log_error "Backup server script finished with ERROR (Exit Code: ${exit_code})."
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
      echo "Log file kept for analysis: ${tmp_log_file}" >&2
    fi
  else
    log_info "Backup server script finished successfully."
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
      rm -f "$tmp_log_file"
    fi
  fi

  # --- Release Lock and Exit ---
  # Lock file descriptor is closed automatically upon script exit, releasing the lock.
  log_detail "Exiting script. Lock will be released (FD ${SCRIPT_INSTANCE_LOCK_FD_NUM})."
  exit "${exit_code}"
}

# --- Main Function Definition ---
# Encapsulates the primary logic of the script.
main() {
  # --- Setup Logging & Traps ---
  tmp_log_file=$(mktemp /tmp/local_backup_log."$SCRIPT_NAME".XXXXXX)
  chmod 600 "$tmp_log_file"
  exec > >(tee -a "$tmp_log_file") 2>&1 # Redirect stdout/stderr
  trap trap_err_handler ERR
  trap trap_exit_handler EXIT
  # Trap SIGINT and SIGTERM to allow graceful shutdown
  trap 'trap_sigterm_sigint_handler SIGINT' SIGINT
  trap 'trap_sigterm_sigint_handler SIGTERM' SIGTERM

  # Enable errexit and pipefail now that traps and logging are set up
  set -eo pipefail

  # --- Start Actual Process ---
  log_info "Successfully acquired script instance lock: ${SCRIPT_INSTANCE_LOCK_FILE} (FD ${SCRIPT_INSTANCE_LOCK_FD_NUM})"
  if [[ "${dry_run}" -eq 1 ]]; then
    log_info "*** DRY-RUN MODE ACTIVATED ***"
  fi

  # --- Load Common Config ---
  log_info "Loading common configuration from ${COMMON_CONFIG_FILE}..."
  if ! syntax_check_shell_script "${COMMON_CONFIG_FILE}"; then
    exit 1
  fi
  if [[ ! -f "$COMMON_CONFIG_FILE" ]]; then
    log_error "Common config file '${COMMON_CONFIG_FILE}' not found."
    exit 1
  fi
  if ! check_perms "${COMMON_CONFIG_FILE}" "600" "root"; then
    log_error "Aborting: Insecure permissions on '${COMMON_CONFIG_FILE}'."
    exit 1
  fi
  local source_exit_code # Local var
  # Source directly, common_config should be robust
  # shellcheck source=/dev/null
  source "${COMMON_CONFIG_FILE}"; source_exit_code=$?
  if [[ ${source_exit_code} -ne 0 ]]; then
    log_error "Failed to source common config file '${COMMON_CONFIG_FILE}'. Syntax error?"
    exit 1
  fi
  log_detail "Common configuration sourced."

  # --- Load Server Specific Config (YAML) ---
  log_info "Loading server configuration from ${SERVER_CONFIG_FILE}..."
  if ! syntax_check_yaml_file "${SERVER_CONFIG_FILE}"; then
    exit 1
  fi
  if [[ ! -f "$SERVER_CONFIG_FILE" ]]; then
    log_error "Server config file '${SERVER_CONFIG_FILE}' not found."
    exit 1
  fi
  if ! check_perms "${SERVER_CONFIG_FILE}" "600" "root"; then
    log_error "Aborting: Insecure permissions on '${SERVER_CONFIG_FILE}'."
    exit 1
  fi
  # Set defaults for tool paths before reading overrides
  YQ_CMD="${YQ_CMD:-yq}"
  JQ_CMD="${JQ_CMD:-jq}"
  RESTIC_CMD="${RESTIC_CMD:-restic}"
  TAR_CMD="${TAR_CMD:-tar}"
  GZIP_CMD="${GZIP_CMD:-gzip}"
  SSH_CMD="${SSH_CMD:-ssh}"
  SCP_CMD="${SCP_CMD:-scp}"
  MSMTP_CMD="${MSMTP_CMD:-msmtp}"
  # Check YQ command *before* using it to parse server_config.yml
  if ! check_command_exists "$YQ_CMD"; then
    log_error "yq command ('$YQ_CMD') not found."
    exit 1
  fi

  # Read values, overriding common defaults if present
  local val # Temp var for yq output
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.local_temp_base_dir" ""); if [[ -n "$val" ]]; then LOCAL_TEMP_BASE_DIR="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.admin_email" ""); if [[ -n "$val" ]]; then ADMIN_EMAIL_GLOBAL="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.msmtp_cmd" ""); if [[ -n "$val" ]]; then MSMTP_CMD="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.yq_cmd" ""); if [[ -n "$val" ]]; then YQ_CMD="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.jq_cmd" ""); if [[ -n "$val" ]]; then JQ_CMD="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.repository_root" ""); if [[ -n "$val" ]]; then RESTIC_REPO_ROOT="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.password_file" ""); if [[ -n "$val" ]]; then RESTIC_PW_FILE="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.restic_cmd" ""); if [[ -n "$val" ]]; then RESTIC_CMD="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.backup_options" ""); if [[ -n "$val" ]]; then RESTIC_BACKUP_OPTIONS="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".email_subject_prefix" "[Backup Server]"); EMAIL_SUBJECT_PREFIX="$val"
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".hostname" "$(hostname -f)"); HOSTNAME="$val"
  # Read LOG_LEVEL from server_config.yml, overriding common_config if set
  local log_level_yml; log_level_yml=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.log_level" "")
  if [[ -n "$log_level_yml" ]] && [[ "$log_level_yml" =~ ^[0-3]$ ]]; then
    LOG_LEVEL="$log_level_yml"
  elif [[ -n "${LOG_LEVEL_COMMON}" ]] && [[ "${LOG_LEVEL_COMMON}" =~ ^[0-3]$ ]]; then # Check if LOG_LEVEL_COMMON was set by common_config
    LOG_LEVEL="$LOG_LEVEL_COMMON"
  fi


  # --- Set Defaults for any remaining unset global variables ---
  LOCAL_TEMP_BASE_DIR="${LOCAL_TEMP_BASE_DIR:-/var/tmp/backup_server_work}"
  ADMIN_EMAIL_GLOBAL="${ADMIN_EMAIL_GLOBAL:-${DEFAULT_ADMIN_EMAIL}}" # From common_config
  HOSTNAME="${HOSTNAME:-$(hostname -f)}" # Ensure HOSTNAME is set for emails
  # If verbose flag set, override LOG_LEVEL to DEBUG
  if [[ "$verbose" -eq 1 ]]; then
    LOG_LEVEL=3
  fi

  # --- Validate Loaded Configuration ---
  log_info "Validating loaded configuration..."
  local validation_ok=1
  if [[ -z "$LOCAL_TEMP_BASE_DIR" ]] || \
     ! is_valid_path "$LOCAL_TEMP_BASE_DIR" "-d" || \
     ! is_valid_path "$LOCAL_TEMP_BASE_DIR" "-w"; then
    log_error "Config Error: global.local_temp_base_dir ('$LOCAL_TEMP_BASE_DIR') is invalid/missing/not writable."
    validation_ok=0
  fi
  if [[ -z "$ADMIN_EMAIL_GLOBAL" ]] && [[ "${dry_run}" -eq 0 ]]; then # Only warn if not dry run
    log_warn "Config Warning: global.admin_email is not set. No summary/fallback error emails will be sent."
  fi
  if [[ -z "$RESTIC_REPO_ROOT" ]] || ! is_valid_path "$RESTIC_REPO_ROOT" "-d"; then
    log_error "Config Error: restic.repository_root ('$RESTIC_REPO_ROOT') is invalid or missing."
    validation_ok=0
  fi
  if [[ -z "$RESTIC_PW_FILE" ]]; then
    log_error "Config Error: restic.password_file is not set."
    validation_ok=0
  elif ! check_perms "$RESTIC_PW_FILE" "600" "root"; then
    validation_ok=0
  fi
  local -a tools_to_check=(YQ_CMD TAR_CMD GZIP_CMD SSH_CMD SCP_CMD RESTIC_CMD MSMTP_CMD)
  # JQ_CMD is optional, so check it separately and only warn
  if [[ -n "$JQ_CMD" ]] && ! check_command_exists "$JQ_CMD"; then
      log_warn "Optional command jq ('${JQ_CMD}') not found. Restic snapshot timestamp check might be slower or less reliable."
  fi
  local tool_var tool_cmd
  for tool_var in "${tools_to_check[@]}"; do
    tool_cmd=$(echo "${!tool_var}" | cut -d' ' -f1)
    if [[ -n "$tool_cmd" ]] && ! check_command_exists "$tool_cmd"; then
      log_error "Config Error: Command for ${tool_var} ('${!tool_var}') not found."
      validation_ok=0
    fi
  done

  if [[ "$validation_ok" -eq 0 ]]; then
    log_error "Configuration validation failed. Aborting."
    exit 1
  fi
  log_info "Configuration validated successfully."

  # --- Print Startup Info ---
  log_info "============================================================"
  log_info "Starting Backup Server Script (Version ${SCRIPT_VERSION}) - Locked (PID $$)"
  log_info "Server Config File: ${SERVER_CONFIG_FILE}"
  log_info "Common Config: ${COMMON_CONFIG_FILE}"
  log_info "Log Level: ${LOG_LEVEL} (0=ERR,1=WARN,2=INFO,3=DEBUG)"
  log_info "Temp Base Dir: ${LOCAL_TEMP_BASE_DIR}"
  log_info "Restic Repo Root: ${RESTIC_REPO_ROOT}"
  log_detail "Restic Password File: ${RESTIC_PW_FILE}"
  log_info "Global Admin Email: ${ADMIN_EMAIL_GLOBAL}"
  if [[ "${dry_run}" -eq 1 ]]; then
    log_info "*** DRY-RUN MODE ACTIVATED ***"
  fi
  if [[ "${verbose}" -eq 1 ]]; then # Redundant if LOG_LEVEL=3, but good for clarity
    log_info "Verbose mode enabled (implies DEBUG log level)."
  fi
  log_info "============================================================"

  # --- Read Host Configurations ---
  log_info "Reading host configurations from ${SERVER_CONFIG_FILE}..."
  # HOSTS_CONFIG is global array, reset it
  HOSTS_CONFIG=()
  local host_count
  host_count=$(get_yaml_value "$SERVER_CONFIG_FILE" ".hosts | length" "0")

  if [[ "$host_count" -eq 0 ]]; then
    log_error "No host configurations found in '.hosts[]'. Nothing to do."
    exit 1
  fi

  local i host_config_json host_valid # Local loop vars
  for (( i=0; i<host_count; i++ )); do
      host_config_json=$("$YQ_CMD" e ".hosts[${i}]" -o=json "$SERVER_CONFIG_FILE")
      declare -A host_map # Local associative array
      # Safely parse JSON into associative array
      while IFS="=" read -r key value; do
        # Remove surrounding quotes from JSON string values
        value="${value%\"}"; value="${value#\"}"
        # Unescape JSON special characters (simple version)
        value=$(echo -e "$value")
        host_map["$key"]="$value"
      done < <("$YQ_CMD" e 'to_entries | .[] | .key + "=" + (.value | @json)' - <<< "$host_config_json")
      # Validate this host's config
      host_valid=1
      if [[ -z "${host_map[hostname]}" ]]; then log_error "Host config ${i}: 'hostname' is missing."; host_valid=0; fi
      if [[ -z "${host_map[ssh_user]}" ]]; then log_error "Host config ${i} (${host_map[hostname]:-UNKNOWN}): 'ssh_user' is missing."; host_valid=0; fi
      if [[ -z "${host_map[ssh_key_file]}" ]]; then log_error "Host config ${i} (${host_map[hostname]:-UNKNOWN}): 'ssh_key_file' is missing."; host_valid=0; fi
      if [[ -n "${host_map[ssh_key_file]}" ]] && ! check_perms "${host_map[ssh_key_file]}" "600" "root"; then host_valid=0; fi
      if [[ -z "${host_map[remote_tar_dir]}" ]]; then log_error "Host config ${i} (${host_map[hostname]:-UNKNOWN}): 'remote_tar_dir' is missing."; host_valid=0; fi
      if [[ -z "${host_map[admin_email]}" ]]; then host_map["admin_email"]="$ADMIN_EMAIL_GLOBAL"; fi
      if [[ -z "${host_map[admin_email]}" ]]; then log_info "Host config ${i} (${host_map[hostname]:-UNKNOWN}): No admin email configured."; fi

      if [[ "$host_valid" -eq 1 ]]; then
          HOSTS_CONFIG+=("$host_config_json")
          log_detail "Host ${i} (${host_map[hostname]}): Configuration loaded and validated."
      else
          log_error "Host configuration at index ${i} is invalid. Skipping this host."
      fi
      unset host_map
  done

  if [[ ${#HOSTS_CONFIG[@]} -eq 0 ]]; then
    log_error "No valid host configurations loaded. Nothing to do."
    exit 1
  fi
  log_info "Loaded configuration for ${#HOSTS_CONFIG[@]} hosts."

  # --- Main Host Processing Loop ---
  log_info "============================================================"
  log_info "Starting backup run for configured hosts..."
  succeeded_hosts_final=(); failed_hosts_final=(); skipped_hosts_final=() # Use final arrays for summary

  local host_config_json # Local loop var
  for host_config_json in "${HOSTS_CONFIG[@]}"; do
    # Create a temporary status file for this host's subshell
    local host_status_file
    host_status_file=$(create_secure_temp_file ".host_status.XXXXXX" "$LOCAL_TEMP_BASE_DIR")

    # Use a subshell for each host to isolate errors and cleanup
    (
      set -e # Exit subshell on error
      # Local variables for this host's processing
      local hostname ssh_user ssh_key_file remote_tar_dir admin_email
      local remote_host temp_download_dir unpack_parent_dir unpack_content_dir
      local remote_latest_tar remote_tar_path local_tar_path timestamp_tag repo_path
      local -a restic_tags restic_cmd_args

      # Parse JSON again inside subshell to populate local vars
      declare -A host_map
      while IFS="=" read -r key value; do 
        value="${value%\"}"
        value="${value#\"}"
        value=$(echo -e "$value")
        host_map["$key"]="$value"
      done < <("$YQ_CMD" e 'to_entries | .[] | .key + "=" + (.value | @json)' - <<< "$host_config_json")
      hostname="${host_map[hostname]}"
      ssh_user="${host_map[ssh_user]}"
      ssh_key_file="${host_map[ssh_key_file]}"
      remote_tar_dir="${host_map[remote_tar_dir]}"
      admin_email="${host_map[admin_email]}"
      remote_host="$hostname"

      log_info ">>> Processing host: ${remote_host} <<<"

      # --- SSH Connection Test ---
      log_info "  Testing SSH connection to ${remote_host}..."
      if [[ "${dry_run}" -eq 1 ]]; then
        log_info "  DRY-RUN: Skipping SSH connection test."
      elif ! "$SSH_CMD" -i "$ssh_key_file" \
          -o BatchMode=yes \
          -o ConnectTimeout=10 \
          -o StrictHostKeyChecking=yes \
          "$ssh_user@$remote_host" exit; then
        log_error "SSH connection test failed for ${remote_host}. Check key, user, host, network. Ensure host key is in known_hosts."
        return 1 # Fail this host early
      else
        log_info "  -> SSH connection successful."
      fi

      # --- Check for Client-Side TAR Creation Lock ---
      local remote_lock_file_path="${remote_tar_dir}/${CLIENT_TAR_LOCK_FILENAME}"
      log_info "  Checking for client-side TAR lock: ${remote_host}:${remote_lock_file_path}"
      local lock_check_retry=0
      while "$SSH_CMD" -i "$ssh_key_file" -o BatchMode=yes -o ConnectTimeout=5 "$ssh_user@$remote_host" "test -e \"${remote_lock_file_path}\""; do
        lock_check_retry=$((lock_check_retry + 1))
        if [[ "$lock_check_retry" -gt "$SHARED_LOCK_CHECK_RETRY_COUNT" ]]; then
          log_warn "  Client-side TAR lock '${remote_lock_file_path}' still present on ${remote_host} after ${SHARED_LOCK_CHECK_RETRY_COUNT} retries. Skipping this host for current run."
          if [[ -n "$admin_email" ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
            local skip_subject="Backup SKIPPED for host ${remote_host} (Client TAR Lock)"
            local skip_body; printf -v skip_body "Backup for host %s was skipped because the client-side TAR creation lock file '%s' was present after multiple checks.\nThis indicates the client backup might still be in progress or failed to clean up its lock.\nNo data was fetched for this host in this run." "$remote_host" "$remote_lock_file_path"
            send_email "$admin_email" "$skip_subject" "$skip_body"
          fi
          echo "SKIPPED_CLIENT_LOCK:${remote_host}" > "$host_status_file" # Mark as skipped
          return 0 # Exit subshell successfully, but mark as skipped
        fi
        log_info "  Client-side TAR lock found. Retrying in ${SHARED_LOCK_CHECK_RETRY_DELAY_SECONDS}s... (Attempt ${lock_check_retry}/${SHARED_LOCK_CHECK_RETRY_COUNT})"
        sleep "$SHARED_LOCK_CHECK_RETRY_DELAY_SECONDS"
      done
      log_info "  Client-side TAR lock not present or released."


      # --- Restic Repository Initialization Check ---
      repo_path="${RESTIC_REPO_ROOT}/${remote_host}"
      log_info "  Checking Restic repository: ${repo_path}"
      if [[ "${dry_run}" -eq 1 ]]; then
        log_info "  DRY-RUN: Skipping Restic repository check."
      elif ! "$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" cat config > /dev/null 2>&1; then
        log_error "Restic repository at '${repo_path}' not initialized or inaccessible. Run 'restic init' first."
        return 1
      else
        log_info "  -> Restic repository seems initialized."
      fi

      # --- Define Temporary Locations ---
      log_detail "Creating temporary directories for ${remote_host}..."
      # Download directory (unique per run)
      temp_download_dir=$(create_secure_temp_dir "${remote_host}_download.XXXXXX" "$LOCAL_TEMP_BASE_DIR")
      # Consistent unpack directory name per host for Restic path consistency
      local remote_host_sanitized; remote_host_sanitized=$(echo "$remote_host" | sed 's/[^a-zA-Z0-9_.-]/_/g')
      unpack_parent_dir="${LOCAL_TEMP_BASE_DIR}/${remote_host_sanitized}"
      unpack_content_dir="${unpack_parent_dir}/unpacked_content"
      log_detail "Temp download dir: ${temp_download_dir}"
      log_detail "Unpack content dir: ${unpack_content_dir}"
      if [[ "${dry_run}" -eq 0 ]]; then
        if [[ -d "$unpack_content_dir" ]]; then
          log_detail "Cleaning existing unpack content directory: ${unpack_content_dir}"
          if ! rm -rf "${unpack_content_dir:?}"/*; then log_error "Failed to clean unpack content dir: ${unpack_content_dir}"; return 1; fi
        else
          create_dir_secure "$unpack_content_dir"
        fi
      elif [[ ! -d "$unpack_content_dir" ]]; then
         # For dry-run, still ensure parent exists if needed by mktemp later
         create_dir_secure "$unpack_parent_dir"
      fi


      # --- Find Latest TAR on Remote Host ---
      log_info "  Finding latest backup archive on ${remote_host}..."
      remote_latest_tar=$("$SSH_CMD" -i "$ssh_key_file" \
          -o BatchMode=yes \
          -o StrictHostKeyChecking=yes \
          "$ssh_user@$remote_host" \
          "find \"${remote_tar_dir}/\" -maxdepth 1 -name \"${remote_host}-*.tar.gz\" -printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-")
      if [[ -z "$remote_latest_tar" ]]; then
        log_error "No backup archives found for host ${remote_host} in ${remote_tar_dir}."
        return 1
      fi
      remote_latest_tar=$(basename "$remote_latest_tar")
      remote_tar_path="${remote_tar_dir}/${remote_latest_tar}"
      local_tar_path="${temp_download_dir}/${remote_latest_tar}"
      log_info "  Found latest archive: ${remote_latest_tar}"

      # --- Check if newer snapshot already exists in Restic ---
      log_info "  Checking for existing newer snapshots in Restic for ${remote_host}..."
      timestamp_tag=$(echo "$remote_latest_tar" | sed -n "s/^${remote_host}-\([0-9]\{8\}_[0-9]\{6\}\)\.tar\.gz$/\1/p")
      local tar_timestamp_sec=0
      if [[ -n "$timestamp_tag" ]]; then
        tar_timestamp_sec=$(date -d "${timestamp_tag:0:8} ${timestamp_tag:9:2}:${timestamp_tag:11:2}:${timestamp_tag:13:2}" +%s 2>/dev/null || echo 0)
      else
        log_warn "    Could not extract timestamp_tag from TAR filename: ${remote_latest_tar}. Precise newer snapshot check using this tag is not possible."
      fi
      log_detail "    TAR archive timestamp_tag: ${timestamp_tag:-N/A} (Epoch seconds: ${tar_timestamp_sec})"

      local latest_restic_snapshot_time_sec=0
      local latest_snapshot_json
      # First, try to find a snapshot with the exact same timestamp tag
      if [[ -n "$timestamp_tag" ]] && check_command_exists "$JQ_CMD"; then
        latest_snapshot_json=$("$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" snapshots --json --latest 1 --host "$hostname" --tag "$timestamp_tag" 2>/dev/null || echo "[]")
        if [[ $(echo "$latest_snapshot_json" | "$JQ_CMD" 'length') -gt 0 ]]; then
          latest_restic_snapshot_time_sec=$("$JQ_CMD" -r '.[0].time // "0"' <<< "$latest_snapshot_json" | date -f - +%s 2>/dev/null || echo 0)
          log_detail "    Found Restic snapshot with exact tag '${timestamp_tag}', time: ${latest_restic_snapshot_time_sec}s"
           if [[ "$tar_timestamp_sec" -ne 0 ]] && [[ "$latest_restic_snapshot_time_sec" -ne 0 ]]; then # Both timestamps valid
              log_warn "  Skipping backup for ${remote_host}: A Restic snapshot with the exact timestamp tag '${timestamp_tag}' already exists."
              if [[ -n "$admin_email" ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
                local warn_subject="Backup SKIPPED for host ${remote_host} (Exact snapshot exists)"
                local warn_body; printf -v warn_body "Backup for host %s was skipped.\nThe TAR archive '%s' (timestamp: %s) appears to have already been processed, as a Restic snapshot with the identical timestamp tag exists.\nNo new data was backed up." "$remote_host" "$remote_latest_tar" "$timestamp_tag"
                send_email "$admin_email" "$warn_subject" "$warn_body"
              fi
              echo "SKIPPED_DUPLICATE:${remote_host}" > "$host_status_file" # Mark as skipped
              return 0 # Exit subshell successfully
          fi
        fi
      fi
      # If no exact tag match or jq not available, get the latest snapshot for the host
      if [[ "$latest_restic_snapshot_time_sec" -eq 0 ]]; then # If not found by specific tag or jq failed
          if check_command_exists "$JQ_CMD"; then
            latest_snapshot_json=$("$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" snapshots --json --latest 1 --host "$hostname" 2>/dev/null || echo "[]")
            if [[ $(echo "$latest_snapshot_json" | "$JQ_CMD" 'length') -gt 0 ]]; then
                latest_restic_snapshot_time_sec=$("$JQ_CMD" -r '.[0].time // "0"' <<< "$latest_snapshot_json" | date -f - +%s 2>/dev/null || echo 0)
            fi
          else # Fallback without jq
            latest_restic_snapshot_time_sec=$("$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" snapshots --latest 1 --host "$hostname" --no-lock | grep "$hostname" | head -n 1 | awk '{print $2 " " $3}' | date -f - +%s 2>/dev/null || echo 0)
          fi
          log_detail "    Latest Restic snapshot for host ${remote_host} (any tag): ${latest_restic_snapshot_time_sec}s"
      fi

      if [[ "$tar_timestamp_sec" -ne 0 ]] && \
         [[ "$latest_restic_snapshot_time_sec" -ne 0 ]] && \
         [[ "$tar_timestamp_sec" -lt "$latest_restic_snapshot_time_sec" ]]; then # Use -lt strictly
        log_warn "  Skipping backup for ${remote_host}: TAR archive (${remote_latest_tar}) is OLDER than the latest Restic snapshot."
        if [[ -n "$admin_email" ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
          local warn_subject="Backup SKIPPED for host ${remote_host} (Older TAR found)"
          local warn_body; printf -v warn_body "Backup for host %s was skipped.\nThe TAR archive '%s' (timestamp: %s) is OLDER than the latest Restic snapshot (approx: %s).\nNo new data was backed up for this host in this run." "$remote_host" "$remote_latest_tar" "$timestamp_tag" "$(date -d "@${latest_restic_snapshot_time_sec}" --rfc-3339=seconds)"
          send_email "$admin_email" "$warn_subject" "$warn_body"
        fi
        echo "SKIPPED_OLDER:${remote_host}" > "$host_status_file"
        return 0
      fi

      # --- Fetch TAR Archive ---
      if [[ "${dry_run}" -eq 1 ]]; then
        log_info "  DRY-RUN: Would fetch ${remote_host}:${remote_tar_path} to ${local_tar_path}"
      else
        log_info "  Fetching archive from ${remote_host}:${remote_tar_path}..."
        log_detail "Executing: ${SCP_CMD} -i \"${ssh_key_file}\" -o BatchMode=yes -o StrictHostKeyChecking=yes \"${ssh_user}@${remote_host}:${remote_tar_path}\" \"${local_tar_path}\""
        if ! "$SCP_CMD" -i "$ssh_key_file" \
            -o BatchMode=yes \
            -o StrictHostKeyChecking=yes \
            "${ssh_user}@${remote_host}:${remote_tar_path}" \
            "$local_tar_path"; then
          log_error "Failed to fetch archive from ${remote_host}."
          return 1
        fi
        log_info "  -> Archive fetched successfully to ${local_tar_path}"
      fi

      # --- Unpack TAR Archive ---
      if [[ "${dry_run}" -eq 1 ]]; then
        log_info "  DRY-RUN: Would unpack ${local_tar_path} to ${unpack_content_dir}"
      else
        log_info "  Unpacking archive: ${local_tar_path}"
        log_detail "Executing: ${TAR_CMD} -xpzf \"${local_tar_path}\" --numeric-owner -C \"${unpack_content_dir}\""
        if ! "$TAR_CMD" -xpzf "$local_tar_path" --numeric-owner -C "$unpack_content_dir"; then
          log_error "Failed to unpack archive '${local_tar_path}'."
          return 1
        fi
        log_info "  -> Archive unpacked successfully to ${unpack_content_dir}"
      fi

      # --- Restic Backup ---
      log_info "  Performing Restic backup for host ${remote_host}..."
      log_info "  Restic repository: ${repo_path}"
      log_detail "Password file: ${RESTIC_PW_FILE}"
      restic_tags=("$remote_host")
      if [[ -n "$timestamp_tag" ]]; then
        restic_tags+=("$timestamp_tag")
      else 
        restic_tags+=("unknown_timestamp")
      fi

      restic_cmd_args=(
        -r "$repo_path" 
        --password-file "$RESTIC_PW_FILE"
        backup --host "$hostname" --ignore-inode)
      local tag
      for tag in "${restic_tags[@]}"; do
        restic_cmd_args+=(--tag "$tag")
      done
      local -a extra_opts=()
       # Split string into array
      read -r -a extra_opts <<< "$RESTIC_BACKUP_OPTIONS"
      if [[ ${#extra_opts[@]} -gt 0 ]]; then
        restic_cmd_args+=("${extra_opts[@]}")
      fi
      if [[ "${dry_run}" -eq 1 ]]; then
        restic_cmd_args+=(--dry-run)
        log_info "    (Dry Run Enabled for Restic)"
      fi
      # Add path to backup ('.') relative to unpack_content_dir
      restic_cmd_args+=(".")

      log_detail "Executing: (cd \"${unpack_content_dir}\" && ${RESTIC_CMD} ${restic_cmd_args[*]})"
      # Execute restic backup from within the unpacked directory
      if ! (cd "$unpack_content_dir" && "$RESTIC_CMD" "${restic_cmd_args[@]}"); then
        log_error "Restic backup failed for host ${remote_host}."
        return 1
      fi
      log_info "  -> Restic backup command completed successfully for ${remote_host}."

      # --- Remote Cleanup (on Success, skip in dry-run) ---
      if [[ "${dry_run}" -eq 0 ]]; then
        log_info "  Performing remote cleanup on ${remote_host}..."
        local remote_done_dir="${remote_tar_dir}/done"
        local remote_cleanup_cmd="mkdir -p '${remote_done_dir}' && mv -f '${remote_tar_path}' '${remote_done_dir}/' && find '${remote_done_dir}/' -maxdepth 1 -name '*.tar.gz' -type f -printf '%T@ %p\\n' | sort -nr | tail -n +2 | cut -d' ' -f2- | xargs --no-run-if-empty rm -f"
        log_detail "Executing remote cleanup command: ssh ... \"${remote_cleanup_cmd}\""
        if ! "$SSH_CMD" -i "$ssh_key_file" \
            -o BatchMode=yes \
            -o StrictHostKeyChecking=yes \
            "$ssh_user@$remote_host" \
            "$remote_cleanup_cmd"; then
          log_warn "Remote cleanup failed on host ${remote_host}. Manual cleanup of '${remote_tar_path}' might be needed."
        else
          log_info "  -> Remote cleanup successful."
        fi
      else
        log_info "  DRY-RUN: Skipping remote cleanup on ${remote_host}."
      fi

      log_info ">>> Finished host: ${remote_host} SUCCESSFULLY <<<"
      echo "SUCCESS:${remote_host}" > "$host_status_file"

    ) || { # Catch errors from subshell
        local host_fail_code=$?
        local failed_hostname; failed_hostname=$(get_yaml_value <(echo "$host_config_json") '.hostname' "UNKNOWN")
        local failed_admin_email; failed_admin_email=$(get_yaml_value <(echo "$host_config_json") '."admin-email"' "$ADMIN_EMAIL_GLOBAL")

        log_error ">>> Backup FAILED for host ${failed_hostname} (Subshell Exit Code: ${host_fail_code}) <<<"
        echo "FAILURE:${failed_hostname}" > "$host_status_file"

        if [[ -n "$failed_admin_email" ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
            local fail_subject="Backup FAILED for host ${failed_hostname} (Code: ${host_fail_code})"
            local fail_body; printf -v fail_body "Backup process failed for host: %s with exit code %s.\nCheck server log: %s\nError likely occurred near line %s (Cmd: %s)." "$failed_hostname" "$host_fail_code" "$tmp_log_file" "$error_lineno" "$error_command"
            send_email "$failed_admin_email" "$fail_subject" "$fail_body"
        elif [[ -n "$failed_admin_email" ]] && [[ "${dry_run:-0}" -eq 1 ]]; then
          log_info "DRY-RUN: Skipping failure email for host ${failed_hostname}."
        fi
    }

    # --- Host Cleanup (always runs after subshell) ---
    log_detail "Cleaning up temporary files for host ${hostname}..."
    if [[ -n "$temp_download_dir" ]] && [[ -d "$temp_download_dir" ]]; then
      rm -rf "$temp_download_dir"
    fi
    # The consistent unpack_parent_dir (e.g., /var/tmp/backup_server_work/client-a.example.org)
    # and its content (unpack_content_dir) should be cleaned up.
    if [[ -n "$unpack_parent_dir" ]] && [[ -d "$unpack_parent_dir" ]]; then
      log_detail "Cleaning up unpack parent directory: ${unpack_parent_dir}"
      rm -rf "$unpack_parent_dir"
    fi
    log_detail "Temporary file cleanup finished for ${hostname}."
    # Visual separation
    echo
  done # End host loop

  # --- Collect Final Statuses from temp files ---
  succeeded_hosts_final=()
  failed_hosts_final=()
  skipped_hosts_final=()
  local status_file
  for status_file in "${LOCAL_TEMP_BASE_DIR}/.host_status."*; do
    if [[ -f "$status_file" ]]; then
      local status_line; status_line=$(cat "$status_file")
      local status_type; status_type=$(echo "$status_line" | cut -d':' -f1)
      local status_host; status_host=$(echo "$status_line" | cut -d':' -f2-)
      if [[ "$status_type" == "SUCCESS" ]]; then
        succeeded_hosts_final+=("$status_host")
      elif [[ "$status_type" == "FAILURE" ]]; then
        failed_hosts_final+=("$status_host")
      elif [[ "$status_type" == "SKIPPED_CLIENT_LOCK" ]] || \
           [[ "$status_type" == "SKIPPED_DUPLICATE" ]] || \
           [[ "$status_type" == "SKIPPED_OLDER" ]]; then
        skipped_hosts_final+=("${status_host} (${status_type})")
      fi
      rm -f "$status_file" # Clean up status file
    fi
  done


  # --- Final Summary ---
  log_info "============================================================"
  if [[ ${#failed_hosts_final[@]} -gt 0 ]]; then
      log_error "Backup run finished with errors for ${#failed_hosts_final[@]} host(s):"
      local failed_host
      for failed_host in "${failed_hosts_final[@]}"; do
        log_error "  - ${failed_host}"
      done
      exit 1
  elif [[ ${#skipped_hosts_final[@]} -gt 0 ]]; then
      log_warn "Backup run finished with some hosts skipped:"
      local skipped_host
      for skipped_host in "${skipped_hosts_final[@]}"; do
        log_warn "  - ${skipped_host}"
      done
      exit 0 # Still considered overall success, but with skips
  else
      log_info "Backup run finished successfully for all configured hosts."
  fi
  log_info "============================================================"

  exit 0 # Successful exit
} # End of main_logic function


# === Script Execution Starts Here ===

# --- Argument Parsing ---
SHORT_OPTS="vhVd"; LONG_OPTS="verbose,help,version,dry-run"
declare parsed_options=""; parsed_options=$(getopt -o "$SHORT_OPTS" --long "$LONG_OPTS" -n "$SCRIPT_NAME" -- "$@")
if [[ $? != 0 ]] ; then echo "ERROR: Invalid options provided. Use -h for help." >&2 ; exit 1 ; fi
eval set -- "$parsed_options";
while true ; do
  case "$1" in
    -d|--dry-run) dry_run=1 ; shift ;;
    -v|--verbose) verbose=1; LOG_LEVEL=3 ; shift ;; # Set LOG_LEVEL for verbose
    -h|--help) show_help=1 ; shift ;;
    -V|--version) show_version=1 ; shift ;;
    --) shift ; break ;;
    *) echo "Internal error processing options!" >&2 ; exit 1 ;;
  esac
done

# --- Handle -h and -V Options ---
if [[ "$show_help" -eq 1 ]]; then show_help; exit 0; fi
if [[ "$show_version" -eq 1 ]]; then show_version; exit 0; fi

# --- Check Root Privileges ---
if [[ "$(id -u)" -ne 0 ]]; then
  # Use early_error if full logging not yet set up
  if type log_error &>/dev/null; then log_error "This script must be run as root."; else echo "ERROR: This script must be run as root." >&2; fi
  exit 1
fi


# --- Acquire Script Instance Lock (flock) and Run Main Logic ---
exec 200>"$SCRIPT_INSTANCE_LOCK_FILE" # Use literal FD number
if ! flock -n 200; then
  if type log_error &>/dev/null; then 
    log_error "[$SCRIPT_NAME] Another instance is already running (Lock file: '$SCRIPT_INSTANCE_LOCK_FILE'). Exiting."
  else 
    echo "ERROR: [$SCRIPT_NAME] Another instance is already running (Lock file: '$SCRIPT_INSTANCE_LOCK_FILE'). Exiting." >&2
  fi
  exit 1
fi
# Lock Acquired! Call the main function. EXIT trap handles cleanup & lock release.
main "$@"

# Exit code is determined by the 'exit' command within main() or trap_exit_handler()

