#!/bin/bash

# ==============================================================================
# Restic Repository Maintenance Script
# ==============================================================================
# Description:
# Performs maintenance tasks (forget --prune, check) on Restic repositories
# managed by the backup_server.sh script. Reads configuration from the
# central backup config file to locate repositories and password file.
# Uses file locking to prevent concurrent runs. Supports dry-run for forget.
# Sends email notification on error.
# Adheres to Google Shell Style Guide. Root privileges required.
# Includes signal handling and granular logging.
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
# Date: 2025-05-22
# Version: 0.2
# ==============================================================================

# --- Script Metadata and Constants ---
readonly SCRIPT_VERSION="0.2"
readonly SCRIPT_NAME=$(basename "$0")
# Path to the *server's* main backup configuration file
readonly SERVER_CONFIG_FILE="/etc/backup/server_config.yml"
# Path to common config for tool paths etc.
readonly COMMON_CONFIG_FILE="/etc/backup/common_config"
# Lock file location (different from the main backup script's lock)
readonly LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
readonly LOCK_FD_NUM=201 # Use a different FD number

# Default Restic forget policy (can be overridden in server_config.yml)
readonly DEFAULT_RESTIC_FORGET_POLICY="--keep-daily 7 --keep-weekly 4 --keep-monthly 12 --keep-yearly 3"
# Default plugin dir to find common_functions.sh
readonly DEFAULT_PLUGIN_DIR="/opt/backup/lib/plugins"

# --- Script Flags and State Variables ---
# Command line flags (lowercase)
verbose=0
show_help=0
show_version=0
dry_run=0
# Config variables (UPPERCASE)
LOG_LEVEL=2 # Default to INFO (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)
ADMIN_EMAIL_GLOBAL="" # For error reporting
MSMTP_CMD=""
YQ_CMD=""
RESTIC_REPO_ROOT=""
RESTIC_PW_FILE=""
RESTIC_CMD=""
RESTIC_FORGET_POLICY=""
RESTIC_PRUNE="true" # Default to true
RESTIC_CHECK="true" # Default to true
RESTIC_CHECK_OPTIONS=""
EMAIL_SUBJECT_PREFIX="" # Loaded from config
HOSTNAME=""             # Loaded from config
# Runtime state (lowercase)
tmp_log_file=""
declare -a hosts_config_maint=() # Array to hold host JSON chunks
declare -a failed_repos=() # Track repos that failed maintenance
# Error context variables (lowercase)
error_lineno=0
error_command=""
declare -a error_funcstack=()

# --- Shell Options ---
# 'set -e' and 'set -o pipefail' are set inside main_logic after traps.

# --- Source Common Functions ---
COMMON_FUNCTIONS_SCRIPT_PATH="${DEFAULT_PLUGIN_DIR}/common_functions.sh"
if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
else
    echo "WARNING: common_functions.sh not found at '$COMMON_FUNCTIONS_SCRIPT_PATH', using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [Maint] $1"; }
    log_info() { if [[ "${LOG_LEVEL:-2}" -ge 2 ]]; then _log_base "INFO:  $1"; fi; }
    log_error() { _log_base "ERROR: $1" >&2; }
    log_warn() { if [[ "${LOG_LEVEL:-2}" -ge 1 ]]; then _log_base "WARN:  $1" >&2; fi; }
    log_detail() { if [[ "${LOG_LEVEL:-2}" -ge 3 ]]; then _log_base "DEBUG: $1"; fi; }
    check_perms() { log_detail "Permissions check skipped (common_functions.sh not found)."; return 0; }
    check_command_exists() { command -v "$1" &>/dev/null; }
    syntax_check_shell_script() { log_detail "Shell syntax check skipped."; return 0; }
    syntax_check_yaml_file() { log_detail "YAML syntax check skipped."; return 0; }
    send_email() { log_error "send_email function not available from common_functions.sh"; return 1; }
fi

# --- Function Definitions ---

# Function: show_help
# Description:
#   Displays the help message for this maintenance script.
# Arguments:
#   None.
# Outputs:
#   Help text to stdout.
show_help() {
  cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Performs Restic maintenance (forget --prune, check) on repositories defined
in '${SERVER_CONFIG_FILE}'. Uses file locking '${LOCK_FILE}'. Sends email
on failure.

Options:
  -d, --dry-run    Enable dry-run mode for 'restic forget --prune'. Shows what
                   would be removed without actually removing anything. 'restic check'
                   will still run as it doesn't modify data. Emails are not sent
                   for dry-run failures.
  -v, --verbose    Enable verbose output (sets LOG_LEVEL to DEBUG).
  -h, --help       Display this help message and exit.
  -V, --version    Display script version (${SCRIPT_VERSION}) and exit.

Configuration:
  Reads Restic settings and the hosts list from '${SERVER_CONFIG_FILE}'.
  Reads tool paths and default log level from '${COMMON_CONFIG_FILE}'.
  Log level can be overridden by 'MAINTENANCE_LOG_LEVEL' in server_config.yml.

Prerequisites:
  restic, yq (v4+), flock, standard coreutils, msmtp (for email). Root privileges.

Example:
  sudo ${SCRIPT_NAME} -v        # Run maintenance with verbose output.
  sudo ${SCRIPT_NAME} --dry-run  # Simulate forget/prune actions.
EOF
}

# Function: show_version
# Description:
#   Displays the version of this maintenance script.
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
  if [[ "$signal_name" == "SIGINT" ]]; then
    trap_exit_handler 130 # Standard exit code for Ctrl+C
  else # SIGTERM or other
    trap_exit_handler 143 # Standard exit code for SIGTERM
  fi
}

# Function: trap_exit_handler
# Description:
#   EXIT trap handler. Cleans up the temporary log file and sends an error email
#   if the script failed (and not in dry-run mode).
# Arguments:
#   $1 (optional): Explicit exit code to use. Defaults to $?.
# shellcheck disable=SC2317  # Don't warn about unreachable commands in this function
trap_exit_handler() {
  local exit_code=${1:-$?}
  # Disable exit-on-error within this trap function to ensure all cleanup runs
  set +e

  log_detail "--- Running Maintenance EXIT trap (Exit code: ${exit_code}) ---"

  if [[ "$exit_code" -ne 0 ]]; then
    log_error "Restic maintenance script finished with ERROR (Exit Code: ${exit_code})."
    # Send email on error, unless in dry-run mode
    if [[ "${dry_run:-0}" -eq 0 ]] && [[ -n "$ADMIN_EMAIL_GLOBAL" ]]; then
      local subject="${EMAIL_SUBJECT_PREFIX:-[Restic Maint]} ${HOSTNAME} - Maintenance FAILED (Code: ${exit_code})"
      local email_body
      # Use printf for body to correctly interpret \n
      printf -v email_body "Restic maintenance script failed on host: %s\n" "${HOSTNAME}"
      printf -v email_body "%sTimestamp: %s\n" "$email_body" "$(date --rfc-3339=seconds)"
      printf -v email_body "%sExit Code: %s\n" "$email_body" "${exit_code}"
      printf -v email_body "%sError Line: %s\n" "$email_body" "${error_lineno}"
      printf -v email_body "%sFailed Command: %s\n" "$email_body" "${error_command}"
      printf -v email_body "%sCall Stack: %s\n\n" "$email_body" "$(IFS=" -> "; echo "${error_funcstack[*]}")"
      printf -v email_body "%sFailed Repositories:\n" "$email_body"
      if [[ ${#failed_repos[@]} -gt 0 ]]; then
        local repo
        for repo in "${failed_repos[@]}"; do
          printf -v email_body "%s  - %s\n" "$email_body" "${repo}"
        done
      else
        printf -v email_body "%s  (None listed, or error was global)\n" "$email_body"
      fi
      printf -v email_body "%s\nFull log available on server at: %s" "$email_body" "${tmp_log_file:-N/A}"

      # send_email is from common_functions.sh
      send_email "$ADMIN_EMAIL_GLOBAL" "$subject" "$email_body"
    elif [[ "${dry_run:-0}" -eq 1 ]]; then
      log_info "DRY-RUN: Maintenance script failed (Code: ${exit_code}). Email reporting skipped."
    fi

    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
      echo "Log file kept for analysis: ${tmp_log_file}" >&2
    fi
  else
    log_info "Restic maintenance script finished successfully."
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
      rm -f "$tmp_log_file"
    fi
  fi

  # --- Release Lock and Exit ---
  log_detail "Exiting maintenance script. Lock will be released (FD ${LOCK_FD_NUM})."
  # File descriptor for flock is closed automatically on script exit.
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
  trap 'trap_sigterm_sigint_handler SIGINT' SIGINT
  trap 'trap_sigterm_sigint_handler SIGTERM' SIGTERM

  # Enable errexit and pipefail now that traps and logging are set up
  set -eo pipefail

  # --- Start Process ---
  log_info "============================================================"
  log_info "Starting Restic Maintenance Script (Version ${SCRIPT_VERSION}) - Locked (PID $$)"
  if [[ "${dry_run}" -eq 1 ]]; then
    log_info "*** DRY-RUN MODE ACTIVATED (Applies to forget --prune) ***"
  fi

  # --- Load Common Config ---
  log_info "Loading common configuration from ${COMMON_CONFIG_FILE}..."
  if ! syntax_check_shell_script "${COMMON_CONFIG_FILE}"; then
    exit 1 # Exit if common_config has syntax errors
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
  # Source directly, common_config should be robust against 'set -u' if used by caller
  # shellcheck source=/dev/null
  source "${COMMON_CONFIG_FILE}"; source_exit_code=$?
  if [[ ${source_exit_code} -ne 0 ]]; then
    log_error "Failed to source common config file '${COMMON_CONFIG_FILE}'. Syntax error?"
    exit 1
  fi
  log_detail "Common configuration sourced."

  # --- Load Server Config (YAML) ---
  log_info "Loading server configuration from ${SERVER_CONFIG_FILE}..."
  if ! syntax_check_yaml_file "${SERVER_CONFIG_FILE}"; then
    exit 1 # Exit if server_config.yml has syntax errors
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
  RESTIC_CMD="${RESTIC_CMD:-restic}"
  MSMTP_CMD="${MSMTP_CMD:-msmtp}" # For email notifications
  # Check required commands
  if ! check_command_exists "$YQ_CMD"; then exit 1; fi
  if ! check_command_exists "$RESTIC_CMD"; then exit 1; fi
  if ! check_command_exists "$MSMTP_CMD"; then
    log_warn "msmtp command ('$MSMTP_CMD') not found. Email notifications on failure will not be sent."
  fi

  # Read Restic settings from YAML, overriding common defaults if present
  local val # Temp var for yq output
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.repository_root" ""); if [[ -n "$val" ]]; then RESTIC_REPO_ROOT="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.password_file" ""); if [[ -n "$val" ]]; then RESTIC_PW_FILE="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.restic_cmd" ""); if [[ -n "$val" ]]; then RESTIC_CMD="$val"; fi
  # Read maintenance specific settings
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.forget_policy" ""); if [[ -n "$val" ]]; then RESTIC_FORGET_POLICY="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.prune" "true"); RESTIC_PRUNE="$val"
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.check" "true"); RESTIC_CHECK="$val"
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.check_options" ""); RESTIC_CHECK_OPTIONS="$val"
  # Read global settings needed for email
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.admin_email" ""); if [[ -n "$val" ]]; then ADMIN_EMAIL_GLOBAL="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".global.msmtp_cmd" ""); if [[ -n "$val" ]]; then MSMTP_CMD="$val"; fi
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".email_subject_prefix" "[Restic Maint]"); EMAIL_SUBJECT_PREFIX="$val"
  val=$(get_yaml_value "$SERVER_CONFIG_FILE" ".hostname" "$(hostname -f)"); HOSTNAME="$val"
  # Fallback to common_config for ADMIN_EMAIL_GLOBAL if not set in server_config
  ADMIN_EMAIL_GLOBAL="${ADMIN_EMAIL_GLOBAL:-${DEFAULT_ADMIN_EMAIL}}"
  # Read and set LOG_LEVEL
  local log_level_yml; log_level_yml=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.log_level" "")
  if [[ -n "$log_level_yml" ]] && [[ "$log_level_yml" =~ ^[0-3]$ ]]; then
    LOG_LEVEL="$log_level_yml"
  elif [[ -n "${LOG_LEVEL_COMMON}" ]] && [[ "${LOG_LEVEL_COMMON}" =~ ^[0-3]$ ]]; then # Check if LOG_LEVEL_COMMON was set by common_config
    LOG_LEVEL="$LOG_LEVEL_COMMON"
  fi
  # Override with verbose flag if set
  if [[ "${verbose}" -eq 1 ]]; then
    LOG_LEVEL=3
  fi


  # --- Validate Restic Config ---
  log_info "Validating Restic configuration..."
  local validation_ok=1 # Use local var
  if [[ -z "$RESTIC_REPO_ROOT" ]] || ! is_valid_path "$RESTIC_REPO_ROOT" "-d"; then
    log_error "Config Error: restic.repository_root ('$RESTIC_REPO_ROOT') is invalid or missing."
    validation_ok=0
  fi
  if [[ -z "$RESTIC_PW_FILE" ]]; then
    log_error "Config Error: restic.password_file is not set."
    validation_ok=0
  elif ! check_perms "$RESTIC_PW_FILE" "600" "root"; then
    # check_perms logs its own error
    validation_ok=0
  fi
  if [[ "$RESTIC_PRUNE" != "true" ]] && [[ "$RESTIC_PRUNE" != "false" ]]; then
    log_error "Config Error: restic.maintenance.prune must be true or false."
    validation_ok=0
  fi
  if [[ "$RESTIC_CHECK" != "true" ]] && [[ "$RESTIC_CHECK" != "false" ]]; then
    log_error "Config Error: restic.maintenance.check must be true or false."
    validation_ok=0
  fi
  if [[ -z "$RESTIC_FORGET_POLICY" ]]; then
    RESTIC_FORGET_POLICY="$DEFAULT_RESTIC_FORGET_POLICY"
    log_detail "Using default Restic forget policy."
  fi

  if [[ "$validation_ok" -eq 0 ]]; then
    log_error "Restic configuration validation failed. Aborting."
    exit 1
  fi
  log_info "Restic configuration validated."

  # --- Read Host List ---
  log_info "Reading host list from ${SERVER_CONFIG_FILE}..."
  HOSTS_CONFIG_MAINT=() # Reset global array
  local host_count
  host_count=$(get_yaml_value "$SERVER_CONFIG_FILE" ".hosts | length" "0")
  if [[ "$host_count" -eq 0 ]]; then
    log_error "No host configurations found in '.hosts[]'. Nothing to do."
    exit 1
  fi

  local i host_config_json hostname # Local loop vars
  for (( i=0; i<host_count; i++ )); do
      host_config_json=$("$YQ_CMD" e ".hosts[${i}]" -o=json "$SERVER_CONFIG_FILE")
      hostname=$(get_yaml_value <(echo "$host_config_json") '.hostname' "") # Parse from JSON chunk
      if [[ -z "$hostname" ]]; then
        log_error "Host config ${i}: 'hostname' is missing. Skipping."
        continue
      fi
      # Store the valid JSON chunk for iteration
      HOSTS_CONFIG_MAINT+=("$host_config_json")
      log_detail "Host ${i} (${hostname}): Configuration found."
  done

  if [[ ${#HOSTS_CONFIG_MAINT[@]} -eq 0 ]]; then
    log_error "No valid host configurations loaded. Nothing to do."
    exit 1
  fi
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
        local host_forget_policy # Per-host forget policy

        # Parse hostname and per-host forget policy
        hostname=$(get_yaml_value <(echo "$host_config_json") '.hostname' "")
        host_forget_policy=$(get_yaml_value <(echo "$host_config_json") '.restic_forget_policy // ""' "") # Use yq's default if key missing

        if [[ -z "$hostname" ]]; then
          log_error "Internal Error: Missing hostname in validated config chunk."
          return 1 # Should not happen
        fi

        log_info ">>> Processing Maintenance for Host Repository: $hostname <<<"
        repo_path="${RESTIC_REPO_ROOT}/${hostname}"
        log_detail "Repository path: ${repo_path}"

        # Check if repository directory exists
        if ! is_valid_path "$repo_path" "-d"; then # Use common function
          log_error "Restic repository directory not found for host '$hostname' at: ${repo_path}. Skipping."
          return 1
        fi

        # --- Restic Forget --prune ---
        log_info "  Running 'restic forget' for repository: ${repo_path}"
        # Build forget arguments safely
        local -a forget_args=() # Local array
        local current_forget_policy
        if [[ -n "$host_forget_policy" ]]; then
            current_forget_policy="$host_forget_policy"
            log_detail "  Using per-host forget policy: ${current_forget_policy}"
        else
            current_forget_policy="$RESTIC_FORGET_POLICY" # Global or default
            log_detail "  Using global/default forget policy: ${current_forget_policy}"
        fi
        read -r -a forget_args <<< "$current_forget_policy" # Split policy string

        if [[ "$RESTIC_PRUNE" == "true" ]]; then
          forget_args+=(--prune)
        fi
        if [[ "${dry_run}" -eq 1 ]]; then
          forget_args+=(--dry-run)
          log_info "    (Dry Run Enabled for forget/prune)"
        fi
        if [[ "${verbose}" -eq 1 ]]; then # verbose implies LOG_LEVEL=3
          forget_args+=(-v)
        fi

        log_detail "Executing: ${RESTIC_CMD} -r \"${repo_path}\" --password-file \"${RESTIC_PW_FILE}\" forget ${forget_args[*]}"
        if ! "$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" forget "${forget_args[@]}"; then
            log_error "Restic forget/prune failed for repository: ${repo_path}"
            return 1 # Exit subshell with error
        fi
        log_info "  -> Restic forget/prune completed."

        # --- Restic Stats (Optional Detailed Reporting) ---
        # Example: Add a config option like '.restic.maintenance.show_stats: true'
        local show_stats
        show_stats=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.show_stats" "false")
        if [[ "$show_stats" == "true" ]]; then
            log_info "  Running 'restic stats' for repository: ${repo_path}"
            # Capture output to log it, as stats can be verbose
            local stats_output
            stats_output=$("$RESTIC_CMD" -r "$repo_path" --password-file "$RESTIC_PW_FILE" stats --mode raw-data --json 2>/dev/null || echo "Error getting stats")
            log_info "  Restic Stats for ${repo_path}:\n${stats_output}"
        fi


        # --- Restic Check ---
        if [[ "$RESTIC_CHECK" == "true" ]]; then
            log_info "  Running 'restic check' for repository: ${repo_path}"
            local -a check_args=() # Local array
            read -r -a check_args <<< "$RESTIC_CHECK_OPTIONS" # Split options
            if [[ "${verbose}" -eq 1 ]]; then
              check_args+=(-v)
            fi
            # Example: Add --read-data or --read-data-subset from config
            local read_data_mode
            read_data_mode=$(get_yaml_value "$SERVER_CONFIG_FILE" ".restic.maintenance.check_read_data_mode" "") # e.g. "10%" or "true"
            if [[ "$read_data_mode" == "true" ]]; then
                check_args+=(--read-data)
                log_info "    (Performing full data read for check)"
            elif [[ -n "$read_data_mode" ]] && [[ "$read_data_mode" != "false" ]]; then
                check_args+=(--read-data-subset "$read_data_mode")
                log_info "    (Performing partial data read ('$read_data_mode') for check)"
            fi

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
        local failed_hostname
        failed_hostname=$(get_yaml_value <(echo "$host_config_json") '.hostname' "UNKNOWN")
        log_error ">>> Maintenance FAILED for host repository ${failed_hostname} (Subshell Exit Code: ${host_fail_code}) <<<"
        # Use declare -g to modify global array from subshell error handler context
        declare -g -a FAILED_REPOS+=("$failed_hostname")
        echo # Blank line for separation
    }
  done # End host loop

  # --- Final Summary ---
  log_info "============================================================"
  if [[ ${#FAILED_REPOS[@]} -gt 0 ]]; then
      log_error "Restic maintenance run finished with errors for ${#FAILED_REPOS[@]} repositories:"
      local failed_repo # Local loop var
      for failed_repo in "${FAILED_REPOS[@]}"; do
        log_error "  - ${failed_repo}"
      done
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
if [[ "$(id -u)" -ne 0 ]]; then echo "ERROR: This script must be run as root."; exit 1; fi


# --- Acquire Lock and Run Main Logic ---
exec 200>"$LOCK_FILE" # Use literal FD number
if ! flock -n 200; then
  # Use early_error as full logging might not be set up if lock fails
  if type log_error &>/dev/null; then
    log_error "[$SCRIPT_NAME] Another instance is already running (Lock file: '$LOCK_FILE'). Exiting."
  else
    echo "ERROR: [$SCRIPT_NAME] Another instance is already running (Lock file: '$LOCK_FILE'). Exiting." >&2
  fi
  exit 1
fi
# Lock Acquired! Call the main function. EXIT trap handles cleanup & lock release.
main "$@"

# Exit code is determined by the 'exit' command within main() or trap_exit_handler()

