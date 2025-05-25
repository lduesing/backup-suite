#!/bin/bash

# ==============================================================================
# Local Backup Script - Core Orchestrator
# ==============================================================================
# Description:
# Core script for modular backup on client machines. Reads common defaults from
# /etc/backup/common_config and client specifics from /etc/backup/client_config.yml.
# Discovers services (YAML) & plugins (.sh). Orchestrates plugin calls using
# defined stages. Handles setup, script instance locking (flock), shared
# directory locking for TAR creation (mkdir-based with retries), logging,
# traps (SIGINT, SIGTERM), TAR creation/verification, cleanup, error reporting.
# Excludes plugin state dirs from TAR. Supports dry-run.
# Adheres to Google Shell Style Guide. Root privileges required.
# Ensures correct permissions for server-side cleanup in 'done' directory.
#
# Installation Path: /opt/backup/bin/local_backup.sh
#
# License: AGPL-3.0-or-later
# Copyright (c) 2025 Lars Duesing  <lars.duesing@camelotsweb.de>
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
# Author: Lars Duesing
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
# Path to client-specific config file (YAML)
readonly CLIENT_CONFIG_FILE="${CONFIG_DIR}/client_config.yml"
# Internal script defaults (UPPERCASE with SCRIPT_ prefix)
readonly SCRIPT_DEFAULT_MIN_FREE_SPACE_MB=500
readonly SCRIPT_DEFAULT_PLUGIN_DIR="/opt/backup/lib/plugins" # Default install path
# Script instance lock file location (for flock)
readonly SCRIPT_INSTANCE_LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
readonly SCRIPT_INSTANCE_LOCK_FD_NUM=200 # Literal FD number for flock
# Shared directory lock constants (for TAR creation)
readonly SHARED_LOCK_RETRY_COUNT=3
readonly SHARED_LOCK_RETRY_DELAY_SECONDS=60
# SHARED_LOCK_DIR_PATH is defined in main() after BASE_BACKUP_DIR is known

# --- Script Flags and State Variables ---
# Command line flags (lowercase)
verbose=0 # 0=No, 1=Yes. If 1, LOG_LEVEL will be set to 3 (DEBUG).
show_help=0
show_version=0
dry_run=0 # 0=No, 1=Yes
# Config variables (UPPERCASE, loaded from configs)
LOG_LEVEL=2 # Default to INFO (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)
BASE_BACKUP_DIR=""
BACKUP_USER=""
BACKUP_GROUP=""
EMAIL_RECIPIENT=""
KEEP_DAYS=""
EMAIL_SUBJECT_PREFIX=""
HOSTNAME=""
DOCKER_COMMAND=""
MIN_FREE_SPACE_MB=""
PLUGIN_DIR=""
YQ_CMD=""
TAR_CMD=""
RSYNC_CMD=""
PG_DUMP_CMD=""
MYSQL_DUMP_CMD=""
MSMTP_CMD=""
# Runtime state (lowercase)
tmp_log_file=""
work_dir=""
# Path to the directory used as a lock for TAR creation
shared_lock_dir_path="" 
error_lineno=0
error_command=""
declare -a error_funcstack=()
declare -a discovered_plugins=()
any_docker_service_action_taken=false # Tracks if docker plugin performed start/stop


# --- Shell Options ---
# 'set -e' and 'set -o pipefail' are set inside main_logic after traps.

# --- Source Common Functions ---
# Determine potential common functions path using script default plugin dir initially.
# This path might be updated after loading the actual PLUGIN_DIR config.
COMMON_FUNCTIONS_SCRIPT_PATH="${SCRIPT_DEFAULT_PLUGIN_DIR}/common_functions.sh"
if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
else
    # Define minimal logging if common script not found.
    # These will be overridden if common_functions.sh is successfully sourced later.
    echo "WARNING: common_functions.sh not found at '$COMMON_FUNCTIONS_SCRIPT_PATH', using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"; }
    log_info() { if [[ "${LOG_LEVEL:-2}" -ge 2 ]]; then _log_base "INFO:  $1"; fi; }
    log_error() { _log_base "ERROR: $1" >&2; }
    log_warn() { if [[ "${LOG_LEVEL:-2}" -ge 1 ]]; then _log_base "WARN:  $1" >&2; fi; }
    log_detail() { if [[ "${LOG_LEVEL:-2}" -ge 3 ]]; then _log_base "DEBUG: $1"; fi; }
    check_perms() { log_detail "Permissions check skipped (common_functions.sh not found)."; return 0; }
    check_disk() { log_detail "Disk space check skipped (common_functions.sh not found)."; return 0; }
    create_dir_secure() { local dir_path="$1"; mkdir -p "$dir_path" && chmod 700 "$dir_path" || { echo "ERROR: Failed to create dir: ${dir_path}" >&2; exit 1; }; }
    create_secure_temp_file() { local tmpl="${1:-tmp.XXXXXX}"; local dir="${2:-/tmp}"; mktemp "${dir}/${tmpl}"; }
    check_command_exists() { command -v "$1" &>/dev/null; }
    syntax_check_shell_script() { log_detail "Shell syntax check skipped."; return 0; }
    syntax_check_yaml_file() { log_detail "YAML syntax check skipped."; return 0; }
    get_yaml_value() { echo "${3:-}"; return 1; }
    send_email() { log_error "send_email function not available from common_functions.sh"; return 1; }
fi

# --- Function Definitions (Core Script Specific) ---

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

Orchestrates local backups using a plugin architecture. Reads common defaults
from '${COMMON_CONFIG_FILE}', client settings from '${CLIENT_CONFIG_FILE}',
and service definitions from 'service.yaml' files found within subdirectories
of '${CONFIG_DIR}/'. Discovers plugins in the configured PLUGIN_DIR.
Includes a dry-run mode.

Options:
  -d, --dry-run    Enable dry-run mode. Simulates backup without making changes.
  -v, --verbose    Enable verbose output (sets LOG_LEVEL to DEBUG).
  -h, --help       Display this help message and exit.
  -V, --version    Display script version (${SCRIPT_VERSION}) and exit.

Configuration:
  See '${COMMON_CONFIG_FILE}', '${CLIENT_CONFIG_FILE}', and README.md for details.

Plugins:
  See plugin directory (defined by PLUGIN_DIR, default: ${SCRIPT_DEFAULT_PLUGIN_DIR})
  and its README.md.

Instance Lock File (flock):
  Uses lock file '${SCRIPT_INSTANCE_LOCK_FILE}' via file descriptor ${SCRIPT_INSTANCE_LOCK_FD_NUM}.
Shared Directory Lock (mkdir):
  A directory named ".backup_archive_in_progress.lock" is created in BASE_BACKUP_DIR
  during TAR creation to prevent server fetching an incomplete archive.

Example:
  sudo ${SCRIPT_NAME} -v     # Run backup with verbose output.
  sudo ${SCRIPT_NAME} --dry-run # Simulate backup run.
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

# Function: validate_loaded_config
# Description:
#   Performs detailed validation of configuration variables that have been
#   loaded from both common_config and client_config.yml.
#   Uses helper functions from common_functions.sh for checks.
# Arguments:
#   None. Uses global UPPERCASE configuration variables.
# Returns:
#   0 if all validations pass.
#   1 if any validation fails, logging specific errors.
validate_loaded_config() {
  log_info "Validating loaded configuration..."
  local validation_ok=1 # Assume OK
  # Check mandatory variables that should be defined after loading configs
  local mandatory_vars=(
    BASE_BACKUP_DIR BACKUP_USER BACKUP_GROUP EMAIL_RECIPIENT KEEP_DAYS PLUGIN_DIR
  )
  local var
  for var in "${mandatory_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
      log_error "Config Error: Mandatory variable '$var' is not defined."
      validation_ok=0
    fi
  done

  log_detail "Checking BASE_BACKUP_DIR ('${BASE_BACKUP_DIR}')..."
  # For BASE_BACKUP_DIR, initially only check if it's a directory and writable by root.
  # The main() function will handle creating it and setting more specific group permissions later.
  if ! is_valid_path "${BASE_BACKUP_DIR}" "-d"; then
    # If it doesn't exist, main() will try to create it.
    # If it exists but is not a directory, that's an error.
    if [[ -e "$BASE_BACKUP_DIR" ]]; then
        log_error "Config Error: BASE_BACKUP_DIR '$BASE_BACKUP_DIR' exists but is not a directory."
        validation_ok=0
    else
        log_info "Config Info: BASE_BACKUP_DIR '$BASE_BACKUP_DIR' does not exist. Will attempt to create."
    fi
  elif ! is_valid_path "${BASE_BACKUP_DIR}" "-w"; then
    log_error "Config Error: BASE_BACKUP_DIR '$BASE_BACKUP_DIR' is not writable by current user (root)."
    validation_ok=0
  fi

  log_detail "Checking PLUGIN_DIR ('${PLUGIN_DIR}')..."
  if ! is_valid_path "${PLUGIN_DIR}" "-d"; then
    validation_ok=0
  fi

  log_detail "Checking BACKUP_USER ('${BACKUP_USER}')..."
  if ! id -u "$BACKUP_USER" &>/dev/null; then
    log_error "Config Error: BACKUP_USER '$BACKUP_USER' does not exist."
    validation_ok=0
  fi
  log_detail "Checking BACKUP_GROUP ('${BACKUP_GROUP}')..."
  if ! getent group "$BACKUP_GROUP" &>/dev/null; then
    log_error "Config Error: BACKUP_GROUP '$BACKUP_GROUP' does not exist."
    validation_ok=0
  fi

  log_detail "Checking EMAIL_RECIPIENT ('${EMAIL_RECIPIENT}')..."
  if ! [[ "$EMAIL_RECIPIENT" =~ ^.+@.+\..+$ ]]; then
    log_warn "Config Warning: EMAIL_RECIPIENT '$EMAIL_RECIPIENT' does not look like a valid email address."
  fi

  log_detail "Checking KEEP_DAYS ('${KEEP_DAYS}')..."
  if ! [[ "$KEEP_DAYS" =~ ^[1-9][0-9]*$ ]]; then
    log_error "Config Error: KEEP_DAYS '$KEEP_DAYS' must be a positive integer."
    validation_ok=0
  fi

  log_detail "Checking MIN_FREE_SPACE_MB ('${MIN_FREE_SPACE_MB}')..."
  if ! [[ "$MIN_FREE_SPACE_MB" =~ ^[0-9]+$ ]]; then
    log_error "Config Error: MIN_FREE_SPACE_MB '$MIN_FREE_SPACE_MB' must be a non-negative integer."
    validation_ok=0
  fi

  local -a tool_vars_to_check=(
    YQ_CMD TAR_CMD RSYNC_CMD DOCKER_CMD PG_DUMP_CMD MYSQL_DUMP_CMD MSMTP_CMD
  )
  local tool_var tool_cmd
  for tool_var in "${tool_vars_to_check[@]}"; do
    tool_cmd=$(echo "${!tool_var}" | cut -d' ' -f1) # Get first word (command)
    if [[ -n "$tool_cmd" ]] && ! check_command_exists "$tool_cmd"; then
      # check_command_exists logs its own error
      validation_ok=0
    fi
  done

  if [[ "$validation_ok" -eq 0 ]]; then
    log_error "Loaded configuration validation failed."
    return 1
  fi
  log_info "Loaded configuration validation passed."
  return 0
}

# --- Trap Functions ---

# Function: trap_err_handler
# Description:
#   ERR trap handler. Captures context (line number, command, function stack)
#   when a command fails (due to 'set -e'). Sets global error_* variables.
# Arguments:
#   None (implicitly receives error context from Bash).
# shellcheck disable=SC2317  # Don't warn about unreachable commands in this function
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
#   Performs final cleanup (temporary working directory, temporary log file, lock file),
#   attempts emergency plugin cleanup actions, and sends a detailed error
#   report email if the script failed (and not in dry-run mode).
# Arguments:
#   $1 (optional): Explicit exit code to use. Defaults to $?.
# shellcheck disable=SC2317  # Don't warn about unreachable commands in this function
trap_exit_handler() {
  local exit_code=${1:-$?}
  # Disable exit-on-error within this trap function to ensure all cleanup runs
  set +e

  log_detail "--- Running EXIT trap (Exit code: ${exit_code}) ---"

  # --- Attempt Emergency Plugin Cleanup ---
  log_detail "Running emergency cleanup for plugins..."
  if [[ -n "$work_dir" ]] && [[ -d "$work_dir" ]]; then
    local state_dir_list_file
    state_dir_list_file=$(mktemp)
    # Ignore find errors if work_dir vanished during script execution
    find "$work_dir" -mindepth 2 -maxdepth 3 -type d -name '.state' -print > "$state_dir_list_file" 2>/dev/null || true
    local state_dir service_backup_dir service_context_name plugin_script
    while IFS= read -r state_dir; do
      # Skip empty lines if any (e.g., if find had no results)
      if [[ -z "$state_dir" ]] || [[ ! -d "$state_dir" ]]; then
        continue
      fi
      service_backup_dir=$(dirname "$state_dir")
      # Check if service backup dir still exists (might fail very early)
      if [[ ! -d "$service_backup_dir" ]]; then
        continue
      fi
      service_context_name=$(basename "$(dirname "$service_backup_dir")")/$(basename "$service_backup_dir")
      log_detail "Checking emergency cleanup for: ${service_context_name}"
      for plugin_script in "${discovered_plugins[@]}"; do
        if [[ -f "$plugin_script" ]] && [[ -x "$plugin_script" ]]; then
          log_detail "  Calling emergency_cleanup in $(basename "${plugin_script}") for ${service_backup_dir}"
          # Pass DRY_RUN status via environment variable for subshell
          export DRY_RUN_MODE="${dry_run}"
          # Source and call in subshell, passing service backup dir
          (
            # Source common functions first if available
            if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
              # shellcheck source=/dev/null
              source "$COMMON_FUNCTIONS_SCRIPT_PATH"
            fi
            # Source the specific plugin script
            # shellcheck source=/dev/null
            source "$plugin_script"
            # Check if function exists before calling
            if command -v plugin_emergency_cleanup &>/dev/null; then
              plugin_emergency_cleanup "$service_backup_dir"
            fi
            # Ignore return code of cleanup function - best effort
          )
          unset DRY_RUN_MODE # Unset immediately after subshell
        fi
      done # Plugin loop
    done < "$state_dir_list_file"
    rm -f "$state_dir_list_file" # Clean up temp file list
  else
    log_detail "Work directory '$work_dir' not found, skipping plugin emergency cleanup."
  fi
  log_detail "Finished emergency plugin cleanup attempts."

  # --- Send Email Report on Error (Skip in dry-run) ---
  if [[ "$exit_code" -ne 0 ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
    # Ensure log file exists before trying to read/send it
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
      _log_base "################ ERRORS ################" >> "$tmp_log_file"
      _log_base "ERROR: Backup script finished with exit code ${exit_code}!" >> "$tmp_log_file"
      _log_base "Error near line: ${error_lineno}" >> "$tmp_log_file"
      _log_base "Failed Command: ${error_command}" >> "$tmp_log_file"
      _log_base "Call Stack: ${error_funcstack[*]}" >> "$tmp_log_file"
      _log_base "Sending log to ${EMAIL_RECIPIENT}..." >> "$tmp_log_file"
      _log_base "####################################" >> "$tmp_log_file"

      echo "ERROR: Backup failed (Code: ${exit_code}). Log: ${tmp_log_file}" >&2
      echo "Error near line ${error_lineno}, Command: ${error_command}" >&2
      echo "Attempting to send error report..." >&2

      local subject="${EMAIL_SUBJECT_PREFIX} ${HOSTNAME} - Backup FAILED (Code: ${exit_code}, Line: ${error_lineno})"
      local email_body
      printf -v email_body "Hostname: %s\nTimestamp: %s\nExit Code: %s\nError Line: %s\nFailed Command: %s\nCall Stack: %s\n\n--- Full Backup Log ---\n%s" \
        "${HOSTNAME}" \
        "$(date --rfc-3339=seconds)" \
        "${exit_code}" \
        "${error_lineno}" \
        "${error_command}" \
        "$(IFS=" -> "; echo "${error_funcstack[*]}")" \
        "$(cat "${tmp_log_file}")"

      send_email "$EMAIL_RECIPIENT" "$subject" "$email_body" || \
        log_error "Failed to send error email via common function."

      echo "Log kept: ${tmp_log_file}" >&2
    else
      # Error occurred very early, before log file setup? Send minimal email.
      echo "ERROR: Backup script failed early (Code: ${exit_code}). No log file." >&2
      if command -v "$MSMTP_CMD" &>/dev/null && [[ -n "${EMAIL_RECIPIENT}" ]]; then
        local subject="${EMAIL_SUBJECT_PREFIX} ${HOSTNAME} - Backup FAILED EARLY (Code: ${exit_code})"
        printf "To: %s\nSubject: %s\n\nBackup script failed very early. Exit code: %s." \
          "${EMAIL_RECIPIENT}" "${subject}" "${exit_code}" | "$MSMTP_CMD" "${EMAIL_RECIPIENT}"
      fi
    fi
  elif [[ "$exit_code" -ne 0 ]] && [[ "${dry_run:-0}" -eq 1 ]]; then
    log_info "DRY-RUN: Backup script failed (Code: ${exit_code}). Email skipped."
    echo "DRY-RUN: Error. Log: ${tmp_log_file}" >&2
  else
    # --- Success Case ---
    log_info "Backup script finished successfully."
    # Clean up the temporary log file *only* on success
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
      rm -f "$tmp_log_file"
    fi
  fi

  # --- Always Cleanup Working Directory ---
  # This runs AFTER potential email sending so WORK_DIR path is valid in log/email
  if [[ -n "$work_dir" ]] && [[ -d "$work_dir" ]]; then
    log_detail "Cleaning up work dir: ${work_dir}"
    if ! rm -rf "$work_dir"; then
      log_error "Failed to remove work dir '${work_dir}'. Manual cleanup needed."
      # If backup was otherwise successful, ensure we exit with error code due to cleanup failure
      if [[ $exit_code -eq 0 ]]; then
        exit_code=1
      fi
    fi
  fi

  # --- Release Shared Directory Lock File ---
  if [[ -n "$shared_lock_dir_path" ]] && [[ -d "$shared_lock_dir_path" ]]; then
    if rmdir "$shared_lock_dir_path"; then
      log_detail "Shared directory lock released: ${shared_lock_dir_path}"
    else
      # This is a problem, as it might block future runs or server fetches.
      log_error "CRITICAL: Failed to release shared directory lock: ${shared_lock_dir_path}. Manual removal is required!"
      # If script was successful otherwise, ensure we reflect this critical failure
      if [[ $exit_code -eq 0 ]]; then
        exit_code=1 # Or a more specific error code for lock release failure
      fi
    fi
  fi

  # --- Release Script Instance Lock (flock) and Exit ---
  # flock is released automatically when the file descriptor is closed on script exit.
  log_detail "Exiting script with final code ${exit_code}. Instance lock (flock) will be released (FD ${SCRIPT_INSTANCE_LOCK_FD_NUM})."
  exit "${exit_code}"
}

# Function: run_plugin_func
# Description:
#   Helper function to run a specific function within a plugin script.
#   It creates a temporary config file containing the relevant YAML section for the plugin,
#   exports DRY_RUN_MODE, executes the plugin function in a subshell for isolation,
#   and then cleans up the temporary config file.
# Arguments:
#   $1: plugin_script_path - Absolute path to the plugin script.
#   $2: function_name      - Name of the plugin function to call (e.g., "plugin_validate_config").
#   $3: service_yaml_file  - Path to the service's main YAML config file.
#   $4: task_type          - The specific task key from YAML (e.g., "docker", "postgresql").
#   $5: service_config_dir - Path to the directory containing the service.yaml. (Passed to plugin)
#   $6: service_backup_dir - Path to the service's specific temp backup directory. (Passed to plugin)
# Returns:
#   Exit code of the called plugin function.
run_plugin_func() {
  local plugin_script="$1"
  local function_name="$2"
  local service_yaml_file="$3"
  local task_type="$4"
  local service_config_dir="$5"
  local service_backup_dir="$6"

  local plugin_name
  local temp_config_file
  local plugin_exit_code=0 # Default to success

  plugin_name=$(basename "$plugin_script" .sh)
   # Use common function to create temp file
  if ! temp_config_file=$(create_secure_temp_file "${plugin_name}_${function_name}_config.XXXXXX" "${service_backup_dir}/.state"); then
    log_error "Failed to create temp config file for plugin ${plugin_name}."
    return 1
  fi

  # Extract relevant YAML section using YQ
  if ! check_command_exists "$YQ_CMD"; then
    log_error "yq command ('${YQ_CMD}') not found. Cannot run plugin."
    rm -f "$temp_config_file"
    return 1
  fi

  if ! "$YQ_CMD" e ".${task_type}" "$service_yaml_file" > "$temp_config_file"; then
    log_error "Failed to extract YAML section '.${task_type}' for plugin '${plugin_name}' from '${service_yaml_file}'."
    rm -f "$temp_config_file"
    return 1
  fi

  # If yq outputs 'null' for a missing key, the file might be non-empty but contain "null".
  # Ensure it's truly empty if the key was missing or explicitly null.
  if [[ ! -s "$temp_config_file" ]] || \
     [[ $($YQ_CMD e ".${task_type}" "$service_yaml_file") == "null" ]]; then
    log_detail "YAML section '.${task_type}' is empty or null for plugin '${plugin_name}'."
    # Ensure the file is empty for plugins expecting that for missing sections
    echo -n > "$temp_config_file"
  fi

  # Export DRY_RUN_MODE for the subshell where plugin function runs
  export DRY_RUN_MODE="${dry_run}"

  log_detail "Executing plugin function: ${plugin_name} -> ${function_name}"
# Execute the plugin function in a subshell for isolation.
  (
    # Source common functions first (path might have been updated after config load)
    if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
      # shellcheck source=/dev/null
      source "$COMMON_FUNCTIONS_SCRIPT_PATH"
    fi
    # Source the specific plugin script
    # shellcheck source=/dev/null
    source "$plugin_script"
    # Check if the function actually exists within the sourced plugin before calling
    if command -v "$function_name" &>/dev/null; then
      # Call the function, passing the path to the temp config file and other args
      "$function_name" "$temp_config_file" "$service_config_dir" "$service_backup_dir"
    else
      # Function doesn't exist - treat as success ONLY for known optional functions
      if [[ "$function_name" == "plugin_prepare_backup" || \
            "$function_name" == "plugin_post_backup_success" || \
            "$function_name" == "plugin_emergency_cleanup" ]]; then
        log_detail "Optional function '${function_name}' not found in plugin '${plugin_name}'. Skipping."
        exit 0 # Not an error for optional functions
      else
        log_error "Required function '${function_name}' not found in plugin '${plugin_name}'."
        exit 1 # Error if a required function is missing
      fi
    fi
  )
  plugin_exit_code=$? # Capture exit code of the subshell

  # Unset DRY_RUN_MODE immediately after subshell to avoid polluting parent shell
  unset DRY_RUN_MODE

  # Clean up the temporary config file
  rm -f "$temp_config_file"

  log_detail "Plugin function '${function_name}' finished with exit code ${plugin_exit_code}."
  # Return the plugin function's exit code
  return ${plugin_exit_code}
}


# --- Stage Handler Functions (Private to main logic) ---

# Function: _handle_validation_stage
# Description:
#   Identifies relevant plugins for each task type in a service's YAML and
#   calls their 'plugin_validate_config' function.
# Arguments:
#   $1: service_yaml_file  - Path to the service.yaml file.
#   $2: service_config_dir - Path to the directory containing service.yaml.
#   $3: service_backup_dir - Path to the service's temp backup directory.
#   $4: task_types_ref     - Name of an array holding task type strings for the service.
#   $5: service_tasks_ref  - Name of an associative array to be populated with
#                            (task_type -> plugin_script_path) mappings.
# Returns:
#   0 if all plugin validations for the service pass.
#   1 if any plugin validation fails.
_handle_validation_stage() {
  local service_yaml_file="$1"
  local service_config_dir="$2"
  local service_backup_dir="$3"
  local -n task_types_ref="$4"    # Nameref to the task_types array
  local -n service_tasks_ref="$5" # Nameref to the service_tasks map

  log_info "  Stage 1: Identifying plugins and validating config..."
  local validation_overall_ok=1 # 1 for OK, 0 for error
  local task_type
  local plugin_script
  local plugin_name
  local handled

  for task_type in "${task_types_ref[@]}"; do
    handled=false
    for plugin_script in "${discovered_plugins[@]}"; do
      plugin_name=$(basename "$plugin_script" .sh)
      # Check if plugin handles this task type (using subshell for isolation)
      # shellcheck source=/dev/null
      if ( source "$plugin_script" &>/dev/null && plugin_handles_task_type "$task_type" ); then
        log_detail "    Plugin '${plugin_name}' handles task type '${task_type}'. Validating..."


        service_tasks_ref["$task_type"]="$plugin_script" # Store mapping
        # Validate config using the plugin helper function
        if ! run_plugin_func \
            "$plugin_script" \
            "plugin_validate_config" \
            "$service_yaml_file" \
            "$task_type" \
            "$service_config_dir" \
            "$service_backup_dir"; then
           log_error "Config validation failed for task '${task_type}' (Plugin: ${plugin_name})."
           validation_overall_ok=0 # Set to 0 on error
        else
           log_detail "    -> Config validated for '${task_type}'."
        fi
        handled=true
        break # Assume one plugin per task type
      fi # handles task type
    done # plugin discovery loop
    if ! ${handled}; then
      log_warn "  No plugin found to handle task type '${task_type}'."
    fi
  done # task type loop (validation)

  if [[ "$validation_overall_ok" -eq 0 ]]; then
    return 1 # Return 1 if any validation failed
  fi
  return 0 # Return 0 for overall success
}

# Function: _handle_prepare_stage
# Description:
#   Calls the 'plugin_prepare_backup' function for relevant plugins, ensuring
#   Docker plugin (if present) runs its prepare step first. Populates the
#   'prepared_plugins_ref' map.
# Arguments:
#   $1: service_yaml_file
#   $2: service_config_dir
#   $3: service_backup_dir
#   $4: service_tasks_ref     - Nameref to an assoc. array (task_type -> plugin_script).
#   $5: prepared_plugins_ref - Nameref to an assoc. array to be populated
#                               (plugin_script_path -> 1 if prepare successful).
# Returns:
#   0 on success (all prepare steps succeeded or were not needed).
#   1 if any prepare step fails.
_handle_prepare_stage() {
  local service_yaml_file="$1"; local service_config_dir="$2"; local service_backup_dir="$3"
  local -n service_tasks_ref="$4"; local -n prepared_plugins_ref="$5"
  log_info "  Stage 2: Preparing backup (e.g., stopping services)..."
  # prepared_plugins_ref is local to the service loop in main(), reset there.
  local docker_plugin_path=""; local task_type plugin_script plugin_name

  if [[ -v "service_tasks_ref[docker]" ]]; then
    docker_plugin_path="${service_tasks_ref[docker]}"
  fi

  if [[ -n "$docker_plugin_path" ]]; then
    # shellcheck source=/dev/null
    if ( source "$docker_plugin_path" &>/dev/null && type plugin_prepare_backup &>/dev/null ); then
      log_detail "  Preparing task 'docker' using plugin '$(basename "$docker_plugin_path" .sh)'..."
      if run_plugin_func \
          "$docker_plugin_path" "plugin_prepare_backup" \
          "$service_yaml_file" "docker" \
          "$service_config_dir" "$service_backup_dir"; then
        prepared_plugins_ref["$docker_plugin_path"]=1
        log_detail "  -> Prepare successful for 'docker'."
      else
        log_error "Prepare step failed for task 'docker'. Aborting service backup."
        return 1
      fi
    else
      log_detail "  Plugin '$(basename "$docker_plugin_path" .sh)' for 'docker' has no prepare_backup function."
    fi
  fi

  for task_type in "${!service_tasks_ref[@]}"; do
    plugin_script="${service_tasks_ref[$task_type]}"
    plugin_name=$(basename "$plugin_script" .sh)
    if [[ "$plugin_script" == "$docker_plugin_path" ]]; then
      continue
    fi
    # shellcheck source=/dev/null
    if ( source "$plugin_script" &>/dev/null && type plugin_prepare_backup &>/dev/null ); then
        log_detail "  Preparing task '${task_type}' using plugin '${plugin_name}'..."
        if run_plugin_func \
            "$plugin_script" "plugin_prepare_backup" \
            "$service_yaml_file" "$task_type" \
            "$service_config_dir" "$service_backup_dir"; then
          prepared_plugins_ref["$plugin_script"]=1
          log_detail "  -> Prepare successful for '${task_type}'."
        else
          log_error "Prepare step failed for task '${task_type}'. Aborting service backup."
          return 1
        fi
    else
      log_detail "  No prepare step defined for plugin '${plugin_name}' for task '${task_type}'."
    fi
  done
  return 0
}

# Function: _handle_run_stage
# Description:
#   Calls the 'plugin_run_backup' function for all relevant plugins for the service.
#   Performs a disk space check after each plugin's run_backup completes.
# Arguments:
#   $1: service_yaml_file
#   $2: service_config_dir
#   $3: service_backup_dir
#   $4: service_tasks_ref - Nameref to an assoc. array (task_type -> plugin_script).
# Returns:
#   0 on success (all run steps succeeded).
#   1 if any run step or disk check fails.
_handle_run_stage() {
  local service_yaml_file="$1"; local service_config_dir="$2"; local service_backup_dir="$3"
  local -n service_tasks_ref="$4"
  local task_type plugin_script plugin_name
  log_info "  Stage 3: Executing backup tasks..."
  for task_type in "${!service_tasks_ref[@]}"; do
      plugin_script="${service_tasks_ref[$task_type]}"
      plugin_name=$(basename "$plugin_script" .sh)
      log_detail "  Running backup task for '${task_type}' using plugin '${plugin_name}'..."
      if ! run_plugin_func \
          "$plugin_script" "plugin_run_backup" \
          "$service_yaml_file" "$task_type" \
          "$service_config_dir" "$service_backup_dir"; then
         log_error "Backup task failed for '${task_type}'. Aborting service backup."
         return 1
      fi
      log_detail "  -> Backup task successful for '${plugin_name}'."
      # Check disk space after each backup task (skip in dry run)
      if [[ "${dry_run}" -eq 0 ]]; then
          log_detail "    Checking disk space after ${plugin_name} task..."
          # Use common function check_disk, ensure it's available
          if ! check_disk "${work_dir}" "${MIN_FREE_SPACE_MB}"; then
            return 1
          fi
      fi
  done
  return 0
}

# Function: _handle_post_success_stage
# Description:
#   Calls 'plugin_post_backup_success' for plugins that successfully ran 'prepare'.
#   Ensures Docker plugin (if present) runs its post_success step last.
# Arguments:
#   $1: service_yaml_file
#   $2: service_config_dir
#   $3: service_backup_dir
#   $4: service_tasks_ref    - Nameref to an assoc. array (task_type -> plugin_script).
#   $5: prepared_plugins_ref - Nameref to an assoc. array (plugin_script_path -> 1).
# Returns:
#   0 on success (all post_success steps succeeded or were not needed).
#   1 if any post_success step fails.
_handle_post_success_stage() {
  local service_yaml_file="$1"; local service_config_dir="$2"; local service_backup_dir="$3"
  local -n service_tasks_ref="$4"; local -n prepared_plugins_ref="$5"
  local docker_plugin_path=""; if [[ -v "service_tasks_ref[docker]" ]]; then docker_plugin_path="${service_tasks_ref[docker]}"; fi
  local plugin_script plugin_name task_type_for_plugin task_type

  log_info "  Stage 4: Finalizing backup for service..."
  for plugin_script in "${!prepared_plugins_ref[@]}"; do
      plugin_name=$(basename "$plugin_script" .sh)
      if [[ "$plugin_script" == "$docker_plugin_path" ]]; then
        continue # Skip docker for now
      fi
      log_detail "  Running post-backup success actions for plugin '${plugin_name}'..."
      task_type_for_plugin="" # Find task type for this plugin
      for task_type in "${!service_tasks_ref[@]}"; do
        if [[ "${service_tasks_ref[$task_type]}" == "$plugin_script" ]]; then
          task_type_for_plugin="$task_type"
          break
        fi
      done
      if [[ -n "$task_type_for_plugin" ]]; then
          # shellcheck source=/dev/null
          if (source "$plugin_script" &>/dev/null && type plugin_post_backup_success &>/dev/null); then
            if ! run_plugin_func \
                "$plugin_script" "plugin_post_backup_success" \
                "$service_yaml_file" "$task_type_for_plugin" \
                "$service_config_dir" "$service_backup_dir"; then
              log_error "Post-backup success failed for plugin '${plugin_name}'. Aborting."
              return 1
            fi
            log_detail "  -> Post-backup success successful for '${plugin_name}'."
          else
            log_detail "  Plugin '${plugin_name}' has no post_backup_success function."
          fi
      else
        log_error "Internal Error: Could not find task type for prepared plugin '${plugin_name}'"
      fi
  done

  if [[ -v "prepared_plugins_ref[$docker_plugin_path]" ]]; then
    log_detail "  Running post-backup success actions for plugin 'docker_compose'..."
    # shellcheck source=/dev/null
    if (source "$docker_plugin_path" &>/dev/null && type plugin_post_backup_success &>/dev/null); then
      if ! run_plugin_func \
             "$docker_plugin_path" "plugin_post_backup_success" \
             "$service_yaml_file" "docker" \
             "$service_config_dir" "$service_backup_dir"; then
        log_error "Post-backup success failed for 'docker_compose'. Aborting."
        return 1
      fi
      log_detail "  -> Post-backup success successful for 'docker_compose'."
      # any_docker_service_action_taken is handled by the docker plugin itself
    else
      log_detail "  Plugin 'docker_compose' has no post_backup_success function."
    fi
  fi
  return 0
}


# --- Main Function Definition ---
# Encapsulates the primary logic of the script.
main() {
  # --- Setup Logging & Traps ---
  tmp_log_file=$(mktemp /tmp/local_backup_log."$SCRIPT_NAME".XXXXXX)
  chmod 600 "$tmp_log_file"
  exec > >(tee -a "$tmp_log_file") 2>&1
  trap trap_err_handler ERR
  trap trap_exit_handler EXIT
  trap 'trap_sigterm_sigint_handler SIGINT' SIGINT
  trap 'trap_sigterm_sigint_handler SIGTERM' SIGTERM

  # Enable errexit and pipefail now that traps and logging are set up
  set -eo pipefail

  # --- Start Actual Backup Process ---
  log_info "Starting Local Backup Script (Version ${SCRIPT_VERSION}) - PID $$"
  if [[ "${dry_run}" -eq 1 ]]; then
    log_info "*** DRY-RUN MODE ACTIVATED ***"
  fi

  # --- Load Common Config ---
  log_info "Loading common configuration from ${COMMON_CONFIG_FILE}..."
  if ! syntax_check_shell_script "${COMMON_CONFIG_FILE}"; then exit 1; fi
  if [[ ! -f "$COMMON_CONFIG_FILE" ]]; then log_error "Common config file '${COMMON_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${COMMON_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${COMMON_CONFIG_FILE}'."; exit 1; fi
  local source_exit_code # Local var
  # Source directly, common_config should be robust
  # shellcheck source=/dev/null
  source "${COMMON_CONFIG_FILE}"; source_exit_code=$?
  if [[ ${source_exit_code} -ne 0 ]]; then log_error "Failed to source common config file '${COMMON_CONFIG_FILE}'. Syntax error?"; exit 1; fi
  log_detail "Common configuration sourced."

  # --- Load Client Specific Config (YAML) ---
  log_info "Loading client configuration from ${CLIENT_CONFIG_FILE}..."
  if ! syntax_check_yaml_file "${CLIENT_CONFIG_FILE}"; then exit 1; fi
  if [[ ! -f "$CLIENT_CONFIG_FILE" ]]; then log_error "Client config file '${CLIENT_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${CLIENT_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${CLIENT_CONFIG_FILE}'."; exit 1; fi
  YQ_CMD="${YQ_CMD:-yq}"; if ! check_command_exists "$YQ_CMD"; then log_error "yq command ('$YQ_CMD') not found."; exit 1; fi

  local val; # Temp var for yq output
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.base_backup_dir' ""); if [[ -n "$val" ]]; then BASE_BACKUP_DIR="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.backup_user' ""); if [[ -n "$val" ]]; then BACKUP_USER="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.backup_group' ""); if [[ -n "$val" ]]; then BACKUP_GROUP="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.admin_email' ""); if [[ -n "$val" ]]; then EMAIL_RECIPIENT="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.keep_days' ""); if [[ -n "$val" ]]; then KEEP_DAYS="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.plugin_dir' ""); if [[ -n "$val" ]]; then PLUGIN_DIR="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.email_subject_prefix' ""); if [[ -n "$val" ]]; then EMAIL_SUBJECT_PREFIX="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.hostname' ""); if [[ -n "$val" ]]; then HOSTNAME="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.min_free_space_mb' ""); if [[ -n "$val" ]]; then MIN_FREE_SPACE_MB="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.yq_cmd' ""); if [[ -n "$val" ]]; then YQ_CMD="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.tar_cmd' ""); if [[ -n "$val" ]]; then TAR_CMD="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.rsync_cmd' ""); if [[ -n "$val" ]]; then RSYNC_CMD="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.docker_cmd' ""); if [[ -n "$val" ]]; then DOCKER_COMMAND="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.pg_dump_cmd' ""); if [[ -n "$val" ]]; then PG_DUMP_CMD="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.mysqldump_cmd' ""); if [[ -n "$val" ]]; then MYSQL_DUMP_CMD="$val"; fi
  val=$(get_yaml_value "$CLIENT_CONFIG_FILE" '.tools.msmtp_cmd' ""); if [[ -n "$val" ]]; then MSMTP_CMD="$val"; fi
  # Read LOG_LEVEL from client_config.yml, overriding common_config if set
  local log_level_yml; log_level_yml=$(get_yaml_value "$CLIENT_CONFIG_FILE" ".log_level" "")
  if [[ -n "$log_level_yml" ]] && [[ "$log_level_yml" =~ ^[0-3]$ ]]; then
    LOG_LEVEL="$log_level_yml"
  # Check if LOG_LEVEL_COMMON was set by common_config
  elif [[ -n "${LOG_LEVEL_COMMON}" ]] && [[ "${LOG_LEVEL_COMMON}" =~ ^[0-3]$ ]]; then
    LOG_LEVEL="$LOG_LEVEL_COMMON"
  fi


  # --- Set Defaults for any remaining unset variables ---
  BASE_BACKUP_DIR="${BASE_BACKUP_DIR:-/var/tmp/backups}"; BACKUP_USER="${BACKUP_USER:-root}"; BACKUP_GROUP="${BACKUP_GROUP:-root}"
  EMAIL_RECIPIENT="${EMAIL_RECIPIENT:-${DEFAULT_ADMIN_EMAIL}}"; KEEP_DAYS="${KEEP_DAYS:-$DEFAULT_KEEP_DAYS}"; PLUGIN_DIR="${PLUGIN_DIR:-$SCRIPT_DEFAULT_PLUGIN_DIR}"
  EMAIL_SUBJECT_PREFIX="${EMAIL_SUBJECT_PREFIX:-[Backup Error]}"; HOSTNAME="${HOSTNAME:-$(hostname -f)}"
  DOCKER_COMMAND="${DOCKER_COMMAND:-docker compose}"
  MIN_FREE_SPACE_MB="${MIN_FREE_SPACE_MB:-$SCRIPT_DEFAULT_MIN_FREE_SPACE_MB}"; YQ_CMD="${YQ_CMD:-yq}"; TAR_CMD="${TAR_CMD:-tar}"; RSYNC_CMD="${RSYNC_CMD:-rsync}"
  PG_DUMP_CMD="${PG_DUMP_CMD:-pg_dump}"; MYSQL_DUMP_CMD="${MYSQL_DUMP_CMD:-mysqldump}"; MSMTP_CMD="${MSMTP_CMD:-msmtp}"
  # Update common functions path based on final PLUGIN_DIR
  COMMON_FUNCTIONS_SCRIPT_PATH="${PLUGIN_DIR}/common_functions.sh"
  if [[ "$PLUGIN_DIR" != "$SCRIPT_DEFAULT_PLUGIN_DIR" ]] && [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    log_detail "Re-sourcing common_functions.sh from: $COMMON_FUNCTIONS_SCRIPT_PATH"
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
  elif [[ "$PLUGIN_DIR" != "$SCRIPT_DEFAULT_PLUGIN_DIR" ]]; then
    log_error "Configured PLUGIN_DIR '$PLUGIN_DIR' but common_functions.sh not found there."
  fi
  # If verbose flag set, override LOG_LEVEL to DEBUG
  if [[ "$verbose" -eq 1 ]]; then
    LOG_LEVEL=3
  fi

  # --- Validate Final Loaded Configuration ---
  if ! validate_loaded_config; then
    exit 1
  fi

  # --- Define and Acquire Shared Directory Lock (for TAR creation) ---
  # This lock is specific to operations within BASE_BACKUP_DIR
  shared_lock_dir_path="${BASE_BACKUP_DIR}/.backup_archive_in_progress.lock"
  # The script instance lock (flock) is acquired by the wrapper.

  # --- Setup BASE_BACKUP_DIR and done/ directory permissions ---
  log_info "Setting up base backup directory permissions..."
  if ! is_valid_path "$BASE_BACKUP_DIR" "-d"; then
    log_detail "Base backup directory '${BASE_BACKUP_DIR}' does not exist. Attempting to create..."
    # create_dir_secure sets 700 root:root initially
    create_dir_secure "$BASE_BACKUP_DIR"
  fi
  # Ensure group ownership and permissions for server-side cleanup
  log_detail "Setting group '${BACKUP_GROUP}' and permissions for '${BASE_BACKUP_DIR}'."
  if ! chgrp "$BACKUP_GROUP" "$BASE_BACKUP_DIR"; then
    log_warn "Could not set group '${BACKUP_GROUP}' on '${BASE_BACKUP_DIR}'."
  fi
  # Set permissions to allow group to read, write, and execute (e.g., 770 or 2770 if setgid is desired)
  # o-rwx removes all permissions for 'others'
  if ! chmod u=rwx,g=rwx,o-rwx "$BASE_BACKUP_DIR"; then
    log_warn "Could not set group rwx permissions on '${BASE_BACKUP_DIR}'. Remote cleanup might fail."
  fi
  # Setup 'done' directory
  local done_dir="${BASE_BACKUP_DIR}/done"
  log_detail "Ensuring 'done' directory exists: ${done_dir}"
  if ! mkdir -p "$done_dir"; then
    log_error "Failed to create 'done' directory: ${done_dir}"
    exit 1
  fi
  log_detail "Setting ownership and permissions for '${done_dir}'."
  if ! chown "${BACKUP_USER}:${BACKUP_GROUP}" "$done_dir"; then
    log_warn "Could not set ownership on '${done_dir}'. Remote cleanup might fail."
  fi
  if ! chmod u=rwx,g=rwx,o-rwx "$done_dir"; then # 770, allows group write for mv
    log_warn "Could not set permissions on '${done_dir}'. Remote cleanup might fail."
  fi


  # --- Print Startup Info ---
  log_info "============================================================"
  log_info "Starting Local Backup Script (Version ${SCRIPT_VERSION}) - PID $$"
  log_info "Config Directory: ${CONFIG_DIR}"
  log_info "Plugin Directory: ${PLUGIN_DIR}"
  log_info "Backup Base Directory: ${BASE_BACKUP_DIR}"
  log_info "Log Level: ${LOG_LEVEL} (0=ERR,1=WARN,2=INFO,3=DEBUG)"
  log_detail "Temporary Log File: ${tmp_log_file}"
  log_info "Final Archive Owner: ${BACKUP_USER}:${BACKUP_GROUP}"
  log_info "Error Email Recipient: ${EMAIL_RECIPIENT}"
  log_info "Keep Backups (Days): ${KEEP_DAYS}"
  log_info "Min Free Space Required: ${MIN_FREE_SPACE_MB} MB"
  [[ "${dry_run}" -eq 1 ]] && log_info "*** DRY-RUN MODE ENABLED ***"
  [[ "${verbose}" -eq 1 ]] && log_info "Verbose mode enabled (implies DEBUG log level)."
  log_info "============================================================"

  # --- Discover Plugins ---
  log_info "Discovering plugins in '${PLUGIN_DIR}'..."
  discovered_plugins=() # Reset global array
  if [[ -d "$PLUGIN_DIR" ]]; then
    local file
    while IFS= read -r file; do
      if [[ "$file" == *common_functions.sh ]]; then
        continue # Skip common_functions itself
      fi
      if [[ -x "$file" ]]; then
        log_detail "Found executable plugin: $file"
        discovered_plugins+=("$file")
      else
        log_detail "Skipping non-executable file in plugin dir: $file"
      fi
    done < <(find "$PLUGIN_DIR" -maxdepth 1 -type f -name '*.sh' -print)
  else
    log_error "Plugin directory '${PLUGIN_DIR}' not found!"
    exit 1
  fi
  if [[ ${#discovered_plugins[@]} -eq 0 ]]; then
    log_error "No executable plugins (*.sh) found in '${PLUGIN_DIR}'."
    exit 1
  fi
  log_info "Found ${#discovered_plugins[@]} potential plugins."

  # --- Create Temporary Working Directory ---
  log_info "Creating temporary working directory..."
  # Assign to global work_dir
  work_dir=$(create_secure_temp_dir "backup.${SCRIPT_NAME}.XXXXXX" "$BASE_BACKUP_DIR")
  log_info "Temporary working directory: ${work_dir}"

  # --- Initial Disk Space Check ---
  if ! check_disk "${work_dir}" "${MIN_FREE_SPACE_MB}"; then
    exit 1
  fi

  # --- Service Backup Loop ---
  any_docker_service_action_taken=false # Reset global flag
  log_info "Scanning for service configurations (service.yaml/yml) in '${CONFIG_DIR}'..."
  local service_yaml_file # Local loop var
  find "$CONFIG_DIR" -mindepth 2 -maxdepth 3 -type f \( -name 'service.yaml' -o -name 'service.yml' \) | while read -r service_yaml_file; do
    log_info "--- Processing Service Config: ${service_yaml_file} ---"
    # Use local variables inside the loop for service-specific data
    local service_config_dir
    local service_type
    local service_name
    local service_backup_dir
    local -a task_types # Local array for tasks for this service
    # Use local associative arrays (requires Bash 4+) - **FIXED SCOPE**
    local -A service_tasks # task_type -> plugin_script_path
    local -A prepared_plugins # plugin_script_path -> 1 (if prepare ran successfully)

    service_config_dir=$(dirname "$service_yaml_file")
    service_type=$(basename "$(dirname "$service_config_dir")") # Type is parent dir name

    log_detail "Parsing YAML file: ${service_yaml_file}"
    if ! syntax_check_yaml_file "${service_yaml_file}"; then 
      log_warn "Syntax error in ${service_yaml_file}. Skipping service."
      continue
    fi
    if ! check_perms "${service_yaml_file}" "600" "root"; then
      log_error "Insecure permissions on '${service_yaml_file}'. Skipping service."
      continue
    fi
    service_name=$("$YQ_CMD" e '.service.name' "$service_yaml_file")
    if [[ -z "$service_name" ]] || [[ "$service_name" == "null" ]]; then
      log_error "Mandatory 'service.name' missing/empty in '${service_yaml_file}'. Skipping."
      continue
    fi
    log_info "  Service Name: ${service_name} (Type: ${service_type})"
    service_backup_dir="${work_dir}/${service_type}/${service_name}"
    create_dir_secure "$service_backup_dir"
    create_dir_secure "${service_backup_dir}/config_used"
    cp "$service_yaml_file" "${service_backup_dir}/config_used/"
    create_dir_secure "${service_backup_dir}/.state"

    # Get task types from YAML
    mapfile -t task_types < <("$YQ_CMD" e 'keys | .[] | select(. != "service")' "$service_yaml_file")
    if [[ ${#task_types[@]} -eq 0 ]]; then
      log_info "  No backup task types found in '${service_yaml_file}'. Skipping."
      continue
    fi
    log_detail "Found task types in YAML: ${task_types[*]}"

    # --- Orchestrate Plugins ---
    service_tasks=()
    prepared_plugins=()


    # Call stage handlers, passing NAMEREFS to local associative arrays
    if ! _handle_validation_stage \
        "$service_yaml_file" \
        "$service_config_dir" \
        "$service_backup_dir" \
        task_types \
        service_tasks; then
      log_error "Validation stage failed for service '${service_name}'. Skipping."
      continue
    fi

    if ! _handle_prepare_stage \
        "$service_yaml_file" \
        "$service_config_dir" \
        "$service_backup_dir" \
        service_tasks \
        prepared_plugins; then
      log_error "Preparation stage failed for service '${service_name}'. Skipping."
      # EXIT trap will call emergency cleanup for plugins that might have run prepare
      continue
    fi
    if ! _handle_run_stage \
        "$service_yaml_file" \
        "$service_config_dir" \
        "$service_backup_dir" \
        service_tasks; then
      log_error "Run stage failed for service '${service_name}'. Skipping."
      # EXIT trap will handle emergency cleanup
      continue
    fi

    if ! _handle_post_success_stage \
        "$service_yaml_file" \
        "$service_config_dir" \
        "$service_backup_dir" \
        service_tasks \
        prepared_plugins; then
      log_error "Post-success stage failed for service '${service_name}'."
      # Critical failure if post-success fails, as services might be left in wrong state
      exit 1
    fi

    log_info "--- Finished Backup for Service: ${service_type}/${service_name} ---"
    # Empty line for readability in log
    echo
  done # End service config file loop


  # --- Acquire Shared Directory Lock for TAR Creation ---
  log_info "Attempting to acquire shared TAR creation lock: ${shared_lock_dir_path}"
  local retry_num=0
  while ! mkdir "$shared_lock_dir_path" 2>/dev/null; do
    retry_num=$((retry_num + 1))
    if [[ "$retry_num" -gt "$SHARED_LOCK_RETRY_COUNT" ]]; then
      log_error "Failed to acquire shared TAR lock '${shared_lock_dir_path}' after ${SHARED_LOCK_RETRY_COUNT} retries. Server might be accessing files."
      local lock_fail_subject="${EMAIL_SUBJECT_PREFIX} ${HOSTNAME} - SHARED LOCK FAILED (TAR Creation)"
      local lock_fail_body="Failed to acquire shared lock directory for TAR creation: ${shared_lock_dir_path}\nAnother process (likely backup_server.sh) might be accessing the backup directory.\nBackup run aborted before TAR creation."
      send_email "$EMAIL_RECIPIENT" "$lock_fail_subject" "$lock_fail_body"
      exit 1 # Critical, cannot proceed to TAR
    fi
    log_warn "Shared TAR lock '${shared_lock_dir_path}' exists. Retrying in ${SHARED_LOCK_RETRY_DELAY_SECONDS}s... (Attempt ${retry_num}/${SHARED_LOCK_RETRY_COUNT})"
    sleep "$SHARED_LOCK_RETRY_DELAY_SECONDS"
  done
  log_info "Successfully acquired shared TAR creation lock: ${shared_lock_dir_path}"


  # --- Step 5: Create final TAR Archive ---
  log_info "============================================================"
  log_info "Creating compressed TAR archive..."
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  local tar_filename
  tar_filename="${BASE_BACKUP_DIR}/${HOSTNAME}-${timestamp}.tar.gz"

  log_info "Archive file: ${tar_filename}"
  log_detail "Archiving contents of working directory: ${work_dir}"

  if [[ "${dry_run}" -eq 1 ]]; then
   log_info "DRY-RUN: Skipping TAR archive creation."
  else
    if ! id -u "${BACKUP_USER}" &>/dev/null; then
      log_error "Archive owner '${BACKUP_USER}' not found!"
      exit 1
    fi
    if ! getent group "${BACKUP_GROUP}" &>/dev/null; then
      log_error "Archive group '${BACKUP_GROUP}' not found!"
      exit 1
    fi

    log_detail "Executing tar command (excluding */.state)..."
    # Add --exclude='*/.state' to prevent including plugin state files
    if "$TAR_CMD" -cpzf "$tar_filename" --numeric-owner --exclude='*/.state' -C "$work_dir" . ; then
      log_info "  -> TAR archive created successfully."
      log_detail "Setting owner:group to '${BACKUP_USER}:${BACKUP_GROUP}'"
      if chown "${BACKUP_USER}":"${BACKUP_GROUP}" "$tar_filename"; then
        log_detail "-> Owner/Group set successfully."
        log_detail "Setting permissions to '600'"
        if chmod 600 "$tar_filename"; then
          log_detail "-> Permissions set successfully (600)."
        else
          log_error "Failed: chmod 600: ${tar_filename}"
          exit 1
        fi
      else
        log_error "Failed: chown '${BACKUP_USER}:${BACKUP_GROUP}': ${tar_filename}"
        exit 1
      fi
    else
      log_error "Failed to create TAR archive: ${tar_filename}"
      rm -f "$tar_filename" # Attempt to remove partial archive
      exit 1
    fi

    # --- Step 6: Verify TAR Archive ---
    log_info "Verifying TAR archive integrity: ${tar_filename}"
    if gzip -t "$tar_filename" &>/dev/null && "$TAR_CMD" -tf "$tar_filename" > /dev/null; then
      log_info "  -> TAR archive verified successfully."
    else
      log_error "TAR archive verification failed! File may be corrupt: ${tar_filename}"
      rm -f "$tar_filename" # Delete corrupt archive
      exit 1
    fi
  fi # End if not DRY_RUN for TAR

  # --- Release Shared Directory Lock for TAR Creation ---
  if [[ -n "$shared_lock_dir_path" ]] && [[ -d "$shared_lock_dir_path" ]]; then
    if rmdir "$shared_lock_dir_path"; then
      log_info "Shared TAR creation lock released: ${shared_lock_dir_path}"
    else
      log_error "CRITICAL: Failed to release shared TAR lock: ${shared_lock_dir_path}. Manual removal required!"
      # This is a critical issue, but the backup TAR might have been created.
      # The EXIT trap will still run.
    fi
    shared_lock_dir_path="" # Ensure it's not removed again by EXIT trap
  fi


  # --- Step 7: Cleanup Old Backups ---
  log_info "============================================================"
  log_info "Cleaning up old backups (older than ${KEEP_DAYS} days) in ${BASE_BACKUP_DIR}..."
  # Use local array for find arguments
  local -a find_cmd_base=("${BASE_BACKUP_DIR}" -maxdepth 1 -mtime +"${KEEP_DAYS}" -print)
  log_detail "Looking for old TAR files (${HOSTNAME}-*.tar.gz)..."
  if [[ "${dry_run}" -eq 1 ]]; then
    find "${find_cmd_base[@]}" -name "${HOSTNAME}-*.tar.gz" -type f
  else
    find "${find_cmd_base[@]}" -name "${HOSTNAME}-*.tar.gz" -type f -delete
  fi
  log_detail "Looking for old temporary directories (backup.${SCRIPT_NAME}.*)..."
  if [[ "${dry_run}" -eq 1 ]]; then
    find "${find_cmd_base[@]}" -name "backup.${SCRIPT_NAME}.*" -type d
  else
    # Use -exec rm -rf {} + for potentially faster deletion of multiple directories
    find "${find_cmd_base[@]}" -name "backup.${SCRIPT_NAME}.*" -type d -exec rm -rf {} +
  fi
  log_info "Old backups cleanup finished."
  log_info "============================================================"


  # --- Final Success Message ---
  if [[ "${dry_run}" -eq 1 ]]; then
    log_info "*** DRY-RUN COMPLETED SUCCESSFULLY (No changes made) ***"
  else 
    log_info "Local Backup Script finished successfully."
    log_info "Final Backup Archive: ${tar_filename}"
  fi
  log_info "============================================================"

  exit 0 # Successful exit
} # End of main function definition


# === Script Execution Starts Here ===

# --- Argument Parsing ---
# Use local variable for getopt result
declare parsed_options=""
parsed_options=$(getopt -o vhVd --long verbose,help,version,dry-run -n "$SCRIPT_NAME" -- "$@")
if [[ $? != 0 ]] ; then
  # Use early_error if full logging not yet set up
  echo "ERROR: Invalid options provided. Use -h for help." >&2
  exit 1
fi
# Set the parsed options as the new positional parameters ($1, $2, etc.)
eval set -- "$parsed_options";
while true ; do
  case "$1" in
    -d|--dry-run) dry_run=1 ; shift ;;
    -v|--verbose) verbose=1; LOG_LEVEL=3 ; shift ;; # Set LOG_LEVEL for verbose
    -h|--help) show_help=1 ; shift ;;
    -V|--version) show_version=1 ; shift ;;
    --) shift ; break ;; # End of options marker
    *) echo "Internal error processing options!" >&2; exit 1 ;;
  esac
done

# --- Handle -h and -V Options ---
if [[ "$show_help" -eq 1 ]]; then show_help; exit 0; fi
if [[ "$show_version" -eq 1 ]]; then show_version; exit 0; fi

# --- Check Root Privileges ---
if [[ "$(id -u)" -ne 0 ]]; then
  # Use early_error as full logging might not be set up
  if type log_error &>/dev/null; then log_error "This script must be run as root."; else echo "ERROR: This script must be run as root." >&2; fi
  exit 1
fi


# --- Acquire Script Instance Lock (flock) and Run Main Logic ---
# This lock prevents multiple instances of this script from running simultaneously.
# The shared directory lock for TAR creation is handled within main().
exec 200>"$SCRIPT_INSTANCE_LOCK_FILE"
if ! flock -n 200; then
  # Use early_error as full logging might not be set up if lock fails
  if type log_error &>/dev/null; then
    log_error "[$SCRIPT_NAME] Another instance is already running (Instance lock file: '$SCRIPT_INSTANCE_LOCK_FILE'). Exiting."
  else
    echo "ERROR: [$SCRIPT_NAME] Another instance is already running (Instance lock file: '$SCRIPT_INSTANCE_LOCK_FILE'). Exiting." >&2
  fi
  exit 1
fi
# Instance Lock Acquired! Call the main function.
# The EXIT trap (set inside main) handles cleanup & release of the shared directory lock.
# The flock is released when FD 200 is closed on script exit.
main "$@"

# Exit code is determined by the 'exit' command within main() or trap_exit_handler()

