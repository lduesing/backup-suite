#!/bin/bash

# ==============================================================================
# Local Backup Script - Core Orchestrator
# ==============================================================================
# Description:
# Core script for modular backup on client machines. Reads common defaults from
# /etc/backup/common_config and client specifics from /etc/backup/client_config.yml.
# Discovers services (YAML) & plugins (.sh). Orchestrates plugin calls using
# defined stages. Handles setup, locking, logging, traps, TAR creation/verification,
# cleanup, error reporting. Excludes plugin state dirs from TAR. Supports dry-run.
# Adheres to Google Shell Style Guide. Root privileges required.
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
# Date: 2025-05-06
# Version: 0.1
# ==============================================================================

# --- Script Metadata and Constants ---
readonly SCRIPT_VERSION="0.1"
readonly SCRIPT_NAME=$(basename "$0")
# Standardized configuration directory
readonly CONFIG_DIR="/etc/backup" # Corrected Path
# Path to common config file (shell variables)
readonly COMMON_CONFIG_FILE="${CONFIG_DIR}/common_config"
# Path to client-specific config file (YAML)
readonly CLIENT_CONFIG_FILE="${CONFIG_DIR}/client_config.yml"
# Internal script defaults (UPPERCASE with SCRIPT_ prefix)
readonly SCRIPT_DEFAULT_MIN_FREE_SPACE_MB=500
readonly SCRIPT_DEFAULT_PLUGIN_DIR="/opt/backup/lib/plugins" # Default install path
# Lock file location
readonly LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
readonly LOCK_FD_NUM=200 # Literal FD number for flock

# --- Script Flags and State Variables ---
# Command line flags (lowercase)
verbose=0; show_help=0; show_version=0; dry_run=0
# Config variables (UPPERCASE, loaded from configs)
BASE_BACKUP_DIR=""; BACKUP_USER=""; BACKUP_GROUP=""; EMAIL_RECIPIENT=""; KEEP_DAYS=""
EMAIL_SUBJECT_PREFIX=""; HOSTNAME=""; DOCKER_COMMAND=""
MIN_FREE_SPACE_MB=""; PLUGIN_DIR=""
YQ_CMD=""; TAR_CMD=""; RSYNC_CMD=""; PG_DUMP_CMD=""; MYSQL_DUMP_CMD=""
MSMTP_CMD=""
# Runtime state (lowercase)
tmp_log_file=""; work_dir=""
error_lineno=0; error_command=""; declare -a error_funcstack=()
declare -a discovered_plugins=()

# --- Shell Options ---
set -eo pipefail
# set -u # Consider enabling exit on unset variables

# --- Source Common Functions ---
# Determine potential common functions path using script default plugin dir initially
# This path might be updated after loading the actual PLUGIN_DIR config
COMMON_FUNCTIONS_SCRIPT_PATH="${SCRIPT_DEFAULT_PLUGIN_DIR}/common_functions.sh"
if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
else
    echo "WARNING: common_functions.sh not found at '$COMMON_FUNCTIONS_SCRIPT_PATH', using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }
fi

# --- Function Definitions (Core Script Specific) ---

# Display Help Message
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
  -v, --verbose    Enable verbose output (shows DEBUG messages).
  -h, --help       Display this help message and exit.
  -V, --version    Display script version (${SCRIPT_VERSION}) and exit.

Configuration:
  See '${COMMON_CONFIG_FILE}', '${CLIENT_CONFIG_FILE}', and README.md for details.

Plugins:
  See plugin directory (defined by PLUGIN_DIR, default: ${SCRIPT_DEFAULT_PLUGIN_DIR})
  and its README.md.

Lock File:
  Uses lock file '${LOCK_FILE}' via file descriptor ${LOCK_FD_NUM}.

Example:
  sudo ${SCRIPT_NAME} -v     # Run backup with verbose output.
  sudo ${SCRIPT_NAME} --dry-run # Simulate backup run.
EOF
}

# Display Version
show_version() { echo "${SCRIPT_NAME} Version ${SCRIPT_VERSION}"; }

# Securely Create Directory (700)
create_dir_secure() { local dir_path="$1"; mkdir -p "$dir_path" && chmod 700 "$dir_path" || { log_error "Failed to create or set permissions on directory: ${dir_path}"; exit 1; }; log_detail "Directory created/permission set (700): ${dir_path}"; }

# Check Available Disk Space
check_disk() { local path_to_check="$1"; local min_mb_required="$2"; log_detail "Checking disk space for '$path_to_check', requires min ${min_mb_required} MB free."; local available_kb required_kb avail_mb; available_kb=$(df --output=avail -k "$path_to_check" | tail -n 1); required_kb=$((min_mb_required * 1024)); if ! [[ "$available_kb" =~ ^[0-9]+$ ]]; then log_error "Could not determine available disk space for '$path_to_check'."; return 1; fi; log_detail "Available KB: $available_kb, Required free KB: $required_kb"; if [[ "$available_kb" -lt "$required_kb" ]]; then avail_mb=$((available_kb / 1024)); log_error "Insufficient disk space for '$path_to_check'. Available: ${avail_mb} MB, Required minimum: ${min_mb_required} MB."; return 1; else avail_mb=$((available_kb / 1024)); log_detail "Disk space check passed. Available: ${avail_mb} MB."; return 0; fi; }

# Validate Loaded Configuration Variables
# Checks variables populated from common_config and client_config.yml
validate_loaded_config() {
  log_info "Validating loaded configuration..."
  local validation_ok=1 # Use local var

  # Check mandatory variables that should be defined after loading configs
  local mandatory_vars=(BASE_BACKUP_DIR BACKUP_USER BACKUP_GROUP EMAIL_RECIPIENT KEEP_DAYS PLUGIN_DIR)
  local var # Local loop var
  for var in "${mandatory_vars[@]}"; do
      if [[ -z "${!var}" ]]; then # Check if variable is empty
          log_error "Config Error: Mandatory variable '$var' is not defined after loading configs."
          validation_ok=0
      fi
  done

  # Paths and Permissions
  log_detail "Checking BASE_BACKUP_DIR ('${BASE_BACKUP_DIR}')..."; if [[ ! -d "$BASE_BACKUP_DIR" ]]; then log_error "Config Error: BASE_BACKUP_DIR '$BASE_BACKUP_DIR' is not a directory."; validation_ok=0; elif [[ ! -w "$BASE_BACKUP_DIR" ]]; then log_error "Config Error: BASE_BACKUP_DIR '$BASE_BACKUP_DIR' is not writable by user $(whoami)."; validation_ok=0; fi
  log_detail "Checking PLUGIN_DIR ('${PLUGIN_DIR}')..."; if [[ ! -d "$PLUGIN_DIR" ]]; then log_error "Config Error: PLUGIN_DIR '$PLUGIN_DIR' is not a directory."; validation_ok=0; fi
  # User/Group existence
  log_detail "Checking BACKUP_USER ('${BACKUP_USER}')..."; if ! id -u "$BACKUP_USER" &>/dev/null; then log_error "Config Error: BACKUP_USER '$BACKUP_USER' does not exist."; validation_ok=0; fi
  log_detail "Checking BACKUP_GROUP ('${BACKUP_GROUP}')..."; if ! getent group "$BACKUP_GROUP" &>/dev/null; then log_error "Config Error: BACKUP_GROUP '$BACKUP_GROUP' does not exist."; validation_ok=0; fi
  # Email basic format
  log_detail "Checking EMAIL_RECIPIENT ('${EMAIL_RECIPIENT}')..."; if ! [[ "$EMAIL_RECIPIENT" =~ ^.+@.+\..+$ ]]; then log_info "Config Warning: EMAIL_RECIPIENT '$EMAIL_RECIPIENT' does not look like a valid email address."; fi
  # Numeric checks
  log_detail "Checking KEEP_DAYS ('${KEEP_DAYS}')..."; if ! [[ "$KEEP_DAYS" =~ ^[1-9][0-9]*$ ]]; then log_error "Config Error: KEEP_DAYS '$KEEP_DAYS' must be a positive integer."; validation_ok=0; fi
  log_detail "Checking MIN_FREE_SPACE_MB ('${MIN_FREE_SPACE_MB}')..."; if ! [[ "$MIN_FREE_SPACE_MB" =~ ^[0-9]+$ ]]; then log_error "Config Error: MIN_FREE_SPACE_MB '$MIN_FREE_SPACE_MB' must be a non-negative integer."; validation_ok=0; fi

  # Check Tool Paths (ensure commands exist)
  local -a tool_vars_to_check=(YQ_CMD TAR_CMD RSYNC_CMD DOCKER_CMD PG_DUMP_CMD MYSQL_DUMP_CMD MSMTP_CMD)
  local tool_var tool_cmd # Local loop vars
  for tool_var in "${tool_vars_to_check[@]}"; do
      tool_cmd=$(echo "${!tool_var}" | cut -d' ' -f1) # Get first word
      if [[ -n "$tool_cmd" ]] && ! command -v "$tool_cmd" &>/dev/null; then log_error "Config Error: Command specified in ${tool_var} ('${!tool_var}') not found in PATH."; validation_ok=0; fi
  done

  # Attempt to set group permissions on BASE_BACKUP_DIR
  if [[ "$validation_ok" -eq 1 ]] && [[ -d "$BASE_BACKUP_DIR" ]] && getent group "$BACKUP_GROUP" &>/dev/null; then
    log_detail "Attempting to set group '${BACKUP_GROUP}' and 'g+rx' on '${BASE_BACKUP_DIR}'..."
    local chgrp_exit_code chmod_exit_code; set +e; chgrp "$BACKUP_GROUP" "$BASE_BACKUP_DIR"; chgrp_exit_code=$?; chmod g+rx "$BASE_BACKUP_DIR"; chmod_exit_code=$?; set -e
    if [[ $chgrp_exit_code -ne 0 || $chmod_exit_code -ne 0 ]]; then log_info "Config Warning: Could not set group '${BACKUP_GROUP}' or permissions 'g+rx' on '${BASE_BACKUP_DIR}'. Manual adjustment might be needed."; else log_detail "-> Group and permissions set successfully on '${BASE_BACKUP_DIR}'."; fi
  fi

  if [[ "$validation_ok" -eq 0 ]]; then log_error "Loaded configuration validation failed."; return 1; fi
  log_info "Loaded configuration validation passed."
  return 0
}

# --- Trap Functions ---

# ERR Trap Handler: Captures context on command failure
trap_err_handler() { error_lineno=${BASH_LINENO[0]}; error_command=${BASH_COMMAND}; local i; error_funcstack=(); for ((i=0; i < ${#FUNCNAME[@]}; i++)); do error_funcstack+=("${FUNCNAME[$i]:-main}:${BASH_LINENO[$i+1]}"); done; log_detail "Error context captured: Line ${error_lineno}, Command '${error_command}'"; }

# EXIT Trap Handler: Cleanup, emergency actions, reporting
trap_exit_handler() {
  local exit_code=$?; set +e # Capture exit code, disable exit-on-error for trap
  log_detail "--- Running EXIT trap (Exit code: ${exit_code}) ---"

  # --- Attempt Emergency Plugin Cleanup ---
  log_detail "Running emergency cleanup for plugins..."
  if [[ -n "$work_dir" ]] && [[ -d "$work_dir" ]]; then
    local state_dir_list_file; state_dir_list_file=$(mktemp)
    find "$work_dir" -mindepth 2 -maxdepth 3 -type d -name '.state' -print > "$state_dir_list_file" 2>/dev/null || true
    while IFS= read -r state_dir; do
        if [[ -z "$state_dir" ]] || [[ ! -d "$state_dir" ]]; then continue; fi
        local service_backup_dir service_context_name plugin_script
        service_backup_dir=$(dirname "$state_dir")
        if [[ ! -d "$service_backup_dir" ]]; then continue; fi
        service_context_name=$(basename "$(dirname "$service_backup_dir")")/$(basename "$service_backup_dir")
        log_detail "Checking emergency cleanup for service context: ${service_context_name} (State dir: ${state_dir})"
        for plugin_script in "${discovered_plugins[@]}"; do
            if [[ -f "$plugin_script" ]] && [[ -x "$plugin_script" ]]; then
                log_detail "  Calling emergency_cleanup in plugin: $(basename "${plugin_script}") for service dir ${service_backup_dir}"
                export DRY_RUN_MODE="${dry_run}"
                ( source "$COMMON_FUNCTIONS_SCRIPT_PATH"; source "$plugin_script" && command -v plugin_emergency_cleanup &>/dev/null && plugin_emergency_cleanup "$service_backup_dir" )
                unset DRY_RUN_MODE
            fi
        done
    done < "$state_dir_list_file"
    rm -f "$state_dir_list_file"
  else log_detail "Work directory '$work_dir' not found or not set, skipping plugin emergency cleanup."; fi
  log_detail "Finished emergency plugin cleanup attempts."

  # --- Send Email Report on Error (Skip in dry-run) ---
  if [[ "$exit_code" -ne 0 ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
        _log_base "####################################################" >> "$tmp_log_file"; _log_base "ERROR: Backup script finished with exit code ${exit_code}!" >> "$tmp_log_file"; _log_base "Error occurred near line: ${error_lineno}" >> "$tmp_log_file"; _log_base "Failed Command: ${error_command}" >> "$tmp_log_file"; _log_base "Function Stack (func:line): ${error_funcstack[*]}" >> "$tmp_log_file"; _log_base "Sending log to ${EMAIL_RECIPIENT}..." >> "$tmp_log_file"; _log_base "####################################################" >> "$tmp_log_file"
        echo "ERROR: Backup failed (Exit Code: ${exit_code}). Check log file: ${tmp_log_file}" >&2; echo "Error near line ${error_lineno}, Command: ${error_command}" >&2; echo "Attempting to send error report via msmtp..." >&2
        local subject="${EMAIL_SUBJECT_PREFIX} ${HOSTNAME} - Backup FAILED (Code: ${exit_code}, Line: ${error_lineno})"; local email_body; email_body=$(cat <<MAILBODY
Hostname: ${HOSTNAME}
Timestamp: $(date --rfc-3339=seconds)
Exit Code: ${exit_code}
Error Line: ${error_lineno}
Failed Command: ${error_command}
Call Stack: $(IFS=" -> "; echo "${error_funcstack[*]}")

--- Full Backup Log ---
$(cat "${tmp_log_file}")
MAILBODY
)
        if command -v "$MSMTP_CMD" &>/dev/null; then printf "To: %s\nSubject: %s\nContent-Type: text/plain; charset=utf-8\nX-Priority: 1 (Highest)\nImportance: High\n\n%s" "${EMAIL_RECIPIENT}" "${subject}" "${email_body}" | "$MSMTP_CMD" "${EMAIL_RECIPIENT}"; if [[ $? -eq 0 ]]; then echo "Email notification sent successfully." >&2; else echo "ERROR: Failed to send email notification!" >&2; _log_base "ERROR: Failed to send email notification!" >> "$tmp_log_file"; fi; else log_error "msmtp command ('${MSMTP_CMD}') not found. Cannot send email report."; _log_base "ERROR: msmtp command not found." >> "$tmp_log_file"; fi
        echo "Log file kept for analysis: ${tmp_log_file}" >&2
    else echo "ERROR: Backup script failed early (Exit Code: ${exit_code}). No log file available." >&2; if command -v "$MSMTP_CMD" &>/dev/null && [[ -n "${EMAIL_RECIPIENT}" ]]; then local subject="${EMAIL_SUBJECT_PREFIX} ${HOSTNAME} - Backup FAILED EARLY (Code: ${exit_code})"; printf "To: %s\nSubject: %s\n\nBackup script failed very early. Exit code: %s." "${EMAIL_RECIPIENT}" "${subject}" "${exit_code}" | "$MSMTP_CMD" "${EMAIL_RECIPIENT}"; fi; fi
  elif [[ "$exit_code" -ne 0 ]] && [[ "${dry_run:-0}" -eq 1 ]]; then
    log_info "DRY-RUN: Backup script failed (Exit Code: ${exit_code}). Email reporting skipped."
    echo "DRY-RUN: Error occurred. Log file kept for analysis: ${tmp_log_file}" >&2
  else
    # --- Success Case ---
    log_info "Backup script finished successfully."
    if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then rm -f "$tmp_log_file"; fi
  fi

  # --- Always Cleanup Working Directory ---
  if [[ -n "$work_dir" ]] && [[ -d "$work_dir" ]]; then
    log_detail "Cleaning up final working directory: ${work_dir}"; if ! rm -rf "$work_dir"; then log_error "Failed to remove working directory '${work_dir}'. Manual cleanup required."; if [[ $exit_code -eq 0 ]]; then exit_code=1; fi; fi
  fi

  # --- Release Lock and Exit ---
  log_detail "Exiting script with code ${exit_code}. Lock will be released (FD ${LOCK_FD_NUM})."
  exit "${exit_code}"
}

# Helper function to run a plugin function
# Creates temp config file, runs plugin function in subshell, cleans up temp file
run_plugin_func() {
  local plugin_script="$1"; local function_name="$2"; local service_yaml_file="$3"; local task_type="$4"; local service_config_dir="$5"; local service_backup_dir="$6"
  local plugin_name temp_config_file plugin_exit_code=0

  plugin_name=$(basename "$plugin_script" .sh)
  temp_config_file=$(mktemp "${service_backup_dir}/.state/${plugin_name}_${function_name}_config.XXXXXX")
  chmod 600 "$temp_config_file"

  # Extract relevant YAML section using YQ
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('$YQ_CMD') not found. Cannot run plugin."; rm -f "$temp_config_file"; return 1; fi
  if ! "$YQ_CMD" e ".${task_type}" "$service_yaml_file" > "$temp_config_file"; then log_error "Failed to extract YAML section '.${task_type}' for plugin '${plugin_name}'."; rm -f "$temp_config_file"; return 1; fi
  if [[ ! -s "$temp_config_file" ]] || [[ $($YQ_CMD e ".${task_type}" "$service_yaml_file") == "null" ]]; then log_detail "YAML section '.${task_type}' is empty or null for plugin '${plugin_name}'."; echo -n > "$temp_config_file"; fi

  # Export DRY_RUN_MODE for the subshell
  export DRY_RUN_MODE="${dry_run}"

  log_detail "Executing plugin function: ${plugin_name} -> ${function_name}"
  (
    # Source common functions first (path might have been updated)
    if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then source "$COMMON_FUNCTIONS_SCRIPT_PATH"; fi
    source "$plugin_script" # Source the actual plugin
    if command -v "$function_name" &>/dev/null; then "$function_name" "$temp_config_file" "$service_config_dir" "$service_backup_dir";
    else
      if [[ "$function_name" == "plugin_prepare_backup" || "$function_name" == "plugin_post_backup_success" || "$function_name" == "plugin_emergency_cleanup" ]]; then log_detail "Optional function '${function_name}' not found in plugin '${plugin_name}'. Skipping."; exit 0;
      else log_error "Required function '${function_name}' not found in plugin '${plugin_name}'."; exit 1; fi
    fi
  )
  plugin_exit_code=$? # Capture exit code

  unset DRY_RUN_MODE # Unset immediately
  rm -f "$temp_config_file" # Clean up temp config file

  log_detail "Plugin function '${function_name}' finished with exit code ${plugin_exit_code}."
  return ${plugin_exit_code} # Return plugin's exit code
}


# --- Main Function Definition ---
# Encapsulates the primary logic of the script.
main() {
  # --- Setup Logging & Traps ---
  tmp_log_file=$(mktemp /tmp/local_backup_log."$SCRIPT_NAME".XXXXXX); chmod 600 "$tmp_log_file"
  exec > >(tee -a "$tmp_log_file") 2>&1 # Redirect stdout/stderr
  trap trap_err_handler ERR
  trap trap_exit_handler EXIT

  # --- Start Actual Backup Process ---
  log_info "Successfully acquired lock file: ${LOCK_FILE} (FD ${LOCK_FD_NUM})"
  if [[ "${dry_run}" -eq 1 ]]; then log_info "*** DRY-RUN MODE ACTIVATED ***"; fi

  # --- Load Common Config ---
  log_info "Loading common configuration from ${COMMON_CONFIG_FILE}..."
  if [[ ! -f "$COMMON_CONFIG_FILE" ]]; then log_error "Common config file '${COMMON_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${COMMON_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${COMMON_CONFIG_FILE}'. Requires 600 owned by root."; exit 1; fi
  local source_exit_code; set +e; source "${COMMON_CONFIG_FILE}"; source_exit_code=$?; set -e
  if [[ ${source_exit_code} -ne 0 ]]; then log_error "Failed to source common config file '${COMMON_CONFIG_FILE}'. Syntax error?"; exit 1; fi
  log_detail "Common configuration sourced."

  # --- Load Client Specific Config (YAML) ---
  log_info "Loading client configuration from ${CLIENT_CONFIG_FILE}..."
  if [[ ! -f "$CLIENT_CONFIG_FILE" ]]; then log_error "Client config file '${CLIENT_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${CLIENT_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${CLIENT_CONFIG_FILE}'. Requires 600 owned by root."; exit 1; fi
  YQ_CMD="${YQ_CMD:-yq}"; if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('$YQ_CMD') not found. Cannot parse client config."; exit 1; fi

  # Read values from YAML, overriding defaults from common_config if present
  local base_backup_dir_yml; base_backup_dir_yml=$("$YQ_CMD" e '.base_backup_dir // ""' "$CLIENT_CONFIG_FILE"); [[ "$base_backup_dir_yml" != "" ]] && BASE_BACKUP_DIR="$base_backup_dir_yml"
  local backup_user_yml; backup_user_yml=$("$YQ_CMD" e '.backup_user // ""' "$CLIENT_CONFIG_FILE"); [[ "$backup_user_yml" != "" ]] && BACKUP_USER="$backup_user_yml"
  local backup_group_yml; backup_group_yml=$("$YQ_CMD" e '.backup_group // ""' "$CLIENT_CONFIG_FILE"); [[ "$backup_group_yml" != "" ]] && BACKUP_GROUP="$backup_group_yml"
  local admin_email_yml; admin_email_yml=$("$YQ_CMD" e '.admin_email // ""' "$CLIENT_CONFIG_FILE"); [[ "$admin_email_yml" != "" ]] && EMAIL_RECIPIENT="$admin_email_yml"
  local keep_days_yml; keep_days_yml=$("$YQ_CMD" e '.keep_days // ""' "$CLIENT_CONFIG_FILE"); [[ "$keep_days_yml" != "" ]] && KEEP_DAYS="$keep_days_yml"
  local plugin_dir_yml; plugin_dir_yml=$("$YQ_CMD" e '.plugin_dir // ""' "$CLIENT_CONFIG_FILE"); [[ "$plugin_dir_yml" != "" ]] && PLUGIN_DIR="$plugin_dir_yml"
  local email_subj_yml; email_subj_yml=$("$YQ_CMD" e '.email_subject_prefix // ""' "$CLIENT_CONFIG_FILE"); [[ "$email_subj_yml" != "" ]] && EMAIL_SUBJECT_PREFIX="$email_subj_yml"
  local hostname_yml; hostname_yml=$("$YQ_CMD" e '.hostname // ""' "$CLIENT_CONFIG_FILE"); [[ "$hostname_yml" != "" ]] && HOSTNAME="$hostname_yml"
  local min_free_yml; min_free_yml=$("$YQ_CMD" e '.min_free_space_mb // ""' "$CLIENT_CONFIG_FILE"); [[ "$min_free_yml" != "" ]] && MIN_FREE_SPACE_MB="$min_free_yml"
  local yq_tool_yml; yq_tool_yml=$("$YQ_CMD" e '.tools.yq_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$yq_tool_yml" != "" ]] && YQ_CMD="$yq_tool_yml"
  local tar_tool_yml; tar_tool_yml=$("$YQ_CMD" e '.tools.tar_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$tar_tool_yml" != "" ]] && TAR_CMD="$tar_tool_yml"
  local rsync_tool_yml; rsync_tool_yml=$("$YQ_CMD" e '.tools.rsync_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$rsync_tool_yml" != "" ]] && RSYNC_CMD="$rsync_tool_yml"
  local docker_tool_yml; docker_tool_yml=$("$YQ_CMD" e '.tools.docker_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$docker_tool_yml" != "" ]] && DOCKER_COMMAND="$docker_tool_yml"
  local pg_dump_tool_yml; pg_dump_tool_yml=$("$YQ_CMD" e '.tools.pg_dump_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$pg_dump_tool_yml" != "" ]] && PG_DUMP_CMD="$pg_dump_tool_yml"
  local mysql_dump_tool_yml; mysql_dump_tool_yml=$("$YQ_CMD" e '.tools.mysqldump_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$mysql_dump_tool_yml" != "" ]] && MYSQL_DUMP_CMD="$mysql_dump_tool_yml"
  local msmtp_tool_yml; msmtp_tool_yml=$("$YQ_CMD" e '.tools.msmtp_cmd // ""' "$CLIENT_CONFIG_FILE"); [[ "$msmtp_tool_yml" != "" ]] && MSMTP_CMD="$msmtp_tool_yml"

  # --- Set Defaults for any remaining unset variables ---
  BASE_BACKUP_DIR="${BASE_BACKUP_DIR:-/var/tmp/backups}"; BACKUP_USER="${BACKUP_USER:-root}"; BACKUP_GROUP="${BACKUP_GROUP:-root}"
  EMAIL_RECIPIENT="${EMAIL_RECIPIENT:-${DEFAULT_ADMIN_EMAIL}}"; KEEP_DAYS="${KEEP_DAYS:-$DEFAULT_KEEP_DAYS}"; PLUGIN_DIR="${PLUGIN_DIR:-$DEFAULT_PLUGIN_DIR}"
  EMAIL_SUBJECT_PREFIX="${EMAIL_SUBJECT_PREFIX:-[Backup Error]}"; HOSTNAME="${HOSTNAME:-$(hostname -f)}"
  DOCKER_COMMAND="${DOCKER_COMMAND:-docker compose}"
  MIN_FREE_SPACE_MB="${MIN_FREE_SPACE_MB:-$MIN_FREE_SPACE_MB_DEFAULT}"; YQ_CMD="${YQ_CMD:-yq}"; TAR_CMD="${TAR_CMD:-tar}"; RSYNC_CMD="${RSYNC_CMD:-rsync}"
  PG_DUMP_CMD="${PG_DUMP_CMD:-pg_dump}"; MYSQL_DUMP_CMD="${MYSQL_DUMP_CMD:-mysqldump}"; MSMTP_CMD="${MSMTP_CMD:-msmtp}"
  # Update common functions path based on final PLUGIN_DIR
  COMMON_FUNCTIONS_SCRIPT_PATH="${PLUGIN_DIR}/common_functions.sh"

  # --- Validate Final Loaded Configuration ---
  if ! validate_loaded_config; then exit 1; fi

  # --- Print Startup Info ---
  log_info "============================================================"
  log_info "Starting Local Backup Script (Version ${SCRIPT_VERSION}) - Locked (PID $$)"
  log_info "Config Directory: ${CONFIG_DIR}"; log_info "Plugin Directory: ${PLUGIN_DIR}"; log_info "Backup Base Directory: ${BASE_BACKUP_DIR}"
  log_detail "Temporary Log File: ${tmp_log_file}"; log_info "Final Archive Owner: ${BACKUP_USER}:${BACKUP_GROUP}"
  log_info "Error Email Recipient: ${EMAIL_RECIPIENT}"; log_info "Keep Backups (Days): ${KEEP_DAYS}"
  log_info "Min Free Space Required: ${MIN_FREE_SPACE_MB} MB";
  [[ "${dry_run}" -eq 1 ]] && log_info "*** DRY-RUN MODE ENABLED ***"
  [[ "${verbose}" -eq 1 ]] && log_info "Verbose mode enabled."
  log_info "============================================================"

  # --- Check Core Tools ---
  log_detail "Checking required orchestration tools..."; local required_tools=(realpath dirname basename find grep cut sed tee mktemp date tar id stat df tail "${YQ_CMD}" "${TAR_CMD}" "${RSYNC_CMD}");
  local tool_cmd; for tool_cmd in "${required_tools[@]}"; do if ! command -v "$tool_cmd" &>/dev/null; then log_error "Required command '$tool_cmd' not found."; exit 1; fi; done; log_detail "Core tools found."

  # --- Discover Plugins ---
  log_info "Discovering plugins in '${PLUGIN_DIR}'..."
  discovered_plugins=() # Reset global array
  if [[ -d "$PLUGIN_DIR" ]]; then local file; while IFS= read -r file; do if [[ "$file" == *common_functions.sh ]]; then continue; fi; if [[ -x "$file" ]]; then log_detail "Found executable plugin: $file"; discovered_plugins+=("$file"); else log_detail "Skipping non-executable file: $file"; fi; done < <(find "$PLUGIN_DIR" -maxdepth 1 -type f -name '*.sh' -print);
  else log_error "Plugin directory '${PLUGIN_DIR}' not found!"; exit 1; fi
  if [[ ${#discovered_plugins[@]} -eq 0 ]]; then log_error "No executable plugins (*.sh) found in '${PLUGIN_DIR}'."; exit 1; fi
  log_info "Found ${#discovered_plugins[@]} potential plugins."

  # --- Create Temporary Working Directory ---
  log_info "Creating temporary working directory..."
  work_dir=$(mktemp -d -p "$BASE_BACKUP_DIR" backup."$SCRIPT_NAME".XXXXXX)
  chmod 700 "$work_dir"; log_info "Temporary working directory: ${work_dir}"

  # --- Initial Disk Space Check ---
  if ! check_disk "${work_dir}" "${MIN_FREE_SPACE_MB}"; then exit 1; fi

  # --- Service Backup Loop ---
  ANY_DOCKER_SERVICE_STARTED=false # Reset global flag
  log_info "Scanning for service configurations (service.yaml/yml) in '${CONFIG_DIR}'..."
  local service_yaml_file # Local loop var
  find "$CONFIG_DIR" -mindepth 2 -maxdepth 3 -type f \( -name 'service.yaml' -o -name 'service.yml' \) | while read -r service_yaml_file; do
    log_info "--- Processing Service Config: ${service_yaml_file} ---"
    # Use local variables inside the loop for service-specific data
    local service_config_dir service_type service_name service_backup_dir
    local -a task_types # Local array for tasks
    # Use local associative arrays (requires Bash 4+) - **FIXED SCOPE**
    local -A service_tasks # task_type -> plugin_script_path
    local -A prepared_plugins # plugin_script_path -> 1 (if prepare ran successfully)

    service_config_dir=$(dirname "$service_yaml_file"); service_type=$(basename "$(dirname "$service_config_dir")")
    log_detail "Parsing YAML file: ${service_yaml_file}"
    if ! check_perms "${service_yaml_file}" "600" "root"; then log_error "Insecure permissions on '${service_yaml_file}'. Skipping service."; continue; fi
    service_name=$("$YQ_CMD" e '.service.name' "$service_yaml_file")
    if [[ -z "$service_name" ]] || [[ "$service_name" == "null" ]]; then log_error "Mandatory 'service.name' missing/empty in '${service_yaml_file}'. Skipping."; continue; fi
    log_info "  Service Name: ${service_name} (Type: ${service_type})"
    service_backup_dir="${work_dir}/${service_type}/${service_name}"
    create_dir_secure "$service_backup_dir"; create_dir_secure "${service_backup_dir}/config_used"; cp "$service_yaml_file" "${service_backup_dir}/config_used/"; create_dir_secure "${service_backup_dir}/.state"

    mapfile -t task_types < <("$YQ_CMD" e 'keys | .[] | select(. != "service")' "$service_yaml_file")
    if [[ ${#task_types[@]} -eq 0 ]]; then log_info "  No backup task types found in '${service_yaml_file}'. Skipping."; continue; fi
    log_detail "Found task types in YAML: ${task_types[*]}"

    # --- Orchestrate Plugins ---
    # Initialize local arrays for THIS service **INSIDE** the loop
    service_tasks=(); prepared_plugins=()

    # -- Stage 1: Identify Plugins & Validate Config --
    log_info "  Stage 1: Identifying plugins and validating config..."
    local validation_overall_ok=1; local task_type; local handled plugin_script plugin_name
    for task_type in "${task_types[@]}"; do
      handled=false
      for plugin_script in "${discovered_plugins[@]}"; do
        plugin_name=$(basename "$plugin_script" .sh)
        if ( source "$plugin_script" &>/dev/null && plugin_handles_task_type "$task_type" ); then
          log_detail "    Plugin '${plugin_name}' handles task type '${task_type}'. Validating..."
          service_tasks["$task_type"]="$plugin_script"
          if ! run_plugin_func "$plugin_script" "plugin_validate_config" "$service_yaml_file" "$task_type" "$service_config_dir" "$service_backup_dir"; then log_error "Config validation failed for task '${task_type}' (Plugin: ${plugin_name})."; validation_overall_ok=0; else log_detail "    -> Config validated for '${task_type}'."; fi
          handled=true; break
        fi
      done
      if ! ${handled}; then log_info "  WARN: No plugin found for task type '${task_type}'."; fi
    done
    if [[ "$validation_overall_ok" -eq 0 ]]; then log_error "Config validations failed for service '${service_name}'. Skipping backup stages."; continue; fi

    # -- Stage 2: Prepare Backup (Docker First) --
    log_info "  Stage 2: Preparing backup (e.g., stopping services)..."
    prepared_plugins=() # Initialize local array for THIS service
    local docker_plugin=""; if [[ -v "service_tasks[docker]" ]]; then docker_plugin="${service_tasks[docker]}"; fi

    if [[ -n "$docker_plugin" ]]; then
      if ( source "$docker_plugin" &>/dev/null && type plugin_prepare_backup &>/dev/null ); then
        log_detail "  Preparing task 'docker' using plugin 'docker_compose'..."
        if run_plugin_func "$docker_plugin" "plugin_prepare_backup" "$service_yaml_file" "docker" "$service_config_dir" "$service_backup_dir"; then prepared_plugins["$docker_plugin"]=1; log_detail "  -> Prepare successful for 'docker'."; else log_error "Prepare step failed for task 'docker'. Aborting service backup."; exit 1; fi
      else log_detail "  Plugin 'docker_compose' has no prepare step."; fi
    fi

    for task_type in "${!service_tasks[@]}"; do
      local plugin_script="${service_tasks[$task_type]}"; local plugin_name=$(basename "$plugin_script" .sh)
      if [[ "$plugin_script" == "$docker_plugin" ]]; then continue; fi
      if ( source "$plugin_script" &>/dev/null && type plugin_prepare_backup &>/dev/null ); then
          log_detail "  Preparing task '${task_type}' using plugin '${plugin_name}'..."
          if run_plugin_func "$plugin_script" "plugin_prepare_backup" "$service_yaml_file" "$task_type" "$service_config_dir" "$service_backup_dir"; then prepared_plugins["$plugin_script"]=1; log_detail "  -> Prepare successful for '${task_type}'."; else log_error "Prepare step failed for task '${task_type}'. Aborting service backup."; exit 1; fi
      else log_detail "  No prepare step needed for plugin '${plugin_name}'."; fi
    done

    # -- Stage 3: Run Backup Tasks --
    log_info "  Stage 3: Executing backup tasks..."
    for task_type in "${!service_tasks[@]}"; do
        local plugin_script="${service_tasks[$task_type]}"; local plugin_name=$(basename "$plugin_script" .sh)
        log_detail "  Running backup task for '${task_type}' using plugin '${plugin_name}'..."
        if ! run_plugin_func "$plugin_script" "plugin_run_backup" "$service_yaml_file" "$task_type" "$service_config_dir" "$service_backup_dir"; then log_error "Backup task failed for '${task_type}'. Aborting service backup."; exit 1; fi
        log_detail "  -> Backup task successful for '${plugin_name}'."
        # Check disk space after each task (skip in dry run)
        if [[ "${dry_run}" -eq 0 ]]; then log_detail "    Checking disk space after ${plugin_name} task..."; if ! check_disk "${work_dir}" "${MIN_FREE_SPACE_MB}"; then exit 1; fi; fi
    done

    # -- Stage 4: Post-Backup Success Actions (Docker Start Last) --
    log_info "  Stage 4: Finalizing backup for service..."
    local plugin_script plugin_name task_type_for_plugin task_type # Reuse local vars
    for plugin_script in "${!prepared_plugins[@]}"; do
        plugin_name=$(basename "$plugin_script" .sh); if [[ "$plugin_script" == "$docker_plugin" ]]; then continue; fi
        log_detail "  Running post-backup success actions for plugin '${plugin_name}'..."
        task_type_for_plugin=""; for task_type in "${!service_tasks[@]}"; do if [[ "${service_tasks[$task_type]}" == "$plugin_script" ]]; then task_type_for_plugin="$task_type"; break; fi; done
        if [[ -n "$task_type_for_plugin" ]]; then
            if (source "$plugin_script" &>/dev/null && type plugin_post_backup_success &>/dev/null); then if ! run_plugin_func "$plugin_script" "plugin_post_backup_success" "$service_yaml_file" "$task_type_for_plugin" "$service_config_dir" "$service_backup_dir"; then log_error "Post-backup success failed for plugin '${plugin_name}'. Aborting."; exit 1; fi; log_detail "  -> Post-backup success successful for '${plugin_name}'."; else log_detail "  Plugin '${plugin_name}' has no post_backup_success function."; fi
        else log_error "Internal Error: Could not find task type for prepared plugin '${plugin_name}'"; fi
    done

    if [[ -v "prepared_plugins[$docker_plugin]" ]]; then
         log_detail "  Running post-backup success actions for plugin 'docker_compose'..."
         if (source "$docker_plugin" &>/dev/null && type plugin_post_backup_success &>/dev/null); then
             if ! run_plugin_func "$docker_plugin" "plugin_post_backup_success" "$service_yaml_file" "docker" "$service_config_dir" "$service_backup_dir"; then log_error "Post-backup success failed for 'docker_compose'. Aborting."; exit 1; fi
             log_detail "  -> Post-backup success successful for 'docker_compose'."
             if [[ "${dry_run}" -eq 0 ]]; then ANY_DOCKER_SERVICE_STARTED=true; fi # Set global flag
         else log_detail "  Plugin 'docker_compose' has no post_backup_success function."; fi
    fi

    log_info "--- Finished Backup for Service: ${service_type}/${service_name} ---"; echo

  done # End service config file loop


  # --- Step 5: Create final TAR Archive ---
  log_info "============================================================"
  log_info "Creating compressed TAR archive..."
  local timestamp; timestamp=$(date +%Y%m%d_%H%M%S) # Local var
  local tar_filename; tar_filename="${BASE_BACKUP_DIR}/${HOSTNAME}-${timestamp}.tar.gz" # Local var
  log_info "Archive file: ${tar_filename}"; log_detail "Archiving contents of working directory: ${work_dir}"

  if [[ "${dry_run}" -eq 1 ]]; then log_info "DRY-RUN: Skipping TAR archive creation.";
  else
    if ! id -u "${BACKUP_USER}" &>/dev/null; then log_error "Archive owner '${BACKUP_USER}' not found!"; exit 1; fi
    if ! getent group "${BACKUP_GROUP}" &>/dev/null; then log_error "Archive group '${BACKUP_GROUP}' not found!"; exit 1; fi
    log_detail "Executing tar command (excluding */.state)..."
    if "$TAR_CMD" -cpzf "$tar_filename" --numeric-owner --exclude='*/.state' -C "$work_dir" . ; then
      log_info "  -> TAR archive created successfully."
      log_detail "Setting owner:group to '${BACKUP_USER}:${BACKUP_GROUP}'"; if chown "${BACKUP_USER}":"${BACKUP_GROUP}" "$tar_filename"; then
           log_detail "-> Owner/Group set successfully."; log_detail "Setting permissions to '600'"; if chmod 600 "$tar_filename"; then log_detail "-> Permissions set successfully (600)."; else log_error "Failed: chmod 600: ${tar_filename}"; exit 1; fi
      else log_error "Failed: chown '${BACKUP_USER}:${BACKUP_GROUP}': ${tar_filename}"; exit 1; fi
    else log_error "Failed to create TAR archive: ${tar_filename}"; rm -f "$tar_filename"; exit 1; fi

    # --- Step 6: Verify TAR Archive ---
    log_info "Verifying TAR archive integrity: ${tar_filename}"
    if gzip -t "$tar_filename" &>/dev/null && "$TAR_CMD" -tf "$tar_filename" > /dev/null; then log_info "  -> TAR archive verified successfully.";
    else log_error "TAR archive verification failed! File may be corrupt: ${tar_filename}"; rm -f "$tar_filename"; exit 1; fi
  fi


  # --- Step 7: Cleanup Old Backups ---
  log_info "============================================================"
  log_info "Cleaning up old backups (older than ${KEEP_DAYS} days) in ${BASE_BACKUP_DIR}..."
  local -a find_cmd_base=("${BASE_BACKUP_DIR}" -maxdepth 1 -mtime +"${KEEP_DAYS}" -print) # Local array
  log_detail "Looking for old TAR files (${HOSTNAME}-*.tar.gz)..."
  if [[ "${dry_run}" -eq 1 ]]; then find "${find_cmd_base[@]}" -name "${HOSTNAME}-*.tar.gz" -type f; else find "${find_cmd_base[@]}" -name "${HOSTNAME}-*.tar.gz" -type f -delete; fi
  log_detail "Looking for old temporary directories (backup.${SCRIPT_NAME}.*)..."
  if [[ "${dry_run}" -eq 1 ]]; then find "${find_cmd_base[@]}" -name "backup.${SCRIPT_NAME}.*" -type d; else find "${find_cmd_base[@]}" -name "backup.${SCRIPT_NAME}.*" -type d -exec rm -rf {} + ; fi
  log_info "Old backups cleanup finished."
  log_info "============================================================"


  # --- Final Success Message ---
  if [[ "${dry_run}" -eq 1 ]]; then log_info "*** DRY-RUN COMPLETED SUCCESSFULLY (No changes made) ***"; else log_info "Local Backup Script finished successfully."; log_info "Final Backup Archive: ${tar_filename}"; fi
  log_info "============================================================"

  # Successful exit - EXIT trap will run for final cleanup
  exit 0

} # End of main function definition


# === Script Execution Starts Here ===

# --- Argument Parsing ---
declare parsed_options="" # Use declare for clarity
parsed_options=$(getopt -o vhVd --long verbose,help,version,dry-run -n "$SCRIPT_NAME" -- "$@")
if [[ $? != 0 ]] ; then echo "ERROR: Invalid options provided. Use -h for help." >&2 ; exit 1 ; fi
eval set -- "$parsed_options"; # Set positional parameters
while true ; do case "$1" in -d|--dry-run) dry_run=1 ; shift ;; -v|--verbose) verbose=1 ; shift ;; -h|--help) show_help=1 ; shift ;; -V|--version) show_version=1 ; shift ;; --) shift ; break ;; *) echo "Internal error!" >&2 ; exit 1 ;; esac; done

# --- Handle -h and -V Options ---
if [[ "$show_help" -eq 1 ]]; then show_help; exit 0; fi
if [[ "$show_version" -eq 1 ]]; then show_version; exit 0; fi

# --- Check Root Privileges ---
if [[ "$(id -u)" -ne 0 ]]; then echo "ERROR: This script must be run as root."; exit 1; fi


# --- Acquire Lock and Run Main Logic ---
# Use flock with explicit file descriptor number 200
exec 200>"$LOCK_FILE"
if ! flock -n 200; then echo "ERROR: [$SCRIPT_NAME] Another instance is already running (Lock file: '$LOCK_FILE'). Exiting." >&2; exit 1; fi
# Lock Acquired! Call the main function. The EXIT trap handles cleanup & lock release.
main "$@"

# Exit code is determined by the 'exit' command within main() or trap_exit_handler()
