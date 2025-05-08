#!/bin/bash

# ==============================================================================
# Backup Server Script
# ==============================================================================
# Description:
# Fetches the latest backup archive (.tar.gz) from configured client hosts via SSH/SCP,
# unpacks it locally, backs up the content using Restic into host-specific
# sub-repositories, manages the archive on the remote host upon success,
# cleans up local temporary files, and sends email notifications on per-host errors.
# Uses file locking to prevent concurrent runs. Reads configuration from YAML
# and common shell config. Supports dry-run mode. Adheres to Google Shell Style Guide.
# Root privileges required.
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
# Date: 2025-05-02
# Version: 0.1
# ==============================================================================

# --- Script Metadata and Constants ---
readonly SCRIPT_VERSION="0.1"
readonly SCRIPT_NAME=$(basename "$0")
# Standardized configuration directory
readonly CONFIG_DIR="/etc/backup"
# Path to common config file (shell variables)
readonly COMMON_CONFIG_FILE="${CONFIG_DIR}/common_config"
# Path to server-specific config file (YAML)
readonly SERVER_CONFIG_FILE="${CONFIG_DIR}/server_config.yml"
# Default values for optional settings if not found anywhere
readonly MIN_FREE_SPACE_MB_DEFAULT=500
readonly DEFAULT_PLUGIN_DIR="/opt/backup/lib/plugins" # For common_functions path default
# Lock file location
readonly LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
readonly LOCK_FD_NUM=200 # File descriptor number for flock

# --- Script Flags and State Variables ---
# Command line flags
verbose=0; show_help=0; show_version=0; dry_run=0
# Config variables (UPPERCASE, loaded from common_config and server_config.yml)
LOCAL_TEMP_BASE_DIR=""; ADMIN_EMAIL_GLOBAL=""
MSMTP_CMD=""; YQ_CMD=""; RESTIC_REPO_ROOT=""; RESTIC_PW_FILE=""
RESTIC_CMD=""; RESTIC_BACKUP_OPTIONS=""
# Tool Paths from common_config (lowercase defaults, uppercase final)
TAR_CMD=""; GZIP_CMD=""; SSH_CMD=""; SCP_CMD=""
# Runtime state (lowercase)
tmp_log_file=""
declare -a failed_hosts=() # Track hosts that failed

# --- Shell Options ---
set -eo pipefail

# --- Source Common Functions ---
# Use default plugin dir initially to find common functions
COMMON_FUNCTIONS_SCRIPT_PATH="${DEFAULT_PLUGIN_DIR}/common_functions.sh"
if [[ -f "$COMMON_FUNCTIONS_SCRIPT_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS_SCRIPT_PATH"
else
    echo "WARNING: common_functions.sh not found at '$COMMON_FUNCTIONS_SCRIPT_PATH', using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [Server] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }
fi

# --- Function Definitions ---

# Display Help Message
show_help() {
  cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Fetches backup archives from client hosts, unpacks them, and backs them up using Restic.
Reads common defaults from '${COMMON_CONFIG_FILE}', server settings from '${SERVER_CONFIG_FILE}'.
Uses file locking '${LOCK_FILE}'. Includes dry-run mode.

Options:
  -d, --dry-run    Enable dry-run mode. Simulates actions without modifying remote files,
                   Restic repositories, or sending failure emails. Restic backup uses --dry-run.
  -v, --verbose    Enable verbose output (shows DEBUG messages).
  -h, --help       Display this help message and exit.
  -V, --version    Display script version (${SCRIPT_VERSION}) and exit.

Configuration:
  See '${COMMON_CONFIG_FILE}', '${SERVER_CONFIG_FILE}', and README.md for details.

Prerequisites:
  ssh, scp, tar, gzip, restic, yq (v4+), mktemp, msmtp, flock, getent, stat, df. Root privileges.
  Manual SSH host key verification required for clients. Restic repos must be initialized.

Example:
  sudo ${SCRIPT_NAME} -v        # Run backup server with verbose output.
  sudo ${SCRIPT_NAME} --dry-run  # Simulate backup fetching and processing.
EOF
}

# Display Version
show_version() { echo "${SCRIPT_NAME} Version ${SCRIPT_VERSION}"; }

# Securely Create Directory (700)
create_dir_secure() { local dir_path="$1"; mkdir -p "$dir_path" && chmod 700 "$dir_path" || { log_error "Failed to create or set permissions on directory: ${dir_path}"; exit 1; }; log_detail "Directory created/permission set (700): ${dir_path}"; }

# Check File Permissions (Sourced or minimal definition)
if ! command -v check_perms &> /dev/null; then
  check_perms() { log_detail "Permissions check skipped (common_functions.sh not found)."; return 0; }
fi

# Check Available Disk Space (Sourced or minimal definition)
if ! command -v check_disk &> /dev/null; then
  check_disk() { log_detail "Disk space check skipped (common_functions.sh not found)."; return 0; }
fi


# Send Error Email
# Args: $1=Recipient Email, $2=Subject, $3=Body
send_error_email() {
    local recipient="$1" subject="$2" body="$3" # Use local vars
    # Skip sending in dry-run mode
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "DRY-RUN: Would send email to ${recipient}"
        log_detail "DRY-RUN: Subject: ${subject}"
        log_detail "DRY-RUN: Body:\n${body}"
        return 0
    fi

    # Actual sending logic
    if [[ -z "$recipient" ]]; then log_error "Cannot send email: Recipient address is empty."; return 1; fi
    if ! command -v "$MSMTP_CMD" &>/dev/null; then log_error "Cannot send email: '${MSMTP_CMD}' command not found."; return 1; fi

    log_info "Sending error email to ${recipient}..."
    printf "To: %s\nSubject: %s\nContent-Type: text/plain; charset=utf-8\nX-Priority: 1 (Highest)\nImportance: High\n\n%s" \
        "$recipient" "$subject" "$body" | "$MSMTP_CMD" "$recipient"

    if [[ $? -ne 0 ]]; then log_error "Failed to send email to ${recipient} using '${MSMTP_CMD}'."; return 1; fi
    log_detail "Error email sent successfully to ${recipient}."
    return 0
}


# --- Trap Functions ---

# ERR Trap Handler: Captures context on command failure
trap_err_handler() { error_lineno=${BASH_LINENO[0]}; error_command=${BASH_COMMAND}; local i; error_funcstack=(); for ((i=0; i < ${#FUNCNAME[@]}; i++)); do error_funcstack+=("${FUNCNAME[$i]:-main}:${BASH_LINENO[$i+1]}"); done; log_detail "Error context captured: Line ${error_lineno}, Command '${error_command}'"; }

# EXIT Trap Handler: Cleanup log file
# Specific temp dir cleanup is handled within the host processing loop/subshell
trap_exit_handler() {
  local exit_code=$?; set +e
  log_detail "--- Running EXIT trap (Exit code: ${exit_code}) ---"

  if [[ "$exit_code" -ne 0 ]]; then
      log_error "Backup server script finished with ERROR (Exit Code: ${exit_code})."
      if [[ -n "$tmp_log_file" ]] && [[ -f "$tmp_log_file" ]]; then
          echo "Log file kept for analysis: ${tmp_log_file}" >&2
      fi
      # Final summary email is not sent here, rely on per-host emails
  else
      log_info "Backup server script finished successfully."
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
  trap trap_exit_handler EXIT # Handles final exit and log cleanup

  # --- Start Actual Process ---
  log_info "Successfully acquired lock file: ${LOCK_FILE} (FD ${LOCK_FD_NUM})"
  if [[ "${dry_run}" -eq 1 ]]; then log_info "*** DRY-RUN MODE ACTIVATED ***"; fi

  # --- Load Common Config ---
  log_info "Loading common configuration from ${COMMON_CONFIG_FILE}..."
  if [[ ! -f "$COMMON_CONFIG_FILE" ]]; then log_error "Common config file '${COMMON_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${COMMON_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${COMMON_CONFIG_FILE}'. Requires 600 owned by root."; exit 1; fi
  local source_exit_code; set +e; source "${COMMON_CONFIG_FILE}"; source_exit_code=$?; set -e
  if [[ ${source_exit_code} -ne 0 ]]; then log_error "Failed to source common config file '${COMMON_CONFIG_FILE}'. Syntax error?"; exit 1; fi
  log_detail "Common configuration sourced."

  # --- Load Server Specific Config (YAML) ---
  log_info "Loading server configuration from ${SERVER_CONFIG_FILE}..."
  if [[ ! -f "$SERVER_CONFIG_FILE" ]]; then log_error "Server config file '${SERVER_CONFIG_FILE}' not found."; exit 1; fi
  if ! check_perms "${SERVER_CONFIG_FILE}" "600" "root"; then log_error "Aborting: Insecure permissions on '${SERVER_CONFIG_FILE}'. Requires 600 owned by root."; exit 1; fi
  # Set default YQ_CMD if not set in common_config before using it
  YQ_CMD="${YQ_CMD:-yq}"
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('$YQ_CMD') not found. Cannot parse server config."; exit 1; fi

  # Read values, overriding common defaults if present
  local temp_base_dir_yml; temp_base_dir_yml=$("$YQ_CMD" e '.global.local_temp_base_dir // ""' "$SERVER_CONFIG_FILE"); [[ -n "$temp_base_dir_yml" ]] && LOCAL_TEMP_BASE_DIR="$temp_base_dir_yml"
  local admin_email_yml; admin_email_yml=$("$YQ_CMD" e '.global.admin_email // ""' "$SERVER_CONFIG_FILE"); [[ -n "$admin_email_yml" ]] && ADMIN_EMAIL_GLOBAL="$admin_email_yml"
  local msmtp_cmd_yml; msmtp_cmd_yml=$("$YQ_CMD" e '.global.msmtp_cmd // ""' "$SERVER_CONFIG_FILE"); [[ -n "$msmtp_cmd_yml" ]] && MSMTP_CMD="$msmtp_cmd_yml"
  local yq_cmd_yml; yq_cmd_yml=$("$YQ_CMD" e '.global.yq_cmd // ""' "$SERVER_CONFIG_FILE"); [[ -n "$yq_cmd_yml" ]] && YQ_CMD="$yq_cmd_yml"
  local repo_root_yml; repo_root_yml=$("$YQ_CMD" e '.restic.repository_root // ""' "$SERVER_CONFIG_FILE"); [[ -n "$repo_root_yml" ]] && RESTIC_REPO_ROOT="$repo_root_yml"
  local pw_file_yml; pw_file_yml=$("$YQ_CMD" e '.restic."password_file" // ""' "$SERVER_CONFIG_FILE"); [[ -n "$pw_file_yml" ]] && RESTIC_PW_FILE="$pw_file_yml" # Correct key lookup
  local restic_cmd_yml; restic_cmd_yml=$("$YQ_CMD" e '.restic.restic_cmd // ""' "$SERVER_CONFIG_FILE"); [[ -n "$restic_cmd_yml" ]] && RESTIC_CMD="$restic_cmd_yml"
  local backup_opts_yml; backup_opts_yml=$("$YQ_CMD" e '.restic.backup_options // ""' "$SERVER_CONFIG_FILE"); [[ -n "$backup_opts_yml" ]] && RESTIC_BACKUP_OPTIONS="$backup_opts_yml"

  # --- Set Defaults for any remaining unset variables ---
  LOCAL_TEMP_BASE_DIR="${LOCAL_TEMP_BASE_DIR:-/var/tmp/backup_server_work}"
  ADMIN_EMAIL_GLOBAL="${ADMIN_EMAIL_GLOBAL:-${DEFAULT_ADMIN_EMAIL}}"
  MSMTP_CMD="${MSMTP_CMD:-msmtp}"
  YQ_CMD="${YQ_CMD:-yq}"; RESTIC_CMD="${RESTIC_CMD:-restic}"; TAR_CMD="${TAR_CMD:-tar}"; GZIP_CMD="${GZIP_CMD:-gzip}"; SSH_CMD="${SSH_CMD:-ssh}"; SCP_CMD="${SCP_CMD:-scp}"

  # --- Validate Loaded Configuration ---
  log_info "Validating loaded configuration..."
  local validation_ok=1 # Use local var
  if [[ -z "$LOCAL_TEMP_BASE_DIR" ]] || [[ ! -d "$LOCAL_TEMP_BASE_DIR" ]] || [[ ! -w "$LOCAL_TEMP_BASE_DIR" ]]; then log_error "Config Error: global.local_temp_base_dir ('$LOCAL_TEMP_BASE_DIR') is invalid/missing/not writable."; validation_ok=0; fi
  if [[ -z "$ADMIN_EMAIL_GLOBAL" ]]; then log_info "Config Warning: global.admin_email is not set. No fallback error emails."; fi
  if [[ -z "$RESTIC_REPO_ROOT" ]] || [[ ! -d "$RESTIC_REPO_ROOT" ]]; then log_error "Config Error: restic.repository_root ('$RESTIC_REPO_ROOT') is invalid or missing."; validation_ok=0; fi
  if [[ -z "$RESTIC_PW_FILE" ]]; then log_error "Config Error: restic.password_file is not set."; validation_ok=0; elif ! check_perms "$RESTIC_PW_FILE" "600" "root"; then log_error "Config Error: Restic password file '$RESTIC_PW_FILE' requires 600 root:root."; validation_ok=0; fi
  # Check tool commands
  local -a tools_to_check=(YQ_CMD TAR_CMD GZIP_CMD SSH_CMD SCP_CMD RESTIC_CMD MSMTP_CMD)
  local tool_var tool_cmd; for tool_var in "${tools_to_check[@]}"; do tool_cmd=$(echo "${!tool_var}" | cut -d' ' -f1); if [[ -n "$tool_cmd" ]] && ! command -v "$tool_cmd" &>/dev/null; then log_error "Config Error: Command for ${tool_var} ('${!tool_var}') not found."; validation_ok=0; fi; done

  if [[ "$validation_ok" -eq 0 ]]; then log_error "Configuration validation failed. Aborting."; exit 1; fi
  log_info "Configuration validated successfully."

  # --- Print Startup Info ---
  log_info "============================================================"
  log_info "Starting Backup Server Script (Version ${SCRIPT_VERSION}) - Locked (PID $$)"
  log_info "Config File: ${SERVER_CONFIG_FILE}"; log_info "Common Config: ${COMMON_CONFIG_FILE}"
  log_info "Temp Base Dir: ${LOCAL_TEMP_BASE_DIR}"; log_info "Restic Repo Root: ${RESTIC_REPO_ROOT}"
  log_detail "Restic Password File: ${RESTIC_PW_FILE}"; log_info "Global Admin Email: ${ADMIN_EMAIL_GLOBAL}"
  [[ "${dry_run}" -eq 1 ]] && log_info "*** DRY-RUN MODE ENABLED ***"
  [[ "${verbose}" -eq 1 ]] && log_info "Verbose mode enabled."
  log_info "============================================================"

  # --- Read Host Configurations ---
  log_info "Reading host configurations from ${SERVER_CONFIG_FILE}..."
  HOSTS_CONFIG=() # Reset global array
  local host_yaml_list; host_yaml_list=$("$YQ_CMD" e '.hosts' -o=json "$SERVER_CONFIG_FILE") # Get hosts as JSON array string
  local host_count; host_count=$("$YQ_CMD" e '.hosts | length' "$SERVER_CONFIG_FILE")

  if [[ "$host_count" -eq 0 ]]; then log_error "No host configurations found in '.hosts[]'. Nothing to do."; exit 1; fi

  local i host_config_json host_valid # Local loop vars
  for (( i=0; i<host_count; i++ )); do
      host_config_json=$("$YQ_CMD" e ".hosts[${i}]" -o=json "$SERVER_CONFIG_FILE")
      # Use associative array for easier access (requires Bash 4+)
      declare -A host_map
      while IFS="=" read -r key value; do
          # Remove quotes added by yq/jq
          value="${value%\"}"; value="${value#\"}"
          host_map["$key"]="$value"
      done < <("$YQ_CMD" e 'to_entries | .[] | .key + "=" + (.value | @json)' - <<< "$host_config_json") # Output key="json_value"

      # Validate this host's config
      host_valid=1
      if [[ -z "${host_map[hostname]}" ]]; then log_error "Host config ${i}: 'hostname' is missing."; host_valid=0; fi
      if [[ -z "${host_map[ssh_user]}" ]]; then log_error "Host config ${i} (${host_map[hostname]}): 'ssh_user' is missing."; host_valid=0; fi
      if [[ -z "${host_map[ssh_key_file]}" ]]; then log_error "Host config ${i} (${host_map[hostname]}): 'ssh_key_file' is missing."; host_valid=0; fi
      if [[ -n "${host_map[ssh_key_file]}" ]] && ! check_perms "${host_map[ssh_key_file]}" "600" "root"; then log_error "Host config ${i} (${host_map[hostname]}): SSH key '${host_map[ssh_key_file]}' requires 600 root:root."; host_valid=0; fi
      if [[ -z "${host_map[remote_tar_dir]}" ]]; then log_error "Host config ${i} (${host_map[hostname]}): 'remote_tar_dir' is missing."; host_valid=0; fi
      # Set admin email fallback
      if [[ -z "${host_map[admin_email]}" ]]; then host_map["admin_email"]="$ADMIN_EMAIL_GLOBAL"; fi
      if [[ -z "${host_map[admin_email]}" ]]; then log_info "Host config ${i} (${host_map[hostname]}): No admin email configured."; fi

      if [[ "$host_valid" -eq 1 ]]; then
          # Store validated config (e.g., serialize map back or store map name - complex)
          # Simpler: Store the original valid JSON chunk
          HOSTS_CONFIG+=("$host_config_json")
          log_detail "Host ${i} (${host_map[hostname]}): Configuration loaded and validated."
      else
          log_error "Host configuration at index ${i} is invalid. Skipping this host."
      fi
      unset host_map # Clear map for next iteration
  done

  if [[ ${#HOSTS_CONFIG[@]} -eq 0 ]]; then log_error "No valid host configurations loaded. Nothing to do."; exit 1; fi
  log_info "Loaded configuration for ${#HOSTS_CONFIG[@]} hosts."

  # --- Main Host Processing Loop ---
  log_info "============================================================"
  log_info "Starting backup run for configured hosts..."
  FAILED_HOSTS=() # Reset failed hosts list

  local host_config_json # Local loop var
  for host_config_json in "${HOSTS_CONFIG[@]}"; do
    # Use a subshell for each host to isolate errors and cleanup
    (
      set -e # Exit subshell on error
      # Local variables for this host's processing
      local hostname ssh_user ssh_key_file remote_tar_dir admin_email # Config vars
      local remote_host temp_download_dir unpack_dir # Runtime vars
      local remote_latest_tar remote_tar_path local_tar_path timestamp_tag repo_path
      local -a restic_tags restic_cmd_args # Arrays

      # Parse JSON again inside subshell to populate local vars
      # Use declare -A for map requires Bash 4+
      declare -A host_map
      while IFS="=" read -r key value; do value="${value%\"}"; value="${value#\"}"; host_map["$key"]="$value"; done < <("$YQ_CMD" e 'to_entries | .[] | .key + "=" + (.value | @json)' - <<< "$host_config_json")
      hostname="${host_map[hostname]}"; ssh_user="${host_map[ssh_user]}"; ssh_key_file="${host_map[ssh_key_file]}"; remote_tar_dir="${host_map[remote_tar_dir]}"; admin_email="${host_map[admin_email]}"
      remote_host="$hostname" # Alias for clarity

      log_info ">>> Processing host: ${remote_host} <<<"

      # --- Define Temporary Locations ---
      log_detail "Creating temporary directories for ${remote_host}..."
      temp_download_dir=$(mktemp -d -p "$LOCAL_TEMP_BASE_DIR" "${remote_host}_download.XXXXXX"); chmod 700 "$temp_download_dir"
      unpack_dir=$(mktemp -d -p "$LOCAL_TEMP_BASE_DIR" "${remote_host}_unpack.XXXXXX"); chmod 700 "$unpack_dir"
      log_detail "Temp download dir: ${temp_download_dir}"; log_detail "Temp unpack dir: ${unpack_dir}"

      # --- Find Latest TAR on Remote Host ---
      log_info "  Finding latest backup archive on ${remote_host}..."
      # Use precise quoting for remote command
      remote_latest_tar=$("$SSH_CMD" -i "$ssh_key_file" -o BatchMode=yes -o StrictHostKeyChecking=yes "$ssh_user@$remote_host" \
          "find \"${remote_tar_dir}/\" -maxdepth 1 -name \"${remote_host}-*.tar.gz\" -printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-")

      if [[ -z "$remote_latest_tar" ]]; then log_error "No backup archives found for host ${remote_host} in ${remote_tar_dir}."; return 1; fi
      remote_latest_tar=$(basename "$remote_latest_tar") # Get just the filename
      remote_tar_path="${remote_tar_dir}/${remote_latest_tar}"
      local_tar_path="${temp_download_dir}/${remote_latest_tar}"
      log_info "  Found latest archive: ${remote_latest_tar}"

      # --- Fetch TAR Archive ---
      if [[ "${dry_run}" -eq 1 ]]; then log_info "  DRY-RUN: Would fetch ${remote_host}:${remote_tar_path} to ${local_tar_path}";
      else
        log_info "  Fetching archive from ${remote_host}:${remote_tar_path}..."
        log_detail "Executing: ${SCP_CMD} -i \"${ssh_key_file}\" -o BatchMode=yes -o StrictHostKeyChecking=yes \"${ssh_user}@${remote_host}:${remote_tar_path}\" \"${local_tar_path}\""
        if ! "$SCP_CMD" -i "$ssh_key_file" -o BatchMode=yes -o StrictHostKeyChecking=yes "${ssh_user}@${remote_host}:${remote_tar_path}" "$local_tar_path"; then log_error "Failed to fetch archive from ${remote_host}."; return 1; fi
        log_info "  -> Archive fetched successfully to ${local_tar_path}"
      fi

      # --- Unpack TAR Archive ---
      if [[ "${dry_run}" -eq 1 ]]; then log_info "  DRY-RUN: Would unpack ${local_tar_path} to ${unpack_dir}";
      else
        log_info "  Unpacking archive: ${local_tar_path}"
        log_detail "Executing: ${TAR_CMD} -xpzf \"${local_tar_path}\" --numeric-owner -C \"${unpack_dir}\""
        if ! "$TAR_CMD" -xpzf "$local_tar_path" --numeric-owner -C "$unpack_dir"; then log_error "Failed to unpack archive '${local_tar_path}'."; return 1; fi
        log_info "  -> Archive unpacked successfully to ${unpack_dir}"
      fi

      # --- Restic Backup ---
      repo_path="${RESTIC_REPO_ROOT}/${remote_host}"
      log_info "  Performing Restic backup for host ${remote_host}..."
      log_info "  Restic repository: ${repo_path}"
      log_detail "Password file: ${RESTIC_PW_FILE}"

      # Extract timestamp from filename for tagging
      timestamp_tag=$(echo "$remote_latest_tar" | sed -n "s/^${remote_host}-\([0-9]\{8\}_[0-9]\{6\}\)\.tar\.gz$/\1/p")
      restic_tags=("$remote_host") # Start with hostname tag
      if [[ -n "$timestamp_tag" ]]; then restic_tags+=("$timestamp_tag"); fi

      # Build restic command arguments
      restic_cmd_args=(-r "$repo_path" --password-file "$RESTIC_PW_FILE" backup)
      # Add tags
      for tag in "${restic_tags[@]}"; do restic_cmd_args+=(--tag "$tag"); done
      # Add custom options from config
      local -a extra_opts=(); read -r -a extra_opts <<< "$RESTIC_BACKUP_OPTIONS"; [[ ${#extra_opts[@]} -gt 0 ]] && restic_cmd_args+=("${extra_opts[@]}")
      # Add dry-run flag if needed
      if [[ "${dry_run}" -eq 1 ]]; then restic_cmd_args+=(--dry-run); log_info "    (Dry Run Enabled for Restic)"; fi
      # Add path to backup ('.') relative to unpack_dir
      restic_cmd_args+=(".")

      log_detail "Executing: (cd \"${unpack_dir}\" && ${RESTIC_CMD} ${restic_cmd_args[*]})"
      # Execute restic backup from within the unpacked directory
      if ! (cd "$unpack_dir" && "$RESTIC_CMD" "${restic_cmd_args[@]}"); then log_error "Restic backup failed for host ${remote_host}."; return 1; fi
      log_info "  -> Restic backup command completed successfully for ${remote_host}."

      # --- Remote Cleanup (on Success, skip in dry-run) ---
      if [[ "${dry_run}" -eq 0 ]]; then
        log_info "  Performing remote cleanup on ${remote_host}..."
        local remote_done_dir="${remote_tar_dir}/done" # Define 'done' path
        # Commands: create done dir, move current tar, list all but newest tar in done, delete older ones
        local remote_cleanup_cmd="mkdir -p '${remote_done_dir}' && mv -f '${remote_tar_path}' '${remote_done_dir}/' && find '${remote_done_dir}/' -maxdepth 1 -name '*.tar.gz' -type f -printf '%T@ %p\\n' | sort -nr | tail -n +2 | cut -d' ' -f2- | xargs --no-run-if-empty rm -f"
        log_detail "Executing remote cleanup command: ssh ... \"${remote_cleanup_cmd}\""
        if ! "$SSH_CMD" -i "$ssh_key_file" -o BatchMode=yes -o StrictHostKeyChecking=yes "$ssh_user@$remote_host" "$remote_cleanup_cmd"; then
            log_error "WARN: Remote cleanup failed on host ${remote_host}. Manual cleanup of '${remote_tar_path}' might be needed." # Warning only
        else log_info "  -> Remote cleanup successful."; fi
      else
        log_info "  DRY-RUN: Skipping remote cleanup on ${remote_host}."
      fi

      log_info ">>> Finished host: ${remote_host} SUCCESSFULLY <<<"

    # End of subshell for host processing
    # The '|| { ... }' catches errors from within the subshell
    ) || {
        # --- Host Failure Handling ---
        local host_fail_code=$? # Capture exit code from subshell
        # Re-parse hostname as local vars are lost
        local failed_hostname; failed_hostname=$("$YQ_CMD" e '.hostname // "UNKNOWN"' - <<< "$host_config_json")
        local failed_admin_email; failed_admin_email=$("$YQ_CMD" e '."admin-email" // ""' - <<< "$host_config_json"); [[ -z "$failed_admin_email" ]] && failed_admin_email="$ADMIN_EMAIL_GLOBAL"

        log_error ">>> Backup FAILED for host ${failed_hostname} (Subshell Exit Code: ${host_fail_code}) <<<"
        # Use declare -g to modify global array from subshell's error handler context
        declare -g -a FAILED_HOSTS+=("$failed_hostname")

        # Send email notification if configured (and not dry run)
        if [[ -n "$failed_admin_email" ]] && [[ "${dry_run:-0}" -eq 0 ]]; then
            local fail_subject="Backup FAILED for host ${failed_hostname} (Code: ${host_fail_code})"
            local fail_body="Backup process failed for host: ${failed_hostname} with exit code ${host_fail_code}.\nCheck the main backup server log file for details:\n${tmp_log_file}\nError likely occurred near line ${error_lineno} (Command: ${error_command})."
            send_error_email "$failed_admin_email" "$fail_subject" "$fail_body"
        elif [[ -n "$failed_admin_email" ]] && [[ "${dry_run:-0}" -eq 1 ]]; then
             log_info "DRY-RUN: Skipping failure email for host ${failed_hostname}."
        else log_info "No specific admin email configured for failed host ${failed_hostname}. Check global logs."; fi
        # Continue to the next host in the main loop (error handled)
    }

    # --- Host Cleanup (always runs after subshell, even on failure) ---
    log_detail "Cleaning up temporary files for host ${hostname}..."
    if [[ -n "$temp_download_dir" ]] && [[ -d "$temp_download_dir" ]]; then rm -rf "$temp_download_dir"; fi
    if [[ -n "$unpack_dir" ]] && [[ -d "$unpack_dir" ]]; then rm -rf "$unpack_dir"; fi
    log_detail "Temporary file cleanup finished for ${hostname}."
    echo # Add visual separation between hosts in log

  done # End of main host processing loop


  # --- Final Summary ---
  log_info "============================================================"
  if [[ ${#FAILED_HOSTS[@]} -gt 0 ]]; then
      log_error "Backup run finished with errors for ${#FAILED_HOSTS[@]} host(s):"
      local failed_host; for failed_host in "${FAILED_HOSTS[@]}"; do log_error "  - ${failed_host}"; done
      exit 1 # Exit with error code if any host failed
  else
      log_info "Backup run finished successfully for all configured hosts."
  fi
  log_info "============================================================"

  # Successful exit (if no hosts failed) - EXIT trap will run
  exit 0

} # End of main_logic function


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
