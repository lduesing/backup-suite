#!/bin/bash
# Plugin for local_backup.sh: Handles InfluxDB backup using 'influx backup' CLI.
# Note: Assumes InfluxDB v2.x CLI and API token authentication.
# Security Warning: Storing tokens directly in config is insecure. Consider
# environment variables or a secrets management tool in production.

# --- Plugin Interface Functions ---

# Source common functions if they exist
# Determine script's directory to find common_functions relative to itself
plugin_self_dir=$(dirname "$(readlink -f "$0")")
# Use uppercase PLUGIN_DIR as it's set globally by core based on config
common_functions_script="${PLUGIN_DIR:-/opt/backup/lib/plugins}/common_functions.sh"
if [[ -f "$common_functions_script" ]]; then
    # shellcheck source=/dev/null
    source "$common_functions_script"
else
    # Define minimal logging if common functions are not available
    echo "WARNING: [influxdb] common_functions.sh not found, using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [influxdb] $1"; }
    log_info() { _log_base "INFO:  $1"; }
    log_error() { _log_base "ERROR: $1" >&2; }
    log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; } # Use global var directly
fi


# Check if this plugin handles the 'influxdb' task type key from YAML
# $1: Task type string
plugin_handles_task_type() {
  local task_type="$1" # Use local var
  [[ "$task_type" == "influxdb" ]] # Return 0 (success) if type matches
}

# Validate the 'influxdb' section of the YAML config
# Args: $1=path_to_temp_config_file containing YAML section for 'influxdb'
plugin_validate_config() {
  local temp_config_file="$1"; log_detail "Validating config from ${temp_config_file}...";
  local host="" port="" token="" org="" bucket="" validation_ok=1 # local vars

  # Check dependencies first
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('${YQ_CMD}') not found."; return 1; fi
  # Check for influx CLI - path can be configured via common_config if needed
  local influx_cmd="${INFLUX_CMD:-influx}" # Allow override via common_config
  if ! command -v "$influx_cmd" &>/dev/null; then log_error "Required command '${influx_cmd}' not found in PATH."; return 1; fi

  # Read properties using yq from the temp file
  host=$("$YQ_CMD" e '.host // "http://localhost:8086"' "$temp_config_file") # Default host
  token=$("$YQ_CMD" e '.token // ""' "$temp_config_file")
  org=$("$YQ_CMD" e '.org // ""' "$temp_config_file") # Org name or ID
  bucket=$("$YQ_CMD" e '.bucket // ""' "$temp_config_file") # Optional: specific bucket name or ID

  # Trim potential null/empty strings from yq
  [[ "$host" == "null" ]] && host="http://localhost:8086"
  [[ "$token" == "null" ]] && token=""
  [[ "$org" == "null" ]] && org=""
  [[ "$bucket" == "null" ]] && bucket=""

  # Validate mandatory fields (token and org are usually required)
  if [[ -z "$host" ]]; then log_error "Mandatory key 'host' missing (or needs default)."; validation_ok=0; fi
  if [[ -z "$token" ]]; then log_error "Mandatory key 'token' missing. An API token is required."; validation_ok=0; fi
  if [[ -z "$org" ]]; then log_error "Mandatory key 'org' (organization name or ID) missing."; validation_ok=0; fi
  # Bucket is optional for 'influx backup' (backs up all buckets if omitted)

  # Basic host format check (very simple)
  if ! [[ "$host" =~ ^https?:// ]]; then log_info "Config Warning: InfluxDB 'host' ('${host}') does not start with http:// or https://."; fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi # Failure
  log_detail "Config validation successful (Host: ${host}, Org: ${org}, Bucket: ${bucket:-ALL}).";
  log_detail "SECURITY WARNING: Token should ideally be sourced from env var or secret store, not directly in config."
  return 0 # Success
}

# Run backup: Perform the influx backup
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"; local service_backup_dir="$3" # local vars
    local influx_backup_dir="${service_backup_dir}/influxdb_backup" # Subdir for backup files

    log_detail "Run backup task..."
    # Read parameters from temp config file
    local host; host=$("$YQ_CMD" e '.host // "http://localhost:8086"' "$temp_config_file"); [[ "$host" == "null" ]] && host="http://localhost:8086"
    local token; token=$("$YQ_CMD" e '.token // ""' "$temp_config_file"); [[ "$token" == "null" ]] && token=""
    local org; org=$("$YQ_CMD" e '.org // ""' "$temp_config_file"); [[ "$org" == "null" ]] && org=""
    local bucket; bucket=$("$YQ_CMD" e '.bucket // ""' "$temp_config_file"); [[ "$bucket" == "null" ]] && bucket=""
    # Check mandatory params again
    if [[ -z "$host" ]] || [[ -z "$token" ]] || [[ -z "$org" ]]; then log_error "Run backup error: Missing mandatory InfluxDB parameters in config."; return 1; fi

    # Create backup dir
    # Use function if available
    if command -v create_dir_secure &>/dev/null; then create_dir_secure "$influx_backup_dir"; else mkdir -p "$influx_backup_dir"; chmod 700 "$influx_backup_dir"; fi

    log_info "  [InfluxDB] Backing up Org '${org}' from ${host}..."
    if [[ -n "$bucket" ]]; then log_info "  [InfluxDB] Targeting specific bucket: ${bucket}"; fi

    # Handle dry run
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [InfluxDB] DRY-RUN: Would execute 'influx backup' to '${influx_backup_dir}'"
        return 0 # Success for dry run
    fi

    # Actual run: Build command args
    local influx_cmd="${INFLUX_CMD:-influx}" # Use configured or default path
    local -a backup_cmd_args=(backup --host "$host" --token "$token" --org "$org") # local array
    # Add bucket filter if specified
    if [[ -n "$bucket" ]]; then backup_cmd_args+=(--bucket "$bucket"); fi
    # Add destination path (the directory where backup files are stored)
    backup_cmd_args+=("$influx_backup_dir")

    # SECURITY NOTE: Token is passed on the command line here.
    # Consider using INFLUX_TOKEN environment variable if CLI supports it and if preferred.
    log_detail "Running command: ${influx_cmd} ${backup_cmd_args[*]}"
    log_detail "Using API token for authentication."

    # Execute influx backup command
    if "$influx_cmd" "${backup_cmd_args[@]}"; then
        log_detail "-> InfluxDB backup command completed successfully."
        # Verify if files were actually created? influx backup creates a timestamped dir inside.
        if compgen -G "${influx_backup_dir}"/* > /dev/null; then
            log_info "  [InfluxDB] Backup files created in ${influx_backup_dir}"
            return 0 # Success
        else
            log_error "InfluxDB backup command succeeded but no files found in ${influx_backup_dir}!"
            return 1 # Failure
        fi
    else
        log_error "InfluxDB backup command failed! Check connection, token, org, bucket, and InfluxDB logs."
        return 1 # Failure
    fi
}
# No prepare, post_success, or emergency_cleanup typically needed for influx backup

