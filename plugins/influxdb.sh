#!/bin/bash
# Plugin for local_backup.sh: Handles InfluxDB backup using 'influx backup' CLI.
# Note: Assumes InfluxDB v2.x CLI and API token authentication.
# Security Warning: Storing tokens directly in config is insecure. Consider
# environment variables or a secrets management tool in production.

# --- Plugin Interface Functions ---

# Source common functions
common_functions_script="${PLUGIN_DIR:-/opt/backup/lib/plugins}/common_functions.sh"
if [[ -f "$common_functions_script" ]]; then source "$common_functions_script"; else _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [influxdb] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }; fi

# Check if this plugin handles the 'influxdb' task type
plugin_handles_task_type() { local task_type="$1"; [[ "$task_type" == "influxdb" ]]; }

# Validate the 'influxdb' section of the YAML config
# Args: $1=path_to_temp_config_file
plugin_validate_config() {
  local temp_config_file="$1"; log_detail "Validating config from ${temp_config_file}..."; local host="" token="" org="" bucket="" validation_ok=1
  local influx_cmd="${INFLUX_CMD:-influx}" # Global from common_config

  # Check dependencies
  if ! check_command_exists "$YQ_CMD" "yq command ('${YQ_CMD}') is required by influxdb plugin."; then return 1; fi
  if ! check_command_exists "$influx_cmd" "InfluxDB CLI ('${influx_cmd}') is required by influxdb plugin."; then return 1; fi

  # Read properties
  host=$(get_yaml_value "$temp_config_file" ".host" "http://localhost:8086")
  token=$(get_yaml_value "$temp_config_file" ".token" "")
  org=$(get_yaml_value "$temp_config_file" ".org" "")
  bucket=$(get_yaml_value "$temp_config_file" ".bucket" "")

  # Validate
  if [[ -z "$host" ]]; then log_error "Mandatory key 'host' missing (or needs default)."; validation_ok=0; fi
  if [[ -z "$token" ]]; then log_error "Mandatory key 'token' missing. An API token is required."; validation_ok=0; fi
  if [[ -z "$org" ]]; then log_error "Mandatory key 'org' (organization name or ID) missing."; validation_ok=0; fi
  if ! [[ "$host" =~ ^https?:// ]]; then log_info "Config Warning: InfluxDB 'host' ('${host}') does not start with http:// or https://."; fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi
  log_detail "Config validation successful (Host: ${host}, Org: ${org}, Bucket: ${bucket:-ALL}).";
  log_detail "SECURITY WARNING: Token should ideally be sourced from env var or secret store, not directly in config."
  return 0
}

# Run backup: Perform the influx backup
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"; local service_backup_dir="$3"; local influx_backup_dir="${service_backup_dir}/influxdb_backup"
    log_detail "Run backup task..."
    # Read parameters
    local host; host=$(get_yaml_value "$temp_config_file" ".host" "http://localhost:8086")
    local token; token=$(get_yaml_value "$temp_config_file" ".token" "")
    local org; org=$(get_yaml_value "$temp_config_file" ".org" "")
    local bucket; bucket=$(get_yaml_value "$temp_config_file" ".bucket" "")
    if [[ -z "$host" ]] || [[ -z "$token" ]] || [[ -z "$org" ]]; then log_error "Run backup error: Missing mandatory InfluxDB parameters in config."; return 1; fi

    create_dir_secure "$influx_backup_dir"
    log_info "  [InfluxDB] Backing up Org '${org}' from ${host}..."
    if [[ -n "$bucket" ]]; then
      log_info "  [InfluxDB] Targeting specific bucket: ${bucket}"
    fi

    # Handle dry run
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [InfluxDB] DRY-RUN: Would execute 'influx backup' to '${influx_backup_dir}'"
        return 0
    fi

    # Actual run
    local influx_cmd="${INFLUX_CMD:-influx}"
    local -a backup_cmd_args=(backup --host "$host" --token "$token" --org "$org")
    [[ -n "$bucket" ]] && backup_cmd_args+=(--bucket "$bucket")
    backup_cmd_args+=("$influx_backup_dir")

    log_detail "Running command: ${influx_cmd} ${backup_cmd_args[*]}"
    log_detail "Using API token for authentication."

    if "$influx_cmd" "${backup_cmd_args[@]}"; then
        log_detail "-> InfluxDB backup command completed successfully."
        if compgen -G "${influx_backup_dir}"/* > /dev/null; then
          log_info "  [InfluxDB] Backup files created in ${influx_backup_dir}"
          return 0
        else
          log_error "InfluxDB backup command succeeded but no files found in ${influx_backup_dir}!"
          return 1
        fi
    else
      log_error "InfluxDB backup command failed! Check connection, token, org, bucket, and InfluxDB logs."
      return 1
    fi
}
# No prepare, post_success, or emergency_cleanup

