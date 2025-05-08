#!/bin/bash
# Plugin for local_backup.sh: Handles PostgreSQL database backup
# Relies on ~/.pgpass file owned by root with 600 permissions for passwords.

# --- Plugin Interface Functions ---

# Source common functions
common_functions_script="${PLUGIN_DIR:-/opt/backup/lib/plugins}/common_functions.sh"
if [[ -f "$common_functions_script" ]]; then source "$common_functions_script"; else _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [postgresql] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }; fi

# Check if this plugin handles the 'postgresql' task type
plugin_handles_task_type() { local task_type="$1"; [[ "$task_type" == "postgresql" ]]; }

# Validate the 'postgresql' section of the YAML config
# Args: $1=path_to_temp_config_file
plugin_validate_config() {
  local temp_config_file="$1"; log_detail "Validating config from ${temp_config_file}..."; local db_host="" db_user="" db_name="" db_port="" validation_ok=1
  # Check dependencies
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('${YQ_CMD}') not found."; return 1; fi
  if ! command -v "$PG_DUMP_CMD" &>/dev/null; then log_error "Required command '${PG_DUMP_CMD:-pg_dump}' not found."; return 1; fi

  # Read properties
  db_host=$("$YQ_CMD" e '.host' "$temp_config_file"); db_user=$("$YQ_CMD" e '.user' "$temp_config_file"); db_name=$("$YQ_CMD" e '.database' "$temp_config_file"); db_port=$("$YQ_CMD" e '.port // ""' "$temp_config_file")
  [[ "$db_host" == "null" ]] && db_host=""; [[ "$db_user" == "null" ]] && db_user=""; [[ "$db_name" == "null" ]] && db_name=""; [[ "$db_port" == "null" ]] && db_port=""
  # Validate
  if [[ -z "$db_host" ]]; then log_error "Mandatory key 'host' missing."; validation_ok=0; fi
  if [[ -z "$db_user" ]]; then log_error "Mandatory key 'user' missing."; validation_ok=0; fi
  if [[ -z "$db_name" ]]; then log_error "Mandatory key 'database' missing."; validation_ok=0; fi
  if [[ -n "$db_port" ]] && ! [[ "$db_port" =~ ^[0-9]+$ && "$db_port" -ge 1 && "$db_port" -le 65535 ]]; then log_error "Invalid 'port' value '${db_port}'."; validation_ok=0; fi
  # Check pgpass (use function from common)
  local pgpass_file="/root/.pgpass"
  if command -v check_perms &>/dev/null; then
      if [[ ! -f "$pgpass_file" ]]; then log_info "Recommendation: Create '${pgpass_file}' (600 root:root) for password."; elif ! check_perms "$pgpass_file" "600" "root"; then log_error "Security Risk: '${pgpass_file}' exists but has insecure permissions/owner."; validation_ok=0; fi
  else log_error "Cannot check pgpass permissions: 'check_perms' function not found."; validation_ok=0; fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi; log_detail "Config validation successful."; return 0
}

# Run backup: Perform the pg_dump
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"; local service_backup_dir="$3"; local db_backup_dir="${service_backup_dir}/databases"
    log_detail "Run backup task..."
    # Read parameters
    local db_host; db_host=$("$YQ_CMD" e '.host' "$temp_config_file"); [[ "$db_host" == "null" ]] && db_host=""
    local db_user; db_user=$("$YQ_CMD" e '.user' "$temp_config_file"); [[ "$db_user" == "null" ]] && db_user=""
    local db_name; db_name=$("$YQ_CMD" e '.database' "$temp_config_file"); [[ "$db_name" == "null" ]] && db_name=""
    local db_port; db_port=$("$YQ_CMD" e '.port // ""' "$temp_config_file"); [[ "$db_port" == "null" ]] && db_port=""
    local dump_options; dump_options=$("$YQ_CMD" e '.dump_options // ""' "$temp_config_file"); [[ "$dump_options" == "null" ]] && dump_options=""
    if [[ -z "$db_host" ]] || [[ -z "$db_user" ]] || [[ -z "$db_name" ]]; then log_error "Run backup error: Missing mandatory DB parameters in config."; return 1; fi

    # Use function if available
    if command -v create_dir_secure &>/dev/null; then create_dir_secure "$db_backup_dir"; else mkdir -p "$db_backup_dir"; chmod 700 "$db_backup_dir"; fi
    log_info "  [PostgreSQL] Backing up DB: ${db_name} from ${db_host}..."
    local dump_file="${db_backup_dir}/${db_name}_$(date +%Y%m%d).sqlc"

    # Handle dry run
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [PostgreSQL] DRY-RUN: Would execute pg_dump for '${db_name}' to '${dump_file}'"
        return 0
    fi

    # Actual run
    local -a dump_cmd_args=(-Fc -h "$db_host" -U "$db_user")
    [[ -n "$db_port" ]] && dump_cmd_args+=(-p "$db_port")
    local -a extra_opts=(); read -r -a extra_opts <<< "$dump_options"; [[ ${#extra_opts[@]} -gt 0 ]] && dump_cmd_args+=("${extra_opts[@]}")
    dump_cmd_args+=("$db_name")
    log_detail "Running command: ${PG_DUMP_CMD:-pg_dump} ${dump_cmd_args[*]} > ${dump_file}"; log_detail "Using /root/.pgpass for password."

    if "${PG_DUMP_CMD:-pg_dump}" "${dump_cmd_args[@]}" > "$dump_file"; then
        log_detail "-> PostgreSQL dump successful."
        return 0
    else log_error "PostgreSQL dump failed for DB '${db_name}'! Check connection, /root/.pgpass, DB logs."; rm -f "$dump_file"; return 1; fi
}
# No prepare, post_success, or emergency_cleanup needed
