#!/bin/bash
# Plugin for local_backup.sh: Handles MariaDB/MySQL database backup
# Relies on /root/.my.cnf file (600 root:root) for passwords.

# --- Plugin Interface Functions ---

# Source common functions
common_functions_script="${PLUGIN_DIR:-/opt/backup/lib/plugins}/common_functions.sh"
if [[ -f "$common_functions_script" ]]; then source "$common_functions_script"; else _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [mariadb] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }; fi

# Check if this plugin handles the 'mariadb' or 'mysql' task type
plugin_handles_task_type() {
  local task_type="$1"
  if [[ "$task_type" == "mariadb" || "$task_type" == "mysql" ]]; then
    return 0
  else
    return 1
  fi
}

# Validate the 'mariadb'/'mysql' section of the YAML config
# Args: $1=path_to_temp_config_file
plugin_validate_config() {
  local temp_config_file="$1"
  log_detail "Validating config from ${temp_config_file}..."
  local db_host="" db_user="" db_name="" db_port="" validation_ok=1

  # Check dependencies
  if ! check_command_exists "$YQ_CMD" "yq command ('${YQ_CMD}') is required by mariadb plugin."; then return 1; fi
  if ! check_command_exists "${MYSQL_DUMP_CMD:-mysqldump}" "mysqldump command ('${MYSQL_DUMP_CMD:-mysqldump}') is required by mariadb plugin."; then return 1; fi

  # Read properties
  db_host=$(get_yaml_value "$temp_config_file" ".host" "")
  db_user=$(get_yaml_value "$temp_config_file" ".user" "")
  db_name=$(get_yaml_value "$temp_config_file" ".database" "")
  db_port=$(get_yaml_value "$temp_config_file" ".port" "")

  # Validate
  if [[ -z "$db_host" ]]; then log_error "Mandatory key 'host' missing."; validation_ok=0; fi
  if [[ -z "$db_user" ]]; then log_error "Mandatory key 'user' missing."; validation_ok=0; fi
  if [[ -z "$db_name" ]]; then log_error "Mandatory key 'database' missing."; validation_ok=0; fi
  if [[ -n "$db_port" ]] && ! [[ "$db_port" =~ ^[0-9]+$ && "$db_port" -ge 1 && "$db_port" -le 65535 ]]; then
    log_error "Invalid 'port' value '${db_port}'."
    validation_ok=0
  fi
  # Check .my.cnf
  local my_cnf_file="/root/.my.cnf"
  if ! check_perms "$my_cnf_file" "600" "root"; then
    log_info "Recommendation: Create '${my_cnf_file}' (600 root:root) with [client] section for password, or check its permissions."
    # Not fatal, but mysqldump might fail if password is required and not in .my.cnf
  fi

  if [[ "$validation_ok" -eq 0 ]]; then
    return 1
  fi
  log_detail "Config validation successful."
  return 0
}

# Run backup: Perform the mysqldump
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"
    local service_backup_dir="$3"
    local db_backup_dir="${service_backup_dir}/databases"
    local db_host db_user db_name db_port dump_options dump_file
    local -a dump_cmd_args extra_opts

    log_detail "Run backup task..."
    # Read parameters
    db_host=$(get_yaml_value "$temp_config_file" ".host" "")
    db_user=$(get_yaml_value "$temp_config_file" ".user" "")
    db_name=$(get_yaml_value "$temp_config_file" ".database" "")
    db_port=$(get_yaml_value "$temp_config_file" ".port" "")
    dump_options=$(get_yaml_value "$temp_config_file" ".dump_options" "")
    if [[ -z "$db_host" ]] || [[ -z "$db_user" ]] || [[ -z "$db_name" ]]; then
      log_error "Run backup error: Missing mandatory DB parameters in config."
      return 1
    fi

    create_dir_secure "$db_backup_dir"
    log_info "  [MariaDB/MySQL] Backing up DB: ${db_name} from ${db_host}..."
    dump_file="${db_backup_dir}/${db_name}_$(date +%Y%m%d).sql"

    # Handle dry run
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [MariaDB/MySQL] DRY-RUN: Would execute mysqldump for '${db_name}' to '${dump_file}'"
        return 0
    fi

    # Actual run
    dump_cmd_args=(
      --defaults-extra-file=/root/.my.cnf # For password
      --single-transaction
      --skip-lock-tables
      -h "$db_host"
      -u "$db_user"
    )
    if [[ -n "$db_port" ]]; then
      dump_cmd_args+=(-P "$db_port")
    fi
    extra_opts=()
    read -r -a extra_opts <<< "$dump_options"
    if [[ ${#extra_opts[@]} -gt 0 ]]; then
      dump_cmd_args+=("${extra_opts[@]}")
    fi
    dump_cmd_args+=(--databases "$db_name")

    log_detail "Running command: ${MYSQL_DUMP_CMD:-mysqldump} ${dump_cmd_args[*]} > ${dump_file}"
    log_detail "Using /root/.my.cnf for password."

    if "${MYSQL_DUMP_CMD:-mysqldump}" "${dump_cmd_args[@]}" > "$dump_file"; then
        log_detail "-> MariaDB/MySQL dump successful (uncompressed)."
        return 0
    else
        log_error "MariaDB/MySQL dump failed for DB '${db_name}'! Check connection, /root/.my.cnf, DB logs."
        rm -f "$dump_file" # Clean partial file
        return 1
    fi
}
# No prepare, post_success, or emergency_cleanup needed

