#!/bin/bash
# Plugin for local_backup.sh: Handles MariaDB/MySQL database backup
# Relies on /root/.my.cnf file (600 root:root) for passwords.

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
    echo "WARNING: [mariadb] common_functions.sh not found, using minimal logging." >&2
    _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [mariadb] $1"; }
    log_info() { _log_base "INFO:  $1"; }
    log_error() { _log_base "ERROR: $1" >&2; }
    log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; } # Use global var directly
fi


# Check if this plugin handles the 'mariadb' or 'mysql' task type key from YAML
# $1: Task type string
plugin_handles_task_type() {
  local task_type="$1" # Use local var
  [[ "$task_type" == "mariadb" || "$task_type" == "mysql" ]] # Return 0 (success) if type matches
}

# Validate the 'mariadb'/'mysql' section of the YAML config
# Args: $1=path_to_temp_config_file containing YAML section
plugin_validate_config() {
  local temp_config_file="$1"; log_detail "Validating config from ${temp_config_file}..."; local db_host="" db_user="" db_name="" db_port="" validation_ok=1 # local vars
  # Check dependencies
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('${YQ_CMD}') not found."; return 1; fi
  if ! command -v "$MYSQL_DUMP_CMD" &>/dev/null; then log_error "Required command '${MYSQL_DUMP_CMD:-mysqldump}' not found."; return 1; fi

  # Read properties using yq from the temp file
  db_host=$("$YQ_CMD" e '.host' "$temp_config_file"); db_user=$("$YQ_CMD" e '.user' "$temp_config_file"); db_name=$("$YQ_CMD" e '.database' "$temp_config_file"); db_port=$("$YQ_CMD" e '.port // ""' "$temp_config_file")
  # Trim potential null/empty strings from yq
  [[ "$db_host" == "null" ]] && db_host=""; [[ "$db_user" == "null" ]] && db_user=""; [[ "$db_name" == "null" ]] && db_name=""; [[ "$db_port" == "null" ]] && db_port=""

  # Validate mandatory fields
  if [[ -z "$db_host" ]]; then log_error "Mandatory key 'host' missing."; validation_ok=0; fi
  if [[ -z "$db_user" ]]; then log_error "Mandatory key 'user' missing."; validation_ok=0; fi
  if [[ -z "$db_name" ]]; then log_error "Mandatory key 'database' missing."; validation_ok=0; fi
  # Validate optional port
  if [[ -n "$db_port" ]] && ! [[ "$db_port" =~ ^[0-9]+$ && "$db_port" -ge 1 && "$db_port" -le 65535 ]]; then log_error "Invalid 'port' value '${db_port}'."; validation_ok=0; fi

  # Check for /root/.my.cnf existence and permissions (recommendation)
  local my_cnf_file="/root/.my.cnf" # Use local var
  # Use check_perms function if available
  if command -v check_perms &>/dev/null; then
      if [[ ! -f "$my_cnf_file" ]]; then
          log_info "Recommendation: Create '${my_cnf_file}' (600 root:root) to store the MariaDB/MySQL password securely in a [client] section."
      elif ! check_perms "$my_cnf_file" "600" "root"; then
          # If the file exists but has wrong permissions, it's a higher risk
          log_error "Security Risk: '${my_cnf_file}' exists but has insecure permissions or owner. Requires 600 owned by root."
          validation_ok=0
      else
          log_detail "Password file '${my_cnf_file}' found with correct permissions."
      fi
  else
      # Log error if helper function is missing, but don't necessarily fail validation based on this alone
      log_error "Cannot check ~/.my.cnf permissions: 'check_perms' function not found."
      # Allow to proceed, but password might fail later if not configured correctly
  fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi # Failure
  log_detail "Config validation successful."; return 0 # Success
}

# Run backup: Perform the mysqldump
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"; local service_backup_dir="$3"; local db_backup_dir="${service_backup_dir}/databases" # local vars
    log_detail "Run backup task..."
    # Read parameters from temp config file
    local db_host; db_host=$("$YQ_CMD" e '.host' "$temp_config_file"); [[ "$db_host" == "null" ]] && db_host=""
    local db_user; db_user=$("$YQ_CMD" e '.user' "$temp_config_file"); [[ "$db_user" == "null" ]] && db_user=""
    local db_name; db_name=$("$YQ_CMD" e '.database' "$temp_config_file"); [[ "$db_name" == "null" ]] && db_name=""
    local db_port; db_port=$("$YQ_CMD" e '.port // ""' "$temp_config_file"); [[ "$db_port" == "null" ]] && db_port=""
    local dump_options; dump_options=$("$YQ_CMD" e '.dump_options // ""' "$temp_config_file"); [[ "$dump_options" == "null" ]] && dump_options=""
    # Check mandatory params again
    if [[ -z "$db_host" ]] || [[ -z "$db_user" ]] || [[ -z "$db_name" ]]; then log_error "Run backup error: Missing mandatory DB parameters in config."; return 1; fi

    # Create backup dir
    # Use function if available
    if command -v create_dir_secure &>/dev/null; then create_dir_secure "$db_backup_dir"; else mkdir -p "$db_backup_dir"; chmod 700 "$db_backup_dir"; fi
    log_info "  [MariaDB/MySQL] Backing up DB: ${db_name} from ${db_host}..."
    # Define dump file path (uncompressed SQL for better deduplication later)
    local dump_file="${db_backup_dir}/${db_name}_$(date +%Y%m%d).sql" # local var

    # Handle dry run
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [MariaDB/MySQL] DRY-RUN: Would execute mysqldump for '${db_name}' to '${dump_file}'"
        return 0 # Success for dry run
    fi

    # Actual run: Build command args
    # Use --single-transaction for InnoDB consistency, --skip-lock-tables to avoid locking MyISAM if possible
    local -a dump_cmd_args=(--defaults-extra-file=/root/.my.cnf --single-transaction --skip-lock-tables -h "$db_host" -u "$db_user") # local array
    # Add port if specified
    [[ -n "$db_port" ]] && dump_cmd_args+=(-P "$db_port")
    # Add extra dump options if provided
    local -a extra_opts=(); read -r -a extra_opts <<< "$dump_options"; [[ ${#extra_opts[@]} -gt 0 ]] && dump_cmd_args+=("${extra_opts[@]}") # local array
    # Add database name(s) - use --databases to include CREATE DATABASE statement
    dump_cmd_args+=(--databases "$db_name")

    log_detail "Running command: ${MYSQL_DUMP_CMD:-mysqldump} ${dump_cmd_args[*]} > ${dump_file}"; log_detail "Using /root/.my.cnf for password."

    # Execute mysqldump. Relies on /root/.my.cnf [client] section for password.
    if "${MYSQL_DUMP_CMD:-mysqldump}" "${dump_cmd_args[@]}" > "$dump_file"; then
        log_detail "-> MariaDB/MySQL dump successful (uncompressed)."
        return 0 # Success
    else
        log_error "MariaDB/MySQL dump failed for DB '${db_name}'! Check connection, /root/.my.cnf credentials, and DB logs."
        rm -f "$dump_file" # Clean partial file
        return 1 # Failure
    fi
}
# No prepare, post_success, or emergency_cleanup needed for basic dump

