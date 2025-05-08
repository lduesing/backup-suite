#!/bin/bash
# Plugin for local_backup.sh: Handles Docker Compose stop/start and config backup
# Uses state files within the service backup directory (.state/)
# Reads optional 'wait_after_restart' from config temp file.

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
  echo "WARNING: [docker_compose] common_functions.sh not found, using minimal logging." >&2
  _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [docker_compose] $1"; }
  log_info() { _log_base "INFO:  $1"; }
  log_error() { _log_base "ERROR: $1" >&2; }
  log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; } # Use global var directly
fi


# Check if this plugin handles the 'docker' task type key from YAML
# $1: Task type string
plugin_handles_task_type() {
  local task_type="$1" # Use local var
  [[ "$task_type" == "docker" ]] # Return 0 (success) if type is 'docker'
}

# Validate the 'docker' section of the YAML config
# Args: $1=path_to_temp_config_file containing YAML section for 'docker'
plugin_validate_config() {
  local temp_config_file="$1" # Use local var
  log_detail "Validating config from ${temp_config_file}..."
  local compose_path="" wait_seconds="" validation_ok=1 # local vars

  # Check dependencies first (use global UPPERCASE tool path vars)
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('${YQ_CMD}') not found."; return 1; fi
  if ! command -v $(echo "${DOCKER_COMMAND:-docker compose}" | cut -d' ' -f1) &> /dev/null; then log_error "Docker command ('${DOCKER_COMMAND:-docker compose}') not found."; return 1; fi

  # Read properties using yq from the temp file
  compose_path=$("$YQ_CMD" e '.docker_compose_path' "$temp_config_file")
  wait_seconds=$("$YQ_CMD" e '.wait_after_restart // 0' "$temp_config_file") # Default to 0

  # Trim potential null/empty strings from yq
  [[ "$compose_path" == "null" ]] && compose_path=""
  [[ "$wait_seconds" == "null" ]] && wait_seconds="0"

  # Validate mandatory fields
  if [[ -z "$compose_path" ]]; then log_error "Mandatory key 'docker_compose_path' missing or empty."; validation_ok=0; fi
  # Validate file existence only if path is not empty
  if [[ -n "$compose_path" ]] && [[ ! -f "$compose_path" ]]; then log_error "Specified docker_compose_path does not exist or is not a file: '${compose_path}'."; validation_ok=0; fi
  # Validate optional wait time
  if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then log_error "Optional key 'wait_after_restart' ('${wait_seconds}') must be a non-negative integer."; validation_ok=0; fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi # Failure
  log_detail "Config validation successful (Path: ${compose_path}, Wait: ${wait_seconds}s)."
  return 0 # Success
}

# Prepare backup: Stop the Docker Compose service and create state file
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_prepare_backup() {
  local temp_config_file="$1"; local service_backup_dir="$3" # Use local vars
  local state_dir="${service_backup_dir}/.state"
  local stopped_flag_file="${state_dir}/docker_stopped"
  local context_file="${state_dir}/docker_context"
  local compose_path wait_seconds compose_dir

  log_detail "Prepare backup..."
  # Read parameters from temp config file
  compose_path=$("$YQ_CMD" e '.docker_compose_path' "$temp_config_file"); [[ "$compose_path" == "null" ]] && compose_path=""
  wait_seconds=$("$YQ_CMD" e '.wait_after_restart // 0' "$temp_config_file"); [[ "$wait_seconds" == "null" ]] && wait_seconds="0"
  if [[ -z "$compose_path" ]] || [[ ! -f "$compose_path" ]]; then log_error "Prepare error: Valid compose path not found in config."; return 1; fi
  if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then wait_seconds=0; fi # Default to 0 if invalid
  compose_dir=$(dirname "$compose_path")

  # Create state directory first
  # Use function if available, otherwise inline
  if command -v create_dir_secure &>/dev/null; then create_dir_secure "$state_dir"; else mkdir -p "$state_dir" && chmod 700 "$state_dir" || { log_error "Failed to create state dir '${state_dir}'"; return 1; }; fi
  # Write context needed for restart (including wait time) to context file
  # Ensure variables in the heredoc are expanded correctly
  cat > "$context_file" << EOF
COMPOSE_DIR="${compose_dir}"
COMPOSE_FILE_PATH="${compose_path}"
WAIT_SECONDS=${wait_seconds}
EOF
  chmod 600 "$context_file" || { log_error "Failed to set permissions on '${context_file}'"; return 1; }

  # Check dry-run mode (read global var inherited by subshell)
  if [[ "${dry_run:-0}" -eq 1 ]]; then
      log_info "  [Docker] DRY-RUN: Would stop service: ${compose_path}"
      # Still create the stopped flag in dry-run to test state logic
      touch "$stopped_flag_file"; chmod 600 "$stopped_flag_file" || { log_error "Failed to create state flag '${stopped_flag_file}'"; return 1; }
      log_detail "DRY-RUN: Created state files in ${state_dir}"
      return 0 # Success for dry run
  fi

  # Actual run: Stop the service
  log_info "  [Docker] Stopping Docker Compose service: ${compose_path}"
  if (cd "$compose_dir" && ${DOCKER_COMMAND:-docker compose} -f "$compose_path" stop); then
      log_info "  [Docker] -> 'stop' command executed successfully."
      # Create flag file indicating successful stop
      touch "$stopped_flag_file"; chmod 600 "$stopped_flag_file" || { log_error "Failed to create state flag '${stopped_flag_file}'"; return 1; }
      log_detail "Created state files in ${state_dir}"
      return 0 # Success
  else
      log_error "Failed to execute Docker 'stop' command for: ${compose_path}"
      rm -f "$context_file" # Clean up context if stop failed
      return 1 # Failure
  fi
}

# Run backup: Backup the compose file and .env file
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    log_detail "Run backup task (backup compose/env files)..."
    local temp_config_file="$1"; local service_backup_dir="$3"; local docker_config_backup_dir="${service_backup_dir}/docker_config" # local vars
    local compose_path compose_dir env_file

    # Read parameters from temp config file
    compose_path=$("$YQ_CMD" e '.docker_compose_path' "$temp_config_file"); [[ "$compose_path" == "null" ]] && compose_path=""
    if [[ -z "$compose_path" ]] || [[ ! -f "$compose_path" ]]; then log_error "Run backup error: Valid compose path not found in config."; return 1; fi
    compose_dir=$(dirname "$compose_path")

    # Create target dir
    # Use function if available
    if command -v create_dir_secure &>/dev/null; then create_dir_secure "$docker_config_backup_dir"; else mkdir -p "$docker_config_backup_dir"; chmod 700 "$docker_config_backup_dir"; fi

    log_info "  [Docker] Backing up Compose and .env files..."

    # Handle dry run
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [Docker] DRY-RUN: Would copy '${compose_path}'"
        env_file="${compose_dir}/.env"
        if [[ -f "$env_file" ]]; then log_info "  [Docker] DRY-RUN: Would copy '${env_file}'"; fi
        return 0 # Success for dry run
    fi

    # Actual run
    log_detail "Backing up Docker Compose file: ${compose_path}"
    if ! cp -a "$compose_path" "$docker_config_backup_dir/"; then log_error "Failed to copy compose file '${compose_path}'."; return 1; fi
    env_file="${compose_dir}/.env"
    if [[ -f "$env_file" ]]; then
        log_detail "Backing up .env file: ${env_file}"
        if ! cp -a "$env_file" "$docker_config_backup_dir/"; then log_error "Failed to copy .env file '${env_file}'."; return 1; fi
    else
        log_detail "No .env file found in ${compose_dir}."
    fi
    log_detail "Compose/env file backup successful."
    return 0 # Success
}

# Post backup success: Start the Docker Compose service, wait, remove state files
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_post_backup_success() {
  log_detail "Post backup success..."
  local temp_config_file="$1"; local service_backup_dir="$3"; local state_dir="${service_backup_dir}/.state"; local stopped_flag_file="${state_dir}/docker_stopped"; local context_file="${state_dir}/docker_context"
  local compose_dir compose_path wait_seconds # local vars

  # Check if the stopped flag exists (meaning prepare ran successfully)
  if [[ -f "$stopped_flag_file" ]]; then
      # Read context from state file
      compose_dir=""; compose_path=""; wait_seconds=0 # Init local vars
      if [[ -f "$context_file" ]]; then
          # Source the context file safely within this function's scope
          # Use process substitution to feed file content, read vars
          while IFS='=' read -r key value || [[ -n "$key" ]]; do
              value="${value%\"}"; value="${value#\"}" # Remove potential quotes
              case "$key" in COMPOSE_DIR) compose_dir="$value" ;; COMPOSE_FILE_PATH) compose_path="$value" ;; WAIT_SECONDS) wait_seconds="$value" ;; esac
          done < <(cat "$context_file")
      fi
      # Check if context is valid
      if [[ -z "$compose_dir" ]] || [[ -z "$compose_path" ]] || [[ ! -d "$compose_dir" ]] || [[ ! -f "$compose_path" ]]; then log_error "Post backup error: Invalid context read from '${context_file}'. Cannot restart."; return 1; fi
      # Validate wait seconds again
      if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then wait_seconds=0; fi

      # Handle dry run
      if [[ "${dry_run:-0}" -eq 1 ]]; then
          log_info "  [Docker] DRY-RUN: Would start service: ${compose_path}"
          if [[ "$wait_seconds" -gt 0 ]]; then log_info "  [Docker] DRY-RUN: Would wait ${wait_seconds}s after starting."; fi
          rm -f "$stopped_flag_file" "$context_file"; rmdir "$state_dir" 2>/dev/null || true; log_detail "DRY-RUN: Removed state files."
          return 0 # Success for dry run
      fi

      # Actual run: Start the service
      log_info "  [Docker] Starting Docker Compose service: ${compose_path}"
      if (cd "$compose_dir" && ${DOCKER_COMMAND:-docker compose} -f "$compose_path" start); then
          log_info "  [Docker] -> Service started successfully."
          # Wait if configured
          if [[ "$wait_seconds" -gt 0 ]]; then
              log_info "  [Docker] Waiting ${wait_seconds}s after restart..."
              sleep "$wait_seconds"
              log_detail "  [Docker] Wait finished."
          fi
          # Clean up state files on successful start
          rm -f "$stopped_flag_file" "$context_file"; rmdir "$state_dir" 2>/dev/null || true
          log_detail "Removed state files after successful start."
          return 0 # Success
      else
          log_error "Failed to start Docker Compose service: ${compose_path}"
          # Do NOT remove state files on failure
          return 1 # Failure
      fi
  else
      log_detail "Service was not marked as stopped by this plugin, no start/wait needed."
      return 0 # Success, nothing to do
  fi
}

# Emergency cleanup: Ensure Docker Compose service is started if state file exists
# Args: $1=service_backup_dir
plugin_emergency_cleanup() {
    local service_backup_dir="$1"; # Use local var
    # Check if the service backup directory itself exists
    if [[ ! -d "$service_backup_dir" ]]; then log_detail "[docker_compose] Emergency cleanup: Service backup dir '$service_backup_dir' not found."; return 0; fi

    local state_dir="${service_backup_dir}/.state"
    local stopped_flag_file="${state_dir}/docker_stopped"
    local context_file="${state_dir}/docker_context"
    local service_context; service_context=$(basename "$(dirname "$service_backup_dir")")/$(basename "$service_backup_dir") # For logging
    local compose_dir compose_path wait_seconds restart_ecode # local vars

    log_detail "[docker_compose] Emergency cleanup check for service ${service_context}..."

    # Check if the stopped flag exists
    if [[ -f "$stopped_flag_file" ]]; then
        log_detail "[docker_compose] Service '${service_context}' was left stopped. Attempting emergency restart."
        # Read context needed for restart from state file
        compose_dir=""; compose_path=""; wait_seconds=0 # Init
        if [[ -f "$context_file" ]]; then
             while IFS='=' read -r key value || [[ -n "$key" ]]; do value="${value%\"}"; value="${value#\"}"; case "$key" in COMPOSE_DIR) compose_dir="$value" ;; COMPOSE_FILE_PATH) compose_path="$value" ;; WAIT_SECONDS) wait_seconds="$value" ;; esac; done < <(cat "$context_file")
        fi
        # Validate wait seconds
        if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then wait_seconds=0; fi

        # Check if context is valid for restart
        if [[ -z "$compose_dir" ]] || [[ -z "$compose_path" ]] || [[ ! -d "$compose_dir" ]] || [[ ! -f "$compose_path" ]]; then
            # Log error to main log file (TMP_LOG_FILE is global from core) and stderr
            _log_base "!!! ERROR [docker_compose] Emergency restart failed for '${service_context}': Invalid context in '${context_file}'. Manual check required! !!!" >> "$TMP_LOG_FILE"; echo "!!! ERROR [docker_compose] Emergency restart failed for '${service_context}': Invalid context! Manual check required! !!!" >&2
            return 1 # Indicate failure (but don't exit trap)
        fi

        # Handle dry run for emergency cleanup too
        if [[ "${dry_run:-0}" -eq 1 ]]; then
            log_info "  [Docker] DRY-RUN: Would attempt emergency start for: ${compose_path}"
            # Clean up state files in dry run
            rm -f "$stopped_flag_file" "$context_file"; rmdir "$state_dir" 2>/dev/null || true
            log_detail "DRY-RUN: Removed state files."
            return 0
        fi

        # Actual emergency restart attempt
        _log_base "!!! [docker_compose] EMERGENCY RESTARTING: ${compose_path} for service ${service_context}" >> "$TMP_LOG_FILE"; echo "!!! [docker_compose] EMERGENCY RESTARTING: ${compose_path} for service ${service_context}" >&2
        if (cd "$compose_dir" && ${DOCKER_COMMAND:-docker compose} -f "$compose_path" start); then
             _log_base "!!! OK [docker_compose] EMERGENCY RESTART successful for ${service_context}." >> "$TMP_LOG_FILE"; echo "!!! OK [docker_compose] EMERGENCY RESTART successful for ${service_context}." >&2
             # Optional: Wait after emergency restart? Use configured value.
             if [[ "$wait_seconds" -gt 0 ]]; then _log_base "!!! [docker_compose] Waiting ${wait_seconds}s after emergency restart..." >> "$TMP_LOG_FILE"; sleep "$wait_seconds"; fi
             # Clean up state files ONLY if restart was successful
             rm -f "$stopped_flag_file" "$context_file"; rmdir "$state_dir" 2>/dev/null || true
             log_detail "[docker_compose] Cleaned up state files after successful emergency restart."
             return 0 # Success
        else
            restart_ecode=$?; _log_base "!!! ERROR [docker_compose] EMERGENCY RESTART FAILED (Code: ${restart_ecode})! Manual intervention required for ${service_context}. !!!" >> "$TMP_LOG_FILE"; echo "!!! ERROR [docker_compose] EMERGENCY RESTART FAILED (Code: ${restart_ecode})! Manual intervention required for ${service_context}. !!!" >&2; return 1 # Indicate failure (but trap continues)
        fi
    else
        log_detail "[docker_compose] No emergency restart needed for service ${service_context}."
        return 0 # Success, nothing to do
    fi
}

