#!/bin/bash
# Plugin for local_backup.sh: Handles Docker Compose services.
# - Stops/starts services around backup operations.
# - Backs up the docker-compose.yml and .env file.
# - Modifies the backed-up docker-compose.yml to pin images to their
#   SHA256 digest at the time of backup.

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
  log_info() { if [[ "${LOG_LEVEL:-2}" -ge 2 ]]; then _log_base "INFO:  $1"; fi; }
  log_error() { _log_base "ERROR: $1" >&2; }
  log_warn() { if [[ "${LOG_LEVEL:-2}" -ge 1 ]]; then _log_base "WARN:  $1" >&2; fi; }
  log_detail() { if [[ "${LOG_LEVEL:-2}" -ge 3 ]]; then _log_base "DEBUG: $1"; fi; }
  check_command_exists() { command -v "$1" &>/dev/null; }
  is_valid_path() { [[ -e "$1" ]]; }
  get_yaml_value() { echo "${3:-}"; return 1; }
  create_dir_secure() { mkdir -p "$1" && chmod 700 "$1" || return 1; }
fi


# Function: plugin_handles_task_type
# Description:
#   Checks if this plugin handles the given task type key from service.yaml.
# Arguments:
#   $1: task_type - The task type string to check (e.g., "docker").
# Returns:
#   0 if this plugin handles the task type ("docker").
#   1 otherwise.
plugin_handles_task_type() {
  local task_type="$1"

  if [[ "$task_type" == "docker" ]]; then
    return 0
  else
    return 1
  fi
}

# Function: plugin_validate_config
# Description:
#   Validates the 'docker' section of the YAML configuration passed via a
#   temporary file. Checks for mandatory parameters like 'docker_compose_path'
#   and existence of Docker CLI and yq.
# Arguments:
#   $1: temp_config_file - Path to a temporary file containing the YAML
#                          section for this plugin's task type.
# Returns:
#   0 if configuration is valid.
#   1 otherwise, logging specific errors.
plugin_validate_config() {
  local temp_config_file="$1"
  log_detail "Validating Docker Compose config from ${temp_config_file}..."
  local compose_path=""
  local wait_seconds=""
  local pin_images=""
  local validation_ok=1

  # Check dependencies (use global UPPERCASE tool path vars from core)
  if ! check_command_exists "$YQ_CMD" "yq command ('${YQ_CMD}') is required by docker_compose plugin."; then
    return 1
  fi
  local docker_base_cmd
  docker_base_cmd=$(echo "${DOCKER_COMMAND:-docker compose}" | cut -d' ' -f1)
  if ! check_command_exists "$docker_base_cmd" "Docker command ('${DOCKER_COMMAND:-docker compose}') is required by docker_compose plugin."; then
    return 1
  fi
  # Docker inspect is needed if pinning images
  if ! check_command_exists "docker" "Docker CLI ('docker') is required for image pinning."; then
      # This might be a warning if pinning is optional and disabled by default
      log_warn "Docker CLI ('docker') not found. Image pinning will not be possible."
  fi


  # Read properties using get_yaml_value
  compose_path=$(get_yaml_value "$temp_config_file" ".docker_compose_path" "")
  wait_seconds=$(get_yaml_value "$temp_config_file" ".wait_after_restart" "0")
  pin_images=$(get_yaml_value "$temp_config_file" ".pin_images_to_digest" "false")


  # Validate mandatory fields
  if [[ -z "$compose_path" ]]; then
    log_error "Mandatory key 'docker_compose_path' missing or empty."
    validation_ok=0
  elif ! is_valid_path "$compose_path" "-f"; then
    # is_valid_path logs its own error
    validation_ok=0
  fi

  # Validate optional wait time
  if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
    log_error "Optional key 'wait_after_restart' ('${wait_seconds}') must be a non-negative integer."
    validation_ok=0
  fi

  # Validate pin_images_to_digest
  if [[ "$pin_images" != "true" ]] && [[ "$pin_images" != "false" ]]; then
    log_error "Optional key 'pin_images_to_digest' must be 'true' or 'false'."
    validation_ok=0
  fi


  if [[ "$validation_ok" -eq 0 ]]; then
    return 1
  fi
  log_detail "Docker Compose config validation successful (Path: ${compose_path}, Wait: ${wait_seconds}s, Pin Images: ${pin_images})."
  return 0
}

# Function: plugin_prepare_backup
# Description:
#   Prepares for the backup. If image pinning is enabled, it inspects running
#   containers defined in the docker-compose.yml to get their image digests
#   and stores this information in a state file. Then, it stops the Docker
#   Compose services.
# Arguments:
#   $1: temp_config_file     - Path to temp file with plugin's config.
#   $2: service_config_dir   - Path to service's main config dir (unused here).
#   $3: service_backup_dir   - Path to service's temp backup destination.
# Returns: 0 on success, 1 on failure.
plugin_prepare_backup() {
  local temp_config_file="$1"
  local service_backup_dir="$3"
  local state_dir="${service_backup_dir}/.state"
  local stopped_flag_file="${state_dir}/docker_stopped"
  local context_file="${state_dir}/docker_context"
  local image_digests_file="${state_dir}/docker_image_digests.txt" # For storing image digests
  local compose_path
  local wait_seconds
  local compose_dir
  local pin_images

  log_detail "Prepare Docker backup..."
  # Read parameters from temp config file
  compose_path=$(get_yaml_value "$temp_config_file" ".docker_compose_path" "")
  wait_seconds=$(get_yaml_value "$temp_config_file" ".wait_after_restart" "0")
  pin_images=$(get_yaml_value "$temp_config_file" ".pin_images_to_digest" "false")

  if [[ -z "$compose_path" ]] || ! is_valid_path "$compose_path" "-f"; then
    log_error "Prepare error: Valid compose path not found or invalid in config."
    return 1
  fi
  if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
    wait_seconds=0 # Default to 0 if invalid
  fi
  compose_dir=$(dirname "$compose_path")

  # Create state directory first
  create_dir_secure "$state_dir" # Uses common function
  # Write context needed for restart (including wait time) to context file
  # This context is used by post_backup_success and emergency_cleanup
  {
    echo "COMPOSE_DIR=\"${compose_dir}\""
    echo "COMPOSE_FILE_PATH=\"${compose_path}\""
    echo "WAIT_SECONDS=${wait_seconds}"
  } > "$context_file"
  chmod 600 "$context_file" || {
    log_error "Failed to set permissions on context file '${context_file}'"
    return 1
  }

  # Get image digests BEFORE stopping containers if pinning is enabled
  if [[ "$pin_images" == "true" ]]; then
    log_info "  [Docker] Attempting to get image digests for services in ${compose_path}..."
    # Ensure docker CLI is available
    if ! check_command_exists "docker" "Docker CLI ('docker') is required for image pinning."; then
      log_warn "  [Docker] Docker CLI not found. Cannot pin images. Skipping digest collection."
      # Do not fail the backup, just skip pinning.
      # Create an empty digests file to signify that pinning was attempted but failed for this reason.
      >"$image_digests_file"
    else
      # Get service names from docker-compose.yml
      local service_names
      # yq 'keys | .[]' extracts top-level keys. For services, it's usually '.services | keys | .[]'
      # This assumes a standard compose file structure.
      mapfile -t service_names < <("$YQ_CMD" e '.services | keys | .[]' "$compose_path")

      if [[ ${#service_names[@]} -eq 0 ]]; then
        log_warn "  [Docker] No services found in ${compose_path} to get image digests for."
        >"$image_digests_file" # Create empty file
      else
        log_detail "  [Docker] Services found: ${service_names[*]}"
        # Clear or create the image digests file
        >"$image_digests_file"
        local service_name
        for service_name in "${service_names[@]}"; do
          # Get the container ID for the service. Assumes default project name or one service per container.
          # This might need refinement if compose project names are custom or multiple containers per service.
          # `docker compose ps -q <service_name>` is a more direct way if DOCKER_COMMAND is `docker compose`
          local container_id
          # Try to get container ID using docker compose ps
          container_id=$(${DOCKER_COMMAND:-docker compose} -f "$compose_path" -p "$(basename "$compose_dir")" ps -q "$service_name" 2>/dev/null | head -n 1)

          if [[ -n "$container_id" ]]; then
            local image_digest
            # Get image digest (Image field from inspect)
            image_digest=$(docker inspect "$container_id" --format='{{.Image}}' 2>/dev/null)
            if [[ -n "$image_digest" ]]; then
              log_detail "    [Docker] Service '${service_name}' (Container ID: ${container_id}) uses image digest: ${image_digest}"
              echo "${service_name}:${image_digest}" >> "$image_digests_file"
            else
              log_warn "    [Docker] Could not get image digest for service '${service_name}' (Container ID: ${container_id}). It might not be running or inspect failed."
            fi
          else
            log_warn "    [Docker] Could not find running container for service '${service_name}'. Cannot get image digest."
          fi
        done
        chmod 600 "$image_digests_file"
      fi
    fi
  fi


  # Check dry-run mode
  if [[ "${dry_run:-0}" -eq 1 ]]; then
      log_info "  [Docker] DRY-RUN: Would stop service defined in: ${compose_path}"
      # Still create the stopped flag in dry-run to test state logic
      touch "$stopped_flag_file"
      chmod 600 "$stopped_flag_file" || {
        log_error "Failed to create state flag '${stopped_flag_file}'"
        return 1
      }
      log_detail "DRY-RUN: Created state files in ${state_dir}"
      return 0 # Success for dry run
  fi

  # Actual run: Stop the service
  log_info "  [Docker] Stopping Docker Compose services defined in: ${compose_path}"
  if (cd "$compose_dir" && ${DOCKER_COMMAND:-docker compose} -f "$compose_path" stop); then
      log_info "  [Docker] -> 'stop' command executed successfully."
      # Create flag file indicating successful stop
      touch "$stopped_flag_file"
      chmod 600 "$stopped_flag_file" || {
        log_error "Failed to create state flag '${stopped_flag_file}'"
        return 1
      }
      log_detail "Created state files in ${state_dir}"
      return 0 # Success
  else
      log_error "Failed to execute Docker 'stop' command for: ${compose_path}"
      rm -f "$context_file" "$image_digests_file" # Clean up context if stop failed
      return 1 # Failure
  fi
}

# Function: plugin_run_backup
# Description:
#   Backs up the docker-compose.yml file and any associated .env file.
#   If image pinning was enabled and digests were collected, it modifies the
#   *backed-up* docker-compose.yml to use image digests.
# Arguments:
#   $1: temp_config_file     - Path to temp file with plugin's config.
#   $2: service_config_dir   - Path to service's main config dir (unused here).
#   $3: service_backup_dir   - Path to service's temp backup destination.
# Returns: 0 on success, 1 on failure.
plugin_run_backup() {
    log_detail "Run Docker backup task (backup compose/env files and pin images)..."
    local temp_config_file="$1"
    local service_backup_dir="$3"
    local docker_config_backup_dir="${service_backup_dir}/docker_config"
    local state_dir="${service_backup_dir}/.state"
    local image_digests_file="${state_dir}/docker_image_digests.txt"
    local compose_path
    local compose_dir
    local env_file
    local pin_images

    # Read parameters from temp config file
    compose_path=$(get_yaml_value "$temp_config_file" ".docker_compose_path" "")
    pin_images=$(get_yaml_value "$temp_config_file" ".pin_images_to_digest" "false")

    if [[ -z "$compose_path" ]] || ! is_valid_path "$compose_path" "-f"; then
      log_error "Run backup error: Valid compose path not found in config."
      return 1
    fi
    compose_dir=$(dirname "$compose_path")

    # Create target dir for docker config files
    create_dir_secure "$docker_config_backup_dir"

    log_info "  [Docker] Backing up Docker Compose and .env files..."

    # Handle dry run for file copying
    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [Docker] DRY-RUN: Would copy '${compose_path}' to '${docker_config_backup_dir}/'"
        env_file="${compose_dir}/.env"
        if [[ -f "$env_file" ]]; then
          log_info "  [Docker] DRY-RUN: Would copy '${env_file}' to '${docker_config_backup_dir}/'"
        fi
        if [[ "$pin_images" == "true" ]] && [[ -f "$image_digests_file" ]]; then
            log_info "  [Docker] DRY-RUN: Would modify the backed-up compose file with image digests."
        elif [[ "$pin_images" == "true" ]]; then
            log_warn "  [Docker] DRY-RUN: Image pinning enabled, but no digest file found. Compose file would not be modified."
        fi
        return 0 # Success for dry run
    fi

    # Actual run: Copy original files
    local backed_up_compose_file="${docker_config_backup_dir}/$(basename "$compose_path")"
    log_detail "Backing up Docker Compose file: ${compose_path} to ${backed_up_compose_file}"
    if ! cp -a "$compose_path" "$backed_up_compose_file"; then
      log_error "Failed to copy compose file '${compose_path}'."
      return 1
    fi

    env_file="${compose_dir}/.env"
    if [[ -f "$env_file" ]]; then
        log_detail "Backing up .env file: ${env_file}"
        if ! cp -a "$env_file" "$docker_config_backup_dir/"; then
          log_error "Failed to copy .env file '${env_file}'."
          return 1
        fi
    else
        log_detail "No .env file found in ${compose_dir}."
    fi
    log_detail "Original Docker Compose/env file(s) backup successful."

    # Modify the *backed-up* compose file if pinning is enabled and digests are available
    if [[ "$pin_images" == "true" ]] && [[ -f "$image_digests_file" ]] && [[ -s "$image_digests_file" ]]; then
        log_info "  [Docker] Modifying backed-up compose file to pin image digests: ${backed_up_compose_file}"
        local temp_modified_compose_file; temp_modified_compose_file=$(mktemp)
        cp "$backed_up_compose_file" "$temp_modified_compose_file"

        local service_name image_digest original_image_line
        while IFS=':' read -r service_name image_digest; do
            if [[ -z "$service_name" ]] || [[ -z "$image_digest" ]]; then
                continue
            fi
            log_detail "    Pinning image for service '${service_name}' to digest '${image_digest}'"
            # This sed command is complex. It tries to find the service block, then its image line.
            # It comments out the old line and inserts the new one.
            # It assumes standard YAML indentation (2 spaces).
            # Using yq for modification would be safer but is more complex for in-place line changes.
            # Example:
            # services:
            #   app:
            #     image: myimage:latest  <-- find this
            # becomes:
            # services:
            #   app:
            #     # image: myimage:latest # Digest at backup: sha256:...
            #     image: myimage@sha256:...
            if sed -i.bak \
                -e "/^services:/,/^[^[:space:]]/ { /^[[:space:]]*${service_name}:/,/^[[:space:]]*[^[:space:]]/ { /^[[:space:]]*image:[[:space:]]*/ { h; s/^/\# /; s/$/ # Digest at backup: ${image_digest}/; p; g; s/\(image:[[:space:]]*\)[^@[:space:]]*/\1${image_digest}/;} } }" \
                "$temp_modified_compose_file"; then
                log_detail "      Successfully modified image line for service '${service_name}'."
            else
                log_warn "      Failed to modify image line for service '${service_name}' in compose file copy. Original will be kept."
                # Revert if sed failed for this service, or handle more gracefully
                cp "$backed_up_compose_file" "$temp_modified_compose_file" # Revert to original copy
                break # Stop trying to modify if one sed fails
            fi
        done < "$image_digests_file"
        # Replace the backed up compose file with the modified one
        mv "$temp_modified_compose_file" "$backed_up_compose_file"
        rm -f "$backed_up_compose_file.bak" # Clean up sed backup
        log_info "  [Docker] Finished processing image digests for backed-up compose file."
    elif [[ "$pin_images" == "true" ]]; then
        log_warn "  [Docker] Image pinning enabled, but no valid image digests found in '${image_digests_file}'. Backed-up compose file will not be modified."
    fi

    return 0 # Success
}

# Function: plugin_post_backup_success
# Description:
#   Starts the Docker Compose services that were previously stopped by
#   `plugin_prepare_backup`. Performs an optional wait after starting.
#   Cleans up state files.
# Arguments:
#   $1: temp_config_file     - Path to temp file with plugin's config (not used here).
#   $2: service_config_dir   - Path to service's main config dir (unused here).
#   $3: service_backup_dir   - Path to service's temp backup destination.
# Returns: 0 on success, 1 on failure.
plugin_post_backup_success() {
  log_detail "Post Docker backup success..."
  # local temp_config_file="$1" # Unused
  local service_backup_dir="$3"
  local state_dir="${service_backup_dir}/.state"
  local stopped_flag_file="${state_dir}/docker_stopped"
  local context_file="${state_dir}/docker_context"
  local image_digests_file="${state_dir}/docker_image_digests.txt"
  local compose_dir
  local compose_path
  local wait_seconds

  # Check if the stopped flag exists (meaning prepare ran successfully)
  if [[ -f "$stopped_flag_file" ]]; then
      compose_dir=""; compose_path=""; wait_seconds=0 # Init local vars
      # Read context from state file
      if [[ -f "$context_file" ]]; then
          # Source the context file safely
          while IFS='=' read -r key value || [[ -n "$key" ]]; do
              value="${value%\"}"; value="${value#\"}" # Remove potential quotes
              case "$key" in
                  COMPOSE_DIR) compose_dir="$value" ;;
                  COMPOSE_FILE_PATH) compose_path="$value" ;;
                  WAIT_SECONDS) wait_seconds="$value" ;;
              esac
          done < <(cat "$context_file")
      fi
      # Check if context is valid
      if [[ -z "$compose_dir" ]] || \
         [[ -z "$compose_path" ]] || \
         ! is_valid_path "$compose_dir" "-d" || \
         ! is_valid_path "$compose_path" "-f"; then
        log_error "Post backup error: Invalid context read from '${context_file}'. Cannot restart."
        return 1
      fi
      # Validate wait seconds again
      if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
        wait_seconds=0
      fi

      # Handle dry run
      if [[ "${dry_run:-0}" -eq 1 ]]; then
          log_info "  [Docker] DRY-RUN: Would start service defined in: ${compose_path}"
          if [[ "$wait_seconds" -gt 0 ]]; then
            log_info "  [Docker] DRY-RUN: Would wait ${wait_seconds}s after starting."
          fi
      else
        # Actual run: Start the service
        log_info "  [Docker] Starting Docker Compose services defined in: ${compose_path}"
        if ! (cd "$compose_dir" && ${DOCKER_COMMAND:-docker compose} -f "$compose_path" start); then
          log_error "Failed to start Docker Compose service: ${compose_path}"
          # Do NOT remove state files on failure, emergency cleanup will try
          return 1 # Failure
        fi
        log_info "  [Docker] -> Services started successfully."
        # Wait if configured
        if [[ "$wait_seconds" -gt 0 ]]; then
            log_info "  [Docker] Waiting ${wait_seconds}s after restart..."
            sleep "$wait_seconds"
            log_detail "  [Docker] Wait finished."
        fi
      fi # End dry_run check

      # Clean up state files on successful start (or if dry-run)
      rm -f "$stopped_flag_file" "$context_file" "$image_digests_file"
      # Attempt to remove the .state directory if it's empty
      rmdir "$state_dir" 2>/dev/null || true
      log_detail "Removed state files after successful start/dry-run."
      return 0 # Success
  else
      log_detail "Service was not marked as stopped by this plugin, no start/wait needed."
      return 0 # Success, nothing to do
  fi
}

# Function: plugin_emergency_cleanup
# Description:
#   Attempts to restart Docker Compose services if the main backup script
#   exited unexpectedly after services were stopped by this plugin.
#   Reads context from state files.
# Arguments:
#   $1: service_backup_dir - Absolute path to the service's temp backup directory.
# Returns:
#   0 if restart was successful or not needed.
#   1 if restart was attempted and failed (logged to main log and stderr).
plugin_emergency_cleanup() {
    local service_backup_dir="$1"
    # Check if the service backup directory itself exists
    if [[ ! -d "$service_backup_dir" ]]; then
      log_detail "[docker_compose] Emergency cleanup: Service backup dir '$service_backup_dir' not found."
      return 0
    fi

    local state_dir="${service_backup_dir}/.state"
    local stopped_flag_file="${state_dir}/docker_stopped"
    local context_file="${state_dir}/docker_context"
    local image_digests_file="${state_dir}/docker_image_digests.txt"
    local service_context
    service_context=$(basename "$(dirname "$service_backup_dir")")/$(basename "$service_backup_dir")
    local compose_dir compose_path wait_seconds restart_ecode

    log_detail "[docker_compose] Emergency cleanup check for service ${service_context}..."

    # Check if the stopped flag exists
    if [[ -f "$stopped_flag_file" ]]; then
        log_detail "[docker_compose] Service '${service_context}' was left stopped. Attempting emergency restart."
        # Read context needed for restart from state file
        compose_dir=""; compose_path=""; wait_seconds=0
        if [[ -f "$context_file" ]]; then
             while IFS='=' read -r key value || [[ -n "$key" ]]; do
                value="${value%\"}"; value="${value#\"}"
                case "$key" in
                  COMPOSE_DIR) compose_dir="$value" ;;
                  COMPOSE_FILE_PATH) compose_path="$value" ;;
                  WAIT_SECONDS) wait_seconds="$value" ;;
                esac
             done < <(cat "$context_file")
        fi
        # Validate wait seconds
        if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
          wait_seconds=0
        fi

        # Check if context is valid for restart
        if [[ -z "$compose_dir" ]] || [[ -z "$compose_path" ]] || \
           ! is_valid_path "$compose_dir" "-d" || \
           ! is_valid_path "$compose_path" "-f"; then
            _log_base "!!! ERROR [docker_compose] Emergency restart failed for '${service_context}': Invalid context! Manual check required! !!!" >> "$TMP_LOG_FILE"
            echo "!!! ERROR [docker_compose] Emergency restart failed for '${service_context}': Invalid context! Manual check required! !!!" >&2
            return 1 # Indicate failure (but don't exit trap)
        fi

        # Handle dry run for emergency cleanup too
        if [[ "${dry_run:-0}" -eq 1 ]]; then
            log_info "  [Docker] DRY-RUN: Would attempt emergency start for: ${compose_path}"
            # Clean up state files in dry run
            rm -f "$stopped_flag_file" "$context_file" "$image_digests_file"
            rmdir "$state_dir" 2>/dev/null || true
            log_detail "DRY-RUN: Removed state files."
            return 0
        fi

        # Actual emergency restart attempt
        _log_base "!!! [docker_compose] EMERGENCY RESTARTING: ${compose_path} for service ${service_context}" >> "$TMP_LOG_FILE"
        echo "!!! [docker_compose] EMERGENCY RESTARTING: ${compose_path} for service ${service_context}" >&2
        if (cd "$compose_dir" && ${DOCKER_COMMAND:-docker compose} -f "$compose_path" start); then
             _log_base "!!! OK [docker_compose] EMERGENCY RESTART successful for ${service_context}." >> "$TMP_LOG_FILE"
             echo "!!! OK [docker_compose] EMERGENCY RESTART successful for ${service_context}." >&2
             # Wait after emergency restart if configured
             if [[ "$wait_seconds" -gt 0 ]]; then
                 _log_base "!!! [docker_compose] Waiting ${wait_seconds}s after emergency restart..." >> "$TMP_LOG_FILE"
                 sleep "$wait_seconds"
             fi
             # Clean up state files ONLY if restart was successful
             rm -f "$stopped_flag_file" "$context_file" "$image_digests_file"
             rmdir "$state_dir" 2>/dev/null || true
             log_detail "[docker_compose] Cleaned up state files after successful emergency restart."
             return 0 # Success
        else
            restart_ecode=$?
             _log_base "!!! ERROR [docker_compose] EMERGENCY RESTART FAILED (Code: ${restart_ecode})! Manual intervention required for ${service_context}. !!!" >> "$TMP_LOG_FILE"
             echo "!!! ERROR [docker_compose] EMERGENCY RESTART FAILED (Code: ${restart_ecode})! Manual intervention required for ${service_context}. !!!" >&2
            return 1 # Indicate failure (but trap continues)
        fi
    else
        log_detail "[docker_compose] No emergency restart needed for service ${service_context}."
        return 0 # Success, nothing to do
    fi
}

