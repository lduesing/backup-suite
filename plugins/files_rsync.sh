#!/bin/bash
# Plugin for local_backup.sh: Handles file and directory backup using rsync

# --- Plugin Interface Functions ---

# Source common functions
common_functions_script="${PLUGIN_DIR:-/opt/backup/lib/plugins}/common_functions.sh"
if [[ -f "$common_functions_script" ]]; then source "$common_functions_script"; else _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [files_rsync] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }; fi

# Check if this plugin handles the 'files' task type
plugin_handles_task_type() { local task_type="$1"; [[ "$task_type" == "files" ]]; }

# Validate the 'files' section of the YAML config
# Args: $1=path_to_temp_config_file
plugin_validate_config() {
  local temp_config_file="$1"; log_detail "Validating config from ${temp_config_file}..."; local validation_ok=1
  # Check dependencies
  if ! command -v "$YQ_CMD" &>/dev/null; then log_error "yq command ('${YQ_CMD}') not found."; return 1; fi
  if ! command -v "${RSYNC_CMD:-rsync}" &>/dev/null; then log_error "Required command '${RSYNC_CMD:-rsync}' not found."; return 1; fi
  if ! command -v realpath &>/dev/null; then log_error "Required command 'realpath' not found."; return 1; fi

  # Check if 'paths' key exists and is a sequence/list
  if ! "$YQ_CMD" e '.paths | type == "!!seq"' "$temp_config_file" >/dev/null ; then log_error "Config Error: Mandatory 'paths' key missing or not a list/sequence."; validation_ok=0; fi
  # Check if optional 'exclude' key exists and is a sequence/list
  if "$YQ_CMD" e '.exclude ' "$temp_config_file" >/dev/null; then
    if ! "$YQ_CMD" e '.exclude | type == "!!seq"' "$temp_config_file" >/dev/null ; then log_error "Config Error: Optional 'exclude' key exists but is not a list/sequence."; validation_ok=0; fi
  fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi; log_detail "Config validation successful."; return 0
}

# Run backup: Perform the rsync operation
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"; local service_backup_dir="$3"; local files_backup_dir="${service_backup_dir}/data"
    log_detail "Run backup task..."
    # Use function if available
    if command -v create_dir_secure &>/dev/null; then create_dir_secure "$files_backup_dir"; else mkdir -p "$files_backup_dir"; chmod 700 "$files_backup_dir"; fi
    log_info "  [Files] Backing up files/directories via rsync..."

    # Read paths and excludes using yq from the temp config file
    local -a include_paths=() exclude_patterns=() path_items=() exclude_items=() # local arrays
    local item pattern # local loop vars

    # Read include paths
    mapfile -t path_items < <("$YQ_CMD" e '.paths[]' "$temp_config_file")
    if [[ $? -ne 0 ]]; then log_error "Failed to parse required 'paths' using yq from temp config '${temp_config_file}'."; return 1; fi
    for item in "${path_items[@]}"; do include_paths+=("$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"); done # Trim and add

    # Read optional exclude paths
    mapfile -t exclude_items < <("$YQ_CMD" e '.exclude[] // ""' "$temp_config_file") # // "" handles missing key
    if [[ $? -ne 0 ]]; then log_error "Failed to parse optional 'exclude' paths using yq from temp config '${temp_config_file}'."; return 1; fi
    for item in "${exclude_items[@]}"; do
        pattern=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'); # Trim
        if [[ -n "$pattern" ]]; then exclude_patterns+=("$pattern"); fi # Add non-empty
    done

    log_detail "Paths to include: ${#include_paths[@]}. Exclude patterns: ${#exclude_patterns[@]}"; for pattern in "${exclude_patterns[@]}"; do log_detail "  Exclude: '$pattern'"; done

    local success_count=0 # local counter
    local src_path src_parent src_base # local vars
    local -a exclude_opts # local array
    local abs_files_backup_dir # local var
    for src_path in "${include_paths[@]}"; do
        if [[ -z "$src_path" ]]; then continue; fi # Skip empty paths
        if [[ ! -e "$src_path" ]]; then log_info "  [Files] WARN: Source path not found, skipping: '${src_path}'"; continue; fi
        src_parent=$(dirname "$src_path"); src_base=$(basename "$src_path"); log_detail "Processing source: '${src_path}' (Base: '${src_base}')"
        # Build exclude options array
        exclude_opts=()
        for pattern in "${exclude_patterns[@]}"; do exclude_opts+=(--exclude "$pattern"); done
        abs_files_backup_dir=$(realpath "$files_backup_dir") # Get absolute path

        # Handle dry run
        if [[ "${dry_run:-0}" -eq 1 ]]; then
            log_info "  [Files] DRY-RUN: Would sync '${src_path}' (as '${src_base}') to '${abs_files_backup_dir}/' with excludes."
            success_count=$((success_count + 1)); continue # Count as success
        fi

        # Actual run: Execute rsync in subshell
        log_detail "Executing rsync: (cd '${src_parent}' && ${RSYNC_CMD:-rsync} -a --delete-excluded ${exclude_opts[*]} '${src_base}' '${abs_files_backup_dir}/')"
        if (cd "$src_parent" && ${RSYNC_CMD:-rsync} -a --delete-excluded "${exclude_opts[@]}" "$src_base" "$abs_files_backup_dir/"); then
            log_detail "-> Source '${src_base}' successfully backed up."
            success_count=$((success_count + 1))
        else
            log_error "rsync failed for source '${src_path}'!"; return 1 # Signal failure
        fi
    done # End loop through include paths
    log_detail "-> File backup finished (${success_count}/${#include_paths[@]} paths processed)."
    return 0 # Signal success
}
# No prepare, post_success, or emergency_cleanup needed
