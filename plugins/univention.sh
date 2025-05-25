#!/bin/bash
# Plugin for local_backup.sh: Handles Univention Corporate Server (UCS) backup.
# Primarily uses 'univention-backup' for system state (LDAP, config, etc.).
# Can optionally back up additional custom paths using rsync.
# Version: 1.0 (Utilizes common_functions.sh v1.0, Google Style Guide)

# --- Plugin Interface Functions ---

# Source common functions
common_functions_script="${PLUGIN_DIR:-/opt/backup/lib/plugins}/common_functions.sh"
if [[ -f "$common_functions_script" ]]; then source "$common_functions_script"; else _log_base() { echo "$(date +'%Y-%m-%d %H:%M:%S') - [univention] $1"; }; log_info() { _log_base "INFO:  $1"; }; log_error() { _log_base "ERROR: $1" >&2; }; log_detail() { if [[ "${verbose:-0}" -eq 1 ]]; then _log_base "DEBUG: $1"; fi; }; fi

# Check if this plugin handles the 'univention' task type
plugin_handles_task_type() { local task_type="$1"; [[ "$task_type" == "univention" ]]; }

# Validate the 'univention' section of the YAML config
# Args: $1=path_to_temp_config_file
plugin_validate_config() {
  local temp_config_file="$1"; log_detail "Validating config from ${temp_config_file}..."; local validation_ok=1
  local ucs_backup_cmd="${UNIVENTION_BACKUP_CMD:-univention-backup}" # Global from common_config

  # Check dependencies
  if ! check_command_exists "$YQ_CMD" "yq command ('${YQ_CMD}') is required by univention plugin."; then return 1; fi
  if ! check_command_exists "$ucs_backup_cmd" "Univention backup command ('${ucs_backup_cmd}') is required."; then validation_ok=0; fi

  # Check for optional 'custom_paths' and 'custom_exclude' which use rsync
  if "$YQ_CMD" e '.custom_paths ' "$temp_config_file" >/dev/null; then
    if ! "$YQ_CMD" e '.custom_paths | type == "!!seq"' "$temp_config_file" >/dev/null ; then log_error "Config Error: Optional 'custom_paths' key exists but is not a list/sequence."; validation_ok=0; fi
    if ! check_command_exists "${RSYNC_CMD:-rsync}" "rsync command ('${RSYNC_CMD:-rsync}') is required for custom_paths."; then validation_ok=0; fi
    if ! check_command_exists "realpath" "realpath command is required for custom_paths."; then validation_ok=0; fi
    if "$YQ_CMD" e '.custom_exclude ' "$temp_config_file" >/dev/null; then
        if ! "$YQ_CMD" e '.custom_exclude | type == "!!seq"' "$temp_config_file" >/dev/null ; then log_error "Config Error: Optional 'custom_exclude' key exists but is not a list/sequence."; validation_ok=0; fi
    fi
  fi

  if [[ "$validation_ok" -eq 0 ]]; then return 1; fi; log_detail "Config validation successful."; return 0
}

# Run backup: Perform 'univention-backup' and optional rsync of custom paths
# Args: $1=temp_config_file, $2=service_config_dir(unused), $3=service_backup_dir
plugin_run_backup() {
    local temp_config_file="$1"; local service_backup_dir="$3"
    local ucs_dump_target_dir="${service_backup_dir}/univention_system_dump"
    local custom_files_target_dir="${service_backup_dir}/custom_files_data"
    local ucs_backup_cmd="${UNIVENTION_BACKUP_CMD:-univention-backup}"
    local univention_backup_default_output_dir="/var/univention-backup"
    local univention_backup_options

    log_detail "Run backup task for Univention Corporate Server..."

    # --- Part 1: univention-backup ---
    log_info "  [Univention] Preparing to run '${ucs_backup_cmd}'..."
    univention_backup_options=$(get_yaml_value "$temp_config_file" ".univention_backup_options" "")

    create_dir_secure "$ucs_dump_target_dir"

    if [[ "${dry_run:-0}" -eq 1 ]]; then
        log_info "  [Univention] DRY-RUN: Would execute '${ucs_backup_cmd} ${univention_backup_options}'"
        log_info "  [Univention] DRY-RUN: Would then copy latest archive from '${univention_backup_default_output_dir}' to '${ucs_dump_target_dir}/'"
    else
        log_info "  [Univention] Executing system backup using '${ucs_backup_cmd}'..."
        log_detail "Command: ${ucs_backup_cmd} ${univention_backup_options}"
        if ${ucs_backup_cmd} "${univention_backup_options}"; then
            log_info "  [Univention] '${ucs_backup_cmd}' command completed."
            log_detail "Looking for latest backup archive in '${univention_backup_default_output_dir}'..."
            local latest_ucs_archive
            latest_ucs_archive=$(find "$univention_backup_default_output_dir" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tar.bz2' \) -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2-)
            if [[ -n "$latest_ucs_archive" ]] && [[ -f "$latest_ucs_archive" ]]; then
                log_info "  [Univention] Found latest UCS backup archive: $(basename "$latest_ucs_archive")"
                log_detail "Copying '$latest_ucs_archive' to '$ucs_dump_target_dir/'"
                if cp -a "$latest_ucs_archive" "$ucs_dump_target_dir/"; then log_info "  [Univention] System dump archive successfully copied.";
                else log_error "Failed to copy UCS backup archive from '$latest_ucs_archive'."; return 1; fi
            else log_error "Could not find backup archive in '${univention_backup_default_output_dir}'."; return 1; fi
        else log_error "'${ucs_backup_cmd}' command failed."; return 1; fi
    fi

    # --- Part 2: Custom Files (rsync) ---
    if "$YQ_CMD" e '.custom_paths ' "$temp_config_file" >/dev/null; then
        log_info "  [Univention] Processing custom file paths..."
        create_dir_secure "$custom_files_target_dir"
        local -a include_paths=() exclude_patterns=() path_items=() exclude_items=(); local item pattern
        mapfile -t path_items < <("$YQ_CMD" e '.custom_paths[]' "$temp_config_file")
        if [[ $? -ne 0 && ${#path_items[@]} -eq 0 ]]; then log_info "  [Univention] No custom paths to include, or failed to parse.";
        else for item in "${path_items[@]}"; do include_paths+=("$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"); done; fi
        mapfile -t exclude_items < <("$YQ_CMD" e '.custom_exclude[] // ""' "$temp_config_file")
        if [[ $? -ne 0 && ${#exclude_items[@]} -gt 0 ]]; then log_detail "Failed to parse optional 'custom_exclude' paths.";
        else for item in "${exclude_items[@]}"; do pattern=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'); if [[ -n "$pattern" ]]; then exclude_patterns+=("$pattern"); fi; done; fi

        if [[ ${#include_paths[@]} -gt 0 ]]; then
            log_detail "Custom paths to include: ${#include_paths[@]}. Excludes: ${#exclude_patterns[@]}"; for pattern in "${exclude_patterns[@]}"; do log_detail "  Exclude: '$pattern'"; done
            local success_count=0 src_path src_parent src_base; local -a exclude_opts; local abs_custom_files_target_dir
            for src_path in "${include_paths[@]}"; do
                if [[ -z "$src_path" ]]; then continue; fi
                if ! is_valid_path "$src_path" "-e"; then log_info "  [Univention] WARN: Custom source path not found: '${src_path}'"; continue; fi
                src_parent=$(dirname "$src_path"); src_base=$(basename "$src_path"); log_detail "Processing custom source: '${src_path}'"
                exclude_opts=(); for pattern in "${exclude_patterns[@]}"; do exclude_opts+=(--exclude "$pattern"); done
                abs_custom_files_target_dir=$(realpath "$custom_files_target_dir")
                if [[ "${dry_run:-0}" -eq 1 ]]; then log_info "  [Univention] DRY-RUN: Would sync custom path '${src_path}'"; success_count=$((success_count + 1)); continue; fi
                log_detail "Executing rsync: (cd '${src_parent}' && ${RSYNC_CMD:-rsync} -a --delete-excluded ${exclude_opts[*]} '${src_base}' '${abs_custom_files_target_dir}/')"
                if (cd "$src_parent" && ${RSYNC_CMD:-rsync} -a --delete-excluded "${exclude_opts[@]}" "$src_base" "$abs_custom_files_target_dir/"); then log_detail "-> Custom source '${src_base}' backed up."; success_count=$((success_count + 1)); else log_error "rsync failed for custom source '${src_path}'!"; return 1; fi
            done; log_detail "-> Custom file backup finished (${success_count}/${#include_paths[@]} paths processed)."
        else log_detail "No custom paths specified to include with rsync."; fi
    else log_detail "No 'custom_paths' section found in config."; fi

    log_detail "[Univention] Backup task completed."; return 0
}
# No prepare, post_success, or emergency_cleanup

