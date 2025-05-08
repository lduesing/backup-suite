#!/bin/bash
# Common functions shared between local_backup.sh core and plugins
# Should be sourced by the core script and potentially by plugins if needed directly.

# --- Logging Functions ---
# These rely on the VERBOSE variable being set globally (or defaulted to 0)
# and output redirection being handled by the core script's 'exec'.

# Internal function for timestamp and base format.
# $1: Message string
_log_base() {
  echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Logs important operational information (INFO level). Always visible on console.
# $1: Message string
log_info() {
  _log_base "INFO:  $1"
}

# Logs error messages (ERROR level). Always visible on console (stderr).
# $1: Message string
log_error() {
  _log_base "ERROR: $1" >&2 # Redirect to standard error
}

# Logs detailed/debug information (DEBUG level).
# Only appears on console if VERBOSE mode (-v) is enabled.
# Output always goes to the log file via the core script's redirection.
# $1: Message string
log_detail() {
  # Check global VERBOSE flag (should be inherited)
  # Use lowercase var name per style guide
  if [[ "${verbose:-0}" -eq 1 ]]; then
    _log_base "DEBUG: $1"
  fi
}

# --- Permission Check Function ---

# Check File/Directory Permissions and Ownership
# Verifies if a path exists, has exact required permissions, and owner.
# Accepts stricter read-only permissions (400) if 600 is required for a file.
# Arguments:
#   $1: Path to the file or directory.
#   $2: Required permission string (e.g., "600", "700").
#   $3: Required owner username (e.g., "root").
# Returns:
#   0 on success, 1 on failure. Logs details on failure.
check_perms() {
  # Use local variables within the function
  local filepath="$1"
  local required_perm="$2"
  local require_owner="$3"
  local perms owner is_ok=1 # Assume okay

  # 1. Check existence
  if [[ ! -e "$filepath" ]]; then
    # Use logging functions defined above
    log_error "Permissions check failed: Path '$filepath' does not exist."
    return 1
  fi

  # 2. Get actual permissions and owner using stat
  # Check if stat command exists first
  if ! command -v stat &>/dev/null; then
      log_error "Command 'stat' not found, cannot check permissions for '$filepath'."
      return 1 # Cannot perform check
  fi
  perms=$(stat -c '%a' "$filepath")
  owner=$(stat -c '%U' "$filepath")

  # 3. Check owner
  if [[ "$owner" != "$require_owner" ]]; then
    log_error "Permissions check failed: '$filepath' owned by '$owner', requires '$require_owner'."
    is_ok=0
  fi

  # 4. Check permissions
  if [[ "$perms" != "$required_perm" ]]; then
    # Allow 400 (read-only) if 600 (read-write) was required for a file, as it's stricter/safer.
    if [[ -f "$filepath" && "$required_perm" == "600" && "$perms" == "400" ]]; then
      log_detail "Permissions info: '$filepath' has '$perms' (stricter than ${required_perm}), accepting."
    else
      log_error "Permissions check failed: '$filepath' has permissions '${perms}', requires exactly '${required_perm}'."
      is_ok=0
    fi
  fi

  # 5. Return result
  if [[ "$is_ok" -eq 0 ]]; then
    return 1 # Failure
  else
    log_detail "Permissions check passed for '$filepath'."
    return 0 # Success
  fi
}


# --- Other Potential Common Functions (Add as needed) ---
