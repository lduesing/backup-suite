#!/bin/bash
# Common functions shared between local_backup.sh core and plugins (v1.1)
# Should be sourced by the core script and potentially by plugins if needed directly.
# Version: 1.1 (Granular Log Levels, Syntax Checks, send_email, get_yaml_value fix)

# --- Global Variables (Expected to be set by calling script) ---
# LOG_LEVEL: Controls verbosity.
#   0: ERRORs only
#   1: WARNings and ERRORs
#   2: INFO, WARNings, and ERRORs (Typical Default)
#   3: DEBUG, INFO, WARNings, and ERRORs (Set by -v flag)
# verbose: 0 or 1, often used by calling script to set LOG_LEVEL to 3.
# YQ_CMD: Path to yq executable (should be set by calling script after config load)
# MSMTP_CMD: Path to msmtp executable (should be set by calling script after config load)
# DRY_RUN: 0 or 1, indicates if script is in dry-run mode.

# --- Logging Functions ---

# Internal function for timestamp and base format.
# Arguments:
#   $1: log_level_name - e.g., "INFO", "ERROR"
#   $2: message_string - The message to log.
_log_base() {
  local log_level_name="$1"
  local message_string="$2"
  # POSIX-compliant date format
  echo "$(date +'%Y-%m-%d %H:%M:%S') - ${log_level_name}: ${message_string}"
}

# Logs messages at ERROR level (0).
# Always printed if LOG_LEVEL >= 0. Output to stderr.
# Arguments:
#   $1: message_string - The message to log.
log_error() {
  # ERROR messages are always critical and go to stderr.
  _log_base "ERROR" "$1" >&2
}

# Logs messages at WARN level (1).
# Printed if LOG_LEVEL >= 1. Output to stderr.
# Arguments:
#   $1: message_string - The message to log.
log_warn() {
  if [[ "${LOG_LEVEL:-2}" -ge 1 ]]; then
    _log_base "WARN " "$1" >&2 # Warnings also to stderr for visibility
  fi
}

# Logs messages at INFO level (2).
# Printed if LOG_LEVEL >= 2. Output to stdout.
# Arguments:
#   $1: message_string - The message to log.
log_info() {
  if [[ "${LOG_LEVEL:-2}" -ge 2 ]]; then
    _log_base "INFO " "$1"
  fi
}

# Logs messages at DEBUG level (3).
# Printed if LOG_LEVEL >= 3 (typically when verbose flag is set). Output to stdout.
# Arguments:
#   $1: message_string - The message to log.
log_detail() {
  if [[ "${LOG_LEVEL:-2}" -ge 3 ]]; then
    _log_base "DEBUG" "$1"
  fi
}

# --- Permission Check Function ---

# Check File/Directory Permissions and Ownership.
# Verifies if a path exists, has exact required permissions, and is owned by
# the required user. Accepts stricter read-only permissions (e.g., 400) if 600
# is required for a file.
# Arguments:
#   $1: filepath      - The absolute path to the file or directory.
#   $2: required_perm - Required permission string (e.g., "600", "700").
#   $3: require_owner - Required owner username (e.g., "root").
# Returns:
#   0 on success (permissions are okay).
#   1 on failure (path doesn't exist, or permissions/owner mismatch).
#   Logs details on failure using log_error().
check_perms() {
  local filepath="$1"
  local required_perm="$2"
  local require_owner="$3"
  local current_perms
  local current_owner
  local is_ok=1 # Assume okay initially

  # 1. Check existence of the path.
  if [[ ! -e "$filepath" ]]; then
    log_error "Permissions check failed: Path '$filepath' does not exist."
    return 1
  fi

  # 2. Get actual permissions and owner using stat.
  # Check if stat command exists first (should be a core utility).
  if ! command -v stat &>/dev/null; then
    log_error "Command 'stat' not found, cannot check permissions for '$filepath'."
    return 1 # Cannot perform check
  fi
  current_perms=$(stat -c '%a' "$filepath")
  current_owner=$(stat -c '%U' "$filepath")

  # 3. Check owner.
  if [[ "$current_owner" != "$require_owner" ]]; then
    log_error "Permissions check failed: '$filepath' owned by '$current_owner', requires '$require_owner'."
    is_ok=0
  fi

  # 4. Check permissions.
  if [[ "$current_perms" != "$required_perm" ]]; then
    # Allow 400 (read-only) if 600 (read-write) was required for a file,
    # as it's a stricter and often acceptable permission setting.
    if [[ -f "$filepath" && "$required_perm" == "600" && "$current_perms" == "400" ]]; then
      log_detail "Permissions info: '$filepath' has '$current_perms' (stricter than ${required_perm}), accepting."
    else
      log_error "Permissions check failed: '$filepath' has permissions '${current_perms}', requires exactly '${required_perm}'."
      is_ok=0
    fi
  fi

  # 5. Return result.
  if [[ "$is_ok" -eq 0 ]]; then
    return 1 # Failure
  else
    log_detail "Permissions check passed for '$filepath'."
    return 0 # Success
  fi
}

# --- Directory and File Creation Functions ---

# Securely Create Directory.
# Ensures the directory exists and has owner-only permissions (700).
# Arguments:
#   $1: dir_path - The directory path to create.
# Exits calling script on failure as this is usually a critical step.
create_dir_secure() {
  local dir_path="$1"

  # -p creates parent directories as needed, no error if directory exists.
  if ! mkdir -p "$dir_path"; then
    log_error "Failed to create directory: ${dir_path}"
    exit 1 # Critical failure
  fi
  if ! chmod 700 "$dir_path"; then
    log_error "Failed to set permissions on directory: ${dir_path}"
    exit 1 # Critical failure
  fi
  log_detail "Directory created/permission set (700): ${dir_path}"
}

# Create Secure Temporary File.
# Wrapper for mktemp that creates a file with 600 permissions.
# Arguments:
#   $1 (prefix_template, optional): Template for mktemp (e.g., "myprefix.XXXXXX").
#                                    Default: "tmpfile.XXXXXX".
#   $2 (directory, optional): Directory where the temp file should be created.
#                             Default: $TMPDIR or /tmp.
# Behavior:
#   Prints the path to the created temporary file on stdout.
#   Exits calling script on failure.
create_secure_temp_file() {
  local prefix_template="${1:-tmpfile.XXXXXX}"
  local directory="${2:-}" # mktemp handles default if empty
  local temp_file

  if [[ -n "$directory" ]]; then
    if [[ ! -d "$directory" ]]; then
      # Attempt to create it; use log_error and exit if this fails.
      mkdir -p "$directory" || {
        log_error "Cannot create directory for temp file: $directory"
        exit 1
      }
    fi
    if [[ ! -w "$directory" ]]; then
      log_error "Directory for temp file is not writable: $directory"
      exit 1
    fi
    temp_file=$(mktemp "${directory}/${prefix_template}")
  else
    # Fallback to system default temp directory if no specific directory is given.
    temp_file=$(mktemp "/tmp/${prefix_template}")
  fi

  # Check if mktemp succeeded.
  if [[ $? -ne 0 ]] || [[ ! -f "$temp_file" ]]; then
    log_error "Failed to create temporary file with template '${prefix_template}' in '${directory:-/tmp}'."
    exit 1
  fi
  # Set secure permissions.
  chmod 600 "$temp_file" || {
    log_error "Failed to set permissions on temporary file: ${temp_file}"
    rm -f "$temp_file" # Attempt cleanup
    exit 1
  }
  # IMPORTANT: Do NOT log_detail to stdout here, as this function returns value via stdout.
  # log_detail "Secure temporary file created: ${temp_file}" >&2 # Log to stderr if needed.
  echo "$temp_file" # Output the path to the created file
}

# Create Secure Temporary Directory.
# Wrapper for mktemp -d that creates a directory with 700 permissions.
# Arguments:
#   $1 (prefix_template, optional): Template for mktemp (e.g., "mydir.XXXXXX").
#                                    Default: "tmpdir.XXXXXX".
#   $2 (directory, optional): Parent directory where the temp dir should be created.
#                             Default: $TMPDIR or /tmp.
# Behavior:
#   Prints the path to the created temporary directory on stdout.
#   Exits calling script on failure.
create_secure_temp_dir() {
  local prefix_template="${1:-tmpdir.XXXXXX}"
  local directory="${2:-}"
  local temp_dir

  if [[ -n "$directory" ]]; then
    if [[ ! -d "$directory" ]]; then
      mkdir -p "$directory" || { log_error "Cannot create parent directory for temp dir: $directory"; exit 1; }
    fi
    if [[ ! -w "$directory" ]]; then
      log_error "Parent directory for temp dir is not writable: $directory"; exit 1;
    fi
    temp_dir=$(mktemp -d "${directory}/${prefix_template}")
  else
    temp_dir=$(mktemp -d "/tmp/${prefix_template}") # Fallback to /tmp
  fi

  if [[ $? -ne 0 ]] || [[ ! -d "$temp_dir" ]]; then
    log_error "Failed to create temporary directory with template '${prefix_template}' in '${directory:-/tmp}'."
    exit 1
  fi
  # mktemp -d usually creates with 700, but ensure it.
  chmod 700 "$temp_dir" || {
    log_error "Failed to set permissions on temporary directory: ${temp_dir}"
    rm -rf "$temp_dir" # Attempt cleanup
    exit 1
  }
  # IMPORTANT: Do NOT log_detail to stdout here.
  # log_detail "Secure temporary directory created: ${temp_dir}" >&2
  echo "$temp_dir"
}


# --- Path and Command Validation Functions ---

# Check if a path is valid and optionally meets certain criteria.
# Arguments:
#   $1: path_to_check - The path string to validate.
#   $2: check_type (optional) - A string specifying the type of check:
#       "-f": Path must exist and be a regular file.
#       "-d": Path must exist and be a directory.
#       "-r": Path must exist and be readable.
#       "-w": Path must exist and be writable.
#       "-x": Path must exist and be executable.
#       "-e": Path must exist (default if no check_type or invalid one given).
# Returns:
#   0 if the path is valid and meets criteria, 1 otherwise. Logs on failure.
is_valid_path() {
  local path_to_check="$1"
  local check_type="${2:--e}" # Default to -e (exists)

  # Log to stderr to avoid contaminating stdout if this func is used in command substitution
  log_detail "Validating path: '${path_to_check}' with check '${check_type}'" >&2

  if [[ -z "$path_to_check" ]]; then
    log_error "Path validation failed: Provided path is empty."
    return 1
  fi

  # Perform the check based on type
  case "$check_type" in
    -f)
      if [[ ! -f "$path_to_check" ]]; then
        log_error "Path validation failed: '${path_to_check}' is not a regular file or does not exist."
        return 1
      fi
      ;;
    -d)
      if [[ ! -d "$path_to_check" ]]; then
        log_error "Path validation failed: '${path_to_check}' is not a directory or does not exist."
        return 1
      fi
      ;;
    -r)
      if [[ ! -r "$path_to_check" ]]; then # Also implies existence
        log_error "Path validation failed: '${path_to_check}' is not readable or does not exist."
        return 1
      fi
      ;;
    -w)
      if [[ ! -w "$path_to_check" ]]; then # Also implies existence
        log_error "Path validation failed: '${path_to_check}' is not writable or does not exist."
        return 1
      fi
      ;;
    -x)
      if [[ ! -x "$path_to_check" ]]; then # Also implies existence
        log_error "Path validation failed: '${path_to_check}' is not executable or does not exist."
        return 1
      fi
      ;;
    -e|*) # Default or any other implies just existence
      if [[ ! -e "$path_to_check" ]]; then
        log_error "Path validation failed: '${path_to_check}' does not exist."
        return 1
      fi
      ;;
  esac

  log_detail "Path validation successful for '${path_to_check}' (check: ${check_type})." >&2
  return 0
}

# Check if a command exists in PATH or is an absolute path.
# Arguments:
#   $1: command_name       - The command to check (can be just name or full path).
#   $2: error_message (optional) - Custom message if command not found.
#   $3: package_suggestion (optional) - Package to install if command not found.
# Returns:
#   0 if command exists and is executable, 1 otherwise. Logs on failure.
check_command_exists() {
  local command_name="$1"
  # Use parameter expansion for default error message
  local error_message="${2:-Command '${command_name}' not found.}"
  local package_suggestion="${3}"

  if ! command -v "$command_name" &>/dev/null; then
    log_error "$error_message"
    if [[ -n "$package_suggestion" ]]; then
      log_error "Consider installing package: ${package_suggestion}"
    fi
    return 1
  fi
  log_detail "Command '${command_name}' found at: $(command -v "$command_name")" >&2
  return 0
}

# Check Available Disk Space
# Verifies minimum free disk space on the filesystem containing the given path.
# Arguments:
#   $1: path_to_check   - A path on the filesystem to check.
#   $2: min_mb_required - Minimum required free space in Megabytes (MB).
# Returns:
#   0 on success, 1 on failure. Logs details on failure.
check_disk() {
  local path_to_check="$1"
  local min_mb_required="$2"
  local available_kb
  local required_kb
  local avail_mb

  log_detail "Checking disk space for '$path_to_check', requires min ${min_mb_required} MB free." >&2

  # Get available space in Kilobytes (KB) for non-root users.
  available_kb=$(df --output=avail -k "$path_to_check" | tail -n 1)

  # Calculate required space in KB
  required_kb=$((min_mb_required * 1024))

  # Validate df output
  if ! [[ "$available_kb" =~ ^[0-9]+$ ]]; then
    log_error "Could not determine available disk space for '$path_to_check'."
    return 1
  fi

  log_detail "Available KB: $available_kb, Required free KB: $required_kb" >&2

  # Compare
  if [[ "$available_kb" -lt "$required_kb" ]]; then
    avail_mb=$((available_kb / 1024))
    log_error "Insufficient disk space for '$path_to_check'. Available: ${avail_mb} MB, Required minimum: ${min_mb_required} MB."
    return 1
  else
    avail_mb=$((available_kb / 1024))
    log_detail "Disk space check passed. Available: ${avail_mb} MB." >&2
    return 0
  fi
}


# --- YAML Parsing Helper ---

# Get a value from a YAML file using yq.
# Handles null/missing keys gracefully by returning a default or empty string.
# IMPORTANT: This function outputs the value to STDOUT. Any internal logging
# (log_detail, etc.) MUST go to STDERR to avoid contaminating the output.
# Arguments:
#   $1: config_file_path - Path to the YAML file. Can be a regular file or
#                          a named pipe (e.g., from process substitution).
#   $2: yaml_path        - yq query path (e.g., ".global.admin_email").
#   $3: default_value (optional) - Value to return if key is not found or null.
# Prints:
#   The extracted value or default value to stdout.
# Returns:
#   0 on success (value printed).
#   1 if yq fails or file not found (and logs error to stderr).
get_yaml_value() {
  local config_file_path="$1"
  local yaml_path="$2"
  local default_value="${3:-}" # Default to empty string if not provided
  local value

  # Check if yq command is available (use global YQ_CMD)
  if ! command -v "$YQ_CMD" &>/dev/null; then
    log_error "yq command ('${YQ_CMD}') not found. Cannot parse YAML." >&2
    echo "$default_value" # Output default on error
    return 1 # Indicate failure
  fi

  # Check if config_file_path is a readable file or a named pipe
  if [[ ! -f "$config_file_path" && ! -p "$config_file_path" ]]; then
    log_error "YAML input not found or not a file/pipe: '$config_file_path'" >&2
    echo "$default_value"
    return 1
  fi
  if [[ ! -r "$config_file_path" ]]; then
    log_error "YAML input not readable: '$config_file_path'" >&2
    echo "$default_value"
    return 1
  fi


  # Use yq with 'e' (evaluate) and '//' for default if key is null or missing
  # The '|| value="$default_value"' handles cases where yq itself might error or output nothing.
  value=$("$YQ_CMD" e "${yaml_path} // \"${default_value}\"" "$config_file_path") || value="$default_value"

  # If yq outputs literal "null" (as a string), treat it as if default should be used
  if [[ "$value" == "null" ]]; then
    value="$default_value"
  fi

  echo "$value" # This is the intended output
  return 0
}

# --- Syntax Check Functions ---

# Function: syntax_check_shell_script
# Description:
#   Performs a syntax check on a given shell script file using 'bash -n'.
# Arguments:
#   $1: script_path - The absolute path to the shell script to check.
# Returns:
#   0 if syntax is okay.
#   1 if syntax errors are found or script is not readable/found.
syntax_check_shell_script() {
  local script_path="$1"
  log_detail "Performing syntax check on shell script: ${script_path}" >&2

  if ! is_valid_path "$script_path" "-f"; then # Checks existence and if it's a file
    log_error "Shell script syntax check failed: File '${script_path}' not found or is not a regular file." >&2
    return 1
  fi
  if ! is_valid_path "$script_path" "-r"; then # Checks readability
    log_error "Shell script syntax check failed: File '${script_path}' is not readable." >&2
    return 1
  fi

  # Perform syntax check
  if bash -n "$script_path"; then
    log_detail "Shell script syntax OK: ${script_path}" >&2
    return 0
  else
    log_error "Shell script syntax error in file: ${script_path}" >&2
    return 1
  fi
}

# Function: syntax_check_yaml_file
# Description:
#   Performs a basic syntax check on a given YAML file using 'yq .'.
# Arguments:
#   $1: yaml_path - The absolute path to the YAML file to check.
# Returns:
#   0 if syntax is okay.
#   1 if syntax errors are found, yq is missing, or file is not readable/found.
syntax_check_yaml_file() {
  local yaml_path="$1"
  log_detail "Performing syntax check on YAML file: ${yaml_path}" >&2

  if ! check_command_exists "$YQ_CMD" "yq command ('${YQ_CMD}') is required to check YAML syntax."; then
    return 1
  fi
  if ! is_valid_path "$yaml_path" "-f"; then # Checks existence and if it's a file
    log_error "YAML syntax check failed: File '${yaml_path}' not found or is not a regular file." >&2
    return 1
  fi
  if ! is_valid_path "$yaml_path" "-r"; then # Checks readability
    log_error "YAML syntax check failed: File '${yaml_path}' is not readable." >&2
    return 1
  fi

  # Perform syntax check by trying to parse the whole file
  # Redirect yq output to /dev/null, we only care about its exit code
  if "$YQ_CMD" e . "$yaml_path" > /dev/null 2>&1; then
    log_detail "YAML syntax OK: ${yaml_path}" >&2
    return 0
  else
    log_error "YAML syntax error in file: ${yaml_path}. Use '$YQ_CMD e . \"${yaml_path}\"' to see details." >&2
    return 1
  fi
}

# --- Email Function ---

# Function: send_email
# Description:
#   Sends an email using msmtp. Handles dry-run mode by logging instead of sending.
#   Relies on global variables: dry_run, MSMTP_CMD.
# Arguments:
#   $1: recipient - Email address of the recipient.
#   $2: subject   - Subject line of the email.
#   $3: body      - Main content of the email.
# Returns:
#   0 on success or if in dry-run mode for certain types of emails.
#   1 on failure to send email (e.g., msmtp not found or returns error).
send_email() {
  local recipient="$1"
  local subject="$2"
  local body="$3"

  # Skip sending in dry-run mode for failure emails
  # Heuristic: if subject contains "FAILED" or "ERROR", it's a failure/error email
  if [[ "${dry_run:-0}" -eq 1 ]] && \
     ( [[ "$subject" == *"FAILED"* ]] || [[ "$subject" == *"ERROR"* ]] ); then
    log_info "DRY-RUN: Would send failure/error email to ${recipient}" >&2
    log_detail "DRY-RUN: Subject: ${subject}" >&2
    log_detail "DRY-RUN: Body:\n${body}" >&2
    return 0
  fi
  # Also skip summary emails in dry-run if they are not error summaries
  if [[ "${dry_run:-0}" -eq 1 ]] && \
     [[ "$subject" != *"FAILED"* ]] && \
     [[ "$subject" != *"ERROR"* ]] && \
     [[ "$subject" != *"SKIPPED"* ]]; then # Allow skipped summary in dry-run for logging
    log_info "DRY-RUN: Would send summary email to ${recipient}" >&2
    log_detail "DRY-RUN: Subject: ${subject}" >&2
    log_detail "DRY-RUN: Body:\n${body}" >&2
    return 0
  fi


  if [[ -z "$recipient" ]]; then
    log_error "Cannot send email: Recipient address is empty." >&2
    return 1
  fi
  if ! check_command_exists "$MSMTP_CMD" "msmtp command ('${MSMTP_CMD}') not found. Cannot send email."; then
    return 1
  fi

  log_info "Sending email to ${recipient}..."
  # Use printf for the body to correctly interpret newlines
  printf "To: %s\nSubject: %s\nContent-Type: text/plain; charset=utf-8\nX-Priority: 1 (Highest)\nImportance: High\n\n%s" \
    "$recipient" "$subject" "$body" | "$MSMTP_CMD" "$recipient"

  if [[ $? -ne 0 ]]; then
    log_error "Failed to send email to ${recipient} using '${MSMTP_CMD}'." >&2
    return 1
  fi
  log_detail "Email sent successfully to ${recipient}." >&2
  return 0
}
