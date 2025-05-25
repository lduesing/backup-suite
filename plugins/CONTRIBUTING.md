# Backup Plugin Development Guide

**Version:** 0.2
**Date:** May 25, 2025

This document describes the API and conventions for creating new plugins for the `local_backup.sh` client script.

## Table of Contents

1.  [Plugin Philosophy](#1-plugin-philosophy)
2.  [Plugin Structure & Location](#2-plugin-structure--location)
3.  [Required Plugin Functions](#3-required-plugin-functions)
    * [3.1 `plugin_handles_task_type`](#31-plugin_handles_task_type)
    * [3.2 `plugin_validate_config`](#32-plugin_validate_config)
    * [3.3 `plugin_prepare_backup`](#33-plugin_prepare_backup)
    * [3.4 `plugin_run_backup`](#34-plugin_run_backup)
    * [3.5 `plugin_post_backup_success`](#35-plugin_post_backup_success)
    * [3.6 `plugin_emergency_cleanup`](#36-plugin_emergency_cleanup)
4.  [Plugin Execution Stages](#4-plugin-execution-stages)
5.  [Plugin Environment & Available Tools](#5-plugin-environment--available-tools)
    * [5.1 Sourcing `common_functions.sh`](#51-sourcing-common_functionssh)
    * [5.2 Key Environment Variables](#52-key-environment-variables)
    * [5.3 Common Functions (`common_functions.sh`)](#53-common-functions-common_functionssh)
6.  [Configuration (`service.yaml`) & Data Passing](#6-configuration-serviceyaml--data-passing)
7.  [State Management](#7-state-management)
8.  [Output and Logging](#8-output-and-logging)
9.  [Error Handling](#9-error-handling)
10. [Example Plugin Workflow (Docker)](#10-example-plugin-workflow-docker)
11. [Shell Style Guide](#11-shell-style-guide)
12. [Security Considerations for Plugins](#12-security-considerations-for-plugins)
11. [Plugin Development Checklist](#13-plugin-development-checklist)

## 1. Plugin Philosophy

Plugins are designed to be focused, self-contained scripts responsible for handling one specific type of backup task (e.g., `docker`, `postgresql`, `files`). They should be idempotent where possible, especially during the `prepare` and `post` stages. They rely on the core script (`local_backup.sh`) for orchestration, configuration parsing (mostly), locking, TAR creation, and reporting.

## 2. Plugin Structure & Location

* **Location:** Plugins MUST reside in the directory specified by `PLUGIN_DIR` (default: `/opt/backup/lib/plugins`).
* **Naming:** Must end with `.sh` (e.g., `my_plugin.sh`).
* **Executable:** Must have execute permissions (`chmod +x`).
* **Shebang:** Must start with `#!/bin/bash`.
* **Common Functions:** MUST source `common_functions.sh` (see Section 5.1).

## 3. Required Plugin Functions

Each plugin script MUST implement the following functions. The core script will call these functions at specific stages of the backup process for each service configuration that includes a task block matching the plugin's `plugin_handles_task_type`.

### 3.1 `plugin_handles_task_type`

* **Signature:** `plugin_handles_task_type()`
* **Purpose:** This function must `echo` the exact string that identifies the task type this plugin handles. This string must match the top-level key used in the `service.yaml` file (e.g., `docker`, `postgresql`, `files`).
* **Example:**
    ``` bash
    plugin_handles_task_type() {
      echo "my_service_type"
    }
    ```

### 3.2 `plugin_validate_config`

* **Signature:** `plugin_validate_config(config_file)`
* **Arguments:**
    * `$1 (config_file)`: Path to a temporary YAML file containing only the configuration block for this plugin from the current service's `service.yaml`.
* **Purpose:** To validate the configuration parameters provided in the `service.yaml` for this plugin. It should check for mandatory keys, correct data types, and potentially perform basic checks like directory existence or command availability (if not covered by `common_config`).
* **Output:** Must exit with `0` on success. On failure, it should `log_error` a descriptive message and exit with a non-zero code.
* **Example:**
    ``` bash
    plugin_validate_config() {
      local config_file="$1"
      local my_param
      my_param=$(get_yaml_value "${config_file}" ".my_param") || \
        { log_error "Mandatory 'my_param' not found in config."; return 1; }
      [[ -d "${my_param}" ]] || \
        { log_error "Directory '${my_param}' does not exist."; return 1; }
      return 0
    }
    ```

### 3.3 `plugin_prepare_backup`

* **Signature:** `plugin_prepare_backup(config_file, service_backup_dir)`
* **Arguments:**
    * `$1 (config_file)`: Path to the temporary YAML config file.
    * `$2 (service_backup_dir)`: Path to the directory within the main temporary backup directory where this *service's* data should be stored. This directory already exists.
* **Purpose:** To perform any actions *before* the main backup run. This is typically used for tasks like stopping services, creating temporary snapshots, or setting up environments.
* **State:** If this function changes the system state (e.g., stops a service), it **MUST** create a state file in `${service_backup_dir}/.state/` so that `plugin_post_backup_success` or `plugin_emergency_cleanup` can reverse the action.
* **Output:** Must exit `0` on success. On failure, log an error and exit non-zero. The core script will *not* proceed to `plugin_run_backup` if this fails.
* **Example:**
    ``` bash
    plugin_prepare_backup() {
      local config_file="$1"
      local service_backup_dir="$2"
      local state_dir="${service_backup_dir}/.state"
      mkdir -p "${state_dir}"
      log_info "Stopping service X..."
      if ! stop_service_x; then
        log_error "Failed to stop service X."
        return 1
      fi
      touch "${state_dir}/service_x_stopped"
      return 0
    }
    ```

### 3.4 `plugin_run_backup`

* **Signature:** `plugin_run_backup(config_file, service_backup_dir)`
* **Arguments:**
    * `$1 (config_file)`: Path to the temporary YAML config file.
    * `$2 (service_backup_dir)`: Path to the service's backup directory.
* **Purpose:** To perform the *actual* backup operation. Data should be placed *inside* the `service_backup_dir`. Plugins should create subdirectories within `service_backup_dir` if needed for organization (e.g., `data/`, `config/`).
* **Output:** Must exit `0` on success. On failure, log an error and exit non-zero.
* **Example:**
    ``` bash
    plugin_run_backup() {
      local config_file="$1"
      local service_backup_dir="$2"
      local source_path
      source_path=$(get_yaml_value "${config_file}" ".source_path")
      log_info "Backing up ${source_path}..."
      rsync -a --relative "${source_path}" "${service_backup_dir}/" || \
        { log_error "Rsync failed for ${source_path}."; return 1; }
      return 0
    }
    ```

### 3.5 `plugin_post_backup_success`

* **Signature:** `plugin_post_backup_success(config_file, service_backup_dir)`
* **Arguments:**
    * `$1 (config_file)`: Path to the temporary YAML config file.
    * `$2 (service_backup_dir)`: Path to the service's backup directory.
* **Purpose:** To perform cleanup or state-reversal actions *only if* `plugin_prepare_backup` and `plugin_run_backup` both succeeded. This is typically used to restart services stopped during preparation.
* **State:** It **MUST** check for state files in `${service_backup_dir}/.state/` and act accordingly, then *remove* those state files.
* **Output:** Must exit `0` on success. On failure, log an error and exit non-zero (this will cause the *entire* backup run to fail).
* **Example:**
    ``` bash
    plugin_post_backup_success() {
      local config_file="$1"
      local service_backup_dir="$2"
      local state_dir="${service_backup_dir}/.state"
      if [[ -f "${state_dir}/service_x_stopped" ]]; then
        log_info "Restarting service X..."
        if ! start_service_x; then
          log_error "Failed to restart service X!"
          return 1
        fi
        rm -f "${state_dir}/service_x_stopped"
      fi
      return 0
    }
    ```

### 3.6 `plugin_emergency_cleanup`

* **Signature:** `plugin_emergency_cleanup(service_backup_dir)`
* **Arguments:**
    * `$1 (service_backup_dir)`: Path to the service's backup directory.
* **Purpose:** Called by the core script's `EXIT` trap if the script terminates unexpectedly *after* the `prepare` stage but *before* the `post_success` stage completes successfully. Its job is to attempt to restore the system to a working state (e.g., restart services). It should be robust and avoid causing further errors.
* **State:** It **MUST** check for state files in `${service_backup_dir}/.state/` and act accordingly, then *remove* those state files if successful.
* **Output:** Should log actions but *should not* exit non-zero unless absolutely necessary, as it runs during overall script cleanup.
* **Example:**
    ``` bash
    plugin_emergency_cleanup() {
      local service_backup_dir="$1"
      local state_dir="${service_backup_dir}/.state"
      if [[ -d "${state_dir}" && -f "${state_dir}/service_x_stopped" ]]; then
        log_warn "Emergency cleanup: Attempting to restart service X..."
        if start_service_x; then
          rm -f "${state_dir}/service_x_stopped"
        else
          log_error "EMERGENCY CLEANUP FAILED for service X!"
        fi
      fi
      return 0
    }
    ```

## 4. Plugin Execution Stages

The core script calls plugin functions in this order for *each* service:
1.  `plugin_validate_config`
2.  `plugin_prepare_backup` (Docker `prepare` runs first, if present)
3.  `plugin_run_backup`
4.  `plugin_post_backup_success` (Docker `post_success` runs last, if present)
5.  `plugin_emergency_cleanup` (Only on script error/exit after `prepare` but before `post_success` completion)

## 5. Plugin Environment & Available Tools

### 5.1 Sourcing `common_functions.sh`

Every plugin MUST source `common_functions.sh`. This provides access to logging functions and essential environment variables. The path should be determined relative to the plugin's own location.

``` bash
#!/bin/bash
# My Awesome Plugin

# Source common functions and environment variables
COMMON_FUNCTIONS_SCRIPT="$(dirname "$0")/common_functions.sh"
if [[ ! -f "${COMMON_FUNCTIONS_SCRIPT}" ]]; then
    echo "ERROR: ${COMMON_FUNCTIONS_SCRIPT} not found!" >&2
    exit 1
fi
# shellcheck source=plugins/common_functions.sh
source "${COMMON_FUNCTIONS_SCRIPT}" || \
  { echo "ERROR: Failed to source ${COMMON_FUNCTIONS_SCRIPT}!" >&2; exit 1; }

# ... (rest of the plugin code)
```

### 5.2 Key Environment Variables

Plugins have access to all variables exported by `local_backup.sh`, including those from `common_config` and `client_config.yml`. Key variables include:
* `YQ_CMD`: Path to `yq`.
* `TAR_CMD`: Path to `tar`.
* `RSYNC_CMD`: Path to `rsync`.
* `DOCKER_CMD`: Path to `docker compose`.
* `PG_DUMP_CMD`, `MYSQL_DUMP_CMD`: Paths to database tools.
* `LOG_LEVEL`: Current logging level.
* `DRY_RUN`: "true" if in dry-run mode, "false" otherwise. Plugins **MUST** respect this.
* `WORK_DIR`: Path to the *main* temporary working directory for the *entire* backup run. Plugins generally should *not* write here directly, but use the `service_backup_dir` passed to them.

### 5.3 Common Functions (`common_functions.sh`)

Plugins **SHOULD** use these functions:
* `log_error "message"`: Logs an error message.
* `log_warn "message"`: Logs a warning message.
* `log_info "message"`: Logs an informational message (only if `LOG_LEVEL` >= 2).
* `log_debug "message"`: Logs a debug message (only if `LOG_LEVEL` >= 3).
* `get_yaml_value "file.yml" ".key.subkey"`: Safely gets a value from a YAML file.
* `check_command "command_name"`: Checks if a command exists.
* `check_permissions "file_path" "expected_perms"`: Checks file permissions.
* `check_disk_space "path" "min_mb"`: Checks available disk space.
* `run_cmd "command" "args..."`: Executes a command, logging it and checking its exit code (useful for dry-run handling).

Refer to `common_functions.sh` itself for the full list and implementation.

## 6. Configuration (`service.yaml`) & Data Passing

Plugins receive their specific configuration block via a temporary YAML file passed as `$1`. They **MUST** use `get_yaml_value` to extract parameters.

``` yaml
# Example service.yaml
service:
  name: "MyWebApp"

docker: # Task block matching docker_compose.sh
  compose_file: "/opt/mywebapp/docker-compose.yml"
  stop_wait_seconds: 30

postgresql: # Task block matching postgresql.sh
  database: "webapp_db"
  username: "webapp_user"
  # Password MUST be in /root/.pgpass

files: # Task block matching files_rsync.sh
  paths:
    - "/etc/mywebapp/"
    - "/var/www/mywebapp/uploads/"
  exclude:
    - "*.tmp"
    - "cache/"
```

## 7. State Management

Use the `.state/` subdirectory (`${service_backup_dir}/.state/`) for any files needed to track changes made during `plugin_prepare_backup`. These files **MUST** be cleaned up by `plugin_post_backup_success` or `plugin_emergency_cleanup`.

## 8. Output and Logging

* Use the `log_*` functions for all output. Avoid using `echo` directly unless it's for `plugin_handles_task_type`.
* Ensure logs are informative but concise, especially at INFO level. Use DEBUG for detailed step-by-step information.

## 9. Error Handling

* Use `set -e` at the top of your plugin (after sourcing common functions).
* Explicitly check the return codes of critical commands.
* Use `log_error` before exiting non-zero.
* Implement `plugin_emergency_cleanup` to handle script failures gracefully.
* Ensure `plugin_validate_config` catches as many potential issues as possible *before* making changes.

## 10. Example Plugin Workflow (Docker)

1.  `plugin_handles_task_type`: Echos `docker`.
2.  `plugin_validate_config`: Checks if `compose_file` exists and is a file.
3.  `plugin_prepare_backup`: If `compose_file` is defined, runs `docker compose down` (or `stop`), waits, and creates `${state_dir}/docker_stopped` and `${state_dir}/docker_context`.
4.  `plugin_run_backup`: Backs up the `compose_file` and optionally pins images.
5.  `plugin_post_backup_success`: Checks for `${state_dir}/docker_stopped`, runs `docker compose up -d`, and removes state files.
6.  `plugin_emergency_cleanup`: Checks for `${state_dir}/docker_stopped` and attempts to run `docker compose up -d`.

## 11. Shell Style Guide

Please adhere to the [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html), particularly regarding:

* Function comments (Purpose, Arguments, Outputs/Returns).
* Variable names (`lowercase_with_underscores` for local, ensure consistency with core script for global/config vars).
* One command per line where feasible.
* `if`/`fi`, `for`/`done`, `while`/`done` on the same column.
* Consistent 2-space indentation.
* Quoting variables correctly.

## 12. Security Considerations for Plugins

* **Validate Inputs:** Always validate parameters received from the YAML configuration, especially paths or values used in commands.
* **Command Injection:** Be extremely careful when constructing commands dynamically using configuration values. Use arrays for commands and arguments where possible, and quote variables meticulously.
* **Least Privilege:** If a plugin needs to run a command as a different user, ensure this is clearly documented and the `sudo` mechanism is used securely (e.g., with `-n` for non-interactive).
* **Temporary Files:** Use `mktemp` or the `create_secure_temp_file`/`create_secure_temp_dir` helpers for temporary files/directories and ensure they are cleaned up.
* **Sensitive Data:** Avoid logging sensitive data (like tokens or passwords) even in debug logs.

## 13. Plugin Development Checklist

* [ ] Does the plugin have a unique name ending in `.sh`?
* [ ] Is it executable?
* [ ] Does it start with `#!/bin/bash`?
* [ ] Does it source `common_functions.sh` correctly?
* [ ] Does it implement all 6 required functions?
* [ ] Does `plugin_handles_task_type` echo the correct task key?
* [ ] Does `plugin_validate_config` thoroughly check all parameters?
* [ ] Does it correctly use `${service_backup_dir}` to store data?
* [ ] Does it correctly use `${service_backup_dir}/.state/` for state management?
* [ ] Does `plugin_post_backup_success` reliably clean up state?
* [ ] Does `plugin_emergency_cleanup` reliably clean up state?
* [ ] Does it use `log_*` functions for all output?
* [ ] Does it handle errors gracefully and exit non-zero on failure?
* [ ] Does it respect the `DRY_RUN` variable?
* [ ] Have you tested it with various valid and invalid `service.yaml` configurations?
* [ ] Have you tested its behaviour during script failures (simulated via `kill` or `exit 1` in another plugin)?
