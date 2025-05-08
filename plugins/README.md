# Local Backup Script - Plugin Documentation

This document describes the interface and expectations for plugin scripts used by the `local_backup.sh` core orchestrator.

## Overview

Plugins are executable shell scripts (`*.sh`) located in the directory defined by `PLUGIN_DIR` in the central `config` file (default: `/opt/backup/lib/plugins`). They perform specific backup-related tasks for services defined in `service.yaml` files.

The core script discovers plugins and calls standardized functions within them at different stages (Validate, Prepare, Run, Post-Success) based on a **simplified dependency order** (Docker stop first, start last). Configuration parameters are passed via **temporary files**, and state between plugin operations (like Docker stop/start) is managed via **state files**.

## Plugin Discovery

The core script finds all files ending in `.sh` (excluding `common_functions.sh`) within the `PLUGIN_DIR` that have execute permissions (`+x`) set.

## Plugin Interface Functions

Each plugin script **must** be executable and **should** define a specific set of functions. The core script sources plugins within subshells `( ... )` to execute these functions. Logging functions (`log_info`, `log_error`, `log_detail`) and potentially other helpers like `check_perms` are expected to be available (sourced from `common_functions.sh`). All functions should return `0` on success and a non-zero value on failure. Use `local` for variables inside functions. Adhere to Google Shell Style Guide (lowercase variables/functions).

### Required Functions:

1.  **`plugin_handles_task_type "$task_type"`**
    * **Purpose:** Indicate if this plugin handles a specific task type key from `service.yaml`.
    * **Args:** `$1` = Task type string (e.g., "postgresql", "docker", "files").
    * **Returns:** Exit code `0` if handled, `1` otherwise.

2.  **`plugin_validate_config "$temp_config_file"`**
    * **Purpose:** Validate the configuration structure/values provided for its task type within the `service.yaml`.
    * **Args:** `$1` = Path to a temporary file containing the relevant YAML section (e.g., content under `postgresql:`) extracted by the core script using `yq`.
    * **Behavior:** Use `yq` (path in global `$YQ_CMD`) to parse config from `$1`. Check keys, values, formats, dependencies (commands). Use `log_error` for failures.
    * **Returns:** Exit code `0` if valid, non-zero otherwise.

3.  **`plugin_run_backup "$temp_config_file" "$service_config_dir" "$service_backup_dir"`**
    * **Purpose:** Execute the main backup logic.
    * **Args:**
        * `$1`: Path to temp file containing plugin's config section from YAML.
        * `$2`: Path to the directory containing `service.yaml`.
        * `$3`: Path to the service's temporary backup destination directory (e.g., `$WORK_DIR/<type>/<service>`). Write output here.
    * **Dry Run:** Check global environment variable `DRY_RUN_MODE`. If `1`, log intended actions instead of performing them. (`DRY_RUN_MODE` is exported by the core script before calling).
    * **Returns:** `0` on success, non-zero on failure.

### Optional Functions:

4.  **`plugin_prepare_backup "$temp_config_file" "$service_config_dir" "$service_backup_dir"`**
    * **Purpose:** Perform actions *before* `plugin_run_backup` (e.g., stop a service). Core script runs Docker prepare first, then others.
    * **Args:** Same as `run_backup`. Checks `DRY_RUN_MODE`.
    * **State Management:** If system state is changed, MUST create state file(s) in `$3/.state/` (e.g., `touch "$3/.state/docker_stopped"`). Dir/files should be `700`/`600`. Store context needed for reversal in state files (e.g., `$3/.state/docker_context`). State directory (`.state`) is created by the core script.
    * **Returns:** `0` on success. Failure aborts the service backup.

5.  **`plugin_post_backup_success "$temp_config_file" "$service_config_dir" "$service_backup_dir"`**
    * **Purpose:** Perform actions *after* successful `run_backup`, typically reversing `prepare` actions (e.g., start a service, optional wait). Core script runs others first, then Docker last.
    * **Called By Core:** Only if the function exists AND `plugin_prepare_backup` was called and succeeded for this plugin.
    * **Args:** Same as `run_backup`. Checks `DRY_RUN_MODE`.
    * **State Management:** Should check for state file(s) created by `prepare`. If found, perform reversal. **Must remove the state file(s)** upon successful completion.
    * **Returns:** `0` on success. Failure aborts the entire backup script run.

6.  **`plugin_emergency_cleanup "$service_backup_dir"`**
    * **Purpose:** Critical cleanup/reversal if script exits unexpectedly *after* `prepare` might have run but *before* `post_success` completed successfully.
    * **Called By Core:** From the main script's EXIT trap for each service directory containing a `.state` subdirectory.
    * **Args:** `$1`: Absolute path to the service's temporary backup directory (may not exist).
    * **Behavior:** Check for its specific state file(s) (e.g., `$1/.state/docker_stopped`). If found, attempt reversal (read context, run command, `sleep`). Log actions clearly using `_log_base ... >> "$TMP_LOG_FILE"` (global variable from core) and `echo ... >&2`. **Remove state file(s) *only* if reversal succeeds.** Checks `DRY_RUN_MODE`.
    * **Returns:** Should ideally return `0` even on failure.

## Included Example Plugins

*(Located in the directory specified by `PLUGIN_DIR`)*

* **`common_functions.sh`:** Provides shared logging and `check_perms` functions. Not executable. Sourced.
* **`docker_compose.sh`:** Handles `docker` task type. Requires `docker_compose_path`. Optional `wait_after_restart`. Uses state files. Handles dry-run.
* **`files_rsync.sh`:** Handles `files` task type. Requires `paths:` list. Optional `exclude:` list. Runs `rsync`. Handles dry-run.
* **`postgresql.sh`:** Handles `postgresql` task type. Requires `host`, `user`, `database`. Optional `port`, `dump_options`. Requires `/root/.pgpass`. Handles dry-run.
* **`mariadb.sh`:** Handles `mariadb` or `mysql` task type. Requires `host`, `user`, `database`. Optional `port`, `dump_options`. Requires `/root/.my.cnf`. Handles dry-run.
* **`influxdb.sh`:** Handles `influxdb` task type (for v2+). Requires `host`, `token`, `org`. Optional `bucket`. Requires `influx` CLI. Handles dry-run.

## Creating New Plugins

1.  Create `your_plugin_name.sh` in `PLUGIN_DIR`. Make executable (`700`).
2.  Source `common_functions.sh`.
3.  Implement required functions. Read config from temp file path `$1` using `${YQ_CMD}`.
4.  Implement optional functions if needed, using state files in `$service_backup_dir/.state/`. Handle `DRY_RUN_MODE`.
5.  Define the YAML task type key and parameters. Document them.

