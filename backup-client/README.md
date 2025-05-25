# Local Backup Script

**Version:** 0.2
**License:** AGPL-3.0-or-later
**Author:** Lars Duesing [<lars.duesing@camelotsweb.de>](mailto:lars.duesing@camelotsweb.de)
**Date:** May 22, 2025

## Table of Contents

1.  [Description](#1-description)
2.  [Architecture Overview](#2-architecture-overview)
3.  [Features](#3-features)
4.  [Prerequisites](#4-prerequisites)
5.  [Installation](#5-installation)
6.  [Configuration](#6-configuration)
    * [6.1 Common Configuration File (`common_config`)](#61-common-configuration-file-common_config)
    * [6.2 Client Configuration File (`client_config.yml`)](#62-client-configuration-file-client_configyml)
    * [6.3 Service Configuration (`service.yaml`)](#63-service-configuration-serviceyaml)
    * [6.4 Plugin Configuration](#64-plugin-configuration)
7.  [Usage](#7-usage)
    * [7.1 Command Line Options](#71-command-line-options)
    * [7.2 Manual Execution](#72-manual-execution)
    * [7.3 Automated Execution (Systemd Timer)](#73-automated-execution-systemd-timer)
8.  [Backup Process & Archive](#8-backup-process--archive)
9.  [Plugin System Details](#9-plugin-system-details)
    * [9.1 Data Passing](#91-data-passing)
    * [9.2 State Management](#92-state-management)
    * [9.3 Dependency Handling & Stages](#93-dependency-handling--stages)
10. [Error Handling and Email Reporting](#10-error-handling-and-email-reporting)
11. [Locking Mechanisms](#11-locking-mechanisms)
    * [11.1 Script Instance Locking (`flock`)](#111-script-instance-locking-flock)
    * [11.2 Shared Directory Lock (TAR Creation)](#112-shared-directory-lock-tar-creation)
12. [Security Considerations](#12-security-considerations)
    * [12.1 Passwords](#121-passwords)
    * [12.2 File Permissions](#122-file-permissions)
13. [Extensibility (Adding Plugins)](#13-extensibility-adding-plugins)
14. [Troubleshooting](#14-troubleshooting)
15. [Suggestions / Potential Improvements](#15-suggestions--potential-improvements)
16. [License Information](#16-license-information)

## 1. Description

This script (`local_backup.sh`) acts as the core orchestrator for performing local backups on a client machine. It is part of a modular backup system that utilizes plugins for specific backup tasks. The core logic is structured into distinct **stage handler functions** (`_handle_validation_stage`, `_handle_prepare_stage`, `_handle_run_stage`, `_handle_post_success_stage`) for improved clarity and maintainability, adhering to the Google Shell Style Guide.

It reads shared defaults from `/etc/backup/common_config`, client-specific settings from `/etc/backup/client_config.yml`, and discovers services to back up based on `service.yaml` files found within subdirectories of `/etc/backup/`.

The script coordinates the execution of plugins (located in `/opt/backup/lib/plugins` by default) through these defined stages. It handles **script instance locking (`flock`)** and **shared directory locking (mkdir-based with retries)** for TAR creation, granular logging, error reporting via email, TAR archive creation and verification, and cleanup of temporary files and old backups. A dry-run mode is available for testing. It ensures correct permissions on the `BASE_BACKUP_DIR` and its `done/` subdirectory to allow the backup server to manage archives. Signal handling (SIGINT, SIGTERM) is implemented for graceful shutdown.

## 2. Architecture Overview

* **Core Script (`/opt/backup/bin/local_backup.sh`):** This script. Orchestrates the entire process through internal stage handler functions.
* **Plugins (`/opt/backup/lib/plugins/*.sh`):** Handle specific tasks (Docker, PostgreSQL, MariaDB/MySQL, Files, etc.). See `plugins/README.md`.
* **Common Config (`/etc/backup/common_config`):** Shared defaults/paths.
* **Client Config (`/etc/backup/client_config.yml`):** Client-specific overrides and settings.
* **Service Config (`/etc/backup/<type>/<service>/service.yaml`):** Defines tasks/parameters per service.
* **Common Functions (`plugins/common_functions.sh`):** Shared utilities (e.g., logging, permission checks).

## 3. Features

* **Modular Plugin Architecture:** Extensible via plugins.
* **Internal Stage Handlers:** Core script logic organized into private functions for clear execution stages.
* **YAML Service Configuration:** Clear, structured definition per service.
* **Combined Configuration:** Uses common shell config and client-specific YAML.
* **Plugin Autodiscovery:** Finds plugins automatically.
* **Task Autodiscovery:** Runs plugins based on `service.yaml` keys.
* **Robust Data Passing:** Uses temporary files to pass config to plugins.
* **Plugin State Management:** Uses temporary state files for coordinated actions.
* **Simplified Dependency Handling:** Fixed execution order (Docker stop first, start last) managed within stage handlers.
* **Dual Locking Mechanism:**
    * Script instance locking using `flock` to prevent multiple simultaneous runs of `local_backup.sh`.
    * Shared directory locking using `mkdir` (atomic operation) in `BASE_BACKUP_DIR` during TAR archive creation to prevent conflicts with the backup server fetching an incomplete archive. Includes retries and email notification on persistent lock failure.
* **Enhanced Configuration Validation:** Checks configs and permissions. Syntax checks for config files.
* **Corrected Directory Permissions:** Ensures `BASE_BACKUP_DIR` and its `done/` subdirectory have appropriate group permissions for server-side cleanup operations.
* **(Plugin) Database Backups:** Uncompressed dumps, requires secure credential files.
* **(Plugin) File Backups:** Relative paths, separate `exclude:` list.
* **(Plugin) Docker Support:** Config backup, intelligent stop/start, per-service wait. Optional pinning of images to their SHA256 digest.
* **Dry-Run Mode (`--dry-run`):** Simulates backup.
* **Secure Temporary Directory:** Uses `mktemp -d`.
* **TAR Archiving & Verification:** Creates/verifies `.tar.gz`, preserves perms/ownership, owner `BACKUP_USER:BACKUP_GROUP`, perms `600`. Excludes `.state` dirs.
* **Restricted Permissions:** Checks config files (`600`), sets TAR perms (`600`).
* **Timestamped Archive:** Filename includes hostname and timestamp.
* **Disk Space Check:** After *each* backup task (within `_handle_run_stage`).
* **Error Reporting:** Detailed email reports (skipped in dry-run).
* **Robustness:** `set -e`, detailed error traps.
* **Automatic Cleanup:** Manages old backups and temporary files via EXIT trap.
* **Command Line Options:** `-v`, `-h`, `-V`, `-d`.
* **Shell Style:** Adheres to Google Shell Style Guide.
* **Systemd Integration:** Example units provided.
* **AGPLv3 License:** Free software.
* **Granular Logging:** Supports ERROR, WARN, INFO, DEBUG levels controlled by config/verbose flag.
* **Signal Handling:** Graceful shutdown on SIGINT, SIGTERM.

## 4. Prerequisites

* **OS:** Debian-based Linux.
* **Shell:** Bash (v4.3+ recommended for namerefs if used by stage handlers, though current core script avoids them for broader compatibility by passing array names).
* **YAML Parser:** **`yq` version 4+** (REQUIRED).
* **Core Tools:** `bash`, `find`, `mkdir`, `chmod`, `chown`, `date`, `grep`, `cut`, `sed`, `tee`, `mktemp`, `dirname`, `basename`, `gzip`, `tar`, `realpath`, `command`, `id`, `getent`, `getopt`, `stat`, `df`, `tail`, `flock`.
* **Backup Tool:** `rsync` (if using `files_rsync.sh`).
* **DB Clients (Optional):** As required by DB plugins (e.g., `postgresql-client`, `mariadb-client`).
* **Docker (Optional):** `docker` engine, `docker compose` (v2 recommended).
* **Email Client (Optional):** `msmtp`, `msmtp-mta` (configured).
* **Permissions:** Script MUST be run as **`root`**.
* **Backup User/Group:** `BACKUP_USER` and `BACKUP_GROUP` from `client_config.yml` MUST exist.

**Install required packages (Example for Debian/Ubuntu):**
``` bash
# Install yq v4+ (check official instructions)
# Example:
# sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && sudo chmod +x /usr/bin/yq

sudo apt update
sudo apt install -y util-linux rsync postgresql-client mariadb-client msmtp msmtp-mta gzip tar coreutils uidmap yq
# Ensure Docker and Compose v2 are installed if needed
```

## 5. Installation

(Assuming installation via `.deb` packages)

1.  Install `backup-common` package: `sudo apt install ./backup-common*.deb`
2.  Install `backup-client` package: `sudo apt install ./backup-client*.deb`
3.  **Post-Installation Configuration:**
    * Review/Edit `/etc/backup/common_config`. Ensure `600 root:root`.
    * Edit `/etc/backup/client_config.yml`. Ensure `600 root:root`.
    * Create service directories under `/etc/backup/` (e.g., `/etc/backup/docker/my-app`).
    * Create `service.yaml` inside each service directory. Ensure `600 root:root`.
    * Setup secure DB credentials (`/root/.pgpass` etc.) with `600` perms.
    * Enable the systemd timer: `sudo systemctl enable --now local-backup.timer`.

## 6. Configuration

Configuration for the client backup script is split into three main parts:

### 6.1 Common Configuration File (`common_config`)

* **Location:** `/etc/backup/common_config`
* **Format:** Shell script (sourced variables, `KEY="VALUE"`)
* **Permissions:** MUST be `600` owned by `root`. The script verifies this.
* **Purpose:** Defines global default settings and paths to essential command-line tools. These values can be overridden by the `client_config.yml` or, in some cases, are used as fallbacks if not specified elsewhere.
* **Key Variables:**
    * `YQ_CMD`: Path to `yq` (default: `yq`).
    * `TAR_CMD`: Path to `tar` (default: `tar`).
    * `RSYNC_CMD`: Path to `rsync` (default: `rsync`).
    * `DOCKER_CMD`: Command for Docker Compose (default: `docker compose`).
    * `PG_DUMP_CMD`: Path to `pg_dump` (default: `pg_dump`).
    * `MYSQL_DUMP_CMD`: Path to `mysqldump` (default: `mysqldump`).
    * `MSMTP_CMD`: Path to `msmtp` (default: `msmtp`).
    * `DEFAULT_ADMIN_EMAIL`: Default email for notifications (e.g., `admin+backup@example.org`).
    * `DEFAULT_PLUGIN_DIR`: Default directory for plugins (e.g., `/opt/backup/lib/plugins`).
    * `DEFAULT_MIN_FREE_SPACE_MB`: Default minimum free disk space in MB (e.g., `500`).
    * `DEFAULT_KEEP_DAYS`: Default number of days to keep old backups (e.g., `7`).
    * `LOG_LEVEL`: Default logging verbosity (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG). Default is `2`.

### 6.2 Client Configuration File (`client_config.yml`)

* **Location:** `/etc/backup/client_config.yml`
* **Format:** YAML
* **Permissions:** MUST be `600` owned by `root`. The script verifies this.
* **Purpose:** Defines client-specific settings that override or supplement those in `common_config`.
* **Key Parameters:**
    * `base_backup_dir` (Mandatory): String. Absolute path on this client where temporary working directories are created and final TAR archives are stored (e.g., `/var/tmp/backups`). This directory must exist and be writable by root. The script will attempt to set group ownership and permissions to allow the `BACKUP_USER` (via `BACKUP_GROUP`) to manage files in the `done/` subdirectory for server-side cleanup.
    * `backup_user` (Mandatory): String. System username that should own the final TAR archive file (e.g., `backup-ld`). This user must exist.
    * `backup_group` (Mandatory): String. System group for the final TAR archive (e.g., `backup-ld`). This group must exist, and `backup_user` should typically be a member of this group.
    * `admin_email` (Mandatory): String. Email address for sending error reports from this client. Overrides `DEFAULT_ADMIN_EMAIL` from `common_config`.
    * `keep_days` (Mandatory): Integer. How many days to keep old backup TAR archives on this client. Must be a positive integer. Overrides `DEFAULT_KEEP_DAYS`.
    * `plugin_dir` (Optional): String. Absolute path to the directory where plugin scripts (`*.sh`) are located. Overrides `DEFAULT_PLUGIN_DIR` from `common_config`.
    * `email_subject_prefix` (Optional): String. Prefix for error email subjects (e.g., `[ClientBackupError]`). Defaults to `[Backup Error]`.
    * `hostname` (Optional): String. Hostname to use in error emails. Defaults to the output of `hostname -f`.
    * `min_free_space_mb` (Optional): Integer. Minimum free disk space in MB required in `base_backup_dir`'s filesystem before starting and after major operations. Overrides `DEFAULT_MIN_FREE_SPACE_MB`.
    * `log_level` (Optional): Integer (`0`-`3`). Sets the logging verbosity for this client script. Overrides `LOG_LEVEL` from `common_config`. `3` is equivalent to the `-v` command-line flag.
    * `tools` (Optional): YAML map. Allows overriding specific tool paths defined in `common_config`.
        * `yq_cmd`: Path to `yq`.
        * `tar_cmd`: Path to `tar`.
        * (*... and other tool commands like rsync_cmd, docker_cmd, etc.*)
* **Example `client_config.yml`:**
    ``` yaml
    base_backup_dir: "/mnt/backup_staging"
    backup_user: "backupuser"
    backup_group: "backupgroup"
    admin_email: "client01-alerts@example.com"
    keep_days: 10
    plugin_dir: "/opt/custom_backup_plugins" # Optional override
    min_free_space_mb: 1024
    log_level: 2 # INFO level
    tools:
      yq_cmd: "/usr/local/bin/yq"
    ```

### 6.3 Service Configuration (`service.yaml`)

* **Location:** `/etc/backup/<service_type>/<service_name>/service.yaml` (e.g., `/etc/backup/docker/my_app/service.yaml`).
* **Format:** YAML.
* **Permissions:** MUST be `600` owned by `root`. The script verifies this.
* **Purpose:** Defines the specific backup tasks for a single service (e.g., a web application, a database).
* **Key Parameters:**
    * `service.name` (Mandatory): String. A unique name for this service instance. Used in log messages and potentially in directory structures within the backup.
    * **Task Blocks:** One or more top-level keys that match a `plugin_handles_task_type` string from an available plugin (e.g., `docker`, `postgresql`, `files`). Under each task key, plugin-specific parameters are defined.
* **Example:** See the "General Plugin Configuration" section in `plugins/README.md` or specific plugin examples in that file.

### 6.4 Plugin Configuration

* Plugins are configured within the task blocks of a `service.yaml` file.
* Refer to the `plugins/README.md` for a detailed description of each available plugin, its purpose, and its specific configuration options.

## 7. Usage

### 7.1 Command Line Options

* `-d`, `--dry-run`: Simulate backup. No actual changes are made, services are not stopped/started, files are not created/deleted, and emails are not sent. Intended actions are logged.
* `-v`, `--verbose`: Enable verbose output (sets `LOG_LEVEL` to `3` for DEBUG messages).
* `-h`, `--help`: Display the help message and exit.
* `-V`, `--version`: Display the script version and exit.

### 7.2 Manual Execution

To run a backup manually, execute the script as root:
``` bash
sudo /opt/backup/bin/local_backup.sh
```

For verbose output during a manual run:
``` bash
sudo /opt/backup/bin/local_backup.sh -v
```

To simulate a backup run (dry run) with verbose output:
``` bash
sudo /opt/backup/bin/local_backup.sh --dry-run --verbose
```

Check the temporary log file (path logged at script startup, typically `/tmp/local_backup_log.*`) for detailed logs. If the script exits immediately with an error, check for issues with script instance locking (see Section 11.1) or very early configuration parsing errors.

### 7.3 Automated Execution (Systemd Timer)

The recommended way to automate backups is using the provided systemd timer and service units.

1.  **Enable & Start Timer:** After package installation, the units should be in `/lib/systemd/system/`. Enable and start the timer:
    ``` bash
    sudo systemctl enable --now local-backup.timer
    ```
2.  **Check Status:**
    ``` bash
    sudo systemctl status local-backup.timer
    sudo systemctl status local-backup.service
    ```
3.  **View Logs:** Logs from systemd-triggered runs are typically available via `journalctl`:
    ``` bash
    sudo journalctl -u local-backup.service
    # For more detail or to follow logs:
    sudo journalctl -f -u local-backup.service
    ```
4.  **Customize Timer/Service:**
    * To change the schedule, edit `/etc/systemd/system/local-backup.timer` (if you copied it there for overrides) or create an override file. The default is usually daily around 3 AM.
    * To add options like `--verbose` to the script execution or set resource limits, create an override for `local-backup.service`:
        ``` bash
        sudo systemctl edit local-backup.service
        ```
        Then add your changes, for example:
        ``` ini
        [Service]
        ExecStart=
        ExecStart=/opt/backup/bin/local_backup.sh --verbose
        # CPUQuota=50%
        # MemoryMax=1G
        ```
    * Remember to run `sudo systemctl daemon-reload` and `sudo systemctl restart local-backup.timer` after making changes to unit files.

## 8. Backup Process & Archive

The client-side backup process, orchestrated by `local_backup.sh`, involves several key steps:

1.  **Script Instance Lock:** Acquires an exclusive lock using `flock` (typically on `/var/run/local_backup.sh.lock`) to prevent multiple instances of `local_backup.sh` from running concurrently.
2.  **Initialization:** Sets up logging, traps for error handling and cleanup (SIGINT, SIGTERM, ERR, EXIT).
3.  **Configuration Loading:** Loads `/etc/backup/common_config` and then `/etc/backup/client_config.yml`. Performs syntax checks and validates critical parameters.
4.  **Directory Setup:** Ensures `BASE_BACKUP_DIR` exists and sets appropriate permissions for it and its `done/` subdirectory to allow the backup server (via `BACKUP_GROUP`) to manage archives later.
5.  **Plugin Discovery:** Scans the configured `PLUGIN_DIR` for executable `*.sh` plugin files.
6.  **Temporary Working Directory:** Creates a unique, secure temporary working directory within `BASE_BACKUP_DIR` (e.g., `/var/tmp/backups/backup.local_backup.sh.XXXXXX`).
7.  **Initial Disk Space Check:** Verifies sufficient free disk space in `BASE_BACKUP_DIR`.
8.  **Service Processing Loop:** For each `service.yaml` file found under `/etc/backup/`:
    * A service-specific subdirectory is created within the temporary working directory.
    * The `service.yaml` is parsed to identify task types (e.g., `docker`, `files`, `postgresql`).
    * **Validation Stage:** The `_handle_validation_stage` function calls `plugin_validate_config` for each relevant plugin.
    * **Preparation Stage:** The `_handle_prepare_stage` function calls `plugin_prepare_backup` for relevant plugins (Docker plugin's prepare runs first). Plugins may create state files in their service's `.state/` subdirectory.
    * **Run Stage:** The `_handle_run_stage` function calls `plugin_run_backup` for each plugin. Backup data is written by plugins into their designated subdirectories within the service's backup directory. A disk space check is performed after each plugin's run.
    * **Post-Success Stage:** The `_handle_post_success_stage` function calls `plugin_post_backup_success` for plugins whose prepare step ran successfully (Docker plugin's post-success runs last). Plugins clean up their state files.
9.  **Shared Directory Lock (TAR Creation):** Before creating the final TAR archive, the script attempts to acquire a directory-based lock (`.backup_archive_in_progress.lock`) within `BASE_BACKUP_DIR`. This prevents the backup server from trying to fetch an incomplete archive. If the lock cannot be acquired after retries, the script exits with an error and sends an email.
10. **TAR Archive Creation:** If not in `--dry-run` mode:
    * The entire content of the temporary working directory (excluding `*/.state/` directories) is archived into a compressed TAR file named `<CLIENT_HOSTNAME>-<YYYYMMDD_HHMMSS>.tar.gz`.
    * The archive is created with preserved permissions and numeric owner/group IDs (`--numeric-owner -p`).
    * The final TAR archive is owned by `BACKUP_USER:BACKUP_GROUP` and has `600` permissions.
11. **TAR Archive Verification:** If not in `--dry-run` mode, the integrity of the created `.tar.gz` file is verified using `gzip -t` and `tar -tf`. If verification fails, the script exits with an error, and the corrupt archive is deleted.
12. **Shared Directory Lock Release:** The `.backup_archive_in_progress.lock` directory is removed.
13. **Cleanup (Old Backups):** Old TAR archives in `BASE_BACKUP_DIR` (older than `KEEP_DAYS`) and any stale temporary working directories are deleted (or listed if in `--dry-run` mode).
14. **Final Cleanup (EXIT Trap):** The temporary working directory (`work_dir`) and the temporary log file (`tmp_log_file` on success) are removed. The script instance lock (`flock`) is released automatically when the script exits.

## 9. Plugin System Details

The client script uses a plugin architecture to perform backups of different services.

### 9.1 Data Passing

Configuration specific to a plugin's task (defined in a `service.yaml` file) is extracted by the core script and written to a temporary file. The path to this temporary file is then passed as the first argument (`$1`) to the plugin's `plugin_validate_config`, `plugin_prepare_backup`, `plugin_run_backup`, and `plugin_post_backup_success` functions. Plugins use `yq` (via `${YQ_CMD}` or the `get_yaml_value` common function) to parse this file.

### 9.2 State Management

Plugins that modify the state of a service (e.g., stopping a Docker container via `docker_compose.sh`) use state files to manage this.
* **Location:** State files are stored in a `.state/` subdirectory within the service's specific temporary backup directory (e.g., `$WORK_DIR/<type>/<service>/.state/`).
* **Purpose:**
    * `plugin_prepare_backup` creates state files if it changes system state (e.g., `docker_stopped`, `service_context_for_restart`).
    * `plugin_post_backup_success` checks these state files to correctly reverse actions taken during preparation and then removes the state files.
    * `plugin_emergency_cleanup` (called by the main script's `EXIT` trap) also checks these state files to attempt to restore a service to a running state if the backup failed mid-process.
* The `.state/` directories themselves are **excluded** from the final TAR archive.

### 9.3 Dependency Handling & Stages

The core script orchestrates plugin execution through distinct internal "stage handler" functions:
1.  `_handle_validation_stage`: Calls `plugin_validate_config` for all plugins relevant to a service.
2.  `_handle_prepare_stage`: Calls `plugin_prepare_backup`. Docker plugin's prepare (if any) runs first.
3.  `_handle_run_stage`: Calls `plugin_run_backup` for all plugins.
4.  `_handle_post_success_stage`: Calls `plugin_post_backup_success`. Docker plugin's post-success (if any) runs last.

This provides a simplified, fixed order for dependency management, primarily ensuring Docker containers can be stopped before their data is accessed and restarted after.

## 10. Error Handling and Email Reporting

* The script uses `set -e` (within the `main` function, after traps are set) to exit immediately if a command fails.
* An `ERR` trap captures the line number, failed command, and function call stack for logging and email reporting.
* An `EXIT` trap ensures cleanup actions (like removing temporary files and the shared directory lock) are always performed. It also triggers emergency cleanup functions in plugins if necessary and sends a detailed error email if the script did not exit successfully (and not in `--dry-run` mode).
* Specific email notifications are also sent for persistent shared directory lock failures.
* Plugins are expected to return non-zero exit codes on failure, which will be caught by `set -e` in the core script.

## 11. Locking Mechanisms

The script employs two types of locking to ensure data integrity and prevent conflicts:

### 11.1 Script Instance Locking (`flock`)

* **Purpose:** To prevent multiple instances of `local_backup.sh` from running simultaneously on the same client.
* **Mechanism:** Uses `flock` on a lock file (default: `/var/run/local_backup.sh.lock`). The script attempts to acquire an exclusive, non-blocking lock. If the lock cannot be acquired, it means another instance is running, and the script exits immediately with an error message.
* **Release:** The `flock` is automatically released when the script exits (as the file descriptor associated with the lock is closed).

### 11.2 Shared Directory Lock (TAR Creation)

* **Purpose:** To prevent the `backup_server.sh` script (running on the backup server) from attempting to download a TAR archive while `local_backup.sh` is still in the process of creating or verifying it. This ensures the server does not fetch an incomplete or corrupt file.
* **Mechanism:**
    * **Lock Acquisition:** Before starting the final TAR archive creation (after all plugin tasks for all services are complete), `local_backup.sh` attempts to create a lock directory named `.backup_archive_in_progress.lock` inside the `BASE_BACKUP_DIR`. The `mkdir` command is atomic, meaning it will succeed for only one process if multiple try simultaneously.
    * **Retries:** If the lock directory already exists, the script waits for a configurable delay (`SHARED_LOCK_RETRY_DELAY_SECONDS`, default 60s) and retries a configurable number of times (`SHARED_LOCK_RETRY_COUNT`, default 3).
    * **Failure to Acquire Lock:** If the lock cannot be acquired after all retries, `local_backup.sh` logs a critical error, sends a specific email notification indicating the lock conflict, and exits with an error code. This prevents it from creating a TAR file that might conflict with server operations.
* **Lock Release:** The lock directory (`.backup_archive_in_progress.lock`) is reliably removed by the `EXIT` trap in `local_backup.sh`. This ensures the lock is released upon successful completion of TAR creation and verification, or if an error occurs during these final stages, or if the script is terminated by a signal.

## 12. Security Considerations

### 12.1 Passwords

* **No Plaintext in Configs:** Database passwords are **not** stored in `service.yaml` files.
* **Best Practice:** Use standard, secure credential files readable only by `root`:
    * PostgreSQL: `/root/.pgpass` (permissions `600`)
    * MariaDB/MySQL: `/root/.my.cnf` (permissions `600`, with credentials in a `[client]` or `[mysqldump]` section).
    * Plugins for these databases are designed to use these files.

### 12.2 File Permissions

* **Scripts & Plugins:** Should be owned by `root` and have permissions `700` or `755` (`/opt/backup/`).
* **Configuration Directory:** `/etc/backup/` should ideally be `700 root:root`.
* **Configuration Files:** `common_config`, `client_config.yml`, and all `service.yaml` files **MUST be `600 root:root`**. The script performs checks on these.
* **Database Credential Files:** `/root/.pgpass` and `/root/.my.cnf` **MUST be `600 root:root`**. Plugins may check or advise on this.
* **Temporary Working Directory (`work_dir`):** Created with `700 root:root` permissions. Files created by plugins within their service-specific subdirectories will generally inherit permissions based on `umask` or how the plugin creates them.
* **`BASE_BACKUP_DIR`:** The script ensures this directory exists. Permissions are set to allow the `BACKUP_GROUP` write access (typically `u=rwx,g=rwx,o-rwx` or `770`) so that the `backup_server.sh` (running as a user in `BACKUP_GROUP` on the client, or having SSH access as such) can manage files in the `done/` subdirectory.
* **`done/` Directory:** Created under `BASE_BACKUP_DIR` with ownership `BACKUP_USER:BACKUP_GROUP` and permissions `775` (`u=rwx,g=rwx,o=rx`) to allow the server (via SSH as `BACKUP_USER` or a user in `BACKUP_GROUP`) to move archives into it and list/delete older ones.
* **Final TAR Archive:** Owned by `BACKUP_USER:BACKUP_GROUP` with `600` permissions.
* **Lock File (`.backup_archive_in_progress.lock`):** Created as a directory by `root`.
* **`source` Command Risk:** `common_config` is sourced. Strict `600 root:root` permissions are critical to prevent arbitrary code execution if this file is compromised.

## 13. Extensibility (Adding Plugins)

New backup types can be supported by creating new plugin scripts in the `PLUGIN_DIR`. Refer to `plugins/CONTRIBUTING.md` for the plugin API specification and development guidelines.

## 14. Troubleshooting

* **Logs First:** Always check the temporary log file (path logged at script startup, typically `/tmp/local_backup_log.*`, kept on error) and systemd journal (`journalctl -u local-backup.service`) for detailed error messages.
* **Dry Run:** Use `sudo /opt/backup/bin/local_backup.sh -v -d` to test configuration and workflow without making changes.
* **Plugin Issues:**
    * Check verbose logs (`-v` or `LOG_LEVEL=3`).
    * Verify plugin script permissions (must be executable).
    * Ensure the task type key in `service.yaml` matches what the plugin's `plugin_handles_task_type` function expects.
    * Confirm `plugin_validate_config` passes for the plugin.
    * Check for state files in `$WORK_DIR/<type>/<service>/.state/` if a service is not restarting correctly.
    * Ensure `common_functions.sh` is correctly sourced by the plugin.
* **YAML Issues:**
    * Validate syntax using `yq . /path/to/service.yaml`.
    * Check for correct keys, values, and data types as expected by the plugins.
    * Ensure file permissions are `600 root:root`.
* **`yq` Not Found / Version:** Ensure `yq` v4+ is installed and in the `PATH` for the root user or the systemd service environment.
* **Script Not Running / Lock Errors:**
    * Verify root privileges.
    * **Instance Lock (`flock`):** Check for error messages related to `/var/run/local_backup.sh.lock`. If stale, it might need manual removal (though `flock` usually handles this well).
    * **Shared Directory Lock (`.backup_archive_in_progress.lock`):** If TAR creation fails due to this lock, check `BASE_BACKUP_DIR` for a directory named `.backup_archive_in_progress.lock`. A previous run might have failed to clean it up, or the backup server might be actively trying to access files.
* **Manual Run:** `sudo /opt/backup/bin/local_backup.sh -v` is the best way to see detailed output.
* **Permissions:** Double-check permissions for all scripts, plugins, configuration files, `BASE_BACKUP_DIR`, `done/` directory, and database credential files. Ensure `BACKUP_USER` and `BACKUP_GROUP` exist and have appropriate memberships if relevant for accessing `BASE_BACKUP_DIR/done/`.
* **Configuration Values:** Verify paths, numeric values, and email addresses in `common_config` and `client_config.yml`.
* **Tool Paths:** Ensure all necessary command-line tools (tar, gzip, rsync, pg_dump, etc.) are installed and their paths are correctly specified in the configuration if not in the standard `PATH`.

## 15. Suggestions / Potential Improvements

* **TAR Archive Checksum:**
    * After creating the `.tar.gz` archive, generate a checksum file (e.g., SHA256) and store it alongside the archive (e.g., `<archive_name>.sha256`).
    * This checksum can then be used by the `backup_server.sh` script to verify the integrity of the archive after download.
* **Plugin-Specific Dry-Run Output:** Enhance plugins to provide more detailed output during a `--dry-run` about what files/commands *would* have been processed/executed.
* **Resource Limiting for Plugins:** While systemd offers global limits, individual plugins performing intensive operations could internally use `nice`/`ionice` if specific tasks need lower priority, configurable via `service.yaml`.
* **Backup Multiple Databases of Same Type:** Extend database plugins to accept a list of database configurations within a single service's YAML.
* **Flexible Plugin Output Paths:** Allow plugins to specify a subdirectory within the service's temporary backup directory via their YAML configuration.
* **Pre/Post Task Hooks:** Allow defining pre-task and post-task shell commands directly in the `service.yaml` for a specific plugin execution.

## 16. License Information

This script is licensed under the **GNU Affero General Public License v3.0 or later**.
``` license
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
