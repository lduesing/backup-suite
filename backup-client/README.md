# Local Backup Script

**Version:** 0.1
**License:** AGPL-3.0-or-later
**Author:** Lars Duesing [<lars.duesing@camelotsweb.de>](mailto:lars.duesing@camelotsweb.de)
**Date:** 2025-05-02

## Table of Contents

1.  [Description](#description)
2.  [Architecture Overview](#architecture-overview)
3.  [Features](#features)
4.  [Prerequisites](#prerequisites)
5.  [Installation](#installation)
6.  [Configuration](#configuration)
    * [Central Configuration File (`config`)](#central-configuration-file-config)
    * [Service Configuration (`service.yaml`)](#service-configuration-serviceyaml)
    * [Plugin Configuration](#plugin-configuration)
7.  [Usage](#usage)
    * [Command Line Options](#command-line-options)
    * [Manual Execution](#manual-execution)
    * [Automated Execution (Systemd Timer)](#automated-execution-systemd-timer)
8.  [Backup Process & Archive](#backup-process--archive)
9.  [Plugin System Details](#plugin-system-details)
    * [Data Passing](#data-passing)
    * [State Management](#state-management)
    * [Dependency Handling](#dependency-handling)
10. [Error Handling and Email Reporting](#error-handling-and-email-reporting)
11. [Important Notes on Docker](#important-notes-on-docker)
12. [Security Considerations](#security-considerations)
    * [Passwords](#passwords)
    * [File Permissions](#file-permissions)
13. [Extensibility (Adding Plugins)](#extensibility-adding-plugins)
14. [Troubleshooting](#troubleshooting)
15. [Suggestions / Potential Improvements](#suggestions--potential-improvements)
16. [License Information](#license-information)


## 1. Description

This project provides a **modular and extensible** local backup solution for Debian-based Linux systems, using a **core orchestrator script** (`local_backup.sh`) and **plugins**. Configuration is managed through a central `config` file and per-service `service.yaml` files in the `/etc/backup/` directory.

The core script handles setup, locking, discovering services/plugins, calling plugin functions based on YAML task definitions (passing config via **temporary files**), creating the final TAR archive, verification, cleanup, and error reporting. Plugins implement specific backup logic and manage intermediate state (like Docker stop/start) via **state files**. A simplified **dependency order** (Docker stop first, Docker start last) is enforced. A **dry-run mode** allows testing configuration and flow.

## 2. Architecture Overview

* **Core Script (`/opt/backup/bin/local_backup.sh`):** Orchestrator.
* **Plugins (`/opt/backup/lib/plugins/*.sh`):** Handle specific tasks. Implement standard interface. See `plugins/README.md`.
* **Central Config (`/etc/backup/config`):** Global settings.
* **Service Config (`/etc/backup/<type>/<service>/service.yaml`):** Defines tasks/parameters per service using YAML. Parsed by `yq`.
* **Common Functions (`plugins/common_functions.sh`):** Shared utilities (e.g., logging, permission checks).

## 3. Features

* **Modular Plugin Architecture:** Extensible via plugins.
* **YAML Service Configuration:** Clear, structured definition per service.
* **Plugin Autodiscovery:** Core automatically finds plugins.
* **Task Autodiscovery:** Plugins run based on keys in `service.yaml`.
* **Robust Data Passing:** Config passed to plugins via temporary files.
* **Plugin State Management:** Uses temporary state files for coordinated actions.
* **Simplified Dependency Handling:** Executes plugin stages in fixed order (Docker stop first, start last).
* **File Locking:** Prevents concurrent runs via `flock` (using FD 200).
* **Central Configuration:** Global settings managed centrally.
* **Enhanced Configuration Validation:** Checks configs and permissions.
* **(Plugin) Database Backups:** Handled by plugins (e.g., `postgresql.sh`), requires secure credential files (`~/.pgpass`). Uncompressed dumps.
* **(Plugin) File Backups:** Handled by plugins (e.g., `files_rsync.sh`) with relative paths & separate `exclude:` list.
* **(Plugin) Docker Support:** Handled by plugins (e.g., `docker_compose.sh`) for config backup, stop/start, per-service wait time.
* **Dry-Run Mode (`--dry-run`):** Simulates backup without data modification.
* **Secure Temporary Directory:** Uses `mktemp -d`.
* **TAR Archiving & Verification:** Creates/verifies final `.tar.gz`, preserves perms/ownership, owned by `BACKUP_USER:BACKUP_GROUP`, file perms `600`. Excludes plugin `.state` directories.
* **Restricted Permissions:** Temp dir (`700`), final TAR (`600`). Checks config perms (`600`).
* **Timestamped Archive:** Final archive name includes hostname and timestamp.
* **Disk Space Check:** Basic checks after *each* backup task (DBs, files).
* **Error Reporting:** Detailed email reports via `msmtp` on failure (skipped in dry-run).
* **Robustness:** `set -e`, detailed error traps (`ERR`, `EXIT`).
* **Automatic Cleanup:** Manages old backups and temporary files/directories via EXIT trap (cleanup skipped in dry-run).
* **Command Line Options:** `-v`/`--verbose`, `-h`/`--help`, `-V`/`--version`, `-d`/`--dry-run`.
* **Shell Style:** Adheres to Google Shell Style Guide principles.
* **Systemd Integration:** Example units provided.
* **AGPLv3 License:** Free and open-source software.

## 4. Prerequisites

* **OS:** Debian-based Linux.
* **Shell:** Bash (v4+ recommended).
* **YAML Parser:** **`yq` version 4+** (REQUIRED).
* **Core Tools:** `bash`, `find`, `mkdir`, `chmod`, `chown`, `date`, `grep`, `cut`, `sed`, `tee`, `mktemp`, `dirname`, `basename`, `gzip`, `tar`, `realpath`, `command`, `id`, `getent`, `getopt`, `stat`, `df`, `tail`, `flock`.
* **Backup Tool:** `rsync` (if using `files_rsync.sh`).
* **DB Clients (Optional):** As required by DB plugins.
* **Docker (Optional):** `docker` engine, `docker compose` (v2 recommended).
* **Email Client (Optional):** `msmtp`, `msmtp-mta` (configured).
* **Permissions:** Script MUST be run as **`root`**.
* **Backup User/Group:** `BACKUP_USER` and `BACKUP_GROUP` from `config` MUST exist.

**Install required packages (Example for Debian/Ubuntu):**

```bash
# Install yq v4+ (check official install instructions for your distro)
# Example (might need adjustment):
# sudo wget [https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64](https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64) -O /usr/bin/yq && sudo chmod +x /usr/bin/yq

sudo apt update
sudo apt install -y util-linux rsync postgresql-client mariadb-client msmtp msmtp-mta gzip tar coreutils uidmap yq # Added yq, getent is part of libc
# Ensure Docker and Compose v2 are installed if needed
```

## 5. Installation

1.  **Create Base Config Directory:**

    ```bash
    sudo mkdir -p /etc/backup
    sudo chown root:root /etc/backup
    sudo chmod 700 /etc/backup
    ```

2.  **Create Central `config` File:** Create `/etc/backup/config` (see [Section 5.1](#central-configuration-file-config)). Set permissions:

    ```bash
    # Create/Edit the file
    sudo chown root:root /etc/backup/config
    sudo chmod 600 /etc/backup/config
    ```

3.  **Copy Core Backup Script:**

    ```bash
    sudo cp local_backup.sh /opt/backup/bin/local_backup.sh
    sudo chown root:root /opt/backup/bin/local_backup.sh
    sudo chmod 700 /opt/backup/bin/local_backup.sh
    ```

4.  **Create Plugin Directory and Copy Plugins:**

    ```bash
    # Get PLUGIN_DIR path from central config or use default
    PLUGIN_DIR_PATH=$(grep '^PLUGIN_DIR=' /etc/backup/config | cut -d'"' -f2)
    PLUGIN_DIR_PATH="${PLUGIN_DIR_PATH:-/opt/backup/lib/plugins}" # Use default if not set

    sudo mkdir -p "$PLUGIN_DIR_PATH"
    # Copy common_functions.sh first
    sudo cp plugins/common_functions.sh "$PLUGIN_DIR_PATH/"
    # Copy actual plugins
    sudo cp plugins/docker_compose.sh "$PLUGIN_DIR_PATH/"
    sudo cp plugins/files_rsync.sh "$PLUGIN_DIR_PATH/"
    sudo cp plugins/postgresql.sh "$PLUGIN_DIR_PATH/"
    # Copy plugin README
    sudo cp plugins/README.md "$PLUGIN_DIR_PATH/"

    # Set permissions
    sudo chown -R root:root "$PLUGIN_DIR_PATH"
    sudo chmod 700 "$PLUGIN_DIR_PATH"      # Directory readable/executable by root
    sudo chmod 700 "$PLUGIN_DIR_PATH"/*.sh # Plugins executable by root
    sudo chmod 600 "$PLUGIN_DIR_PATH/common_functions.sh" # Common functions not executable
    sudo chmod 644 "$PLUGIN_DIR_PATH/README.md" # README readable
    ```

5.  **(Optional) Copy Main README:**

    ```bash
    sudo cp README.md /etc/backup/README.md
    sudo chown root:root /etc/backup/README.md
    sudo chmod 644 /etc/backup/README.md
    ```

6.  **Create Service Configurations:** Create type/service directories under `/etc/backup/` and place a `service.yaml` file inside each. Ensure dirs `700`, YAML files `600`.

7.  **Setup Systemd Units:** See [Section 6.3](#automated-execution-systemd-timer).

8.  **Setup Secure DB Credentials:** Configure `/root/.pgpass` or `/root/.my.cnf` with `600` permissions.

## 6. Configuration

### Central Configuration File (`config`)

Location: `/etc/backup/config`. Format: `KEY="VALUE"`. Permissions MUST be `600 root:root`.

* `BASE_BACKUP_DIR` (Mandatory): Path for temp dirs & final TARs. Must exist, writable by root. **Note:** Admin manually sets perms (e.g., `750`) if `BACKUP_GROUP` needs directory access. Script attempts `g+rx`.
* `BACKUP_USER` (Mandatory): User owning final `.tar.gz`. Must exist.
* `BACKUP_GROUP` (Mandatory): Group for final `.tar.gz`. Must exist.
* `EMAIL_RECIPIENT` (Mandatory): Email for error reports.
* `KEEP_DAYS` (Mandatory): Days to keep old TARs (positive integer).
* `PLUGIN_DIR` (Mandatory): Absolute path to plugin scripts (`*.sh`). Must exist.
* `EMAIL_SUBJECT_PREFIX` (Optional): Default `[Backup Error]`.
* `HOSTNAME` (Optional): Default `hostname -f`.
* `DOCKER_COMMAND` (Optional): Default `docker compose`.
* `MIN_FREE_SPACE_MB` (Optional): Default 500 (non-negative integer).
* `YQ_CMD`, `TAR_CMD`, etc. (Optional): Override tool paths.

### Service Configuration (`service.yaml`)

Location: `/etc/backup/<type>/<service_name>/service.yaml`. Permissions ideally `600 root:root` (checked by script).

* Uses YAML format. Requires `yq` v4+.
* **`service.name` (Mandatory):** Unique service name.
* **Top-level keys (Task Types):** Match task types handled by plugins (e.g., `docker`, `postgresql`, `files`).
* **Task Content:** Nested keys/values provide parameters for the plugin. Refer to `plugins/README.md` or specific plugin source code.

**Example `service.yaml` (Tandoor Recipes):**

```yaml
---
service:
  name: "tandoor_recipes"
docker:
  docker_compose_path: "/opt/tandoor/docker-compose.yml"
  wait_after_restart: 30 # Optional wait in seconds
postgresql:
  host: "localhost"
  user: "tandoor"
  database: "tandoor"
  # Use /root/.pgpass for password
files:
  # Mandatory list of paths to include
  paths:
    - "/opt/tandoor/mediafiles/"
    - "/opt/tandoor/staticfiles/"
  # Optional list of rsync exclude patterns
  exclude:
    - "cache/"
    - "*.log"
```

### Plugin Configuration

Plugins receive parameters from the relevant section in `service.yaml` via a temporary file path passed as the first argument to their functions. See `plugins/README.md`.

## 7. Usage

### Command Line Options

* `-d`, `--dry-run`: Simulate backup without changing data/creating TAR/sending email/running docker stop|start/deleting old backups.
* `-v`, `--verbose`: Enable verbose output.
* `-h`, `--help`: Display help.
* `-V`, `--version`: Display version.

### Manual Execution

```bash
# Standard execution
sudo /opt/backup/bin/local_backup.sh

# Verbose execution
sudo /opt/backup/bin/local_backup.sh --verbose

# Dry run simulation
sudo /opt/backup/bin/local_backup.sh --dry-run -v
```

Check `/tmp/local_backup_log.*` for full logs. Check for `flock` errors if it exits immediately.

### Automated Execution (Systemd Timer)

1.  **Create/Place Unit Files:** Put `local-backup.service` and `local-backup.timer` in `/etc/systemd/system/`.
2.  **Customize:** Adjust `OnCalendar` and **carefully tune resource limits** in `.service` file. Add options like `--verbose` to `ExecStart` if needed.
3.  **Enable & Start:**

    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable local-backup.timer
    sudo systemctl start local-backup.timer
    ```

4.  **Check Status & Logs:**

    ```bash
    sudo systemctl status local-backup.timer
    sudo journalctl -u local-backup.service
    ```

## 8. Backup Process & Archive

1.  **Locking:** Acquires lock (`/var/run/local_backup.sh.lock`).
2.  **Initialization:** Setup, load/validate config, discover plugins, check root.
3.  **Temporary Directory:** Secure `backup.*.XXXXXX` created in `BASE_BACKUP_DIR`.
4.  **Validation:** Initial disk space check.
5.  **Service Processing:** For each `service.yaml`:
    * Parses YAML, finds tasks, identifies relevant plugins.
    * **Stage 1 (Validate):** Calls `plugin_validate_config`.
    * **Stage 2 (Prepare):** Calls `plugin_prepare_backup` (Docker stop first?). Plugins create state files. Skips actual actions in dry-run.
    * **Stage 3 (Run):** Calls `plugin_run_backup` (DB dump, rsync...). Checks disk space after each task. Skips actual work in dry-run.
    * **Stage 4 (Post-Success):** Calls `plugin_post_backup_success` (Docker start last? Incl. wait). Plugins remove state files. Skips actual actions/wait in dry-run.
6.  **Final Archive:** Contents of temp dir archived to `<BASE_BACKUP_DIR>/<HOSTNAME>-<TIMESTAMP>.tar.gz`, excluding `*/.state` dirs. Skips in dry-run.
7.  **TAR Ownership & Permissions:** Owner `BACKUP_USER:BACKUP_GROUP`, perms `600`. Skips in dry-run.
8.  **TAR Verification:** Checks integrity. Skips in dry-run. Fails script if corrupt.
9.  **Cleanup (via EXIT Trap):** Temp work dir and log file deleted (log kept on error).
10. **Cleanup (Old):** Old TAR archives and leftover temp dirs deleted based on `KEEP_DAYS`. Skips deletion in dry-run (just lists).
11. **Lock Release:** On script exit.

## 9. Plugin System Details

Refer to `//opt/backup/lib/plugins/README.md` for the plugin interface specification.

### Data Passing

Config sections from `service.yaml` are passed to plugin functions via a **temporary file path** (as `$1`). Plugins parse this file (e.g., using `yq`).

### State Management

Plugins requiring coordination (e.g., Docker stop/start) use **state files** located in a `.state` subdirectory within the service's temporary backup directory (`$service_backup_dir/.state/`).

### Dependency Handling

A **simplified, fixed execution order** is used: Validate All -> Prepare Docker -> Prepare Others -> Run All -> Post Others -> Post Docker.

## 10. Error Handling and Email Reporting

* `set -e` ensures exit on most errors.
* Validation/plugin/verification failures cause exit.
* `ERR` trap captures context.
* `EXIT` trap runs always: calls `plugin_emergency_cleanup` (using state files), sends detailed error email (via `msmtp`) unless `--dry-run`, cleans up temps (log kept on error), deletes corrupt TAR.

## 11. Important Notes on Docker

* Handled by `docker_compose.sh` plugin.
* Stop/Start triggered by `docker.docker_compose_path`. Skipped in dry-run. Uses state files.
* `docker.wait_after_restart` in YAML defines optional wait *after* start (also skipped in dry-run).
* **Internal Databases:** Use **filesystem volume backup** via the `files` plugin (add volume host path to `files.paths`). Do *not* configure a network DB dump.

## 12. Security Considerations

### Passwords

* **Plaintext Eliminated:** DB passwords **not** stored in YAML/`config`.
* **Best Practice:** Use standard credential files readable by `root`: **`/root/.pgpass`** (Perms `600`), **`/root/.my.cnf`** (Perms `600`). Plugins rely on these. **This is more secure** than storing passwords in config files (even with 600 perms) because it uses standard tool mechanisms and reduces accidental exposure points.

### File Permissions

* **Script & Plugins:** `700 root:root`.
* **Config Dir:** `700 root:root`.
* **Central Config & Service YAML:** **`600 root:root` (Checked)**.
* **DB Credential Files:** **MUST be `600 root:root`**. Checked by PostgreSQL plugin if present.
* **Temp Work Dir:** `700 root:root`. Files inside **keep original permissions**. Plugin state files `600`.
* **Final TAR Archive:** Belongs to `BACKUP_USER:BACKUP_GROUP`, permissions `600`.
* **Lock File:** `/var/run/local_backup.sh.lock` created by root.
* **`source` Command Risk:** Central `config` file sourced. Strict `600 root:root` permissions critical.

## 13. Extensibility (Adding Plugins)

Create `.sh` file in `PLUGIN_DIR`, make executable, implement functions per `plugins/README.md`.

## 14. Troubleshooting

* **Logs First:** Check `/tmp/local_backup_log.*`, Systemd Journal (`journalctl -u local-backup.service`), error emails.
* **Dry Run:** Use `sudo /opt/backup/bin/local_backup.sh -v -d` to test config/flow.
* **Plugin Issues:** Check verbose logs (`-v`). Check plugin perms (`700`). YAML task key? `plugin_validate_config` pass? State files (`<workdir>/<svc>/.state/`)? Check plugin logic/debug messages. Check if common_functions.sh was sourced correctly by plugin.
* **YAML Issues:** Validate syntax (`yq . service.yaml`). Check keys/values/perms (`600`). Check parameters expected by plugin (see `plugins/README.md`). Separate `paths:` and `exclude:` lists for `files` task.
* **`yq` Not Found / Version:** Ensure `yq` v4+ installed & in `PATH`.
* **Script not running / Lock Errors:** Check root privileges. Check `flock` errors. Check/remove lock file if stale.
* **Manual Run:** `sudo /opt/backup/bin/local_backup.sh -v`.
* **Permissions:** Verify script, configs, sources, `BASE_BACKUP_DIR`, `BACKUP_USER`/`GROUP` existence, DB cred files.
* **Configuration:** Check central `config` and `service.yaml` values. Numeric values correct? File paths exist?
* **Tools / Disk Space / TAR Verification / Docker / msmtp:** As before.
* **Validation Errors:** Check specific error message.

## 15. Suggestions / Potential Improvements

* **Plugin Dependencies:** Implement explicit dependency resolution (graph, topological sort).
* **Stale Lock File Handling:** More robust detection/handling.
* **Backup Verification:** More thorough verification options.
* **Signal Handling:** More graceful handling of `SIGTERM`/`SIGINT`.

## 16. License Information

This script is licensed under the **GNU Affero General Public License v3.0 or later**.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
