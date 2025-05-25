# Backup Server Script

**Version:** 0.2
**License:** AGPL-3.0-or-later
**Author:** Lars Duesing [<lars.duesing@camelotsweb.de>](mailto:lars.duesing@camelotsweb.de)
**Date:** May 25, 2025

## Table of Contents

1.  [Description](#1-description)
2.  [Features](#2-features)
3.  [Prerequisites](#3-prerequisites)
4.  [Installation](#4-installation)
5.  [Configuration (`server_config.yml` & `common_config`)](#5-configuration-server_configyml--common_config)
    * [5.1 Common Settings (`common_config`)](#51-common-settings-common_config)
    * [5.2 Server Specific Settings (`server_config.yml`)](#52-server-specific-settings-server_configyml)
        * [Global Server Settings](#global-server-settings)
        * [Restic Settings](#restic-settings)
        * [Host Definitions](#host-definitions)
6.  [Required Setup](#6-required-setup)
    * [6.1 Restic Repositories & Maintenance](#61-restic-repositories--maintenance)
    * [6.2 SSH Key Authentication & Host Key Verification](#62-ssh-key-authentication--host-key-verification)
    * [6.3 Password Files](#63-password-files)
7.  [Usage](#7-usage)
    * [7.1 Command Line Options](#71-command-line-options)
    * [7.2 Manual Execution](#72-manual-execution)
    * [7.3 Automated Execution (Systemd Timer)](#73-automated-execution-systemd-timer)
8.  [Workflow Details](#8-workflow-details)
9.  [Error Handling and Email Reporting](#9-error-handling-and-email-reporting)
10. [Locking Mechanisms](#10-locking-mechanisms)
    * [10.1 Script Instance Locking (`flock`)](#101-script-instance-locking-flock)
    * [10.2 Client-Side Archive Lock Check](#102-client-side-archive-lock-check)
11. [Security Considerations](#11-security-considerations)
12. [Troubleshooting](#12-troubleshooting)
13. [Suggestions / Potential Improvements](#13-suggestions--potential-improvements)
14. [License Information](#14-license-information)


## 1. Description

This script (`backup_server.sh`) runs on a central backup server and orchestrates the process of fetching pre-generated backup archives (`.tar.gz`) from multiple client hosts (prepared by `local_backup.sh` v1.2+ or similar) and backing up their contents into host-specific [Restic](https://restic.net/) repositories.

It reads its configuration from a central YAML file (`/etc/backup/server_config.yml`) and common settings from `/etc/backup/common_config`. The script applies Google Shell Style Guide principles and performs enhanced validation, including SSH connectivity checks, Restic repository initialization verification, and syntax checks for configuration files.

For each defined client host, it connects via SSH using key-based authentication (requiring manual host key verification beforehand). **Before fetching, it checks for a client-side lock file (`.backup_archive_in_progress.lock`) in the remote TAR directory with retries to avoid conflicts with ongoing client-side TAR creation.**

If the client is not locked, the script finds and downloads the latest backup archive, **unpacks it locally into a consistent per-host temporary directory (emptied before each use to ensure Restic sees consistent paths for deduplication)**, and then runs `restic backup` to store the unpacked data. A **dry-run mode** is available for testing. **A check is performed to avoid backing up data if a Restic snapshot with an identical or newer timestamp (based on the TAR file's timestamp tag) already exists.** The `restic backup` command now uses the `--host <client_hostname>` and `--ignore-inode` flags.

Upon successful Restic backup (in non-dry-run mode), the script remotely commands the client host to move the processed archive to a `done/` subdirectory and cleans up older archives there. If any step fails for a specific host, an email notification is sent (if configured, skipped in dry-run), and the script proceeds to the next host. A final summary email details the status of all hosts. File locking (`flock`) prevents concurrent script instances.

Restic repository maintenance (`forget`, `prune`, `check`) is handled by a **separate script and timer** (`restic_maintenance.sh`), which also supports email notifications on error, granular logging, and per-repository forget policies. Signal handling (SIGINT, SIGTERM) is implemented for graceful shutdown.

## 2. Features

* **Centralized Backup Orchestration:** Manages backups from multiple client hosts.
* **YAML & Shell Configuration:** Clear definition of global, Restic, and per-host settings.
* **Enhanced Configuration Validation:** Checks config values, file permissions, SSH connectivity, Restic repo initialization, and config file syntax.
* **Client-Side Lock Check:** Before fetching, checks for a `.backup_archive_in_progress.lock` file on the client in the `remote_tar_dir` with retries to avoid conflicts.
* **SSH/SCP Based Fetching:** Securely downloads backup archives using SSH keys (**manual host key verification required**).
* **Latest Archive Detection:** Finds the newest `<hostname>-<timestamp>.tar.gz` file on the client.
* **Consistent Unpack Directory:** Unpacks archives for a host always into the same path structure (`<local_temp_base_dir>/<sanitized_hostname>/unpacked_content/`), cleaning it first, for Restic path consistency.
* **Restic Newer Snapshot Check:** Before backing up, checks if the Restic repository already contains a snapshot with an identical or newer timestamp (based on the TAR file's timestamp tag). If so, skips the backup for that host and sends a warning email.
* **Restic `--host <client_hostname>`:** Explicitly sets the host for Restic snapshots.
* **Restic `--ignore-inode`:** Used during `restic backup`.
* **Preserves Permissions/Ownership:** Unpacks TAR archives using `--numeric-owner` and `-p`.
* **Restic Integration:** Backs up unpacked data into per-host Restic repositories using a password file.
    * Automatically tags backups with hostname and archive timestamp.
    * Supports custom `restic backup` options via config.
* **Restic Maintenance Separation:** Designed for use with `restic_maintenance.sh` (v0.4+) for `restic forget --prune` and `restic check`, now with its own error email reporting, granular logging, and per-repo forget policies.
* **Remote Cleanup:** Moves processed archives to `done/` dir on client, keeps only the latest there.
* **Per-Host Error Handling & Summary Email:** Continues processing other hosts if one fails. Sends a final summary email for the main backup run detailing successful, failed, and skipped hosts.
* **Email Notifications:** Sends detailed error reports for failed hosts, warnings for skipped hosts, and a final summary via `msmtp` (skipped in dry-run). Maintenance script also sends emails on its own errors.
* **File Locking:** Uses `flock` via FD 200 (backup) / FD 201 (maintenance) to prevent multiple script instances.
* **Secure Temporary Files:** Uses `mktemp` for temporary directories.
* **Dry-Run Mode (`--dry-run`):** Simulates the entire process without modifying Restic repos, remote files, or sending emails. Restic commands use `--dry-run`.
* **Granular Logging:** Supports ERROR, WARN, INFO, DEBUG levels controlled by config/verbose flag.
* **Signal Handling:** Graceful shutdown on SIGINT, SIGTERM for both main and maintenance scripts.
* **Systemd Integration:** Example `.service` and `.timer` units provided. Includes resource limit examples.
* **Shell Style:** Adheres to Google Shell Style Guide principles.
* **AGPLv3 License:** Free and open-source software.

## 3. Prerequisites

* **OS:** Debian-based Linux for the server.
* **Shell:** Bash (v4+ recommended).
* **Core Tools:** `bash`, `find`, `mkdir`, `chmod`, `chown`, `date`, `grep`, `cut`, `sed`, `tee`, `mktemp`, `dirname`, `basename`, `gzip`, `tar`, `realpath`, `command`, `id`, `getent`, `getopt`, `stat`, `df`, `tail`, `flock`.
* **YAML Parser:** **`yq` version 4+** (REQUIRED).
* **JSON Parser (Recommended):** `jq` for more reliable parsing of Restic JSON output (e.g., snapshot timestamps). If not found, the script falls back to `grep/sed/awk`.
* **Backup Tool:** **`restic`**.
* **Network Tools:** `ssh`, `scp` (from `openssh-client` package).
* **Email Client (Optional):** `msmtp`, `msmtp-mta` (configured).
* **Permissions:** Script MUST be run as **`root`**.
* **Restic Repositories:** Must be pre-initialized for each host.
* **SSH Keys:** Passwordless SSH key pairs configured, private keys stored securely (`600 root:root`), public keys on clients' `authorized_keys`. **Manual host key verification completed.**
* **Client-Side Script:** Clients must generate `<hostname>-<timestamp>.tar.gz` archives and implement the `.backup_archive_in_progress.lock` mechanism.

**Install required packages (Example for Debian/Ubuntu):**
``` bash
# Install yq v4+ (check official install instructions)
# Example: sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && sudo chmod +x /usr/bin/yq

# Install restic (check official restic docs)
# Example: sudo apt install restic

sudo apt update
sudo apt install -y util-linux rsync msmtp msmtp-mta gzip tar coreutils uidmap openssh-client yq restic jq
```

## 4. Installation
1. Install `backup-common` package.
2. Install `backup-server` package.
3. **Post-Installation Configuration:**
    * Review/Edit `/etc/backup/common_config`. Ensure `600 root:root`.
    * Create/Edit `/etc/backup/server_config.yml`. Ensure `600 root:root`.
    * Create Restic password file (e.g., `/etc/backup/restic.pass`). Ensure `600 root:root`.
    * Place SSH private keys (e.g., `/etc/backup/client_a_id_ed25519`). Ensure `600 root:root`.
    * Initialize Restic repositories for each host.
    * Perform manual SSH connection to each client as root to accept host keys.
    * Enable systemd timers: `sudo systemctl enable --now backup-server.timer restic-maintenance.timer`.

## 5. Configuration (`server_config.yml` & `common_config`)

### 5.1 Common Settings (`common_config`)

* **Location:** `/etc/backup/common_config`
* **Format:** Shell script (sourced variables)
* **Permissions:** `600 root:root`
* **Purpose:** Defines global defaults for tool paths (`YQ_CMD`, `RESTIC_CMD`, `SSH_CMD`, `JQ_CMD` etc.) and settings like `DEFAULT_ADMIN_EMAIL`, `LOG_LEVEL`. Syntax is checked with `bash -n` before sourcing.

### 5.2 Server Specific Settings (`server_config.yml`)

* **Location:** `/etc/backup/server_config.yml`
* **Format:** YAML
* **Permissions:** `600 root:root`
* **Purpose:** Defines server-specific settings and the list of client hosts. Syntax is checked with `yq .` before parsing.

#### Global Server Settings
(Located under the `global:` key)
* `local_temp_base_dir` (Mandatory): String. Path for temporary server work (e.g., `/var/tmp/backup_server_work`).
* `admin_email` (Optional): String. Default email for summary/failures (overrides `common_config`).
* `msmtp_cmd` (Optional): String. Path to `msmtp`.
* `yq_cmd` (Optional): String. Path to `yq`.
* `jq_cmd` (Optional): String. Path to `jq`.
* `email_subject_prefix` (Optional): String. Prefix for emails sent by `backup_server.sh` (default: `[Backup Server]`).
* `hostname` (Optional): String. Hostname for emails sent by `backup_server.sh` (defaults to `hostname -f`).
* `log_level` (Optional): Integer (`0`-`3`). Overrides `LOG_LEVEL` from `common_config` for this script.

#### Restic Settings
(Located under the `restic:` key)
* `repository_root` (Mandatory): String. Parent directory of per-host Restic repos (e.g., `/srv/restic_repos`).
* `password_file` (Mandatory): String. Path to Restic password file (permissions `600 root:root`).
* `restic_cmd` (Optional): String. Path to `restic` executable.
* `backup_options` (Optional): String. Additional options for `restic backup` (e.g., `"--compression max"`). Note: `--host <client_hostname>` and `--ignore-inode` are added automatically by the script.
* `maintenance:` (Optional): YAML map. Settings for `restic_maintenance.sh`.
    * `forget_policy` (Optional): String. Global `restic forget` arguments (Default: `--keep-daily 7 --keep-weekly 4 --keep-monthly 12 --keep-yearly 3`). Can be overridden per host.
    * `prune` (Optional): Boolean (`true` or `false`). Default: `true`.
    * `check` (Optional): Boolean (`true` or `false`). Default: `true`.
    * `check_options` (Optional): String. Additional options for `restic check` (e.g., `"--read-data-subset 10%"`).
    * `show_stats` (Optional): Boolean (`true` or `false`). Default: `false`. Whether to run `restic stats` during maintenance.
    * `admin_email` (Optional): String. Email for maintenance script failures.
    * `email_subject_prefix` (Optional): String. Prefix for maintenance emails (Default: `[Restic Maint]`).
    * `log_level` (Optional): Integer (`0`-`3`). Log level for the maintenance script.

#### Host Definitions
(Located under the `hosts:` key as a YAML list)
Each list item is a YAML map defining a client:
* `hostname` (Mandatory): String. FQDN or IP for SSH & Restic repo subdirectory name.
* `ssh_user` (Mandatory): String. Username on client.
* `ssh_key_file` (Mandatory): String. Path on *server* to private SSH key (`600 root:root`).
* `remote_tar_dir` (Mandatory): String. Path on *client* where backup TAR archives are located.
* `admin_email` (Optional): String. Host-specific notification email for *backup failures/warnings of this host*.
* `restic_forget_policy` (Optional): String. Per-host override for the Restic forget policy string (used by `restic_maintenance.sh`).

## 6. Required Setup


* **Restic Repositories:** Manually initialize a Restic repository for **each** client host under the `repository_root` directory specified in `server_config.yml`. Example:
  ``` bash
  export RESTIC_PASSWORD_FILE=/etc/backup/restic.pass
  sudo restic -r /srv/restic_repos/client-a.example.com init
  # Repeat for all clients
  unset RESTIC_PASSWORD_FILE
  sudo chown -R root:root /srv/restic_repos # Ensure root owns repo files
  ```
* **SSH Key Authentication:** Generate SSH key pairs. Copy the public key to each client's `~/.ssh/authorized_keys` file for the `ssh_user` defined for that host. Store the private key securely on the backup server (e.g., in `/etc/backup/keys/`) with `600 root:root` permissions.
* **SSH Host Key Verification (CRITICAL):** Manually connect via SSH *as root* from the server to *each client* **once** to verify and add the client's host key to root's `/root/.ssh/known_hosts` file:
  ``` bash
  sudo ssh -i /etc/backup/keys/client_a_id_ed25519 user@client-a.example.com 'echo Connected to client A'
  # ---> Verify fingerprint and type 'yes' <---
  ```
* **Password Files:** Ensure the Restic password file (specified by `restic.password_file` in `server_config.yml`) exists, contains only the Restic repository password, and has `600 root:root` permissions.


## 7. Usage

### 7.1 Command Line Options
* `-v`, `--verbose`: Enable verbose output (sets `LOG_LEVEL` to DEBUG).
* `-h`, `--help`: Display help.
* `-V`, `--version`: Display version.
* `-d`, `--dry-run`: Simulate run.

### 7.2 Manual Execution
``` bash
# Standard execution
sudo /opt/backup/bin/backup_server.sh

# Verbose dry run
sudo /opt/backup/bin/backup_server.sh -v --dry-run
```
Check `/tmp/local_backup_log.backup_server.sh.*` for full logs.

### 7.3 Automated Execution (Systemd Timer)
1.  **Enable & Start Timers:**
    ``` bash
    sudo systemctl enable --now backup-server.timer
    sudo systemctl enable --now restic-maintenance.timer
    ```
2.  **Check Status & Logs:**
    ``` bash
    sudo systemctl status backup-server.timer restic-maintenance.timer
    sudo journalctl -u backup-server.service
    sudo journalctl -u restic-maintenance.service
    ```

## 8. Workflow Details

For each host (unless `--dry-run`):
1.  **Locking & Initialization:** Acquires global script instance lock (`flock`), loads and validates configs.
2.  **SSH Connection Test:** Verifies basic SSH connectivity and key authentication to the client.
3.  **Client TAR Lock Check:** Via SSH, checks for the existence of `.backup_archive_in_progress.lock` in the client's `remote_tar_dir`. Retries a few times if found. If still locked, skips this client for the current run and sends a warning email.
4.  **Restic Repo Pre-check:** Verifies that the Restic repository for the host is initialized.
5.  **Find Remote TAR:** SSH finds latest `<hostname>-<timestamp>.tar.gz`.
6.  **Newer Snapshot Check:** Compares TAR timestamp (from its filename, used as a Restic tag) with the latest Restic snapshot for the host having the same timestamp tag. If TAR is not newer (or identical tag exists), logs warning, sends warning email (if not dry-run), and skips to next host.
7.  **Fetch TAR:** `scp` downloads TAR. *(Skipped in dry-run)*
8.  **Unpack TAR:** `tar -xpzf --numeric-owner` unpacks to a consistent, clean per-host temp dir. *(Skipped in dry-run)*
9.  **Restic Backup:** `restic backup --host <client_hostname> --ignore-inode` runs on content, tagging snapshot. *(Uses `--dry-run` if enabled)*
10. **Remote Cleanup (on Success):** SSH moves processed TAR on *client* to `done/`, removes older files there. *(Skipped in dry-run)*
11. **Local Cleanup:** Server's temp download and unpack dirs removed. *(Runs in dry-run too)*
12. **Loop/Error:** Continues to next host. Sends email on failure/warning for a specific host.
13. **Final Summary:** Logs success, skips, or list of failed hosts. Sends summary email. Exits non-zero if any host failed.
14. **Lock Release:** On script exit.

## 9. Error Handling and Email Reporting
* Host processing is isolated.
* Specific errors (SSH test, Restic repo check, fetch, unpack, restic backup) trigger failure for that host.
* Failed hosts are logged, and an email is sent to the host's configured `admin_email` (or global one, skipped in dry-run).
* Skipped hosts (due to client TAR lock or newer existing backup) are logged, and a warning email is sent (skipped in dry-run).
* A **final summary email** is sent to `global.admin_email` detailing all successful, skipped, and failed hosts for the `backup_server.sh` run (skipped in dry-run if no errors/skips).
* `restic_maintenance.sh` sends its own error email if it fails (and not in dry-run).
* Main script exits `0` only if all hosts succeed (or are skipped appropriately), `1` otherwise.
* EXIT trap cleans up main log file. ERR trap captures debug context. Signal traps ensure graceful exit.

## 10. Locking Mechanisms

### 10.1 Script Instance Locking (`flock`)
The `backup_server.sh` script uses `flock` with a lock file (typically `/var/run/backup_server.sh.lock`) to ensure that only one instance of the script runs at any given time on the server.

### 10.2 Client-Side Archive Lock Check
Before attempting to list or download files from a client's `remote_tar_dir`, `backup_server.sh` performs an SSH check for the existence of a lock file named `.backup_archive_in_progress.lock` in that directory.
* If this lock file is present (indicating the client's `local_backup.sh` is actively creating/modifying the TAR archive), the server script will wait for a configurable period (`SHARED_LOCK_CHECK_RETRY_DELAY_SECONDS`) and retry the check a configurable number of times (`SHARED_LOCK_CHECK_RETRY_COUNT`).
* If the lock is still present after all retries, the server will skip processing that client for the current backup run, log a warning, and send a notification email to the configured admin for that host (or the global admin). The client will be listed as "skipped" in the final summary email.
* This mechanism prevents the server from fetching incomplete or inconsistent TAR archives.

## 11. Security Considerations
* **Root Execution:** Necessary for many operations (e.g., `flock` in `/var/run`, Restic access, SSH as specific users if keys are root-owned).
* **Configuration File Permissions:** Critical for `/etc/backup/common_config`, `/etc/backup/server_config.yml`, Restic password file, and SSH private keys. These **MUST be `600 root:root`**. The scripts attempt to verify some of these.
* **SSH Security:**
    * **Manual Host Key Verification REQUIRED:** Before the first connection, manually SSH to each client as the user the script will use (often root if running the script as root and using root-owned keys) to accept and store the client's host key in `/root/.ssh/known_hosts`. Do not disable `StrictHostKeyChecking`.
    * Protect private SSH keys with strong permissions (`600 root:root`).
    * Use strong SSH key types (e.g., ed25519).
    * Limit client-side `authorized_keys` entries for the backup user to only allow necessary commands if possible (though `scp` and `find` make this complex).
* **Restic Security:**
    * Protect the Restic password file (`restic.password_file`) with `600 root:root` permissions.
    * Ensure the Restic repository storage location (`restic.repository_root`) has appropriate permissions to prevent unauthorized access.
* **YAML Parsing:** `yq` is used. Ensure it's from a trusted source.
* **Sourcing `common_config`:** This file is sourced directly. Strict `600 root:root` permissions are essential to prevent arbitrary code execution if compromised.

## 12. Troubleshooting
* **Logs First:** Check `/tmp/local_backup_log.backup_server.sh.*` (kept on error), systemd journal (`journalctl -u backup-server.service`), and error emails.
* **Dry Run:** Use `sudo /opt/backup/bin/backup_server.sh -v -d` extensively.
* **Host Failure/Skip:** Check specific error messages for that host in the log.
    * **SSH Issues:** Test manually: `sudo ssh -v -i /path/to/key user@host 'echo "Connection OK"'`. Check key paths, permissions on server and client (`~/.ssh/authorized_keys`), firewalls, and ensure the client's host key is in the server's `/root/.ssh/known_hosts`.
    * **Client Lock:** If skipped due to "Client TAR Lock", check the client machine's `remote_tar_dir` for a stale `.backup_archive_in_progress.lock` directory.
    * **Restic Repo Check Failure:** Ensure the repository path (`<RESTIC_REPO_ROOT>/<hostname>`) exists and was initialized with `restic init` using the correct password file.
    * **Newer Snapshot Skip:** Verify timestamps. The script uses the timestamp from the TAR filename (e.g., `20250521_103000`) as a Restic tag. If `jq` is available, it uses the precise ISO8601 timestamp from Restic's JSON output for comparison.
* **Permissions:** Verify all relevant file/directory permissions on server and client.
* **`yq`/`jq`/`restic` Issues:** Ensure they are installed, correct versions, and in `PATH`.
* **Configuration:** Double-check all paths, hostnames, usernames, and email addresses in `/etc/backup/server_config.yml` and `/etc/backup/common_config`.

## 13. Suggestions / Potential Improvements
* **Restic Maintenance Script (`restic_maintenance.sh`):**
    * **Detailed Reporting:** Enhance the maintenance script to output more detailed statistics from `restic stats` or `restic check --read-data-subset` and include these in its summary email or log.
* **Backup Server Script (`backup_server.sh`):**
    * **TAR Archive Checksum Verification.**
    * **Parallel Host Processing.**
    * **SSH Options:** Make more SSH options configurable per host.
* **General:**
    * **Centralized Secret Management.**

## 14. License Information
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
