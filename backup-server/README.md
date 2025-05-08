# Backup Server Script

**Version:** 0.1
**License:** AGPL-3.0-or-later
**Author:** Lars Duesing [<lars.duesing@camelotsweb.de>](mailto:lars.duesing@camelotsweb.de)
**Date:** 2025-05-02

## Table of Contents

1.  [Description](#description)
2.  [Features](#features)
3.  [Prerequisites](#prerequisites)
4.  [Installation](#installation)
5.  [Configuration (`config` YAML File)](#configuration-config-yaml-file)
    * [Global Settings](#global-settings)
    * [Restic Settings](#restic-settings)
    * [Host Definitions](#host-definitions)
6.  [Required Setup](#required-setup)
    * [Restic Repositories & Maintenance](#restic-repositories--maintenance)
    * [SSH Key Authentication & Host Key Verification](#ssh-key-authentication--host-key-verification)
    * [Password Files](#password-files)
7.  [Usage](#usage)
    * [Command Line Options](#command-line-options)
    * [Manual Execution](#manual-execution)
    * [Automated Execution (Systemd Timer)](#automated-execution-systemd-timer)
8.  [Workflow Details](#workflow-details)
9.  [Error Handling and Email Reporting](#error-handling-and-email-reporting)
10. [Security Considerations](#security-considerations)
11. [Troubleshooting](#troubleshooting)
12. [Suggestions / Potential Improvements](#suggestions--potential-improvements)
13. [License Information](#license-information)


## 1. Description

This script runs on a central backup server and orchestrates the process of fetching pre-generated backup archives (`.tar.gz`) from multiple client hosts (prepared by `local_backup.sh` or similar) and backing up their contents into host-specific [Restic](https://restic.net/) repositories.

It reads its configuration from a central YAML file (`/etc/backup/server_config.yml` by default) and common settings from `/etc/backup/common_config` and performing validation. It iterates through the defined client hosts, connects via SSH using key-based authentication (requiring manual host key verification first), finds and downloads the latest backup archive, unpacks it locally into a secure temporary directory, and then runs `restic backup` to store the unpacked data. A **dry-run mode** is available for testing.

Upon successful backup with Restic (in non-dry-run mode), the script remotely commands the client host to move the processed archive to a `done/` subdirectory and cleans up older archives there. If any step fails for a specific host, an email notification is sent (if configured, skipped in dry-run), and the script proceeds to the next host. File locking prevents concurrent runs. Restic repository maintenance (`forget`, `prune`, `check`) should be handled by a **separate script and timer** (example provided).

## 2. Features

* **Centralized Backup Orchestration:** Manages backups from multiple client hosts.
* **YAML Configuration:** Clear definition of global, Restic, and per-host settings in `server_config.yml`.
* **Common Configuration:** Reads defaults and tool paths from `/etc/backup/common_config`.
* **Configuration Validation:** Performs checks on config file values and required file permissions.
* **SSH/SCP Based Fetching:** Securely downloads backup archives using SSH keys (**manual host key verification required**).
* **Latest Archive Detection:** Finds the newest `<hostname>-<timestamp>.tar.gz` file on the client.
* **Preserves Permissions/Ownership:** Unpacks TAR archives using `--numeric-owner` and `-p`.
* **Restic Integration:** Backs up unpacked data into per-host Restic repositories using a password file.
    * Automatically tags backups with hostname and archive timestamp.
    * Supports custom `restic backup` options via config.
* **Restic Maintenance Separation:** Designed for use with a separate script/timer (example units provided) for `restic forget --prune` and `restic check`.
* **Remote Cleanup:** Moves processed archives to `done/` dir on client, keeps only the latest there.
* **Per-Host Error Handling:** Continues processing other hosts even if one fails.
* **Email Notifications:** Sends detailed error reports for failed hosts via `msmtp` (skipped in dry-run).
* **File Locking:** Uses `flock` via FD 200 to prevent multiple instances.
* **Secure Temporary Files:** Uses `mktemp` for temporary directories.
* **Dry-Run Mode (`--dry-run`):** Simulates the entire process without modifying Restic repos, remote files, or sending emails. Restic backup uses `--dry-run`.
* **Verbose/Quiet Operation:** Supports `-v` flag for detailed logging.
* **Systemd Integration:** Example `.service` and `.timer` units provided for both backup and maintenance. Includes resource limit examples.
* **Shell Style:** Adheres to Google Shell Style Guide principles.
* **AGPLv3 License:** Free and open-source software.

## 3. Prerequisites

* **OS:** Debian-based Linux (e.g., Debian, Ubuntu) for the server.
* **Shell:** Bash (v4+ required for associative arrays used in config loading).
* **Core Tools:** `bash`, `find`, `mkdir`, `chmod`, `chown`, `date`, `grep`, `cut`, `sed`, `tee`, `mktemp`, `dirname`, `basename`, `gzip`, `tar`, `realpath`, `command`, `id`, `getent`, `getopt`, `stat`, `df`, `tail`, `flock`.
* **YAML Parser:** **`yq` version 4+** (REQUIRED).
* **Backup Tool:** **`restic`**.
* **Network Tools:** `ssh`, `scp` (from `openssh-client` package).
* **Email Client (Optional):** `msmtp`, `msmtp-mta` (configured).
* **Permissions:** Script MUST be run as **`root`**.
* **Restic Repositories:** Must be pre-initialized for each host under the configured `repository_root`.
* **SSH Keys:** Passwordless SSH key pairs configured, private keys stored securely (`600 root:root`), public keys on clients' `authorized_keys`. **Manual host key verification completed.**
* **Client-Side Script:** Clients must generate `<hostname>-<timestamp>.tar.gz` archives in the expected `remote_tar_dir`.

**Install required packages (Example for Debian/Ubuntu):**

```bash
# Install yq v4+ (check official install instructions for your distro)
# Example (might need adjustment):
# sudo wget [https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64](https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64) -O /usr/bin/yq && sudo chmod +x /usr/bin/yq

# Install restic (check official restic docs for recommended method)
# Example (might need adjustment):
# sudo apt install restic

sudo apt update
sudo apt install -y util-linux rsync msmtp msmtp-mta gzip tar coreutils uidmap openssh-client yq restic
```

## 4. Installation

(Assuming installation via `.deb` packages)

1.  Install `backup-common` package: `sudo apt install ./backup-common*.deb`
2.  Install `backup-server` package: `sudo apt install ./backup-server*.deb`
3.  **Post-Installation Configuration:**
    * Review/Edit `/etc/backup/common_config`. Ensure `600 root:root`.
    * Create/Edit `/etc/backup/server_config.yml`. Ensure `600 root:root`.
    * Create Restic password file (e.g., `/etc/backup/restic.pass`). Ensure `600 root:root`.
    * Place SSH private keys (e.g., `/etc/backup/client_a_id_ed25519`). Ensure `600 root:root`.
    * Initialize Restic repositories for each host.
    * Perform manual SSH connection to each client as root to accept host keys.
    * Enable systemd timers: `sudo systemctl enable --now backup-server.timer restic-maintenance.timer`.

## 5. Configuration (`config` YAML File)

Location: `/etc/backup/server_config.yml`. Format: YAML. Permissions MUST be `600 root:root`. Reads defaults from `/etc/backup/common_config`.

### Global Settings

Under `global:`:

* `local_temp_base_dir` (Mandatory): Path for temporary server work.
* `admin_email` (Optional): Default email for failures (overrides common_config).
* `msmtp_cmd` (Optional): Path to `msmtp`.
* `yq_cmd` (Optional): Path to `yq`.

### Restic Settings

Under `restic:`:

* `repository_root` (Mandatory): Parent directory of per-host Restic repos.
* `password_file` (Mandatory): Path to Restic password file (`600 root:root`).
* `restic_cmd` (Optional): Path to `restic`.
* `backup_options` (Optional): String of additional options for `restic backup`.
* `maintenance:` (Optional): Settings for `restic_maintenance.sh`.
    * `forget_policy` (Optional): String of `restic forget` arguments (Default: `--keep-daily 7 --keep-weekly 4 --keep-monthly 12 --keep-yearly 3`).
    * `prune` (Optional): `true` or `false` (Default: `true`). Run `prune` after `forget`?
    * `check` (Optional): `true` or `false` (Default: `true`). Run `check` after `forget/prune`?
    * `check_options` (Optional): String of additional options for `restic check`.

### Host Definitions

Under `hosts:`, a YAML list (`-`) of host objects:

* `hostname` (Mandatory): FQDN or IP for SSH & Restic repo subdirectory name.
* `ssh_user` (Mandatory): Username on client.
* `ssh_key_file` (Mandatory): Path on *server* to private SSH key (`600 root:root`).
* `remote_tar_dir` (Mandatory): Path on *client* where archives are located.
* `admin_email` (Optional): Host-specific notification email (overrides global).

## 6. Required Setup

### Restic Repositories & Maintenance

* **Initialization:** Manually initialize a Restic repo for **each** host:
  ```bash
  export RESTIC_PASSWORD_FILE=/etc/backup/restic.pass
  sudo restic -r /media/backup/restic/your_host.example.com init
  # Repeat for all hosts...
  unset RESTIC_PASSWORD_FILE
  sudo chown -R root:root /media/backup/restic # Ensure root owns repo files
  ```
* **Maintenance:** Use the separate `restic_maintenance.sh` script and its systemd timer (e.g., `restic-maintenance.timer`) run less frequently (weekly recommended).

### SSH Key Authentication & Host Key Verification

* Generate SSH keys (`ssh-keygen`). Copy public key to client's `~/.ssh/authorized_keys`. Store private key securely (`/etc/backup/`, `600 root:root`).
* **CRITICAL:** Manually connect via SSH *as root* from the server to *each client* **once** to verify and add the client's host key to root's `/root/.ssh/known_hosts`:
    ```bash
    sudo ssh -i /etc/backup/your_client_keyfile ssh_user@client.example.org 'echo Connected'
    # ---> Verify fingerprint and type 'yes' <---
    ```

### Password Files

Ensure Restic password file exists, contains only the password, `600 root:root`.

## 7. Usage

### Command Line Options

* `-v`, `--verbose`: Enable verbose output.
* `-h`, `--help`: Display help.
* `-V`, `--version`: Display version.
* `-d`, `--dry-run`: Simulate run (no fetch, unpack, restic write, remote move, email). Restic uses `--dry-run`.

### Manual Execution

```bash
# Standard execution
sudo /opt/backup/bin/backup_server.sh

# Verbose dry run
sudo /opt/backup/bin/backup_server.sh -v --dry-run
```
Check `/tmp/local_backup_log.backup_server.sh.*` for full logs. Check for `flock` errors.

### Automated Execution (Systemd Timer)

1.  **Enable & Start Timers:** (Assuming package install handled setup)

    ```bash
    sudo systemctl enable --now backup-server.timer restic-maintenance.timer
    ```

2.  **Check Status & Logs:**

    ```bash
    sudo systemctl status backup-server.timer restic-maintenance.timer
    sudo journalctl -u backup-server.service
    sudo journalctl -u restic-maintenance.service
    ```
3.  **Customize:** Edit timers (`/etc/systemd/system/*.timer`) or use `sudo systemctl edit <unit>.service` for overrides. Remember `sudo systemctl daemon-reload`.

## 8. Workflow Details

For each host (unless `--dry-run`):
1.  **Locking:** Acquires global lock.
2.  **Find Remote TAR:** SSH finds latest `<hostname>-*.tar.gz`.
3.  **Fetch TAR:** `scp` downloads TAR. *(Skipped in dry-run)*
4.  **Unpack TAR:** `tar -xpzf --numeric-owner` unpacks. *(Skipped in dry-run)*
5.  **Restic Backup:** `restic backup` runs on content, tagging snapshot. *(Uses `--dry-run` if enabled)*
6.  **Remote Cleanup (on Success):** SSH moves processed TAR on *client* to `done/`, removes older files there. *(Skipped in dry-run)*
7.  **Local Cleanup:** Server's temp download and unpack dirs removed. *(Runs in dry-run too)*
8.  **Loop/Error:** Continues to next host. Sends email on failure (skipped in dry-run).
9.  **Final Summary:** Logs success or list of failed hosts. Exits non-zero if any host failed.
10. **Lock Release:** On script exit.

## 9. Error Handling and Email Reporting

* Host processing is isolated in subshells.
* Critical errors within a host's processing cause that host to fail, but the script continues to the next host.
* Failed hosts are logged, added to a list, and an email is sent to the configured admin address (skipped in dry-run).
* Main script exits `0` only if all hosts succeed, `1` otherwise.
* EXIT trap cleans up main log file. ERR trap captures debug context.

## 10. Security Considerations

* **Root Execution:** Necessary.
* **Configuration File Permissions:** Critical for `/etc/backup/config`, `restic.pass`, SSH keys (`600 root:root`). Checked by script.
* **SSH Security:** **Manual Host Key Verification REQUIRED.** Protect private keys. Use strong keys.
* **Restic Security:** Protect password file. Secure repository storage.
* **YAML Parsing:** `yq` needed; ensure trusted source.

## 11. Troubleshooting

* **Logs First:** Check `/tmp/local_backup_log.*`, Systemd Journal (`journalctl -u backup-server.service`), error emails.
* **Dry Run:** Use `sudo /opt/backup/bin/backup_server.sh -v -d` first.
* **Host Failure:** Check logs for specific host errors (SSH, SCP, TAR, Restic). Check email.
* **SSH Issues:** Test manually (`sudo ssh -v -i key user@host`). Check keys, `authorized_keys`, firewall, **`/root/.ssh/known_hosts`**.
* **SCP/Fetch Issues:** File existence/permissions on client? Network issues? Path correct?
* **Unpack Issues:** Valid TAR file? Disk space on server `/var/tmp`? Permissions?
* **Restic Issues:** Repo path correct? Initialized? Password file correct/readable (`600`)? Repo permissions? Restic command works manually? Test `restic snapshots`, `restic check`.
* **Remote Cleanup Issues:** `ssh_user` permissions on client's `remote_tar_dir/done`?
* **Permissions:** Check all relevant files/directories on server and client.
* **`yq` / `restic` / Tool Issues:** Installed? Correct version? In `PATH`?

## 12. Suggestions / Potential Improvements

* **Dry Run Enhancements:** Add more detailed simulation output.
* **SSH Options:** Make configurable or use system/user SSH config.
* **Download Method:** Option for `rsync`.
* **Error Handling:** More specific exit codes, summary email at end.
* **Configuration Validation:** Deeper validation.

## 13. License Information

This script is licensed under the **GNU Affero General Public License v3.0 or later**.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

