# Local Backup System (Client/Server)

**Version:** 0.2
**License:** AGPL-3.0-or-later
**Author:** Lars Duesing [<lars.duesing@camelotsweb.de>](mailto:lars.duesing@camelotsweb.de)
**Date:** May 25, 2025

## Table of Contents

1.  [Overview](#1-overview)
2.  [Project Goals](#2-project-goals)
3.  [General Backup Workflow](#3-general-backup-workflow)
    * [Stage 1: Client-Side Snapshot Creation (`local_backup.sh`)](#stage-1-client-side-snapshot-creation-local_backupsh)
    * [Stage 2: Server-Side Fetching and Restic Storage (`backup_server.sh`)](#stage-2-server-side-fetching-and-restic-storage-backup_serversh)
    * [Stage 3: Server-Side Restic Repository Maintenance (`restic_maintenance.sh`)](#stage-3-server-side-restic-repository-maintenance-restic_maintenancesh)
4.  [Build Requirements](#4-build-requirements)
5.  [Building Packages](#5-building-packages)
6.  [Installation](#6-installation)
7.  [License](#7-license)

## 1. Overview

This project provides a modular backup solution consisting of three main Debian packages built from this source tree:

1.  **`backup-common`**: Contains shared configuration files (e.g., `/etc/backup/common_config`), shared library scripts (e.g., `/opt/backup/lib/plugins/common_functions.sh`), and the base plugin directory structure (`/opt/backup/lib/plugins`). It serves as a dependency for both the client and server packages.
2.  **`backup-client`**: Installs the `local_backup.sh` orchestrator script (to `/opt/backup/bin/`), client-specific configuration (`/etc/backup/client_config.yml`), necessary plugins (to `/opt/backup/lib/plugins/`), and systemd units (`local-backup.service`, `local-backup.timer`) for running backups on client machines. This component is responsible for collecting data and creating local TAR archives.
3.  **`backup-server`**: Installs the `backup_server.sh` script (to `/opt/backup/bin/`) for fetching client backups, the `restic_maintenance.sh` script (to `/opt/backup/bin/`), server-specific configuration (`/etc/backup/server_config.yml`), and systemd units (`backup-server.service`, `backup-server.timer`, `restic-maintenance.service`, `restic-maintenance.timer`) for running the backup server and Restic repository maintenance tasks.

This `README.md` provides a top-level overview. For specific details about each component, please refer to the README files within the `backup-client/`, `backup-server/`, `configs/`, `plugins/`, and `systemd/` source directories (or their installed locations under `/usr/share/doc/`).

## 2. Project Goals

* **Modularity:** Separate components for client, server, and shared elements.
* **Extensibility:** A plugin-based architecture for the client to easily add support for backing up new types of services.
* **Centralized Pull Model:** A server pulls backups from clients.
* **Secure Storage:** Utilizes Restic on the server for encrypted, deduplicated backups.
* **Automation:** Systemd timers for scheduling both client backups and server operations.
* **Robustness:** Includes error handling, logging, file locking (both for script instances and shared directories), and configuration validation.
* **Standardization:** Aims to follow good shell scripting practices (e.g., Google Shell Style Guide) and Debian packaging conventions.

## 3. General Backup Workflow

The backup process is a multi-stage operation involving client-side snapshot creation and server-side fetching and storage:

### Stage 1: Client-Side Snapshot Creation (`local_backup.sh`)

1.  **Initiation & Locking:** The `local_backup.sh` script is typically run by a systemd timer on each client machine. It first acquires an instance lock (`flock`) to prevent multiple simultaneous runs of itself.
2.  **Configuration Loading:** It loads common defaults (`/etc/backup/common_config`) and client-specific settings (`/etc/backup/client_config.yml`). Syntax checks are performed on these files.
3.  **Service Discovery:** The script scans predefined directories (e.g., `/etc/backup/docker/`, `/etc/backup/other/`) for `service.yaml` files. Each `service.yaml` defines a specific service to be backed up.
4.  **Plugin Orchestration:** For each service:
    * The core script identifies required backup tasks and calls relevant plugins from `/opt/backup/lib/plugins/`.
    * Plugins perform validation, preparation (e.g., stopping Docker services), execution (e.g., DB dumps, file rsync), and post-backup actions (e.g., restarting services).
5.  **Shared Directory Lock (TAR Creation):** Before creating the final TAR archive, the client script attempts to acquire a directory-based lock (`.backup_archive_in_progress.lock`) in its `BASE_BACKUP_DIR`. This prevents the server from attempting to fetch an incomplete archive. Retries are performed if the lock is held.
6.  **Archive Creation & Verification:** All collected data is consolidated into a compressed TAR archive (`<CLIENT_HOSTNAME>-<TIMESTAMP>.tar.gz`) and its integrity is verified.
7.  **Lock Release & Cleanup:** The shared directory lock is released. Temporary files are removed, and old local TAR archives are pruned.

### Stage 2: Server-Side Fetching and Restic Storage (`backup_server.sh`)

1.  **Initiation & Locking:** The `backup_server.sh` script is typically run by a systemd timer on the central backup server and acquires its own instance lock (`flock`).
2.  **Configuration Loading:** It loads common and server-specific configurations, performing syntax checks.
3.  **Client Iteration:** For each configured client host:
    * **Client Lock Check:** The server connects via SSH and checks for the client-side `.backup_archive_in_progress.lock` in the client's `remote_tar_dir`. If present, it retries a few times before skipping the client for this run and sending a warning.
    * **Fetch Archive:** If no client lock, the server identifies and downloads the latest TAR archive using `scp`.
    * **Unpack Archive:** The archive is unpacked into a consistent, clean per-host temporary directory on the server.
    * **Restic Newer Snapshot Check:** Compares the TAR timestamp (via Restic tag) with existing snapshots to avoid redundant backups.
    * **Restic Backup:** `restic backup --ignore-inode --host <client_hostname>` is executed.
    * **Remote & Local Cleanup:** Processed TAR on client is managed; server-side temporary directories are removed.
4.  **Reporting:** Per-host failures/warnings are logged and emailed. A final summary email details the status of all hosts.

### Stage 3: Server-Side Restic Repository Maintenance (`restic_maintenance.sh`)

1.  **Initiation & Locking:** Run by a separate timer, acquires its own instance lock.
2.  **Maintenance Tasks:** For each Restic repository, it performs `restic forget --prune` (with per-host policy override) and `restic check`.
3.  **Reporting:** Logs actions and sends an email on failure.

This multi-stage process aims for reliable data collection, secure transfer, and efficient, encrypted storage.

## 4. Build Requirements

To build the Debian packages from this source tree, you will need a Debian-based system with the following tools installed:

* `dpkg-dev`
* `debhelper` (version 12 or higher recommended)
* `devscripts` (provides `dpkg-buildpackage`)

Installation example:
``` bash
sudo apt update
sudo apt install dpkg-dev debhelper devscripts
```

## 5. Building Packages

Detailed instructions for building the Debian packages (`backup-common`, `backup-client`, `backup-server`) are provided in the `debian/README.md` file within this source tree. This includes preparing the source, updating Debian control files, and running the `dpkg-buildpackage` command.

## 6. Installation

Install the generated `.deb` packages using `dpkg -i` or preferably `apt install ./<package_name>*.deb` (as `apt` handles dependencies).

1.  **On ALL machines (Client and Server):** Install the common package first, as it's a dependency.
    ``` bash
    sudo apt install ./backup-common*.deb
    ```
2.  **On CLIENT machines:** Install the client package.
    ``` bash
    sudo apt install ./backup-client*.deb
    ```
3.  **On the SERVER machine:** Install the server package.
    ``` bash
    sudo apt install ./backup-server*.deb
    ```

**Post-installation configuration is required** on both client and server machines. Refer to the specific README files installed with the packages (e.g., in `/usr/share/doc/backup-client/`) and the configuration files in `/etc/backup/`.

## 7. License

This project and its components are licensed under the **GNU Affero General Public License v3.0 or later**. See the `LICENSE` file for the full text.
