# Local Backup System (Client/Server)

**Version:** 0.1
**License:** AGPL-3.0-or-later
**Author:** Lars Duesing [<lars.duesing@camelotsweb.de>](mailto:lars.duesing@camelotsweb.de) 
**Date:** 2025-05-07

## 1. Overview

This project provides a modular backup solution consisting of three main Debian packages built from this source tree:

1.  **`backup-common`**: Contains shared configuration files (e.g., `/etc/backup/common_config`), shared library scripts (e.g., `/opt/backup/lib/plugins/common_functions.sh`), and the base plugin directory structure (`/opt/backup/lib/plugins`). It serves as a dependency for both the client and server packages.
2.  **`backup-client`**: Installs the `local_backup.sh` orchestrator script (to `/opt/backup/bin/`), client-specific configuration (`/etc/backup/client_config.yml`), necessary plugins (to `/opt/backup/lib/plugins/`), and systemd units (`local-backup.service`, `local-backup.timer`) for running backups on client machines. This component is responsible for collecting data and creating local TAR archives.
3.  **`backup-server`**: Installs the `backup_server.sh` script (to `/opt/backup/bin/`) for fetching client backups, the `restic_maintenance.sh` script (to `/opt/backup/bin/`), server-specific configuration (`/etc/backup/server_config.yml`), and systemd units (`backup-server.service`, `backup-server.timer`, `restic-maintenance.service`, `restic-maintenance.timer`) for running the backup server and Restic repository maintenance tasks.

This README provides a top-level overview. For specific details about each component, please refer to the README files within the respective source directories:
* `backup-client/README.md`
* `backup-server/README.md`
* `configs/README.md`
* `plugins/README.md`
* `systemd/README.md`

## 2. Project Goals

* **Modularity:** Separate components for client, server, and shared elements.
* **Extensibility:** A plugin-based architecture for the client to easily add support for backing up new types of services.
* **Centralized Pull Model:** A server pulls backups from clients.
* **Secure Storage:** Utilizes Restic on the server for encrypted, deduplicated backups.
* **Automation:** Systemd timers for scheduling both client backups and server operations.
* **Robustness:** Includes error handling, logging, file locking, and configuration validation.
* **Standardization:** Aims to follow good shell scripting practices (e.g., Google Shell Style Guide) and Debian packaging conventions.

## 3. General Backup Workflow

The backup process is a two-stage operation involving client-side snapshot creation and server-side fetching and storage:

** Stage 1: Client-Side Snapshot Creation (`local_backup.sh`)**

1. **Initiation:** The `local_backup.sh` script is typically run by a systemd timer on each client machine.
2. **Configuration Loading:** It loads common defaults (`/etc/backup/common_config`) and client-specific settings (`/etc/backup/client_config.yml`).
3. **Service Discovery:** The script scans predefined directories (e.g., `/etc/backup/docker/`, `/etc/backup/other/`) for `service.yaml` files. Each `service.yaml` defines a specific service to be backed up (e.g., a Docker application, a database, specific file paths).
4. **Plugin Orchestration:** For each service defined in a `service.yaml`:
    * The core script identifies the required backup tasks (e.g., `docker`, `postgresql`, `files`) from the YAML.
    * It discovers and calls relevant plugins from the `/opt/backup/lib/plugins/` directory.
    * **Preparation (Optional):** Plugins like `docker_compose.sh` might stop services to ensure data consistency. State files are used to track these actions.
    * **Execution:** Plugins perform the actual backup tasks:
        * `postgresql.sh` / `mariadb.sh`: Dump databases (uncompressed SQL, relying on `/root/.pgpass` or `/root/.my.cnf` for credentials).
        * `docker_compose.sh`: Backs up `docker-compose.yml` and `.env` files.
        * `files_rsync.sh`: Copies specified directories and files using `rsync`, preserving permissions and handling excludes.
        * Other plugins would handle their specific data sources.
    * **Post-Backup (Optional):** Plugins like `docker_compose.sh` restart any services they stopped and perform optional waits.
5. **Archive Creation:** After all configured services on the client are processed, the `local_backup.sh` script consolidates all collected data from its temporary working directory into a single, compressed TAR archive (`<CLIENT_HOSTNAME>-<TIMESTAMP>.tar.gz`). This archive is stored locally on the client in the directory specified by `BASE_BACKUP_DIR` in `client_config.yml`. Plugin state directories (`.state/`) are excluded from this archive.
6. **Archive Verification:** The integrity of the created TAR archive is verified.
7. **Cleanup:** The temporary working directory is removed. Old local TAR archives are pruned based on the `keep_days` setting.

** Stage 2: Server-Side Fetching and Restic Storage (backup_server.sh)**

1.  **Initiation:** The `backup_server.sh` script is typically run by a systemd timer on the central backup server.
2.  **Configuration Loading:** It loads common defaults (`/etc/backup/common_config`) and server-specific settings (`/etc/backup/server_config.yml`), which includes a list of client hosts to back up.
3.  **Client Iteration:** For each configured client host:
    * **Fetch Archive:** The server connects to the client via SSH (using pre-configured key-based authentication). It identifies and downloads the latest TAR archive created by the client's `local_backup.sh` script using `scp`.
    * **Unpack Archive:** The downloaded TAR archive is unpacked into a temporary directory on the server, preserving all original file permissions and ownership (using `--numeric-owner`).
    * **Restic Backup:** The `restic backup` command is executed on the contents of the unpacked directory. Data is backed up into a host-specific Restic repository located under the server's `restic.repository_root` (e.g., `/media/backup/restic/client-a.example.org`). Snapshots are tagged with the client's hostname and the timestamp from the original TAR archive.
    * **Remote Cleanup:** If the Restic backup is successful, the server script commands the client (via SSH) to move the processed TAR archive into a `done/` subdirectory on the client and then prunes older archives in that `done/` directory, keeping only the most recent one.
    * **Local Cleanup:** The temporary download and unpack directories on the server are removed.
4. **Reporting:** Per-host failures are logged and an email is sent. At the end of the run, a summary email is sent detailing successful and failed hosts.

** Stage 3: Server-Side Restic Repository Maintenance (`restic_maintenance.sh`)**

1. **Initiation:** The `restic_maintenance.sh` script is run by a separate, less frequent systemd timer on the backup server (e.g., weekly).
2. **Repository Iteration:** It iterates through all host-specific Restic repositories under `restic.repository_root`.
3. **Maintenance Tasks:** For each repository, it performs:
    * `restic forget` with a configured policy (e.g., keeping daily, weekly, monthly, yearly snapshots) to remove old snapshots according to the retention policy.
    * `restic prune` (if enabled) to remove unreferenced data from the repository and free up space.
    * `restic check` (if enabled) to verify the integrity of the repository.
4. **Reporting:** Logs its actions. Error reporting for maintenance tasks would typically be handled via its own logging or notifications configured within this script.

This multi-stage process ensures that data is first reliably collected and archived on the client, then securely transferred and stored with deduplication and encryption on the server using Restic.

## 4. Source File Tree

The anticipated source code organization before building Debian packages is as follows:

```text
.
├── backup-client/
│   ├── local_backup.sh         # Core client script
│   └── README.md               # Client-specific README
├── backup-server/
│   ├── backup_server.sh        # Core server script
│   ├── README.md               # Server-specific README
│   └── restic_maintenance.sh   # Restic maintenance script
├── configs/
│   ├── client_config.yml       # Client-specific YAML configuration
│   ├── common_config           # Shared shell variable configuration
│   ├── docker/                 # Example service type directory (for client)
│   │   └── tandoor_recipes/    # Example service directory
│   │       └── service.yaml    # Example service YAML configuration
│   ├── other/                  # Example service type directory (for client)
│   │   └── pihole/             # Example service directory
│   │       └── service.yaml    # Example service YAML configuration
│   ├── README.md               # README for the configs directory
│   └── server_config.yml       # Server-specific YAML configuration
├── debian/                     # Debian packaging files
│   ├── backup-client.install
│   ├── backup-common.install
│   ├── backup-server.install
│   ├── changelog
│   ├── compat
│   ├── control                 # Defines all three packages
│   ├── copyright
│   ├── placeholder             # Empty file for dh_installdirs
│   └── rules                   # Main build script for Debian packages
├── LICENSE                     # AGPLv3 License text file
├── plugins/
│   ├── common_functions.sh     # Shared shell functions
│   ├── docker_compose.sh       # Docker plugin
│   ├── files_rsync.sh          # Files/rsync plugin
│   ├── postgresql.sh           # PostgreSQL plugin
│   └── README.md               # Plugin system README
├── README.md                   # This top-level project README
└── systemd/                    # Source for systemd unit files
    ├── backup-server.service
    ├── backup-server.timer
    ├── local-backup.service
    ├── local-backup.timer
    ├── README.md               # Systemd specific README
    ├── restic-maintenance.service
    └── restic-maintenance.timer
```

## 5. Build Requirements

To build the Debian packages from this source tree, you will need a Debian-based system with the following tools installed:

* `dpkg-dev`
* `debhelper` (version 12 or higher recommended)
* `devscripts` (provides `dpkg-buildpackage`)

Installation example:
```bash
sudo apt update
sudo apt install dpkg-dev debhelper devscripts
```

## 6. Building Packages

1.  **Prepare Source:** Ensure all source files are correctly placed in the structure outlined above.
2.  **License File:** Place the full text of the AGPLv3 license into the `LICENSE` file in the project root.
3.  **Update Debian Files:**
    * Edit `debian/changelog`: Update the version, distribution (e.g., `unstable`, `bookworm`), and your maintainer details. Add new entries for subsequent releases following Debian policy.
    * Edit `debian/control`: Update the `Maintainer:` field. Review and adjust `Depends:` and `Recommends:` fields for each package if necessary.
    * Edit `debian/copyright`: Ensure all copyright information and source URLs are correct.
4.  **Build:** From the project root directory (the one containing the `debian` directory), run the build command:
    ```bash
    dpkg-buildpackage -us -uc
    ```
    * `-us -uc`: Prevents signing the source and changes files, which is fine for local/internal builds. Remove these if you intend to sign your packages for wider distribution.
5.  **Output:** The generated `.deb` files (e.g., `backup-common_0.1-1_all.deb`, `backup-client_0.1-1_all.deb`, `backup-server_0.1-1_all.deb`) will be created in the directory *above* your project root.

## 7. Installation

Install the generated `.deb` packages using `dpkg -i` or preferably `apt install ./<package_name>*.deb` (as `apt` handles dependencies).

1.  **On ALL machines (Client and Server):** Install the common package first, as it's a dependency.
    ```bash
    sudo apt install ./backup-common_0.1-1_all.deb
    ```
2.  **On CLIENT machines:** Install the client package.
    ```bash
    sudo apt install ./backup-client_0.1-1_all.deb
    ```
3.  **On the SERVER machine:** Install the server package.
    ```bash
    sudo apt install ./backup-server_0.1-1_all.deb
    ```

**Post-installation configuration is required** on both client and server machines. This includes:
* Editing `/etc/backup/common_config`.
* Editing `/etc/backup/client_config.yml` on clients.
* Editing `/etc/backup/server_config.yml` on the server.
* Creating service-specific `service.yaml` files under `/etc/backup/` on clients.
* Setting up SSH keys for server-client communication.
* Initializing Restic repositories on the server.
* Configuring secure database credentials (e.g., `/root/.pgpass`) on clients.
* Enabling systemd timers (`sudo systemctl enable --now <timer-name>.timer`).

Refer to the specific README files installed with the packages (e.g., in `/usr/share/doc/backup-client/`) and the configuration files themselves for detailed setup instructions.

## 8. License

This project and its components are licensed under the **GNU Affero General Public License v3.0 or later**. See the `LICENSE` file for the full text.

