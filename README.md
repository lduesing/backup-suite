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

## 3. Source File Tree

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

## 4. Build Requirements

To build the Debian packages from this source tree, you will need a Debian-based system with the following tools installed:

* `dpkg-dev`
* `debhelper` (version 12 or higher recommended)
* `devscripts` (provides `dpkg-buildpackage`)

Installation example:
```bash
sudo apt update
sudo apt install dpkg-dev debhelper devscripts
```

## 5. Building Packages

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

## 6. Installation

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

## 7. License

This project and its components are licensed under the **GNU Affero General Public License v3.0 or later**. See the `LICENSE` file for the full text.

