# Backup Configuration Files (`configs/`)

This directory contains the configuration files used by the `backup-client` and `backup-server` components.

* **`common_config`**: A shell script sourced by both client and server scripts to define common default settings, paths to tools, and potentially shared functions or variables. Ensure it has `600 root:root` permissions. Typically installed to `/etc/backup/common_config`.
* **`client_config.yml`**: YAML file containing settings specific to the `local_backup.sh` (client) script, such as backup user/group, retention days, and plugin directory. Ensure it has `600 root:root` permissions. Typically installed to `/etc/backup/client_config.yml`.
* **`server_config.yml`**: YAML file containing settings specific to the `backup_server.sh` and `restic_maintenance.sh` scripts, including Restic details and the list of client hosts to back up. Ensure it has `600 root:root` permissions. Typically installed to `/etc/backup/server_config.yml`.
* **Service Configuration Directories (e.g., `docker/`, `other/`)**: These directories contain subdirectories for each service to be backed up by the client. Each service subdirectory **must** contain a `service.yaml` file defining the backup tasks and parameters for that specific service. These directories and files should typically reside under `/etc/backup/` on the client machine after installation, not directly in this source tree except for examples. Permissions should be `700 root:root` for directories and `600 root:root` for `service.yaml` files.

**Installation:**

* `common_config`, `client_config.yml`, `server_config.yml` are typically installed to `/etc/backup/`.
* Example service configurations (like `docker/` and `other/`) should be adapted by the administrator and placed under `/etc/backup/` on the relevant client machines.
