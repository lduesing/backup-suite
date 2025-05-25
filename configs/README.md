# Backup Configuration Files (`configs/`)

**Last Updated:** May 25, 2025

This directory in the source tree contains example and template configuration files used by the `backup-client` and `backup-server` components. Upon package installation, these are typically installed to `/etc/backup/` and should be customized by the administrator.

## Table of Contents

1.  [Core Configuration Files](#1-core-configuration-files)
    * [1.1 `common_config`](#11-common_config)
    * [1.2 `client_config.yml`](#12-client_configyml)
    * [1.3 `server_config.yml`](#13-server_configyml)
2.  [Service Configuration Files (`service.yaml`)](#2-service-configuration-files-serviceyaml)
3.  [Important Notes](#3-important-notes)

## 1. Core Configuration Files

### 1.1 `common_config`

* **Installed to:** `/etc/backup/common_config`
* **Format:** Shell script (sourced variables, e.g., `KEY="VALUE"`)
* **Permissions:** MUST be `600` owned by `root`. The main scripts verify this.
* **Purpose:** Defines global default settings and paths to essential command-line tools (e.g., `YQ_CMD`, `TAR_CMD`, `RESTIC_CMD`), and default logging level. Values here can be overridden by more specific configuration files (`client_config.yml`, `server_config.yml`).
* **Syntax Check:** The main scripts perform a `bash -n` syntax check before sourcing.
* **Key Variables (Examples):**
    * `YQ_CMD="/usr/bin/yq"`
    * `TAR_CMD="/bin/tar"`
    * `DEFAULT_ADMIN_EMAIL="root@localhost"`
    * `DEFAULT_PLUGIN_DIR="/opt/backup/lib/plugins"`
    * `LOG_LEVEL="2"` (INFO)

### 1.2 `client_config.yml`

* **Installed to:** `/etc/backup/client_config.yml`
* **Format:** YAML
* **Permissions:** MUST be `600` owned by `root`. The `local_backup.sh` script verifies this.
* **Purpose:** Defines client-specific settings for the `local_backup.sh` script. This includes the base directory for storing local TAR archives (`base_backup_dir`), the user/group for the final archive, email notification settings, backup retention days (`keep_days`), plugin directory, and overrides for tool paths or logging level.
* **Syntax Check:** The `local_backup.sh` script performs a `yq .` syntax check before parsing.
* **Details:** See `backup-client/README.md` for a full list of parameters and examples.

### 1.3 `server_config.yml`

* **Installed to:** `/etc/backup/server_config.yml`
* **Format:** YAML
* **Permissions:** MUST be `600` owned by `root`. The `backup_server.sh` and `restic_maintenance.sh` scripts verify this.
* **Purpose:** Defines server-specific settings, including global parameters for the server script (temporary directories, admin email), Restic repository details (root path, password file), and a list of client hosts to back up with their respective SSH credentials and remote TAR directory paths. It also contains settings for the `restic_maintenance.sh` script.
* **Syntax Check:** The server scripts perform a `yq .` syntax check before parsing.
* **Details:** See `backup-server/README.md` for a full list of parameters and examples.

## 2. Service Configuration Files (`service.yaml`)

* **Location (on Client):** `/etc/backup/<service_type_category>/<specific_service_name>/service.yaml`
    * Example: `/etc/backup/docker/my_web_app/service.yaml`
    * Example: `/etc/backup/database/main_postgres_db/service.yaml`
* **Format:** YAML.
* **Permissions:** MUST be `600` owned by `root`. The `local_backup.sh` script verifies this.
* **Purpose:** Each `service.yaml` file defines the specific backup tasks for a single service or application component on the client machine.
    * It **must** contain a unique `service.name`.
    * It contains one or more "task blocks" (e.g., `docker:`, `files:`, `postgresql:`), where each block key corresponds to a plugin that handles that type of backup.
    * Under each task key, plugin-specific parameters are defined.
* **Examples in Source Tree:**
    * The `configs/docker/tandoor_recipes/service.yaml` and `configs/other/pihole/service.yaml` in the source tree are **examples** of how these files should be structured. Administrators need to create appropriate `service.yaml` files for each service they wish to back up on their client machines and place them in the `/etc/backup/` directory structure.
* **Details:** Refer to `plugins/README.md` for detailed configuration options for each available plugin.

## 3. Important Notes

* **Permissions:** Strict file permissions (`600 root:root`) are crucial for all configuration files containing potentially sensitive information or system paths.
* **Customization:** After package installation, review and customize all files in `/etc/backup/` to match your environment and requirements. The packaged versions are templates or defaults.
* **Tool Paths:** Ensure that paths to external tools (like `yq`, `restic`, `docker`, database dump utilities) are correctly defined in `common_config` or overridden in specific configurations if they are not in the standard `PATH` for the `root` user or the systemd service execution environment.
