# Backup Plugins User Guide

**Version:** 0.2
**Date:** May 25, 2025

This document describes the available standard plugins for the `local_backup.sh` client script and how to configure them using `service.yaml` files.

## Table of Contents

1.  [General Plugin Configuration](#1-general-plugin-configuration)
2.  [Available Plugins](#2-available-plugins)
    * [2.1 `docker_compose.sh` (Task: `docker`)](#21-docker_composesh-task-docker)
    * [2.2 `postgresql.sh` (Task: `postgresql`)](#22-postgresqlsh-task-postgresql)
    * [2.3 `mariadb.sh` (Task: `mariadb`)](#23-mariadbsh-task-mariadb)
    * [2.4 `files_rsync.sh` (Task: `files`)](#24-files_rsyncsh-task-files)
3.  [Configuration Examples](#3-configuration-examples)
    * [3.1 Example 1: Simple Web App (Docker + PostgreSQL)](#31-example-1-simple-web-app-docker--postgresql)
    * [3.2 Example 2: File Server](#32-example-2-file-server)
4.  [Plugin Locations and Extensibility](#4-plugin-locations-and-extensibility)

## 1. General Plugin Configuration

Plugins are configured on a per-service basis within `service.yaml` files located under `/etc/backup/`. The core script (`local_backup.sh`) scans these directories, finds `service.yaml` files, and processes them.

Each `service.yaml` file **must** contain a `service.name` key for identification. It then contains one or more "task blocks". The key for each task block (e.g., `docker:`, `files:`) tells the core script which plugin to call. The content under that key provides the specific configuration for that plugin's task for that service.

``` yaml
# General structure of /etc/backup/<category>/<service_name>/service.yaml
service:
  name: "MyUniqueServiceName" # Used in logs and backup paths

# --- Task Blocks Follow ---

plugin_task_key_1: # e.g., 'docker'
  parameter1: "value1"
  parameter2: 123

plugin_task_key_2: # e.g., 'files'
  paths:
    - "/path/to/backup_1"
    - "/path/to/backup_2"
  exclude:
    - "*.log"
```

## 2. Available Plugins

The following plugins are typically provided as part of the `backup-client` package and installed to `/opt/backup/lib/plugins/`.

### 2.1 `docker_compose.sh` (Task: `docker`)

* **Purpose:** Manages Docker Compose services during backup. It can stop services before other plugins run and restart them afterwards. It can also back up the `docker-compose.yml` file itself and optionally pin service images to their current SHA256 digest in the backup.
* **Task Key:** `docker`
* **Configuration Parameters:**
    * `compose_file` (Mandatory): String. The absolute path to the `docker-compose.yml` file for this service.
    * `project_directory` (Optional): String. The directory where `docker compose` commands should be executed. If not provided, it defaults to the directory containing the `compose_file`.
    * `stop_services` (Optional): Boolean (`true` or `false`). Whether to stop the services before backup. Defaults to `true`. If `false`, only config/pinning is done.
    * `stop_wait_seconds` (Optional): Integer. How many seconds to wait after stopping services to allow them to shut down gracefully. Defaults to `15`.
    * `backup_config` (Optional): Boolean (`true` or `false`). Whether to copy the `compose_file` into the backup. Defaults to `true`.
    * `pin_images` (Optional): Boolean (`true` or `false`). Whether to resolve service image tags to their current SHA256 digests and save them to a `docker-compose.pinned.yml` file within the backup. Defaults to `false`.

### 2.2 `postgresql.sh` (Task: `postgresql`)

* **Purpose:** Dumps a PostgreSQL database using `pg_dump`. It creates an **uncompressed** SQL file.
* **Task Key:** `postgresql`
* **Configuration Parameters:**
    * `database` (Mandatory): String. The name of the database to dump.
    * `username` (Optional): String. The username to connect to the database. If not provided, it uses the default (often the OS user, i.e., `root`).
    * `hostname` (Optional): String. The database host. Defaults to `localhost` (uses local socket if possible).
    * `port` (Optional): Integer. The database port. Defaults to `5432`.
    * `dump_options` (Optional): String. Any additional command-line options to pass directly to `pg_dump`.
* **Authentication:** This plugin relies on standard PostgreSQL authentication methods, primarily **`/root/.pgpass`**. Ensure this file exists, contains the correct password(s), and has `600 root:root` permissions. **Do not put passwords in `service.yaml`!**
    ``` text
    # Example /root/.pgpass entry
    # hostname:port:database:username:password
    localhost:5432:webapp_db:webapp_user:YourSecretPassword
    ```

### 2.3 `mariadb.sh` (Task: `mariadb`)

* **Purpose:** Dumps a MariaDB/MySQL database using `mysqldump`. It creates an **uncompressed** SQL file.
* **Task Key:** `mariadb`
* **Configuration Parameters:**
    * `database` (Mandatory): String. The name of the database to dump.
    * `username` (Optional): String. The username to connect. Defaults to `root`.
    * `hostname` (Optional): String. The database host. Defaults to `localhost`.
    * `port` (Optional): Integer. The database port. Defaults to `3306`.
    * `dump_options` (Optional): String. Any additional command-line options to pass directly to `mysqldump` (e.g., `"--single-transaction"`).
* **Authentication:** This plugin relies on standard MariaDB/MySQL authentication, primarily **`/root/.my.cnf`**. Ensure this file exists and contains credentials in a `[client]` or `[mysqldump]` section with `600 root:root` permissions.
    ``` ini
    # Example /root/.my.cnf entry
    [mysqldump]
    user=backup_user
    password=YourSecretPassword
    host=localhost
    ```

### 2.4 `files_rsync.sh` (Task: `files`)

* **Purpose:** Backs up specified files and directories using `rsync`. It preserves permissions, ownership, and relative paths.
* **Task Key:** `files`
* **Configuration Parameters:**
    * `paths` (Mandatory): A YAML list of strings, where each string is an absolute path to a file or directory to back up.
    * `exclude` (Optional): A YAML list of strings, where each string is a pattern to exclude (passed to `rsync --exclude`).
    * `rsync_options` (Optional): String. Any additional command-line options to pass directly to `rsync` (e.g., `"--acls --xattrs"`).

## 3. Configuration Examples

### 3.1 Example 1: Simple Web App (Docker + PostgreSQL)

* **File:** `/etc/backup/docker/my_webapp/service.yaml`
    ``` yaml
    service:
      name: "MyWebAppService"

    docker:
      compose_file: "/opt/my_webapp/docker-compose.yml"
      stop_wait_seconds: 20
      pin_images: true

    postgresql:
      database: "my_webapp_db"
      username: "webapp_backup_user" # Ensure .pgpass is set up

    files:
      paths:
        - "/etc/nginx/sites-available/my_webapp.conf"
        - "/etc/letsencrypt/live/my_webapp.example.com/"
      exclude:
        - ".*" # Exclude hidden files
    ```

### 3.2 Example 2: File Server

* **File:** `/etc/backup/files/shared_data/service.yaml`
    ``` yaml
    service:
      name: "SharedDataBackup"

    files:
      paths:
        - "/srv/shares/public/"
        - "/srv/shares/private/"
      exclude:
        - "**/Thumbs.db"
        - "**/*.tmp"
        - "lost+found/"
    ```

## 4. Plugin Locations and Extensibility

* **Standard Location:** `/opt/backup/lib/plugins/`
* **Custom Plugins:** You can create your own plugins by following the specifications in `CONTRIBUTING.md`. Place them in the standard plugin directory, or configure a custom directory using the `plugin_dir` setting in `/etc/backup/client_config.yml`.
* **Common Functions:** All plugins rely on `/opt/backup/lib/plugins/common_functions.sh` for logging and utility functions.
