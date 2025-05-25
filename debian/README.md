# Debian Packaging Information

**Last Updated:** May 25, 2025

This `debian/` directory contains all the necessary files to build the `backup-common`, `backup-client`, and `backup-server` Debian packages from the source code. It follows standard Debian packaging practices, primarily using `debhelper`.

## Table of Contents

1.  [Directory Structure Overview](#1-directory-structure-overview)
2.  [Key Packaging Files](#2-key-packaging-files)
    * [2.1 `control`](#21-control)
    * [2.2 `rules`](#22-rules)
    * [2.3 `changelog`](#23-changelog)
    * [2.4 `*.install`](#24-install)
    * [2.5 `*.maintscript`, `*.postinst`, `*.prerm`](#25-maintscript-postinst-prerm)
    * [2.6 `source/format`](#26-sourceformat)
3.  [Building the Packages](#3-building-the-packages)

## 1. Directory Structure Overview

The `debian/` directory holds metadata and scripts for the Debian build system.

* `backup-common.install`: Lists files for the `backup-common` package.
* `backup-common.postinst`: Post-installation script for `backup-common`.
* `backup-client.install`: Lists files for the `backup-client` package.
* `backup-client.maintscript`: Maintenance script for `backup-client`.
* `backup-server.install`: Lists files for the `backup-server` package.
* `backup-server.maintscript`: Maintenance script for `backup-server`.
* `changelog`: Records changes between package versions.
* `control`: Defines package metadata, dependencies, and descriptions.
* `copyright`: Contains license information.
* `rules`: The main build script (Makefile-like) executed by `dpkg-buildpackage`.
* `source/format`: Specifies the source package format.

## 2. Key Packaging Files

### 2.1 `control`

This is a crucial file. It defines:
* **Source Package:** Information about the source package name.
* **Binary Packages:** Defines each package (`backup-common`, `backup-client`, `backup-server`).
    * `Package:`: The name of the package.
    * `Architecture:`: Typically `all` for script-based packages.
    * `Depends:`: Lists runtime dependencies (e.g., `bash`, `yq`, `restic`, and other packages). It also defines dependencies between our packages (e.g., `backup-client` depends on `backup-common`).
    * `Recommends:`: Suggests optional but useful packages (e.g., `msmtp-mta`).
    * `Description:`: A summary and detailed description of the package.

### 2.2 `rules`

This is an executable Makefile. It tells `dpkg-buildpackage` how to build the packages.
* It typically uses `debhelper` sequences (`dh`) to automate most build steps.
* The `override_dh_install` targets are used to install files into their package-specific locations within the temporary build area.
* `override_dh_fixperms` ensures correct permissions are set on installed files, especially scripts (`755`) and configuration files (`644` before `postinst` potentially adjusts them).
* `override_dh_installdocs` installs documentation like `README.md` files.

### 2.3 `changelog`

Follows a specific format. It's essential to update this file before every new build, especially when changing the version number. Tools like `dch` can help manage this.

### 2.4 `*.install`

These simple text files list source files and their destination paths within the final installed system.
* Example (`backup-client.install`):
    ``` text
    backup-client/local_backup.sh /opt/backup/bin/
    backup-client/client_config.yml /etc/backup/
    systemd/local-backup.service /lib/systemd/system/
    systemd/local-backup.timer /lib/systemd/system/
    ```

### 2.5 `*.maintscript`, `*.postinst`, `*.prerm`

These are shell scripts executed at different stages of the package lifecycle (installation, upgrade, removal).
* `*.postinst`: Runs after installation/upgrade. Used here to set strict permissions on configuration files (`600 root:root`) and potentially create users/groups or enable systemd timers.
* `*.prerm`: Runs before removal. Used here to disable/stop systemd timers.
* `*.maintscript`: Can handle more complex upgrade/removal scenarios. Used here for handling configuration file conffile prompts.

### 2.6 `source/format`

Specifies the source package format, usually `3.0 (quilt)` for modern Debian packages.

## 3. Building the Packages

1.  **Navigate:** Change directory to the *root* of the project source tree (the directory containing this `debian/` directory).
2.  **Update Changelog:** Ensure `debian/changelog` is updated with the correct version number and changes. Use `dch -i` or edit manually.
3.  **Clean (Optional but Recommended):**
    ``` bash
    dpkg-buildpackage -T clean
    ```
4.  **Build:** Run `dpkg-buildpackage`. Common options include:
    * `-us -uc`: Don't sign the source package or changes file (useful for local builds).
    * `-b`: Build binary packages only.
    ``` bash
    dpkg-buildpackage -us -uc -b
    ```
5.  **Result:** The generated `.deb` files will appear in the directory *above* the source tree.
6.  **Install:** Use `sudo apt install ./<package_name>*.deb` to install the packages, ensuring dependencies are handled.
