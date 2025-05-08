# Systemd Unit Files for Backup System

This directory contains example Systemd `.service` and `.timer` unit files for automating the execution of the local backup client and the backup server scripts.

## Client-Side Units

* **`local-backup.service`**: Defines how to run the `/opt/backup/bin/local_backup.sh` script.
    * It's a `Type=oneshot` service, meaning it performs a single task and then exits.
    * Runs as `root`.
    * Includes commented-out examples for resource limiting (`CPUQuota`, `MemoryMax`, `IOWeight`) which can be adjusted to prevent the backup process from consuming too many system resources.
* **`local-backup.timer`**: Defines when the `local-backup.service` should be run.
    * By default, it's configured to run daily at 3:00 AM (`OnCalendar=*-*-* 03:00:00`).
    * Includes a `RandomizedDelaySec` to spread the load if multiple clients start their backups around the same time.
    * `Persistent=true` ensures the job runs if the system was down during its scheduled time.

**To use (on a client machine):**

1.  Copy `local-backup.service` and `local-backup.timer` to `/etc/systemd/system/`.
2.  Customize `OnCalendar` in `local-backup.timer` if needed.
3.  Adjust resource limits in `local-backup.service` if necessary.
4.  Reload systemd: `sudo systemctl daemon-reload`
5.  Enable the timer to start on boot and start it now: `sudo systemctl enable --now local-backup.timer`
6.  Check status: `sudo systemctl status local-backup.timer`
7.  View logs: `sudo journalctl -u local-backup.service`

## Server-Side Units

### Backup Fetching

* **`backup-server.service`**: Defines how to run `/opt/backup/bin/backup_server.sh`.
    * `Type=oneshot`, runs as `root`.
    * Includes resource limit examples.
* **`backup-server.timer`**: Defines when `backup-server.service` runs.
    * Default: Daily at 4:00 AM (intended to run after client backups complete).

**To use (on the backup server):**

1.  Copy `backup-server.service` and `backup-server.timer` to `/etc/systemd/system/`.
2.  Customize `OnCalendar` and resource limits.
3.  `sudo systemctl daemon-reload`
4.  `sudo systemctl enable --now backup-server.timer`
5.  Check status: `sudo systemctl status backup-server.timer`
6.  View logs: `sudo journalctl -u backup-server.service`

### Restic Repository Maintenance

* **`restic-maintenance.service`**: Defines how to run `/opt/backup/bin/restic_maintenance.sh`.
    * `Type=oneshot`, runs as `root`.
    * Includes resource limit examples, which might be more relevant here due to potentially I/O and CPU intensive `prune` and `check` operations.
* **`restic-maintenance.timer`**: Defines when `restic-maintenance.service` runs.
    * Default: Weekly on Sunday at 5:00 AM. Maintenance is typically less frequent than backups.

**To use (on the backup server):**

1.  Ensure you have created the `/opt/backup/bin/restic_maintenance.sh` script.
2.  Copy `restic-maintenance.service` and `restic-maintenance.timer` to `/etc/systemd/system/`.
3.  Customize `OnCalendar` and resource limits.
4.  `sudo systemctl daemon-reload`
5.  `sudo systemctl enable --now restic-maintenance.timer`
6.  Check status: `sudo systemctl status restic-maintenance.timer`
7.  View logs: `sudo journalctl -u restic-maintenance.service`

## Notes

* The `.service` files specify `User=root` and `Group=root`.
* The `Environment="PATH=..."` line in the service files ensures that the scripts can find necessary executables even if run in a minimal systemd environment. The `/opt/backup/bin` path is added first.
* Resource limits (`CPUQuota`, `MemoryMax`, `IOWeight`) are powerful but should be used with caution and tuned to your specific system and workload. Incorrectly set limits can kill the backup process or severely degrade system performance. Start without them or with very conservative values if unsure.
* After installation via Debian packages, these files would typically be placed in `/lib/systemd/system/` by `dh_installsystemd`. Administrators can override them by placing modified copies in `/etc/systemd/system/`.

