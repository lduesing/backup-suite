# Systemd Unit Files for Backup System

This directory contains example Systemd `.service` and `.timer` unit files for automating the execution of the local backup client and the backup server scripts.

## Client-Side Units (`local-backup.*`)

* **`local-backup.service`**: Defines how to run `/opt/backup/bin/local_backup.sh`.
    * It's a `Type=oneshot` service, meaning it performs a single task and then exits.
    * Runs as `root`.
    * Includes commented-out examples for resource limiting (`CPUQuota`, `MemoryMax`, `IOWeight`) which can be adjusted to prevent the backup process from consuming too many system resources.

* **`local-backup.timer`**: Defines when `local-backup.service` should run.
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

### Backup Fetching (`backup-server.*`)

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

### Restic Repository Maintenance (`restic-maintenance.*`)

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


## Notes on Resource Limits

The `.service` files include commented-out examples for systemd resource limiting directives:

* **`CPUQuota=`**: Limits CPU usage (e.g., `50%` for half of one core's capacity). Useful for preventing backups from starving other processes.
* **`MemoryMax=`**: Sets a hard limit on memory usage (e.g., `2G`, `500M`). If the process exceeds this, it will be killed. Use with caution, as some backup operations (especially Restic `check` or database dumps) can be memory-intensive.
* **`IOReadBandwidthMax=` / `IOWriteBandwidthMax=`**: Limits disk I/O bandwidth for specified block devices (e.g., `/dev/sda 10M` for 10 MB/s). This requires a newer kernel and systemd version.
* **`IOWeight=`**: Adjusts the I/O scheduling priority (1-10000, default 100 for background tasks if `IOSchedulingClass=idle` is not set, or 1000 for `best-effort`). Lower values give lower I/O priority.
* **`Nice=`**: Sets the process niceness level (-20 to 19, higher is "nicer" / lower priority). `Nice=10` is a common value for background tasks.

**Recommendations:**

1.  **Start without strict limits:** Initially, run the services without aggressive resource limits to observe their typical consumption.
2.  **Monitor:** Use tools like `htop`, `iotop`, `systemd-cgtop` to understand CPU, memory, and I/O usage during backup runs.
3.  **Apply Incrementally:** If backups are impacting system performance, start by setting `Nice=` (e.g., `Nice=10`) and/or `IOWeight=` (e.g., `IOWeight=100`).
4.  **Use `CPUQuota` and `MemoryMax` with caution:** These can kill the backup process if set too low. `MemoryMax` is particularly risky for Restic operations on large repositories.
5.  **Test:** After applying limits, thoroughly test backup runs to ensure they complete successfully and within acceptable timeframes.

Adjust these settings based on your specific hardware, workload, and how critical immediate system responsiveness is during backup windows.

