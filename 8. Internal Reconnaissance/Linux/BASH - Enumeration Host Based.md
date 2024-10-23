# BASH - Enumeration Host Based

## System Information

**System Information**

* `uname -a`: Displays all system information, including kernel version and architecture.
* `cat /etc/os-release`: Shows details about the Linux distribution.
* `hostnamectl`: Provides information about the hostname and operating system version.
* `uptime`: Displays how long the system has been running, and the load average.
* `dmesg`: View kernel ring buffer messages, useful for system and hardware information.
* `lscpu`: Displays CPU architecture information.
* `free -h`: Shows available and used memory in human-readable format.\

* `cat /proc/version`: Provides detailed information about the kernel version, distribution, and GCC version used to build the kernel.
* `ls /lib/modules/$(uname -r)/kernel`: Displays loaded kernel modules, useful for detecting security software or custom modules.
* `uptime -p`: Displays the system uptime in a more human-readable format (e.g., "up 3 days, 4 hours").
* `lsmod`: Lists loaded kernel modules.
* `cat /proc/cpuinfo`: Shows detailed CPU information, including cores, cache size, and processor flags.
* `cat /proc/meminfo`: Displays detailed memory information.
* `lspci`: Shows information about all PCI devices (useful for detecting hardware like GPUs or network cards).
* `lsusb`: Lists all connected USB devices.

**System Logs**

* `journalctl`: Displays logs from the systemd journal (most modern Linux distributions use this).
* `journalctl -u <service_name>`: Displays logs for a specific service managed by systemd.
* `journalctl --since "1 hour ago"`: View logs from the last hour.
* `journalctl --boot`: Show logs from the current boot.
* `grep <keyword> /var/log/messages`: Search for specific keywords in system logs.
* `grep <keyword> /var/log/syslog`: Search for specific keywords in syslog (Debian-based systems).
* `cat /var/log/secure`: Security log for authentication events (RHEL-based).
* `auditctl -l`: Lists active auditing rules.
* `ausearch -m avc`: Search logs for SELinux access violations.

**User Information**

* `whoami`: Prints the current logged-in user.
* `id`: Displays user and group IDs.
* `last`: Shows a list of the most recent successful logins.
* `lastb`: Shows a list of the most recent failed login attempts.
* `w`: Displays who is logged in and what they are doing.
* `users`: Lists all logged-in users.
* `cat /etc/passwd`: Lists all users on the system.
* `getent passwd`: Displays user accounts from the local database or remote systems.
* `cat /etc/shadow`: Shows password hashes (requires root permissions).
* `sudo -l`: Lists commands that can be run with sudo by the current user.\

* `awk -F: '$3 == 0 {print}' /etc/passwd`: Find all users with UID 0 (root equivalent).
* `cat /etc/sudoers`: View sudo privileges. Check for misconfigurations or all-users access.
* `grep '^sudo:.*$' /etc/group`: Lists users in the `sudo` group.
* `getent passwd <username>`: Provides detailed information about a specific user.
* `finger <username>`: Retrieves detailed information about a user, if available.

**Group Information**

* `groups`: Displays groups the current user belongs to.
* `getent group`: Lists all groups on the system.
* `cat /etc/group`: Shows group details, including memberships.\

* `cat /etc/gshadow`: Lists group passwords (rarely used, but might contain valuable info).
* `grep '^wheel:.*$' /etc/group`: Shows users in the `wheel` group (common root access group).

**Scheduled Tasks & Crons**

* `crontab -l`: Displays the current user's cron jobs.
* `ls /etc/cron.*`: Lists cron directories for hourly, daily, weekly, and monthly jobs.
* `cat /etc/crontab`: Displays system-wide cron jobs.
* `cat /var/spool/cron/crontabs/*`: View crons for all users (requires root permissions).\

* `find / -name "*cron*" 2>/dev/null`: Search for any files related to cron jobs across the system.
* `grep -r cron /etc/*`: Searches for cron jobs in configuration files.
* `at -l`: Lists jobs scheduled with the `at` command (used for one-time tasks).
* `find /etc/cron.d/ -type f`: Check for system cron jobs in `/etc/cron.d/`.

**Active Sessions**

* `who`: Shows who is logged in.
* `w`: Detailed view of logged-in users and their active sessions.
* `ps -ef | grep sshd`: List active SSH sessions.

## Network Information

**Network Configuration**

* `ifconfig | ip a`: Display network interfaces and their IP configurations.
* `ip link`: Show link layer information about network interfaces.
* `ip route`: Display or manipulate the system routing table.
* `nmcli`: Shows detailed network configuration and status for NetworkManager-controlled systems.
* `cat /etc/network/interfaces`: Displays network interface configuration (Debian-based systems).
* `resolvectl status`: Displays DNS resolution status and servers.
* `cat /etc/resolv.conf`: Shows the system's DNS server configuration.\

* `cat /etc/hosts`: Displays static host mappings.
* `cat /etc/network/interfaces.d/*`: View detailed network configuration for each interface (Debian-based systems).
* `ifconfig eth0 | grep inet`: Displays the IP address of a specific network interface.
* `nmcli device show <interface>`: Shows detailed information about a specific network device in NetworkManager.
* `iwconfig`: Displays wireless network information (SSID, signal strength).
* `tcpdump -i <interface>`: Start packet capturing on a specific interface.

**Network Connections**

* `netstat -tulnp`: Lists all open ports and the associated processes.
* `ss -tulwn`: Displays listening sockets and established connections.
* `lsof -i`: Lists open files and associated network connections.
* `arp -a`: Displays the ARP cache.
* `ip n`: Shows the ARP table (neighbor table).

**Open Ports and Connections (Advanced)**

* `nmap -sT -O <target_ip>`: Perform a TCP connect scan and attempt to detect the operating system.
* `ss -anp`: Displays network sockets and their associated processes.
* `netstat -an | grep LISTEN`: Shows all listening services.
* `fuser -v <port>`: Displays processes using a specific port.
* `cat /proc/net/tcp`: Displays active TCP connections.
* `cat /proc/net/udp`: Displays active UDP connections.

**ARP & Routing (Advanced)**

* `ip addr show`: Displays all IP addresses assigned to network interfaces.
* `arp -n`: Displays the ARP cache, showing local IP-to-MAC address mappings.
* `ip route add <subnet> via <gateway>`: Adds a new route to the routing table.
* `ip route del <subnet>`: Deletes a route from the routing table.

**Network Services**

* `systemctl list-units --type=service | grep networking`: Check the status of networking services.
* `netstat -nlpt`: Lists all listening services along with their associated PID.
* `chkconfig --list | grep on`: Lists all services enabled at boot (SysVinit systems).

**Firewall Status**

* `iptables -L`: Lists current iptables rules.
* `ufw status`: Displays the status of UFW (Uncomplicated Firewall), if available.
* `firewalld-cmd --list-all`: Shows current firewall configuration in firewalld systems.\

* `iptables -S`: Lists all active iptables rules.
* `iptables -t nat -L`: Displays NAT table rules.
* `iptables-save > /tmp/iptables_backup`: Saves iptables rules to a file for further analysis.
* `firewall-cmd --list-services`: Shows services allowed through the firewall in `firewalld`.

## Process & Service Enumeration

**Running Processes**

* `ps aux`: Lists all running processes with detailed information.
* `top | htop`: Real-time view of processes.
* `pgrep <process_name>`: Find process IDs by name.
* `pstree`: Display a tree of processes.
* `lsof -p <pid>`: List all open files by a specific process.
* `strace -p <pid>`: Trace system calls and signals for a process.\

* `ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head`: Lists top processes by memory usage.
* `ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head`: Lists top processes by CPU usage.
* `ps aux --sort=-rss`: Displays processes sorted by memory consumption.
* `cat /proc/<pid>/status`: Shows detailed status information for a specific process.
* `cat /proc/<pid>/cmdline`: Displays the command line used to start a specific process.
* `cat /proc/<pid>/environ`: Displays environment variables used by a specific process.
* `lsof -p <pid>`: Lists open files used by a specific process.
* `kill -9 <pid>`: Forcefully kills a specific process.
* `nice -n -20 <process>`: Re-prioritizes a process to give it higher priority.

**Services**

* `systemctl list-units --type=service`: Lists all active services.
* `service --status-all`: Displays the status of all services (SysVinit systems).
* `systemctl status <service_name>`: Shows the status of a specific service.
* `chkconfig --list`: Displays services and their run levels (older systems).

## File System Enumeration

**General File Information**

* `df -h`: Displays disk space usage in human-readable format.
* `du -sh *`: Shows disk usage for files and directories in the current path.
* `lsblk`: Lists information about block devices (useful for mounted drives and partitions).
* `mount`: Shows all mounted file systems.
* `cat /etc/fstab`: Lists file systems configured to mount at boot.

**Directory and File Permissions**

* `ls -la`: Displays files and directories with detailed permissions.
* `find / -perm -u=s -type f 2>/dev/null`: Finds all SUID files on the system.
* `find / -perm -g=s -type f 2>/dev/null`: Finds all SGID files.
* `getfacl <file_or_directory>`: Displays access control list (ACL) for a file or directory.

**Sensitive Files**

* `cat /etc/hosts`: Shows static IP mappings.
* `cat ~/.bash_history`: View the bash history of the current user.
* `cat /var/log/auth.log`: Authentication log (useful for login attempts).
* `cat /var/log/syslog`: General system log.
* `cat /var/log/messages`: Log file for kernel and boot messages (Red Hat-based systems).

**Hidden and Backup Files**

* `find / -type f -name "*.bak"`: Searches for backup files, which might contain sensitive information.
* `find / -name ".*"`: Lists hidden files.
* `find / -type f \( -name "*.old" -o -name "*.bak" -o -name "*.orig" \)`: Finds backup or old files that could contain credentials or configurations.

**Disk and Partition Information**

* `fdisk -l`: Lists partitions and file system types.
* `blkid`: Displays UUIDs and file system types of all partitions.
* `cat /proc/mounts`: Shows currently mounted file systems.
* `tune2fs -l <device>`: Displays file system attributes for ext-based file systems (e.g., ext3, ext4).

**Searching for Files**

* `find / -name "<file_name>"`: Searches for specific files across the filesystem.
* `find / -type f -size +50M`: Lists all files larger than 50 MB.
* `find / -type f -mtime -1`: Find all files modified in the last day.
* `grep -r <pattern> <directory>`: Recursively search for patterns in files within a directory.
* `locate <filename>`: Quickly find files (requires the `locate` database to be updated).

## Installed Software & Package Management

**Installed Packages**

* `dpkg -l`: Lists installed packages on Debian-based systems.
* `rpm -qa`: Lists installed packages on Red Hat-based systems.
* `yum list installed | grep <package>`: Checks if a package is installed (RHEL/CentOS).
* `apt list --installed`: Lists installed packages (Debian-based).\

* `dpkg --get-selections`: Lists all installed packages on Debian-based systems.
* `apt-cache policy <package_name>`: Shows detailed version information about a specific package.
* `rpm -qf <file>`: Identifies which package a specific file belongs to.
* `yum history`: Shows the history of installed and removed packages.
* `zypper se <package_name>`: Search for packages on SUSE Linux systems.
* `pip freeze`: Lists installed Python packages.
* `gem list`: Lists installed Ruby gems.

**Services and Binaries**

* `which <binary>`: Locates a binary's path.
* `whereis <binary>`: Finds the binary, source, and manual pages for a command.
* `systemctl list-timers`: Lists timers (systemd equivalent to cron).
