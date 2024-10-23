# Index
- [[Web Application]]
	- [[Web Application Enumeration]]
	- [[Back End Vulnerabilities]]
		- [[1. Insecure File Uploads]]
		- [[2. File Inclusion]]
		- [[3. Command Injection]]
		- [[4. SQL Injection (SQLi)]]
		- [[5. Server-Side Request Forgery (SSRF)]]
		- [[6. Server-Side Template Injection (SSTi)]]
		- [[7. XML External Entity (XXE)]]
		- [[8. Insecure Deserialization]]

# Summary
Back-end vulnerabilities in web application penetration testing refer to security weaknesses in the server-side components of a web application. These vulnerabilities can be exploited to gain unauthorized access, manipulate data, execute arbitrary code, or disrupt services. Understanding and identifying these vulnerabilities are crucial for securing web applications.

# Common Back-End Vulnerabilities

## SQL Injection (SQLi)
SQL injection occurs when an application improperly handles user input in SQL queries, allowing attackers to execute arbitrary SQL commands. This can lead to data leakage, data manipulation, or even remote code execution.

```
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'password';
```

- **Exploitation:** An attacker can manipulate the input to execute malicious SQL queries:

```
admin' OR '1'='1
```

## Command Injection
Command injection occurs when an application improperly handles user input in system commands, allowing attackers to execute arbitrary commands on the server.

```
<?php system("ping -c 4 " . $_GET['ip']); ?>
```

- **Exploitation:** An attacker can manipulate the input to execute arbitrary commands:

```
http://<target_ip>/ping.php?ip=;cat /etc/passwd
```

## Insecure Deserialization
Insecure deserialization occurs when an application deserializes untrusted data, allowing attackers to manipulate serialized objects to execute arbitrary code, conduct data tampering, or perform other malicious actions.

```
$object = unserialize($_POST['data']);
```

- **Exploitation:** An attacker can craft a malicious serialized object to exploit the application.

## Server-Side Request Forgery (SSRF)
SSRF vulnerabilities occur when an application fetches resources specified by user input, allowing attackers to make requests to internal systems, potentially accessing internal services or exploiting vulnerabilities.

```
<?php file_get_contents($_GET['url']); ?>
```

- **Exploitation:** An attacker can manipulate the input to access internal services:

```
http://<target_ip>/fetch.php?url=http://localhost/admin
```

## Authentication and Authorization Flaws
Authentication and authorization flaws occur when an application fails to properly enforce user authentication and authorization, allowing attackers to access unauthorized resources or perform unauthorized actions.

- **Weak Password Policy:** Allowing easily guessable passwords.
- **Privilege Escalation:** Users can escalate their privileges by manipulating requests.

## Security Misconfigurations
Security misconfigurations occur when security settings are not properly configured, exposing the application to various attacks.

- **Exposed Debugging Information:** Leaving debug mode enabled in production.
- **Default Configurations:** Using default settings that are insecure.

## Sensitive Data Exposure
Sensitive data exposure occurs when an application does not adequately protect sensitive information, such as personal data, financial data, or credentials.

- **Unencrypted Data:** Transmitting sensitive data over HTTP instead of HTTPS.
- **Improper Data Storage:** Storing sensitive information in plaintext.

## XML External Entity (XXE)
XXE vulnerabilities occur when an XML parser processes external entities within an XML document, allowing attackers to access local files, execute remote requests, or conduct other malicious activities.

```
<?xml version="1.0"?> <!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <root>&xxe;</root>
```

- **Exploitation:** An attacker can exploit the vulnerability to read local files:

```
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

# Tools for Identifying Back-End Vulnerabilities

|**Tool**|**Description**|
|-|-|
| Burp Suite | An integrated platform for performing security testing of web applications, including back-end vulnerabilities. |
| SQLMap     | An automated tool for detecting and exploiting SQL injection vulnerabilities.                                   |
| OWASP ZAP  | A comprehensive web application security scanner that can detect various back-end vulnerabilities.              |
| Nessus     | A vulnerability scanner that identifies security flaws in web applications and network infrastructure.          |
| Nikto      | A web server scanner for identifying potential vulnerabilities and misconfigurations.                           |
| Arachni    | An open-source web application security scanner designed to identify front-end and back-end vulnerabilities.    |

# Real-world Examples

|**Vulnerability**|**Real-world Scenario**|
|-|-|
| SQL Injection               | An attacker exploits a vulnerable login form to dump the database containing user credentials.                    |
| Command Injection           | An attacker manipulates a vulnerable parameter to execute system commands, gaining shell access to the server.    |
| Insecure Deserialization    | An attacker crafts a malicious serialized object to execute arbitrary code on the server.                         |
| Server-Side Request Forgery | An attacker exploits SSRF to access internal administrative interfaces not directly accessible from the internet. |
| Authentication Flaws        | An attacker bypasses authentication by exploiting weak password policies and gains access to restricted areas.    |
| Security Misconfigurations  | An attacker finds exposed debugging information that reveals internal IP addresses and server configurations.     |
| Sensitive Data Exposure     | An attacker intercepts unencrypted network traffic and captures sensitive data, such as login credentials.        |
| XML External Entity         | An attacker uses an XXE payload to read the server's /etc/passwd file, revealing sensitive system information.    |

# Mitigation Strategies

## Input Validation and Sanitization
Ensure all user inputs are properly validated and sanitized to prevent injection attacks.

- **Whitelist Input:** Only allow expected input values.
- **Parameterized Queries:** Use parameterized queries to prevent SQL injection.

## Secure Deserialization
Avoid deserializing untrusted data and implement strict validation checks on serialized objects.

- **Use Safe Libraries:** Use libraries that enforce secure deserialization practices.
- **Validation Checks:** Implement validation checks to ensure the integrity of serialized data.

## Proper Authentication and Authorization
Implement strong authentication and authorization mechanisms to prevent unauthorized access.

- **Strong Password Policies:** Enforce the use of strong, complex passwords.
- **Multi-Factor Authentication:** Implement multi-factor authentication for added security.

## Secure Configuration Management
Ensure that security settings are properly configured and maintained.

- **Disable Debugging:** Disable debugging in production environments.
- **Use Secure Defaults:** Configure applications with secure default settings.

## Data Protection
Ensure sensitive data is adequately protected both in transit and at rest.

- **Encryption:** Use strong encryption protocols for data transmission and storage.
- **Secure Storage:** Store sensitive information securely, avoiding plaintext storage.

## XML Parser Hardening
Harden XML parsers to prevent XXE vulnerabilities.

- **Disable External Entities:** Configure XML parsers to disable external entity processing.
- **Use Safe Libraries:** Use XML libraries that are configured securely by default.