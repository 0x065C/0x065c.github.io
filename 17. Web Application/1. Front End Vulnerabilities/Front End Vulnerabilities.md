# Index
- [[Web Application]]
	- [[Web Application Enumeration]]
	- [[Front End Vulnerabilities]]
		- [[1. Sensitive Data Exposure]]
		- [[2. HTML Injection]]
		- [[3. Insecure Direct Object References (IDOR)]]
		- [[4. Cross-Site Scripting (XSS)]]
		- [[5. Cross-Site Request Forgery (CSRF)]]
		- [[6. Insufficient Transport Layer Protection]]
		- [[7. Insecure Handling of Cookies and Sessions]]
		- [[8. Security Misconfigurations|8. Security Misconfigurations]]

# Summary
Front-end vulnerabilities in web application penetration testing refer to security weaknesses found in the client-side components of a web application. These vulnerabilities can be exploited by attackers to manipulate the application's behavior, steal sensitive information, or bypass security mechanisms. Understanding and identifying these vulnerabilities is crucial for securing web applications.

# Common Front-End Vulnerabilities

#### Cross-Site Scripting (XSS)
XSS vulnerabilities occur when a web application improperly handles user input, allowing attackers to inject malicious scripts into web pages viewed by other users. These scripts can be used to steal cookies, session tokens, or other sensitive information.

- **Reflected XSS:** Malicious script is reflected off a web server and executed immediately in the user's browser.
- **Stored XSS:** Malicious script is stored on the web server and executed whenever the affected page is viewed.
- **DOM-based XSS:** Malicious script is executed as a result of modifying the Document Object Model (DOM) of the web page.

```
<input type="text" name="user" value="<script>alert('XSS');</script>">
```

#### Cross-Site Request Forgery (CSRF)
CSRF vulnerabilities allow attackers to trick users into performing actions they did not intend to perform. This is done by exploiting the user's authenticated session with a web application.

- **Forged Requests:** Attackers craft malicious requests that exploit the user's session.
- **State-changing Actions:** CSRF attacks usually target actions like changing account settings or performing transactions.

```
<img src="http://<target_ip>/change-email?email=attacker@example.com">
```

#### HTML Injection
HTML injection vulnerabilities occur when an application accepts untrusted input and includes it in the HTML output. This can lead to various attacks, including XSS and defacement.

- **Form Fields:** User input is included in form fields without proper sanitization.
- **Dynamic Content:** User-generated content is displayed on the web page without validation.

```
<input type="text" name="comment" value="<b>Malicious HTML</b>">
```

#### Insecure Direct Object References (IDOR)
IDOR vulnerabilities occur when an application provides direct access to objects based on user input. This can allow attackers to access unauthorized data by modifying parameter values.

- **URL Manipulation:** Changing the URL parameter to access different resources.
- **Form Field Manipulation:** Modifying hidden form fields to access unauthorized data.

```
http://<target_ip>/user-profile?id=12345
```

#### Security Misconfigurations
Security misconfigurations occur when security settings are improperly configured, leaving the application vulnerable to attacks.

- **Exposed Error Messages:** Detailed error messages revealing stack traces or sensitive information.
- **Default Credentials:** Using default usernames and passwords for admin interfaces.
- **Improper CORS Configuration:** Allowing unauthorized domains to make cross-origin requests.

```
{   "error": "Stack trace here" }
```

#### Insufficient Transport Layer Protection
This vulnerability occurs when web applications fail to properly protect data transmitted over the network, making it susceptible to interception.

- **Unencrypted Communication:** Transmitting sensitive data over HTTP instead of HTTPS.
- **Weak Encryption:** Using outdated or weak encryption protocols.

```
http://<target_ip>/login
```

# Tools for Identifying Front-End Vulnerabilities

|**Tool**|**Description**|
|-|-|
| OWASP ZAP  | A comprehensive web application security scanner that can detect various front-end vulnerabilities.              |
| Burp Suite | An integrated platform for performing security testing of web applications, including front-end vulnerabilities. |
| Netsparker | An automated web application security scanner that identifies vulnerabilities, including XSS and CSRF.           |
| Arachni    | An open-source web application security scanner designed to identify front-end and back-end vulnerabilities.     |
| Acunetix   | A web vulnerability scanner that includes checks for XSS, CSRF, and other front-end vulnerabilities.             |

# Real-world Examples

| **Vulnerability**| **Real-world Scenario**|
|-|-|
| Cross-Site Scripting                    | An attacker injects a malicious script into a comment field, which is then executed by any user viewing the comment. |
| Cross-Site Request Forgery              | An attacker sends a link to a user, which when clicked, changes the user's email address in the application.         |
| HTML Injection                          | An attacker includes malicious HTML in a user profile field, causing the profile page to be defaced.                 |
| Insecure Direct Object References       | An attacker modifies the URL parameter to access another user's account details.                                     |
| Security Misconfigurations              | Detailed error messages reveal sensitive information about the application and its server.                           |
| Insufficient Transport Layer Protection | Sensitive data, such as login credentials, are transmitted over HTTP, allowing attackers to intercept it.            |

# Mitigation Strategies

#### Input Validation and Sanitization
Ensure all user inputs are properly validated and sanitized to prevent injection attacks.

- **Whitelist Input:** Only allow expected input values.
- **Escape Output:** Properly escape user inputs included in HTML, JavaScript, or SQL.

#### Anti-CSRF Tokens
Use anti-CSRF tokens to protect against CSRF attacks.

- **Token Generation:** Generate a unique token for each session.
- **Token Validation:** Validate the token with each state-changing request.

#### Secure Coding Practices
Adopt secure coding practices to prevent vulnerabilities.

- **Least Privilege:** Ensure users only have the permissions they need.
- **Error Handling:** Avoid exposing detailed error messages to users.

#### Transport Layer Security (TLS)
Implement TLS to encrypt data transmitted between the client and server.

- **HTTPS Only:** Ensure all data is transmitted over HTTPS.
- **Strong Encryption:** Use strong encryption protocols and ciphers.

#### Security Configurations
Ensure security settings are properly configured to protect the application.

- **Remove Default Credentials:** Change default usernames and passwords.
- **Restrict CORS:** Only allow trusted domains to make cross-origin requests.