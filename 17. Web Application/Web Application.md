# Index
- [[Red Team]]
	- [[Web Application]]
		- [[Web Application Enumeration]]
		- [[Front End Vulnerabilities]]
		- [[Back End Vulnerabilities]]
	- [[P80 HTTP]]
	- [[P443 HTTPS]]

# Summary
Web applications are interactive programs that run within web browsers. They typically use a client-server architecture to handle interactions, with front-end components (user interface) operating on the client-side (browser) and back-end components (application logic and databases) running on the server-side.

# Web Applications vs. Websites

#### Websites (Web 1.0)
Websites of the past, known as Web 1.0, were static and did not change in real-time. These static pages displayed fixed content that could only be modified by developers manually updating the page. These sites lacked interactive functions and did not respond dynamically to user interactions.

#### Web Applications (Web 2.0)
Modern websites typically function as web applications, also known as Web 2.0, presenting dynamic content based on user interactions. Web applications are fully functional, capable of performing various tasks for the user, unlike static websites.

# Web Applications vs. Native Operating System Applications
Web applications are platform-independent, running in a browser on any operating system, without needing installation on the user's system. This centralizes the application execution on the server, reducing local resource consumption and ensuring version unity for all users. Web applications can be continuously updated on the server side without distributing updates to individual users.

Conversely, native OS applications, though faster and capable of utilizing native OS libraries and hardware, require installation on each user's device and often involve complex updates and version management. However, hybrid and progressive web applications are bridging this gap by leveraging modern frameworks to use native OS capabilities, making them more efficient and capable.

# Attacking Web Applications

|**Flaw**|**Real-world Scenario**|
|-|-|
| SQL Injection                             | Obtaining Active Directory usernames and performing a password spraying attack against a VPN or email portal.                                 |
| File Inclusion                            | Reading source code to find a hidden page or directory which exposes additional functionality that can be used to gain remote code execution. |
| Unrestricted File Upload                  | Uploading a malicious file through a web application that allows any file type, potentially gaining full control of the server.               |
| Insecure Direct Object Referencing (IDOR) | Accessing another user's files or functionality by manipulating parameters in the URL.                                                        |
| Broken Access Control                     | Exploiting poorly designed account registration to escalate privileges, such as registering as an admin user.                                 |

# Web Application Layout

#### Web Application Infrastructure
Describes the structure of required components, such as databases, needed for the web application to function. Web applications can adopt various infrastructure setups, commonly grouped into four types:

- **Client-Server:** In a client-server model, a server hosts the web application, distributing it to clients accessing it. Components are divided between front-end (client-side) and back-end (server-side). The server processes client requests and sends back the necessary data for the client's browser to display.
![[Web Application - ClientServer.png]]

- **One Server:** All web application components, including the database, are hosted on a single server. This design is straightforward but risky, as compromising one application can compromise all data on the server.
![[Web Application - OneServer.png]]

- **Many Servers - One Database:** Separates the database onto its server, allowing multiple web application servers to access it. This segmentation enhances security by isolating compromised components.
![[Web Application - OneDatabase.png]]

- **Many Servers - Many Databases:** Builds upon the previous model by hosting separate databases for each web application, enhancing redundancy and security.
![[Web Application - ManyDatabases.png]]

#### Web Application Components
Components are divided into UI/UX, Client, and Server areas, including:

- Client
- Server
    - Webserver
    - Web Application Logic
    - Database
- Services (Microservices)
    - 3rd Party Integrations
    - Web Application Integrations
- Functions (Serverless)

#### Web Application Architecture
Comprises relationships between components, divided into three layers (Three-Tier Architecture):

|**Layer**|**Description**|
|-|-|
| Presentation Layer | UI components enabling communication with the application, accessed via the browser and returned as HTML, JavaScript, and CSS. |
| Application Layer  | Processes client requests, checking authorization, privileges, and data handling.                                              |
| Data Layer         | Works with the application layer to determine where data is stored and how it is accessed.                                     |
![[Web Application - ExampleArchitecture.png]]

- **Microservices:** Microservices are independent components focusing on single tasks (e.g., Registration, Search, Payments), communicating statelessly. They offer agility, flexible scaling, easy deployment, reusable code, and resilience.

- **Serverless:** Cloud providers (AWS, GCP, Azure) offer serverless architectures, allowing web applications to run in stateless computing containers (e.g., Docker). This removes the need for server management, provisioning, and scaling, handled by the cloud provider.

- **Architecture Security:** Understanding web application architecture is crucial for penetration testing. Vulnerabilities may stem from architectural design errors rather than programming mistakes. Proper security measures, like Role-Based Access Control (RBAC), must be implemented during development and throughout the lifecycle.

# Front End vs. Back End

#### Front End
The front end of a web application contains the user's components directly through their web browser (client-side). These components make up the source code of the web page we view when visiting a web application and usually include HTML, CSS, and JavaScript, which is then interpreted in real-time by our browsers. This includes everything that the user sees and interacts with, like the page's main elements such as the title and text HTML, the design and animation of all elements CSS, and what function each part of a page performs JavaScript.
#### Back End
The back end of a web application drives all of the core web application functionalities, all of which is executed at the back end server, which processes everything required for the web application to run correctly. It is the part we may never see or directly interact with, but a website is just a collection of static web pages without a back end. There are four main back end components for web applications:

| **Component**          | **Description**                                                                                    |
| - | -- |
| Back end Servers       | Hardware and operating systems hosting other components, usually on Linux, Windows, or Containers. |
| Web Servers            | Handle HTTP requests and connections (e.g., Apache, NGINX, IIS).                                   |
| Databases              | Store and retrieve web application data (e.g., MySQL, MSSQL, Oracle, PostgreSQL, NoSQL, MongoDB).  |
| Development Frameworks | Used to develop the core web application (e.g., Laravel, ASP.NET, Spring, Django, Express).        |

#### Securing Front/Back End
Penetration testing involves identifying vulnerabilities through techniques like SQL injection or command injection. Code reviews can be conducted for front-end components (white-box testing), while back-end testing is typically black-box unless source code is available.

#### Common Mistakes by Web Developers
1. Permitting invalid data into the database
2. Focusing on the system as a whole
3. Developing insecure custom security methods
4. Treating security as a final step
5. Storing plaintext passwords
6. Creating weak passwords
7. Storing unencrypted data
8. Over-relying on the client-side
9. Being overly optimistic
10. Allowing variables via the URL path
11. Trusting third-party code
12. Hard-coding backdoor accounts
13. Unverified SQL injections
14. Remote file inclusions
15. Insecure data handling
16. Failing to encrypt data properly
17. Not using secure cryptographic systems
18. Ignoring human factors (layer 8)
19. Failing to review user actions
20. Misconfiguring web application firewalls

#### OWASP Top 10 Vulnerabilities
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)