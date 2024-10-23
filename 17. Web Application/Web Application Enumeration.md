# Index
- [[Web Application]]
	- [[Web Application Enumeration]]
	- [[Front End Vulnerabilities]]
	- [[Back End Vulnerabilities]]
- [[P80 HTTP]]
- [[P443 HTTPS]]

# Summary
Web application enumeration is the process of identifying and gathering information about web applications and their components. This phase is crucial in penetration testing as it provides insights into the application's structure, functionalities, and potential vulnerabilities. The information gathered during enumeration can be used to plan and execute further attacks.

# Passive Enumeration
Passive enumeration involves collecting information about a web application without directly interacting with the target system. This method aims to minimize the risk of detection by using publicly available information and indirect techniques. Passive enumeration provides valuable insights into the web application’s structure, technologies, and potential vulnerabilities, which can be used to plan further penetration testing activities.

## Types of Passive Enumeration

#### WHOIS Lookups
[[P43 WhoIs]]
WHOIS lookups provide registration details for a domain, including information about the registrant, registrar, registration dates, and contact information. This data can help identify the organization behind the web application and provide additional targets for social engineering attacks.

- **Domain Registration Details:** Information about the owner of the domain.
- **Registrar Information:** Details about the entity that registered the domain.
- **Contact Information:** Email addresses, phone numbers, and physical addresses associated with the domain.

- **Tools:**
	- [[Whois]]
	- [whoxy.com]
	- [whois.domaintools.com] for domain registration information.

#### DNS Enumeration
[[P53 DNS]]
DNS enumeration involves gathering information about the domain's DNS records to identify subdomains, mail servers, name servers, and other related information. Tools like `dig`, `nslookup`, and automated tools can be used for this purpose.

- **DNS Records:** A, AAAA, MX, TXT, CNAME, and other DNS record types.
- **Subdomains:** Identifying subdomains associated with the main domain.
- **Mail Servers:** Discovering mail servers (MX records) used by the domain.

- **Tools:**
	- [[Dig]]
	- [[Nslookup]]
	- [[DNSRecon]]
	- [[Fierce]]

#### Public Sources
[[Web Resources]]
Information about the web application can be gathered from various public sources, such as search engines, social media, forums, and other online repositories. This type of data can include sensitive information inadvertently exposed by employees or third parties.

- **Search Engines:** Using advanced search operators to find publicly accessible information.
- **Social Media:** Analyzing posts and profiles for information about the target.
- **Forums and Repositories:** Searching for discussions, code snippets, or configurations related to the target.

## Key Enumeration Techniques

#### Google Dorking
[[Dorking]]
Google Dorking uses advanced search operators to find specific information indexed by search engines that may not be easily accessible through standard searches. Common operators include:

- **site:** Restricts results to a specific domain.
- **filetype:** Searches for files of a particular type (e.g., PDF, DOC).
- **intitle:** Searches for pages with specific words in the title.
- **inurl:** Searches for URLs containing specific words.

#### Certificate Transparency Logs
Certificate Transparency logs are public logs of SSL/TLS certificates. These logs can be used to identify all subdomains and domains for which certificates have been issued.

- **Subdomain Discovery:** Finding subdomains associated with the target domain.
- **Domain History:** Viewing the history of issued certificates for the domain.

- **Tools:**
	- [[crt.sh]]
	- [[CertSpotter]]

#### Web Archives
[https://web.archive.org/]
Web archives like the Wayback Machine store historical snapshots of web pages. These archives can be used to view past versions of the target web application, potentially revealing outdated information, previously exposed vulnerabilities, or sensitive data.

- **Historical Analysis:** Viewing previous versions of the web application.
- **Content Discovery:** Finding pages or directories that were once public but are now hidden or removed.

#### Social Media and Public Profiles
[[Web Resources]]
Analyzing social media and public profiles can provide information about the organization's employees, technologies in use, and potential targets for social engineering.

- **Employee Information:** Gathering details about key personnel.
- **Technology Stack:** Identifying technologies and tools mentioned by employees.
- **Public Posts:** Analyzing posts for inadvertent exposure of sensitive information.

# Tools for Passive Enumeration

|**Tool**|**Description**|
|-|-|
| **WHOIS Lookup Tools**       | Tools like `whois` command, `whoxy.com`, and `whois.domaintools.com` for domain registration information.      |
| **DNS Enumeration Tools**    | Tools like `dig`, `nslookup`, `DNSRecon`, and `Fierce` for gathering DNS information.                          |
| **Google Dorking Tools**     | Using Google search with advanced operators for targeted searches.                                             |
| **Certificate Transparency** | Tools like `crt.sh` and `CertSpotter` for searching certificate transparency logs.                             |
| **Web Archives**             | Websites like `archive.org` (Wayback Machine) for viewing historical snapshots of web pages.                   |
| **Social Media Tools**       | Tools like `theHarvester`, `Maltego`, and manual searches on social media platforms for gathering information. |

# Real-world Examples

|**Technique**|**Real-world Scenario**|
|-|-|
| WHOIS Lookup             | Identifying the registrant and contact information for a domain, providing potential targets for social engineering. |
| DNS Enumeration          | Discovering subdomains like `admin.example.com` that may host sensitive interfaces.                                  |
| Google Dorking           | Using the `filetype:pdf site:example.com` operator to find exposed documents on the target domain.                   |
| Certificate Transparency | Finding subdomains like `api.example.com` through certificate transparency logs.                                     |
| Web Archives             | Viewing an older version of a web page that exposes an administrative interface now hidden.                          |
| Social Media Analysis    | Discovering that an employee posted a screenshot showing the internal IP address structure of the organization.      |

## Enumeration Best Practices

#### Stealth and Avoidance
To avoid detection and minimize the risk of tipping off the target:

- **Indirect Methods:** Use indirect methods that do not involve direct interaction with the target.
- **Anonymity:** Use tools and techniques that mask your identity, such as Tor or VPN services.
- **Respect Legal Boundaries:** Ensure that all passive enumeration activities comply with legal and ethical guidelines.

#### Comprehensive Coverage
Ensure thorough coverage by:

- **Multiple Sources:** Gathering information from various sources to build a complete picture.
- **Cross-referencing Data:** Verifying data from multiple sources to ensure accuracy.
- **Continuous Monitoring:** Regularly checking for new information that may become available over time.

#### Documentation
Document all findings meticulously to use them effectively in planning and executing further penetration testing phases. This includes:

- **Domain and DNS Information:** Detailed records of WHOIS and DNS data.
- **Subdomains and Infrastructure:** List of discovered subdomains and associated services.
- **Publicly Exposed Data:** Details of sensitive information found through public sources.

# Active Enumeration
Active enumeration involves directly interacting with the target web application to gather detailed information. This method is more intrusive than passive enumeration and has a higher risk of detection, but it yields more comprehensive data about the application's structure, behavior, and potential vulnerabilities.

## Types of Active Enumeration

#### Network Scanning
Network scanning identifies open ports and services on the target server. Tools like Nmap are commonly used for this purpose. The process includes:

- **Port Scanning:** Detecting open ports on the target server.
- **Service Identification:** Determining the services running on the identified ports.
- **Version Detection:** Gathering information about the version of the services and software.

#### Banner Grabbing
Banner grabbing collects information from service banners to identify software versions and potential vulnerabilities. This can be done using tools like Netcat or Nmap.

- **HTTP Banners:** Retrieving HTTP headers to gather information about the web server.
- **Service Banners:** Collecting banners from services like FTP, SMTP, etc.

#### Web Crawling and Spidering
Web crawling involves systematically exploring the web application to map its structure and discover hidden pages or directories. Tools like OWASP ZAP and Burp Suite can automate this process.

- **Crawling:** Automated tools traverse the website, following links to discover all accessible pages.
- **Spidering:** Similar to crawling, but focuses on extracting and analyzing the content of the pages.

#### Directory and File Enumeration
This technique involves searching for directories and files that may not be linked from the main pages but are accessible if known. Tools like DirBuster and Gobuster can automate this process.

- **Brute Force:** Using a list of common directory and file names to find hidden resources.
- **Fuzzing:** Sending various inputs to identify unexpected responses or errors revealing hidden resources.

#### Parameter Enumeration
Understanding how web applications handle parameters can expose potential vulnerabilities. Techniques include:

- **URL Parameter Manipulation:** Changing URL parameters to test for hidden functionalities or access control issues.
- **Form Parameter Analysis:** Inspecting form fields and inputs to identify security weaknesses.

#### User Enumeration
User enumeration identifies valid usernames, which can aid in brute force attacks and other targeted attacks. Methods include:

- **Error Message Analysis:** Analyzing error messages returned by the application for hints about valid usernames.
- **Login Brute Forcing:** Attempting to log in with common usernames and observing responses.

#### Session and Cookie Enumeration
Examining session and cookie data can reveal security weaknesses, such as insecure cookie handling or session fixation vulnerabilities.

- **Session ID Analysis:** Inspecting session IDs for predictability or vulnerabilities.
- **Cookie Analysis:** Checking cookie attributes for security settings like HttpOnly and Secure flags.

## Tools for Active Enumeration

|**Tool**|**Description**|
|-|-|
| **Nmap**       | Network scanning tool for discovering hosts, open ports, and services.                          |
| **Netcat**     | Versatile networking tool for banner grabbing and port scanning.                                |
| **DirBuster**  | Automated tool for brute force directory and file enumeration.                                  |
| **Gobuster**   | Fast directory and DNS brute forcing tool.                                                      |
| **OWASP ZAP**  | Comprehensive web application security scanner with active and passive enumeration features.    |
| **Burp Suite** | Integrated platform for performing security testing of web applications, including enumeration. |
| **Nikto**      | Web server scanner for identifying potential vulnerabilities and misconfigurations.             |
| **Wfuzz**      | Flexible web application brute forcer for discovering directories, files, and parameters.       |

## Real-world Examples

|**Technique**|**Real-world Scenario**|
|-|-|
| Network Scanning            | Identifying an open port running an outdated version of a service with known vulnerabilities.      |
| Banner Grabbing             | Retrieving HTTP headers that reveal the web server version, which is known to have security flaws. |
| Web Crawling                | Discovering a hidden admin page that is not linked from the main site but accessible directly.     |
| Directory Enumeration       | Finding an /uploads directory that allows unauthenticated file uploads.                            |
| Parameter Enumeration       | Manipulating a parameter ?user=admin to gain unauthorized access to admin functionalities.         |
| User Enumeration            | Detecting valid usernames by analyzing login error messages and using them for targeted attacks.   |
| Session and Cookie Analysis | Finding session IDs that are predictable, allowing session hijacking.                              |

## Enumeration Best Practices

#### Stealth and Avoidance
To minimize the risk of detection during active enumeration:

- **Rate Limiting:** Control the speed of requests to avoid triggering security defenses.
- **Proxy Usage:** Use proxy servers to mask the source of enumeration activities.
- **User-Agent Rotation:** Change user-agent strings to avoid detection by web application firewalls (WAFs).

#### Comprehensive Coverage
Ensure thorough coverage during enumeration by:

- **Enumerating Subdomains:** Identify and test all subdomains associated with the main domain.
- **Testing APIs:** Enumerate and test all APIs exposed by the application.
- **Checking Third-party Integrations:** Verify integrations with third-party services for potential vulnerabilities.

#### Document Findings
Document all findings during the enumeration process to use them effectively in subsequent penetration testing phases. This includes:

- **Open Ports and Services:** List all identified open ports and running services.
- **Discovered Directories and Files:** Document hidden or sensitive directories and files.
- **Identified Parameters:** Record all identified URL and form parameters.
- **Valid Usernames:** List all valid usernames discovered during enumeration.