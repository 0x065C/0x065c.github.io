![[Pasted image 20240801193614.png]]

# Summary 
Reconnaissance is the first and one of the most critical phases in a penetration test or red team operation. It involves gathering as much information as possible about the target network, systems, and even individuals associated with the target. This phase is often referred to as "information gathering" and is crucial because the more information an attacker has, the more likely they are to find vulnerabilities or entry points into the target environment.

Reconnaissance can be divided into two primary categories:

1. **Passive Reconnaissance:** 
   - Involves gathering information without directly interacting with the target. The goal is to collect data without alerting the target to your activities.
   - Tools and techniques used here include WHOIS queries, DNS enumeration, network sniffing, social media monitoring, and examining publicly available information.

2. **Active Reconnaissance:**
   - Involves direct interaction with the target to gather information. This can increase the risk of detection but often yields more detailed and specific data.
   - Tools and techniques include network scanning, port scanning, banner grabbing, OS fingerprinting, and vulnerability scanning.

# Passive Reconnaissance

#####  WHOIS Queries
- **Purpose:** Retrieve domain registration information, such as the owner's name, contact details, and DNS servers.
- **Command Example:**
  ```bash
  whois <target_domain>
  ```
  - **Example:**
    ```bash
    whois example.com
    ```

##### DNS Enumeration
- **Purpose:** Gather information about the target's DNS infrastructure, such as domain names, subdomains, and IP addresses.
- **Tools:**
  - `dig`: A command-line tool used for querying DNS servers.
  - `dnsrecon`: A tool for DNS enumeration.
  - `nslookup`: A command-line tool used for querying the DNS to obtain domain name or IP address mapping.
- **Command Example:**
  ```bash
  dig <target_domain> ANY
  ```
  - **Example:**
    ```bash
    dig example.com ANY
    ```

##### Social Media Monitoring
- **Purpose:** Gather information about employees, their roles, and possible security practices. This can provide insights into potential spear-phishing targets or weak points in the human element of security.
- **Tools:**
  - `Maltego`: A tool that enables the gathering of information from various sources, including social media platforms.
  - `theHarvester`: A tool for gathering email addresses, subdomains, hosts, employee names, open ports, and banners.

##### Public Information Gathering
- **Purpose:** Identify public documents, press releases, and other information that might reveal technical details about the target's infrastructure or security practices.
- **Techniques:**
  - Searching for documents (e.g., PDFs, DOC files) that might contain metadata.
  - Analyzing job postings for IT-related positions to identify technologies used by the target.

# Active Reconnaissance

##### Network Scanning
- **Purpose:** Discover live hosts on a network, typically the first step in understanding the target's infrastructure.
- **Tools:**
  - `Nmap`: The most widely used tool for network scanning.
  - `Masscan`: A tool that can scan the entire Internet, very fast but with less detailed output compared to Nmap.
- **Command Example:**
  ```bash
  nmap -sn <target_ip_range>
  ```
  - **Example:**
    ```bash
    nmap -sn 192.168.1.0/24
    ```

##### Port Scanning
- **Purpose:** Identify open ports and services running on a target machine. This helps in identifying potential entry points for exploitation.
- **Tools:**
  - `Nmap`
  - `Unicornscan`: A tool for high-speed port scanning.
- **Command Example:**
  ```bash
  nmap -p- <target_ip>
  ```
  - **Example:**
    ```bash
    nmap -p- 192.168.1.1
    ```

##### Banner Grabbing
- **Purpose:** Capture banners returned by services running on open ports. These banners often contain information about the service, version, and sometimes even operating system.
- **Tools:**
  - `Telnet`
  - `Netcat`
  - `Nmap` (with version detection enabled)
- **Command Example:**
  ```bash
  nmap -sV <target_ip> -p <target_port>
  ```
  - **Example:**
    ```bash
    nmap -sV 192.168.1.1 -p 80
    ```

##### OS Fingerprinting
- **Purpose:** Determine the operating system running on a target host. Knowing the OS can help in tailoring exploits or attacks.
- **Tools:**
  - `Nmap`
  - `Xprobe2`: A tool specifically designed for OS fingerprinting.
- **Command Example:**
  ```bash
  nmap -O <target_ip>
  ```
  - **Example:**
    ```bash
    nmap -O 192.168.1.1
    ```

##### Vulnerability Scanning
- **Purpose:** Identify known vulnerabilities in the target’s systems or applications.
- **Tools:**
  - `Nessus`: A popular vulnerability scanner.
  - `OpenVAS`: An open-source alternative to Nessus.
- **Command Example:**
  - Launching a scan with `Nessus` typically involves using its GUI, but here's a basic CLI command to start a scan:
  ```bash
  nessuscli scan --start <scan_id>
  ```
  
# Reconnaissance in Context

Reconnaissance isn't just about gathering data; it's about using that data effectively. A penetration tester must analyze the gathered information to identify weak points, potential attack vectors, and formulate a strategy for further exploitation. Often, reconnaissance will lead to multiple paths for exploitation, allowing a tester to prioritize based on the target's security posture.

#### Example of Reconnaissance Workflow
1. **Passive Reconnaissance:**
   - Perform WHOIS lookup to gather information about the domain.
   - Use `theHarvester` to find emails and subdomains.
   - Search for public documents using Google Dorks to identify potential metadata leaks.
   - Monitor social media for information about employees and their roles.

2. **Active Reconnaissance:**
   - Perform network scanning using `Nmap` to identify live hosts.
   - Conduct a full port scan on identified hosts to discover open services.
   - Use `Nmap` for service version detection and banner grabbing.
   - Use `Nmap` or `Xprobe2` for OS fingerprinting.
   - Run a vulnerability scan with `Nessus` or `OpenVAS` on the identified hosts and services.

# Resources

|**Website**|**URL**|
|-|-|
| OSINT Framework | [https://osintframework.com/](https://osintframework.com/)|
| Censys.io       | [https://search.censys.io/](https://search.censys.io/)                                                                                                                         |
| Mind Mapper     | [https://www.mindmaps.app/](https://www.mindmaps.app/)                                                                                                                         |
| OSINT.SH        | [https://osint.sh](https://osint.sh)                                                                                                                                           |
| IntelX          | [https://intelx.io](https://intelx.io)                                                                                                                                         |
| Onyphe          | [https://onyphe.io](https://onyphe.io)                                                                                                                                         |
| RobTex          | [https://robtex.com](https://robtex.com)                                                                                                                                       |
| BinaryEdge      | [https://binaryedge.io](https://binaryedge.io)                                                                                                                                 |
| SecJuice        | [https://www.secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor/](https://www.secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor/) |
| OSINT Dojo      | [https://www.osintdojo.com/resources/](https://www.osintdojo.com/resources/)                                                                                                   |