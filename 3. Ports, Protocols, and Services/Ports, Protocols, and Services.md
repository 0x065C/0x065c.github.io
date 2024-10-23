# Index
- [[Red Team]]
	- [[Ports, Protocols, and Services]]
		- [[P7 ECHO]]
		- [[P21 FTP]]
		- [[P22 SSH]]
		- [[P23 Telnet]]
		- [[P25 SMTP]]
		- [[P43 WhoIs]]
		- [[P53 DNS]]
		- [[P80 HTTP]]
		- [[P88 Kerberos]]
		- [[P110 POP3]]
		- [[P111 RPCBind]]
		- [[P123 NTP]]
		- [[P135 RPC Microsoft Endpoint Mapper]]
		- [[P137 NetBIOS Name Service]]
		- [[P138 NetBIOS Datagram Service]]
		- [[P139 NetBIOS Session Service]]
		- [[P143 IMAP]]
		- [[P161 SNMP]]
		- [[P162 SNMP Trap]]
		- [[P389 LDAP]]
		- [[P443 HTTPS]]
		- [[P445 SMB]]
		- [[P587 SMTPS]]
		- [[P593 RPC HTTP Endpoint Mapper]]
		- [[P623 IPMI]]
		- [[P632 IPP]]
		- [[P636 LDAPS]]
		- [[P873 RSYNC]]
		- [[P993 IMAPS]]
		- [[P995 POP3S]]
		- [[P1433 MSSQL]]
		- [[P1521 Oracle SQL NET]]
		- [[P1723 PPTP]]
		- [[P2049 NFS]]
		- [[P3269 LDAP Global Catalog]]
		- [[P3306 MySQL]]
		- [[P3389 RDP]]
		- [[P4555 RSIP]]
		- [[P5432 5433 PostgreSQL]]
		- [[P5985 WinRM HTTP]]
		- [[P5986 WinRM HTTPS]]
		- [[P6667 IRC]]
		- [[P6697 IRCS]]
		- [[P27017 MongoDB]]

# Summary
Understanding ports, protocols, and services is fundamental in networking and cyber security. These concepts are essential for penetration testers and network administrators. Let’s dive into each of these components in detail.

# Ports
Ports are logical endpoints for communication used by protocols to establish connections between devices over a network. They help differentiate multiple services running on a single device. Each port is associated with a specific protocol and service.

## Types of Ports

1. **Well-Known Ports:** These range from 0 to 1023 and are reserved for commonly used services and protocols (e.g., HTTP, FTP, SMTP).
2. **Registered Ports:** Ranging from 1024 to 49151, these are used by software applications and are registered with IANA (Internet Assigned Numbers Authority).
3. **Dynamic or Private Ports:** From 49152 to 65535, these are used for temporary or private purposes, usually by client applications when establishing a connection.

## Port Numbers and Common Services

**Port 21:** FTP (File Transfer Protocol)
**Port 22:** SSH (Secure Shell)
**Port 25:** SMTP (Simple Mail Transfer Protocol)
**Port 53:** DNS (Domain Name System)
**Port 80:** HTTP (HyperText Transfer Protocol)
**Port 443:** HTTPS (HTTP Secure)

## Usage in Penetration Testing

**Port Scanning:** Tools like Nmap are used to discover open ports on a target system, helping to identify services running and potential vulnerabilities.
**Service Enumeration:** Identifying services running on open ports helps in finding the version and possible exploits.

# Protocols
Protocols are sets of rules governing data communication over networks. They define how data is formatted, transmitted, and received.

## Types of Protocols

1. **Transmission Control Protocol (TCP):** Connection-oriented protocol that ensures reliable data transfer with error checking and flow control.
2. **User Datagram Protocol (UDP):** Connectionless protocol that provides fast, but less reliable, data transfer without error checking.
3. **Internet Protocol (IP):** Responsible for addressing and routing packets of data to their destination.
4. **HyperText Transfer Protocol (HTTP):** Protocol for transferring web pages on the internet.
5. **Simple Mail Transfer Protocol (SMTP):** Protocol for sending emails.
6. **File Transfer Protocol (FTP):** Protocol for transferring files between systems.

## Layers of Protocols (OSI Model)

1. **Application Layer:** Interfaces with software applications (e.g., HTTP, FTP, SMTP).
2. **Presentation Layer:** Translates data formats (e.g., encryption, compression).
3. **Session Layer:** Manages sessions between applications.
4. **Transport Layer:** Ensures data transfer reliability (e.g., TCP, UDP).
5. **Network Layer:** Manages packet routing and addressing (e.g., IP).
6. **Data Link Layer:** Handles physical addressing and access to the media (e.g., Ethernet).
7. **Physical Layer:** Manages the physical connection between devices (e.g., cabling, switches).

## Usage in Penetration Testing

**Protocol Analysis:** Using tools like Wireshark to capture and analyze network traffic to understand the protocols in use and identify anomalies or vulnerabilities.
**Exploitation:** Identifying and exploiting vulnerabilities in specific protocols (e.g., TCP sequence prediction attack).

# Services
Services are applications or processes that run on servers and provide specific functions to clients. They often listen on specific ports and use specific protocols.

## Common Network Services

1. **Web Services:** Provided by web servers (e.g., Apache, Nginx) and typically use HTTP/HTTPS.
2. **File Transfer Services:** Provided by FTP servers or SMB/CIFS for network file sharing.
3. **Email Services:** Provided by mail servers (e.g., Postfix, Exchange) and use SMTP, IMAP, POP3.
4. **Directory Services:** Provided by LDAP servers for managing network resources.
5. **Database Services:** Provided by database servers (e.g., MySQL, PostgreSQL) for storing and retrieving data.

## Usage in Penetration Testing

**Service Detection:** Identifying services running on a target system using tools like Nmap.
**Service Exploitation:** Exploiting vulnerabilities in running services (e.g., using Metasploit to exploit a known vulnerability in a web service).

# Example
Suppose you are conducting a penetration test on a target network. Here’s how you would use the knowledge of ports, protocols, and services:

1. **Port Scanning:** You use Nmap to scan the target for open ports and find the following:    
    - Port 80: Open (HTTP)
    - Port 22: Open (SSH)
    - Port 3306: Open (MySQL)

2. **Service Enumeration:** You perform service enumeration to gather more information about the services running on these ports. For example, using `nmap -sV -p 80,22,3306 target_ip` reveals:    
    - Port 80: Apache HTTPD 2.4.41
    - Port 22: OpenSSH 7.6
    - Port 3306: MySQL 5.7.30

3. **Protocol Analysis:** You capture network traffic on these ports using Wireshark to analyze the protocols in use and look for any anomalies or sensitive data being transmitted.

4. **Exploitation:** You search for known vulnerabilities in the identified services and protocols. For instance, you find a vulnerability in the specific version of MySQL running on port 3306 and attempt to exploit it using Metasploit.

Understanding ports, protocols, and services is crucial for effectively managing network security and conducting penetration testing. These elements are interconnected and form the backbone of network communication and security.

# Resources
https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
