# Index
- [[Networking]]
	- [[IP Addresses]]
	- [[Subnetting and CIDR Notation]]
	- [[Routing]]
	- [[Protocols, Services, & Ports]]
	- [[Seven Layer OSI Model]]

An Internet Protocol (IP) address is a unique identifier assigned to each device connected to a network that uses the Internet Protocol for communication. The primary purpose of an IP address is to enable devices to locate and communicate with each other within a network, similar to how a mailing address works in the postal system.

# IP Address Structure
IP addresses are binary numbers but are typically represented in human-readable formats to make them easier to understand and work with. There are two versions of IP addresses in use today: IPv4 and IPv6.

- **IPv4 (Internet Protocol version 4):**
  - **Structure:** IPv4 addresses are 32-bit numbers, which are divided into four 8-bit octets. Each octet is separated by a period (`.`), and the value of each octet ranges from 0 to 255.
  - **Example:** `192.168.1.1`
  - **Binary Representation:** The above IP address in binary is `11000000.10101000.00000001.00000001`.

- **IPv6 (Internet Protocol version 6):**
  - **Structure:** IPv6 addresses are 128-bit numbers, represented as eight groups of four hexadecimal digits. Each group is separated by a colon (`:`).
  - **Example:** `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
  - **Compressed Notation:** IPv6 addresses can be abbreviated by omitting leading zeros and using `::` to represent consecutive sections of zeros. The example can be compressed to `2001:db8:85a3::8a2e:370:7334`.

# Types of IP Addresses
IP addresses can be categorized based on their purpose and how they are allocated.

- **Public vs. Private IP Addresses:**
  - **Public IP Addresses:** These are globally unique addresses assigned by the Internet Assigned Numbers Authority (IANA) and its regional registries. They are routable on the internet, meaning they can communicate with devices on other networks. Example ranges for public IPv4 addresses include `1.0.0.0` to `223.255.255.255`.
  - **Private IP Addresses:** These are reserved for use within private networks and are not routable on the internet. They are used to identify devices within a local network. Example ranges for private IPv4 addresses include:
    - **Class A:** `10.0.0.0` to `10.255.255.255`
    - **Class B:** `172.16.0.0` to `172.31.255.255`
    - **Class C:** `192.168.0.0` to `192.168.255.255`

- **Static vs. Dynamic IP Addresses:**
  - **Static IP Addresses:** These addresses are manually assigned to a device and do not change over time. They are commonly used for servers, network devices, and other critical infrastructure that requires a consistent IP address.
  - **Dynamic IP Addresses:** These addresses are automatically assigned by a Dynamic Host Configuration Protocol (DHCP) server and can change over time. Most devices in a home or office network receive dynamic IP addresses.

- **Special IP Addresses:**
  - **Loopback Address:** The IPv4 loopback address is `127.0.0.1`, used by a device to refer to itself. The IPv6 equivalent is `::1`.
  - **Broadcast Address:** In IPv4, the broadcast address for a network is the last address in its address range. For example, in a `/24` network with a subnet of `192.168.1.0`, the broadcast address would be `192.168.1.255`.
  - **Multicast Address:** IPv4 multicast addresses range from `224.0.0.0` to `239.255.255.255`, and they are used to deliver packets to multiple destinations.

# Subnetting and CIDR
Subnetting is the practice of dividing a larger network into smaller, more manageable sub-networks (subnets). It involves borrowing bits from the host portion of an IP address to create additional network segments. This is done to optimize IP address allocation and improve network security.

- **Subnet Mask:** A subnet mask defines the network and host portions of an IP address. In binary, it is a series of `1`s followed by `0`s, where the `1`s indicate the network part and the `0`s indicate the host part.
  - **Example:** For an IPv4 address `192.168.1.10` with a subnet mask of `255.255.255.0`, the network portion is `192.168.1`, and the host portion is `10`.

- **CIDR (Classless Inter-Domain Routing):**
  - **CIDR Notation:** CIDR allows more flexible allocation of IP addresses than the traditional classful addressing. It is represented as `<IP address>/<prefix length>`. The prefix length indicates the number of bits used for the network portion.
  - **Example:** `192.168.1.0/24` indicates a subnet with 256 possible IP addresses, where 24 bits are dedicated to the network portion.

# How IP Addresses Work
When a device wants to communicate with another device, it uses the destination's IP address to determine the best route for the data packets. The process involves several key steps:

- **ARP (Address Resolution Protocol):** ARP is used to map an IP address to its corresponding MAC (Media Access Control) address. This is necessary because IP addresses operate at the network layer (Layer 3), while MAC addresses operate at the data link layer (Layer 2).
- **Routing:** Routers use routing tables to determine the best path for data packets to reach their destination. If the destination IP address is on a different network, the packet is forwarded to the appropriate router until it reaches its final destination.
- **NAT (Network Address Translation):** NAT is commonly used in IPv4 networks to allow multiple devices on a local network to share a single public IP address. It translates private IP addresses to a public IP address and vice versa, enabling communication with external networks.

# IPv4 vs. IPv6
IPv4, with its 32-bit address space, can theoretically support approximately 4.3 billion unique addresses. However, due to the exponential growth of the internet and the proliferation of connected devices, the exhaustion of IPv4 addresses became a concern, leading to the development of IPv6.

- **IPv6 Advantages:**
  - **Larger Address Space:** IPv6 uses 128-bit addresses, allowing for a vastly larger number of unique addresses—approximately 340 undecillion (3.4 x 10^38) addresses.
  - **Simplified Header Structure:** IPv6 headers are simpler and more efficient, improving routing performance.
  - **Auto-Configuration:** IPv6 supports auto-configuration of addresses through Stateless Address Autoconfiguration (SLAAC).
  - **Enhanced Security:** IPv6 was designed with security in mind, and IPsec (Internet Protocol Security) is a mandatory component.

- **Transition Mechanisms:** Several mechanisms have been developed to facilitate the transition from IPv4 to IPv6, including dual-stack implementation (supporting both IPv4 and IPv6 on the same device), tunneling (encapsulating IPv6 packets within IPv4), and translation techniques.