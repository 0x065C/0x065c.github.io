# Subnetting and CIDR Notation

## Summary

Subnetting is the process of dividing a larger network into smaller, more manageable sub-networks (subnets). This technique is used to optimize IP address allocation, improve network performance, enhance security, and facilitate better management of network resources.

By creating subnets, network administrators can:

* Reduce network congestion by limiting the size of broadcast domains.
* Improve security by isolating different parts of the network.
* Make more efficient use of IP address space, especially in large organizations.

**Key Concepts in Subnetting:**

* **Subnet Mask:** A subnet mask is a 32-bit number used to differentiate the network portion of an IP address from the host portion. In binary, a subnet mask consists of a series of `1`s (representing the network portion) followed by a series of `0`s (representing the host portion).
  * **Example:** For an IP address `192.168.1.0` with a subnet mask of `255.255.255.0`, the first 24 bits (`192.168.1`) represent the network portion, and the last 8 bits (`0`) represent the host portion.
* **Borrowing Bits:** When subnetting, bits are borrowed from the host portion to create more subnets. The more bits borrowed, the more subnets created, but the fewer hosts each subnet can support.
  * **Example:** In a Class C network `192.168.1.0/24`, borrowing 2 bits from the host portion creates 4 subnets (`2^2 = 4`). Each subnet can now support 62 hosts (`2^6 - 2 = 62`), since 6 bits remain for hosts.
* **Subnet Calculation:**
  * **Network Address:** The first address in a subnet, used to identify the subnet itself. It is not assignable to a host.
  * **Broadcast Address:** The last address in a subnet, used to send data to all hosts within that subnet. It is also not assignable to a host.
  * **Assignable IP Range:** The range of IP addresses within a subnet that can be assigned to hosts.

## IP Address Classes

Before diving into subnetting, it's essential to understand the concept of IP address classes. IP addresses were initially divided into classes (A, B, C, D, and E) based on the leading bits of the address, which determined the size of the network and host portions.

\| Class | IP | Use Case | | | | | | Class A | Class A addresses had the first bit set to 0.\
\
Range from 1.0.0.0 to 126.0.0.0.\
\
The default subnet mask for Class A addresses was 255.0.0.0 or /8 | These addresses were designed for large networks and could accommodate up to 16 million hosts on each network. | | Class B | Class B addresses had the first two bits set to 10.\
\
Range from 128.0.0.0 to 191.0.0.0.\
\
The default subnet mask for Class B addresses was 255.255.0.0 or /16. | These addresses were intended for medium-sized networks and could support up to 65,000 hosts on each network. | | Class C | Class C addresses had the first three bits set to 110.\
\
Range from 192.0.0.0 to 223.0.0.0.\
\
The default subnet mask for Class C addresses was 255.255.255.0 or /24. | Class C addresses were suitable for small networks, accommodating up to 254 hosts on each network. | | Class D | Class D addresses had the first four bits set to 1110.\
\
Range from 224.0.0.0 to 239.0.0.0. | Class D addresses were reserved for multicast groups and not used for regular unicast addressing. | | Class E | Class E addresses had the first four bits set to 1111.\
\
Range from 240.0.0.0 to 255.0.0.0. | Class E addresses were reserved for experimental and research purposes and were not used for general networking. |

## Subnet Masks

A subnet mask is a 32-bit binary number (IPv4) or a 128-bit binary number (IPv6) used to separate the network and host portions of an IP address. In IPv4, a subnet mask is often represented in decimal form, such as 255.255.255.0.

## Address Blocks and CIDR Notation

Classless Inter-Domain Routing (CIDR) was introduced in 1993 as a more efficient way to allocate and manage IP addresses. CIDR allows for variable-length subnet masking (VLSM), enabling network administrators to create subnets of varying sizes based on actual need, rather than adhering to the rigid classful system.

**Key Concepts in CIDR:**

* **CIDR Notation:** CIDR notation represents an IP address and its associated routing prefix. It is written as `<IP address>/<prefix length>`, where the prefix length indicates the number of bits in the subnet mask that represent the network portion.
  * **Example:** `192.168.1.0/24` means the first 24 bits are used for the network portion, and the remaining 8 bits are for hosts.
* **Prefix Length:** The prefix length in CIDR notation indicates the number of bits dedicated to the network portion of the address. The remaining bits define the host portion.
  * **Example:** A `/24` prefix length corresponds to a subnet mask of `255.255.255.0`.

\| CIDR | SUBNET MASK | WILDCARD MASK | # OF IP ADDRESSES | # OF USABLE IP ADDRESSES | | - | | | -- | | | /32 | 255.255.255.255 | 0.0.0.0 | 1 | 1 | | /31 | 255.255.255.254 | 0.0.0.1 | 2 | 2\* | | /30 | 255.255.255.252 | 0.0.0.3 | 4 | 2 | | /29 | 255.255.255.248 | 0.0.0.7 | 8 | 6 | | /28 | 255.255.255.240 | 0.0.0.15 | 16 | 14 | | /27 | 255.255.255.224 | 0.0.0.31 | 32 | 30 | | /26 | 255.255.255.192 | 0.0.0.63 | 64 | 62 | | /25 | 255.255.255.128 | 0.0.0.127 | 128 | 126 | | /24 | 255.255.255.0 | 0.0.0.255 | 256 | 254 | | /23 | 255.255.254.0 | 0.0.1.255 | 512 | 510 | | /22 | 255.255.252.0 | 0.0.3.255 | 1,024 | 1,022 | | /21 | 255.255.248.0 | 0.0.7.255 | 2,048 | 2,046 | | /20 | 255.255.240.0 | 0.0.15.255 | 4,096 | 4,094 | | /19 | 255.255.224.0 | 0.0.31.255 | 8,192 | 8,190 | | /18 | 255.255.192.0 | 0.0.63.255 | 16,384 | 16,382 | | /17 | 255.255.128.0 | 0.0.127.255 | 32,768 | 32,766 | | /16 | 255.255.0.0 | 0.0.255.255 | 65,536 | 65,534 | | /15 | 255.254.0.0 | 0.1.255.255 | 131,072 | 131,070 | | /14 | 255.252.0.0 | 0.3.255.255 | 262,144 | 262,142 | | /13 | 255.248.0.0 | 0.7.255.255 | 524,288 | 524,286 | | /12 | 255.240.0.0 | 0.15.255.255 | 1,048,576 | 1,048,574 | | /11 | 255.224.0.0 | 0.31.255.255 | 2,097,152 | 2,097,150 | | /10 | 255.192.0.0 | 0.63.255.255 | 4,194,304 | 4,194,302 | | /9 | 255.128.0.0 | 0.127.255.255 | 8,388,608 | 8,388,606 | | /8 | 255.0.0.0 | 0.255.255.255 | 16,777,216 | 16,777,214 | | /7 | 254.0.0.0 | 1.255.255.255 | 33,554,432 | 33,554,430 | | /6 | 252.0.0.0 | 3.255.255.255 | 67,108,864 | 67,108,862 | | /5 | 248.0.0.0 | 7.255.255.255 | 134,217,728 | 134,217,726 | | /4 | 240.0.0.0 | 15.255.255.255 | 268,435,456 | 268,435,454 | | /3 | 224.0.0.0 | 31.255.255.255 | 536,870,912 | 536,870,910 | | /2 | 192.0.0.0 | 63.255.255.255 | 1,073,741,824 | 1,073,741,822 | | /1 | 128.0.0.0 | 127.255.255.255 | 2,147,483,648 | 2,147,483,646 | | /0 | 0.0.0.0 | 255.255.255.255 | 4,294,967,296 | 4,294,967,294 |

### Calculating CIDR Notation

To figure out the CIDR notation for a given subnet mask, convert the subnet mask into binary, then count the number of ones or "on" digits.

\| Subnet mask | 255.255.255.0 | 11111111.11111111.11111111.00000000 | /24 | | -- | - | -- | |

Because there's three octets of ones, there are 24 "on" bits meaning that the CIDR notation is /24.

### Calculating Network ID

Insert line at end of subnet mask where 1's stop in converted binary. The space between the beginning of the octet and the line is called the conversion zone. Convert IP address binary bits over the corresponding subnet mask bits within the conversion zone. The converted number from the IP Address is the beginning of the Network ID.

\| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 | | | | | | | | | |

#### Examples

\| IP Address | 192.168.40.55 | 11000000.10101000.00101|000.00110111 | | | -- | | - | | | Subnet mask | 255.255.248.0 | 11111111.11111111.11111|000.00000000 | /21 | | Network ID | 192.168.40.0/21 | | |

\| IP Address | 192.168.45.55 | 11000000.10101000.00101|101.00110111 | | | -- | | - | | | Subnet Mask | 255.255.248.0 | 11111111.11111111.11111|000.00000000 | /21 | | Network ID | 182.168.40.0/21 | | |

\| IP Address | 192.168.45.55 | 11000000.10101000.00101101.00|110111 | | | -- | | - | | | Subnet Mask | 255.255.255.192 | 11111111.11111111.11111111.11|000000 | /26 | | Network ID | 192.168.45.0/26 | | |

\| IP Address | 192.168.45.55 | 11000000.10101000.00101101.00|110111 | | | -- | | - | | | Subnet Mask | 255.255.255.192 | 11111111.11111111.11111111.11|000000 | /26 | | Network ID | 192.168.45.0/26 | | |

### Calculating Broadcast IP Address and Usable IPs

Add all of the binary bits together to the right of the conversion zone. Resulting number is the Broadcast IP Address for the Network ID. Subtract one more digit from the Broadcast IP Address and the resulting number is the number of usable IPs within that Network ID (this is usually because one IP address is assigned to a router).

\| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 | | | | | | | | | |

#### Examples

\| IP Address | 192.168.40.55 | 11000000.10101000.00101|000.00110111 | | | | | - | | | Subnet mask | 255.255.248.0 | 11111111.11111111.11111|000.00000000 | /21 | | Network ID | 192.168.40.0/21 | | | | Broadcast IP | 192.168.7.255 | | | | Usable IPs | | | |

\| IP Address | 192.168.45.55 | 11000000.10101000.00101|101.00110111 | | | | | - | | | Subnet Mask | 255.255.248.0 | 11111111.11111111.11111|000.00000000 | /21 | | Network ID | 182.168.40.0/21 | | | | Broadcast IP | | | | | Usable IPs | | | |

\| IP Address | 192.168.45.55 | 11000000.10101000.00101101.00|110111 | | | | | - | | | Subnet Mask | 255.255.255.192 | 11111111.11111111.11111111.11|000000 | /26 | | Network ID | 192.168.45.0/26 | | | | Broadcast IP | 192.168.45.31 | | | | Usable IPs | 30 IPs | Total Range is 192.168.45.31-61 | |

\| IP Address | 192.168.45.55 | 11000000.10101000.00101101.00|110111 | | | | | - | | | Subnet Mask | 255.255.255.192 | 11111111.11111111.11111111.11|000000 | /26 | | Network ID | 192.168.45.0/26 | | | | Broadcast IP | 192.168.45.63 | | | | Usable IPs | 61 IPs | Total Range is 192.168.45.63-124 | |

## Private and Public Address Blocks

Some IP address blocks are reserved for private use within internal networks and are not routable on the public Internet. Examples include:

10.0.0.0/8

172.16.0.0/12

192.168.0.0/16

Public address blocks are assigned by regional Internet registries (RIRs) and are used for publicly accessible devices and services.

### IP Address Allocation

Regional Internet registries (RIRs) are responsible for allocating IP address blocks to Internet service providers (ISPs), organizations, and entities. ISPs, in turn, allocate smaller address blocks to their customers.

### Routing and Aggregation

Internet routing relies on IP address blocks to efficiently route traffic. Aggregation involves grouping IP address blocks together to reduce the size of routing tables and improve routing efficiency.

### IP Address Management Tools

Various tools and protocols, such as DHCP (Dynamic Host Configuration Protocol) and IPAM (IP Address Management) systems, help manage and allocate IP address blocks within networks.

### 5.4 IP Address Blocks and Security

Understanding IP address blocks is crucial for network security, as it allows organizations to define access control lists (ACLs) and firewall rules based on IP ranges.

## IP Addressing & NICs

Every computer that is communicating on a network needs an IP address. If it doesn't have one, it is not on a network. The IP address is assigned in software and usually obtained automatically from a DHCP server. It is also common to see computers with statically assigned IP addresses. Static IP assignment is common with:

* Servers
* Routers
* Switch virtual interfaces
* Printers
* And any devices that are providing critical services to the network

Whether assigned dynamically or statically, the IP address is assigned to a Network Interface Controller (NIC). Commonly, the NIC is referred to as a Network Interface Card or Network Adapter. A computer can have multiple NICs (physical and virtual), meaning it can have multiple IP addresses assigned, allowing it to communicate on various networks. Identifying pivoting opportunities will often depend on the specific IPs assigned to the hosts we compromise because they can indicate the networks compromised hosts can reach. This is why it is important for us to always check for additional NICs using commands like ifconfig (in macOS and Linux) and ipconfig (in Windows).

### Using ifconfig

```bash
0x065C$ ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        inet6 fe80::e973:b08d:7bdf:dc67  prefixlen 64  scopeid 0x20<link>
        ether 12:ed:13:35:68:f5  txqueuelen 1000  (Ethernet)
        RX packets 8844  bytes 803773 (784.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5698  bytes 9713896 (9.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.106.0.172  netmask 255.255.240.0  broadcast 10.106.15.255
        inet6 fe80::a5bf:1cd4:9bca:b3ae  prefixlen 64  scopeid 0x20<link>
        ether 4e:c7:60:b0:01:8d  txqueuelen 1000  (Ethernet)
        RX packets 15  bytes 1620 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1858 (1.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 19787  bytes 10346966 (9.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19787  bytes 10346966 (9.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.54  netmask 255.255.254.0  destination 10.10.15.54
        inet6 fe80::c85a:5717:5e3a:38de  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::1034  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 336 (336.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

In the output above, each NIC has an identifier (eth0, eth1, lo, tun0) followed by addressing information and traffic statistics. The tunnel interface (tun0) indicates a VPN connection is active. When we connect to any of  VPN servers through Pwnbox or our own attack host, we will always notice a tunnel interface gets created and assigned an IP address. The VPN allows us to access the lab network environments hosted by HTB. Keep in mind that these lab networks are not reachable without having a tunnel established. The VPN encrypts traffic and also establishes a tunnel over a public network (often the Internet), through NAT on a public-facing network appliance, and into the internal/private network. Also, notice the IP addresses assigned to each NIC. The IP assigned to eth0 (134.122.100.200) is a publicly routable IP address. Meaning ISPs will route traffic originating from this IP over the Internet. We will see public IPs on devices that are directly facing the Internet, commonly hosted in DMZs. The other NICs have private IP addresses, which are routable within internal networks but not over the public Internet. At the time of writing, anyone that wants to communicate over the Internet must have at least one public IP address assigned to an interface on the network appliance that connects to the physical infrastructure connecting to the Internet. Recall that NAT is commonly used to translate private IP addresses to public IP addresses.

### Using ipconfig

```powershell
PS> ipconfig

	Windows IP Configuration

	Unknown adapter NordLynx:

	Media State . . . . . . . . . . . : Media disconnected
	Connection-specific DNS Suffix  . :

	Ethernet adapter Ethernet0 2:
	Connection-specific DNS Suffix  . : .htb
	IPv6 Address. . . . . . . . . . . : dead:beef::1a9
	IPv6 Address. . . . . . . . . . . : dead:beef::f58b:6381:c648:1fb0
	Temporary IPv6 Address. . . . . . : dead:beef::dd0b:7cda:7118:3373
	Link-local IPv6 Address . . . . . : fe80::f58b:6381:c648:1fb0%8
	IPv4 Address. . . . . . . . . . . : 10.129.221.36
	Subnet Mask . . . . . . . . . . . : 255.255.0.0
	Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:df81%8
						10.129.0.1

	Ethernet adapter Ethernet:

	Media State . . . . . . . . . . . : Media disconnected
	Connection-specific DNS Suffix  . :
```

The output directly above is from issuing ipconfig on a Windows system. We can see that this system has multiple adapters, but only one of them has IP addresses assigned. There are IPv6 addresses and an IPv4 address. This module will primarily focus on networks running IPv4 as it remains the most common IP addressing mechanism in enterprise LANs. We will notice some adapters, like the one in the output above, will have an IPv4 and an IPv6 address assigned in a dual-stack configuration allowing resources to be reached over IPv4 or IPv6.

Every IPv4 address will have a corresponding subnet mask. If an IP address is like a phone number, the subnet mask is like the area code. Remember that the subnet mask defines the network & host portion of an IP address. When network traffic is destined for an IP address located in a different network, the computer will send the traffic to its assigned default gateway. The default gateway is usually the IP address assigned to a NIC on an appliance acting as the router for a given LAN. In the context of pivoting, we need to be mindful of what networks a host we land on can reach, so documenting as much IP addressing information as possible on an engagement can prove helpful.
