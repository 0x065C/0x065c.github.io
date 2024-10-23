# Index
- [[Networking]]
	- [[IP Addresses]]
	- [[Subnetting and CIDR Notation]]
	- [[Routing]]
	- [[Protocols, Services, & Ports]]
	- [[Seven Layer OSI Model]]

Routing is the process of selecting the best path for data packets to travel from a source to a destination across one or more networks. It is a critical function of network devices like routers, which use routing tables, protocols, and algorithms to make decisions about where to send packets. The goal of routing is to ensure that data is delivered efficiently, reliably, and correctly to its intended destination.

# Key Concepts in Routing
Understanding routing requires familiarity with several key concepts:

- **Router:** A router is a network device that forwards data packets between computer networks. Routers operate at the network layer (Layer 3) of the OSI model and use IP addresses to determine the best path for packet delivery.

- **Routing Table:** The routing table is a data structure maintained by a router. It contains information about routes to different network destinations, including:
  - **Destination Network:** The IP address of the network the packet should be forwarded to.
  - **Subnet Mask:** Used to determine the network portion of an IP address.
  - **Next Hop:** The IP address of the next router along the path to the destination.
  - **Metric:** A value that indicates the cost or preference for a particular route. Lower metrics are preferred.
  - **Interface:** The network interface on the router through which the packet should be sent.

- **Forwarding:** Forwarding is the process of moving packets from one network interface to another based on the information in the routing table.

# Types of Routing
Routing can be classified into two main types: static routing and dynamic routing.

- **Static Routing:**
  - **Definition:** In static routing, routes are manually configured and entered into the routing table by a network administrator. These routes do not change unless manually modified.
  - **Advantages:** Simple to configure, predictable behavior, low overhead.
  - **Disadvantages:** Not scalable for large networks, requires manual intervention for updates, does not adapt to network changes.
  - **Example Configuration:** On a Cisco router, a static route can be configured as follows:
    ```
    ip route <destination_network> <subnet_mask> <next_hop_ip>
    ```
    Example:
    ```
    ip route 192.168.2.0 255.255.255.0 192.168.1.1
    ```

## Routing Tables

```bash
$ netstat -r

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         178.62.64.1     0.0.0.0         UG        0 0          0 eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG        0 0          0 tun0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.106.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth1
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
178.62.64.0     0.0.0.0         255.255.192.0   U         0 0          0 eth0
```

- **Dynamic Routing:**
  - **Definition:** In dynamic routing, routers automatically discover and maintain routes through the use of routing protocols. These routes can change dynamically based on network conditions.
  - **Advantages:** Scalable, adaptive to network changes, less administrative overhead.
  - **Disadvantages:** More complex to configure and troubleshoot, can consume more network resources.
  - **Routing Protocols:** Dynamic routing relies on various protocols to exchange routing information and make decisions. These protocols can be categorized into:
    - **Interior Gateway Protocols (IGPs):** Used within a single autonomous system (AS). Examples include:
      - **RIP (Routing Information Protocol):** A distance-vector protocol using hop count as a metric. It has a maximum hop count of 15, making it suitable for small networks.
      - **OSPF (Open Shortest Path First):** A link-state protocol that uses the Dijkstra algorithm to calculate the shortest path. It supports large and complex networks.
      - **EIGRP (Enhanced Interior Gateway Routing Protocol):** A Cisco proprietary protocol that combines features of both distance-vector and link-state protocols.
    - **Exterior Gateway Protocols (EGPs):** Used between different autonomous systems. The primary example is:
      - **BGP (Border Gateway Protocol):** A path-vector protocol used to route data across the internet. BGP is the protocol that powers the global internet by managing how packets are routed between different organizations and ISPs.

# Routing Algorithms
Routing algorithms are used by routing protocols to determine the best path for data packets. These algorithms can be broadly categorized into:

- **Distance-Vector Algorithms:**
  - **Description:** Each router maintains a table (vector) of distances (metrics) to various network destinations. The distance is typically measured in hops. Routers periodically share their routing tables with neighboring routers, and each router updates its table based on the information received.
  - **Example:** RIP uses distance-vector routing with a hop count as the metric.
  - **Limitations:** Slow convergence, potential for routing loops (e.g., the “count to infinity” problem).
  - **Loop Prevention Techniques:** Distance-vector protocols often use techniques like split horizon, route poisoning, and hold-down timers to prevent routing loops.

- **Link-State Algorithms:**
  - **Description:** Each router has a complete map (or topology) of the network. Routers use this map to calculate the shortest path to each destination. The map is created by exchanging link-state advertisements (LSAs) with other routers.
  - **Example:** OSPF uses link-state routing with the Dijkstra algorithm to determine the shortest path.
  - **Advantages:** Faster convergence, more accurate and up-to-date routing information, better scalability.
  - **Disadvantages:** Higher resource consumption (memory, CPU) due to the complexity of maintaining the entire network topology.

- **Path-Vector Algorithms:**
  - **Description:** Path-vector algorithms maintain the path (a sequence of AS numbers) that data takes to reach a destination. This allows for more control over routing decisions and avoids loops by ensuring that a router can see the entire path to a destination.
  - **Example:** BGP uses a path-vector algorithm where each route advertisement includes the complete AS path.

# Routing Protocols in Detail
Let's delve deeper into some common routing protocols:

- **RIP (Routing Information Protocol):**
  - **Metric:** Hop count, with a maximum of 15 hops (16 is considered unreachable).
  - **Routing Updates:** Broadcast every 30 seconds to all neighbors.
  - **Convergence Time:** Slow, due to periodic updates and hop count limitations.
  - **Use Case:** Small networks, legacy systems.
  - **RIP Version 2:** An enhancement of RIP, which includes support for subnet masks (CIDR), authentication, and multicast routing updates.

- **OSPF (Open Shortest Path First):**
  - **Metric:** Cost, typically based on bandwidth (e.g., the inverse of the interface bandwidth).
  - **Routing Updates:** Sent only when there is a change in the network topology (event-driven).
  - **Convergence Time:** Fast, due to the link-state nature and use of the Dijkstra algorithm.
  - **Areas:** OSPF networks are divided into areas to optimize the distribution of routing information. Area 0 is the backbone area, and all other areas must connect to it.
  - **Use Case:** Large enterprise networks with complex topologies.

- **EIGRP (Enhanced Interior Gateway Routing Protocol):**
  - **Metric:** Composite metric, which can include factors like bandwidth, delay, load, and reliability.
  - **Routing Updates:** Sent only when necessary (triggered updates), with minimal bandwidth usage.
  - **Convergence Time:** Very fast, due to the use of the Diffusing Update Algorithm (DUAL), which ensures loop-free paths.
  - **Features:** Supports unequal-cost load balancing, making it highly flexible.
  - **Use Case:** Large networks, especially in environments where Cisco devices are predominant.

- **BGP (Border Gateway Protocol):**
  - **Metric:** Path attributes, such as AS path length, are used for route selection. BGP also allows for policy-based routing decisions.
  - **Routing Updates:** Incremental updates are sent only when there is a change in network reachability.
  - **Convergence Time:** Slow compared to IGPs, but BGP is designed for scalability across the global internet.
  - **Use Case:** Internet Service Providers (ISPs), large organizations with multiple internet connections (multi-homing).
  - **BGP Features:** BGP supports route filtering, route aggregation, and manipulation of path attributes to influence routing decisions.

# Routing Process in Action
To understand routing in practice, let's consider a scenario where a data packet needs to travel from a source device in one network to a destination device in another network:

1. **Packet Creation:** The source device creates a packet with the destination IP address in the header.
2. **Routing Decision:** The source device (or the default gateway/router) checks its routing table to determine whether the destination IP is in its local network. If not, it forwards the packet to the next hop router.
3. **Intermediate Routers:** Each router along the path receives the packet, examines the destination IP address, and consults its routing table to determine the best route to forward the packet. The packet may pass through several routers, each making independent routing decisions.
4. **Final Delivery:** When the packet reaches the router directly connected to the destination network, the router forwards the packet to the appropriate device within that network.
5. **Reverse Path:** When the destination device responds, the process repeats in the reverse direction.

# Routing Challenges
Routing in large networks, especially across the global internet, presents several challenges:

- **Scalability:** Routing protocols must scale to support large numbers of routes and handle the increasing complexity of the internet's topology.
- **Convergence Time:** Fast convergence is critical to minimize packet loss and downtime during network changes or failures.
- **Security:** Routing protocols are vulnerable to various attacks, such as route poisoning, hijacking, and denial of service. Security measures like authentication, route filtering, and IPsec are used to protect routing information.
- **Policy-Based Routing:** In some cases, organizations may need to implement routing policies that prioritize certain types of traffic or avoid specific routes. BGP allows for extensive policy control through the manipulation of path attributes.


