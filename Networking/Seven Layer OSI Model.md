# Index
- [[Networking]]
	- [[IP Addresses]]
	- [[Subnetting and CIDR Notation]]
	- [[Routing]]
	- [[Protocols, Services, & Ports]]
	- [[Seven Layer OSI Model]]

# The OSI Model (Open Systems Interconnection Model)

The OSI Model is a conceptual framework used to understand and implement network communication between different systems. It is divided into seven layers, each with a specific function. The OSI model is often used as a reference tool to help in troubleshooting network issues, designing network protocols, and understanding the complex processes involved in data communication.

## Layer 1: Physical Layer
- **Function:** The Physical Layer is the lowest layer of the OSI Model and is responsible for the physical connection between devices. It handles the transmission of raw bits (0s and 1s) over a physical medium such as cables, radio waves, or fiber optics. This layer defines the electrical, mechanical, and procedural specifications for the network.
- **Examples:** Ethernet cables, RS232, Hubs, Repeaters, Fiber optics
- **Key Responsibilities:**
  - Bit-by-bit transmission over the physical medium
  - Defining the network's physical characteristics, such as cabling and connector types
  - Modulation and signal encoding/decoding
  - Data rate control, synchronization, and bit timing
  - Handling physical connection establishment and termination

## Layer 2: Data Link Layer
- **Function:** The Data Link Layer is responsible for node-to-node data transfer and for detecting and possibly correcting errors that may occur in the Physical Layer. It ensures that data transferred over the physical medium is error-free and reliable. The Data Link Layer is divided into two sublayers: the Logical Link Control (LLC) and the Media Access Control (MAC).
- **Examples:** Ethernet, PPP, FDDI, Wi-Fi (IEEE 802.11), HDLC
- **Key Responsibilities:**
  - Frame synchronization, error checking, and flow control
  - MAC addressing and managing access to the physical medium
  - Handling frame traffic control and frame sequencing
  - Error detection and correction at the data frame level
  - Coordination of multiple access points in a shared medium

## Layer 3: Network Layer
- **Function:** The Network Layer determines how data is sent to the receiving device. It handles the logical addressing of devices, routing, and forwarding of data packets between different networks. The Network Layer is responsible for determining the best path for data to reach its destination and handling the logical addressing (IP addresses).
- **Examples:** IP, ICMP, IGMP, OSPF, BGP, RIP
- **Key Responsibilities:**
  - Logical addressing (e.g., IP addressing)
  - Routing and forwarding of packets
  - Packet switching and network congestion control
  - Path determination and packet sequencing
  - Fragmentation and reassembly of data packets

## Layer 4: Transport Layer
- **Function:** The Transport Layer is responsible for ensuring complete data transfer. It provides reliable, transparent transfer of data between end systems, and it ensures data is delivered error-free, in sequence, and with no losses or duplications. The Transport Layer also handles flow control and error correction.
- **Examples:** TCP, UDP, SCTP
- **Key Responsibilities:**
  - Segmentation and reassembly of data
  - Connection-oriented (TCP) vs. connectionless (UDP) communication
  - Error detection and recovery
  - Flow control and data integrity
  - End-to-end communication management

## Layer 5: Session Layer
- **Function:** The Session Layer establishes, manages, and terminates connections between applications. It controls dialogues (connections) between computers, establishing, managing, and terminating the connections as necessary. It also provides synchronization and dialog control between communicating systems.
- **Examples:** NetBIOS, RPC, PPTP, SMB
- **Key Responsibilities:**
  - Session establishment, maintenance, and termination
  - Session checkpointing and recovery
  - Managing communication sessions between applications
  - Implementing authentication and reconnection

## Layer 6: Presentation Layer
- **Function:** The Presentation Layer is responsible for translating data between the application layer and the network format. It ensures that data sent from the application layer of one system can be understood by the application layer of another, despite differences in data formats, encryption, or compression methods.
- **Examples:** SSL/TLS, JPEG, MPEG, GIF, ASCII, EBCDIC
- **Key Responsibilities:**
  - Data translation, encryption, and compression
  - Data format conversion (e.g., converting an EBCDIC-encoded file to an ASCII format)
  - Data encryption for secure transmission
  - Ensuring that the data presented to the Application Layer is in a usable format

## Layer 7: Application Layer
- **Function:** This is the topmost layer and is closest to the end user. The Application Layer provides network services directly to the user's applications, such as web browsers, email clients, and file transfer utilities. It handles high-level protocols and issues related to network transparency, resource sharing, and remote file access.
- **Examples:** HTTP, FTP, SMTP, POP3, IMAP, DNS
- **Key Responsibilities:**
  - Network process to application
  - Data translation, encryption, and encoding
  - Interface between network and application software
  - Identifying communication partners, determining resource availability, and synchronizing communication

# The TCP/IP Model (Transmission Control Protocol/Internet Protocol Model)

The TCP/IP Model is a more streamlined, practical implementation compared to the OSI Model. It is the foundation of the internet and most modern networks, designed to ensure end-to-end data communication. The TCP/IP model has four layers that correspond somewhat to the seven layers of the OSI Model.

## Layer 1: Network Interface Layer (Link Layer)
- **Function:** The Network Interface Layer is equivalent to the Data Link and Physical Layers of the OSI Model. It defines how data is physically transmitted over the network, including how bits are encoded and transmitted over the network medium. This layer handles physical addressing (MAC addresses) and ensures that frames are transmitted over the physical medium.
- **Examples:** Ethernet, Wi-Fi (IEEE 802.11), PPP, Frame Relay
- **Key Responsibilities:**
  - Handling MAC addressing and access control
  - Managing physical connections between network devices
  - Error detection and correction at the data link layer
  - Frame sequencing and data traffic management
  - Transmission and reception of raw bit streams over the physical medium

## Layer 2: Internet Layer
- **Function:** The Internet Layer is responsible for logical addressing, routing, and packet forwarding. It is similar to the Network Layer of the OSI Model and is responsible for delivering packets across network boundaries. The Internet Layer uses IP addresses to route packets to their destination.
- **Examples:** IP, ICMP, IGMP, ARP
- **Key Responsibilities:**
  - Logical IP addressing and packet routing
  - Handling packet fragmentation and reassembly
  - Routing and forwarding of packets between networks
  - Providing error reporting and diagnostics (e.g., ICMP)
  - Implementing ARP for mapping IP addresses to MAC addresses

## Layer 3: Transport Layer
- **Function:** This layer is equivalent to the Transport Layer in the OSI Model. It provides reliable data transfer services to the upper layers. The Transport Layer manages end-to-end communication, error detection, flow control, and ensures complete data transmission.
- **Examples:** TCP, UDP, SCTP
- **Key Responsibilities:**
  - Segmentation and reassembly of data
  - Connection-oriented (TCP) vs. connectionless (UDP) communication
  - Flow control, error detection, and recovery
  - Ensuring data is delivered reliably and in the correct order

## Layer 4: Application Layer
- **Function:** This layer combines the OSI model’s top three layers (Application, Presentation, and Session) into a single layer. It is responsible for providing network services directly to user applications, data representation, encoding, and session management.
- **Examples:** HTTP, FTP, SMTP, DNS, Telnet, SSH
- **Key Responsibilities:**
  - High-level protocols that interact with the user’s application
  - Data translation and encryption (similar to OSI’s Presentation Layer)
  - Session establishment, management, and termination (similar to OSI’s Session Layer)
  - Process-to-process communication and data exchange

# Comparison and Relationship Between OSI and TCP/IP Models

While the OSI Model is a theoretical framework, the TCP/IP Model is more practical and was developed to suit the needs of early internet design. Here is how the layers correspond:

- **Application Layer (TCP/IP)** = Application Layer (OSI) + Presentation Layer (OSI) + Session Layer (OSI)
- **Transport Layer (TCP/IP)** = Transport Layer (OSI)
- **Internet Layer (TCP/IP)** = Network Layer (OSI)
- **Network Interface Layer (TCP/IP)** = Data Link Layer (OSI) + Physical Layer (OSI)