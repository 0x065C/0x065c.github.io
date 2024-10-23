# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]
	- [[Impacket]]
		- [[Impacket-getST]]

**[Github - Impacket](https://github.com/fortra/impacket)**

# Summary
Impacket is a collection of Python classes focused on providing low-level programmatic access to network protocols. It is often used in red teaming and penetration testing for lateral movement, information gathering, and other attack vectors. Impacket is highly versatile and supports a variety of protocols, such as SMB, MSRPC, LDAP, and others. 

#### Features

- **Packet crafting and decoding:** Simplifies the creation and analysis of network packets.
- **Protocol support:** Includes support for various network protocols like SMB, MSRPC, and more.
- **Credential dumping:** Extracts credentials from Windows systems using tools like `secretsdump.py`.
- **Remote command execution:** Executes commands on remote Windows systems with tools like `wmiexec.py` and `psexec.py`.
- **File transfer:** Transfers files to and from Windows systems using SMB.
- **Interactive shells:** Provides interactive shells for remote command execution.

#### Typical Use Cases

- **Credential dumping and harvesting:** Extracting and using credentials from compromised systems.
- **Lateral movement:** Moving across systems within a network using various protocols.
- **Remote command execution:** Running commands on remote systems to gather information or further exploit targets.
- **File transfer:** Uploading or downloading files to and from compromised systems.

# How Impacket Works
Impacket works by providing a set of Python classes that encapsulate complex network protocols, allowing for low-level manipulation and interaction. The operation can be broken down into the following steps:

1. **Initialization:** A specific Impacket class is initialized based on the desired protocol or service.
2. **Authentication:** If required, credentials are used to authenticate against a service, often utilizing NTLM or Kerberos.
3. **Protocol Communication:** The Impacket classes enable communication with the target service, sending and receiving network packets according to the specific protocol.
4. **Data Processing:** Data received from the target is parsed and can be used for further operations, such as dumping credentials or executing commands.
5. **Execution and Response:** Commands can be executed on the remote system, with responses captured and processed by Impacket.

# Impacket Components
Impacket consists of several key components:

- **Core Protocols:** Provides the implementation of various network protocols, such as SMB, MSRPC, and LDAP.
- **SMB:** Classes for interacting with SMB shares and services, including file transfer and command execution.
- **MSRPC:** Implements Microsoft Remote Procedure Call, allowing for remote function invocation.
- **LDAP:** Provides support for querying and interacting with LDAP directories.
- **DCE/RPC:** Implements Distributed Computing Environment / Remote Procedure Calls for communication with Windows services.

Additionally, Impacket includes several standalone scripts for specific tasks:

- **psexec.py:** Executes commands on a remote Windows machine using SMB/RPC.
- **secretsdump.py:** Dumps secrets (credentials, hashes) from a remote machine.
- **smbclient.py:** A simple SMB client that can list shares, download, and upload files.
- **wmiexec.py:** Executes commands on a remote Windows machine using WMI.
- **dcomexec.py:** Executes commands using DCOM.

# Impacket Syntax Structure
Impacket’s syntax structure varies depending on the protocol or service being utilized. The general structure involves importing the necessary classes and then invoking methods to perform the desired actions.

# Additional Information

- **Subcategories:** Impacket is not limited to a single use case; it covers multiple aspects of network interaction, including file transfers, command execution, and credential extraction.
- **File Structure:** Impacket is organized into Python modules and scripts, each serving different protocol interactions.
- **Advanced Options:** Many Impacket scripts include advanced flags and parameters for specific functionalities, such as overriding default ports or specifying encryption.
- **Secondary Functions:** Beyond its primary functions, Impacket can be used for advanced scenarios like Pass-the-Hash (PtH) and Pass-the-Ticket (PtT) attacks.
- **Security Considerations:** As a powerful toolset, Impacket should be used responsibly and ethically, adhering to legal and organizational guidelines.

# Resources

|**Website**|**URL**|
|-|-|
|Official Repository|[Impacket GitHub](https://github.com/SecureAuthCorp/impacket)|
|Community Discussions|[Reddit: NetSec](https://www.reddit.com/r/netsec/)|
|Tutorials and Guides|[Pentest Blog](https://www.pentest.blog/)|
|YouTube Tutorials|[Null Byte](https://www.youtube.com/channel/UCgTNupxATBfWmfehv21ym-g)|
|Security Conferences|[Black Hat](https://www.blackhat.com/)|
|Cheat Sheets|[Cheatography](https://cheatography.com/)|
|CTF Challenges|[TryHackMe](https://tryhackme.com/)|
|Advanced Security Topics|[SANS Institute](https://www.sans.org/)|
