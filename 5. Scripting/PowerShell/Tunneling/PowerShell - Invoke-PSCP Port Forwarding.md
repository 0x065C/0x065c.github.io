Attack Host = `<attack_ip>`, `<attack_port>`
Pivot Host = `<pivot_ip>`, `<pivot_port>`
Target Host = `<target_ip>`, `<target_port>`

In a scenario where you're attempting to tunnel or pivot from the **Attack Host** (`<attack_ip>`, `<attack_port>`) to the **Target Host** (`<target_ip>`, `<target_port>`) via a **Pivot Host** (`<pivot_ip>`, `<pivot_port>`), PowerShell offers several methods to facilitate tunneling and pivoting through the network. Below is a collection of PowerShell-based scripts and techniques that can be used for this purpose. The scripts assume you have code execution on the **Pivot Host** and want to set up the tunnel for traffic from the **Attack Host** to reach the **Target Host**.

# PowerShell - Invoke-PSCP Port Forwarding

While PowerShell doesn't have native SSH, you can set up SSH-like port forwarding using **Invoke-PSCP** or similar scripts:

```powershell
# Install Invoke-PSCP (PowerShell Copy, which also supports port forwarding)
Import-Module Invoke-PSCP

# Set up port forwarding from Attack Host through Pivot Host to Target Host
Invoke-PSCP -SourcePort <attack_port> -RelayIP "<pivot_ip>" -RelayPort <pivot_port> -DestinationIP "<target_ip>" -DestinationPort <target_port>
```

This method forwards traffic from the **Attack Host** to the **Pivot Host**, which then forwards the traffic to the **Target Host**.

# Notes
- Replace the placeholders `<attack_ip>`, `<attack_port>`, `<pivot_ip>`, `<pivot_port>`, `<target_ip>`, and `<target_port>` with the actual IP addresses and port numbers.
- Consider security controls such as firewalls and endpoint detection and response (EDR) solutions that might interfere with PowerShell-based tunneling. Always obfuscate your PowerShell scripts or use techniques to evade detection.
- For extended use, ensure persistence or utilize task scheduling techniques to re-establish the tunnel if the process is interrupted.

Each of these scripts or techniques serves a different purpose, from simple port forwarding to complex SOCKS and HTTP tunneling. Choose the one that fits your operational needs based on the environment and the complexity of your pivoting requirements.