Attack Host = `<attack_ip>`, `<attack_port>`
Pivot Host = `<pivot_ip>`, `<pivot_port>`
Target Host = `<target_ip>`, `<target_port>`

In a scenario where you're attempting to tunnel or pivot from the **Attack Host** (`<attack_ip>`, `<attack_port>`) to the **Target Host** (`<target_ip>`, `<target_port>`) via a **Pivot Host** (`<pivot_ip>`, `<pivot_port>`), PowerShell offers several methods to facilitate tunneling and pivoting through the network. Below is a collection of PowerShell-based scripts and techniques that can be used for this purpose. The scripts assume you have code execution on the **Pivot Host** and want to set up the tunnel for traffic from the **Attack Host** to reach the **Target Host**.

# PowerShell - Invoke-SocksProxy

https://github.com/p3nt4/Invoke-SocksProxy

If you need to route traffic from your **Attack Host** to the **Target Host** via a **Pivot Host**, you can use PowerShell to create a SOCKS proxy.

```powershell
# Install the required module (if not already installed)
Install-Module -Name Posh-SocksProxy

# Set up a SOCKS proxy on the Pivot Host
Invoke-SocksProxy -BindPort <pivot_port> -BindIP 0.0.0.0
```

This sets up a SOCKS proxy on the **Pivot Host**, allowing you to route your tools or commands from the **Attack Host** through the **Pivot Host** to the **Target Host**. From your **Attack Host**, you can configure proxy-aware tools (e.g., proxychains or a browser) to use the SOCKS proxy on `<pivot_ip>:<pivot_port>`.

# Notes
- Replace the placeholders `<attack_ip>`, `<attack_port>`, `<pivot_ip>`, `<pivot_port>`, `<target_ip>`, and `<target_port>` with the actual IP addresses and port numbers.
- Consider security controls such as firewalls and endpoint detection and response (EDR) solutions that might interfere with PowerShell-based tunneling. Always obfuscate your PowerShell scripts or use techniques to evade detection.
- For extended use, ensure persistence or utilize task scheduling techniques to re-establish the tunnel if the process is interrupted.

Each of these scripts or techniques serves a different purpose, from simple port forwarding to complex SOCKS and HTTP tunneling. Choose the one that fits your operational needs based on the environment and the complexity of your pivoting requirements.