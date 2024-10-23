# PowerShell -  Sending Keystrokes

## Prerequisites
- **No admin privileges required**.
- PowerShell available on the target machine.

# Step 1: Load the Required Assembly

PowerShell can send keystrokes using the `System.Windows.Forms` assembly, a preinstalled API in Windows.

## Command
Before sending keystrokes, load the assembly with the following command:

```powershell
Add-Type -AssemblyName System.Windows.Forms
```

This loads the necessary functionality for sending keystrokes.

# Step 2: Send Keystrokes

## Basic Example

To simulate typing the word `hello`:

```powershell
[System.Windows.Forms.SendKeys]::SendWait('hello')
```

## Explanation
- The `SendWait()` method simulates key presses in the active window. In this example, it types `hello`.

# Step 3: Automating Browser Actions

You can use PowerShell to open a web browser, navigate to a specific URL, and simulate keystrokes like entering fullscreen mode.

## Example: Open a Browser and Enter Fullscreen

### For Edge Browser
```powershell
$edge = New-Object -ComObject Microsoft.Edge.Application
$edge.Visible = $true
$edge.Navigate("https://smukx.github.io/hacked")
while ($edge.Busy) { Start-Sleep -Milliseconds 100 }
$edge.FullScreen = $true
[System.Windows.Forms.SendKeys]::SendWait("{F11}")
```

### For Chrome Browser
```powershell
$chrome = New-Object -ComObject 'Chrome.Application'
$chrome.Visible = $true
$chrome.Navigate("https://smukx.github.io/hacked")
while ($chrome.Busy) { Start-Sleep -Milliseconds 100 }
$chrome.FullScreen = $true
[System.Windows.Forms.SendKeys]::SendWait("{F11}")
```

## Explanation
- These commands open the browser, navigate to a specified URL, and simulate pressing `F11` to enter fullscreen mode.

# Step 4: Sending Key Combinations

PowerShell can simulate combinations of keys, like `Alt+F4` to close windows or `Ctrl+Alt+Del`.

## Example: Simulate `Alt+F4` (Close Window)
```powershell
Start-Sleep -Seconds 2
[System.Windows.Forms.SendKeys]::SendWait('%')
[System.Windows.Forms.SendKeys]::SendWait('{F4}')
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
```

## Explanation
- This script introduces a 2-second delay, then simulates `Alt+F4`, followed by the `Enter` key to confirm any prompts.

# Step 5: Keystroke Cheat Sheet

Here are some common keystrokes that you can simulate using PowerShell:

- `{ENTER}`: Enter key
- `{TAB}`: Tab key
- `{BACKSPACE}` or `{BKSP}`: Backspace key
- `{DELETE}` or `{DEL}`: Delete key
- `{HOME}`: Home key
- `{END}`: End key
- `{PAGEUP}`: Page Up key
- `{PAGEDOWN}`: Page Down key
- `{UP}`: Up Arrow key
- `{DOWN}`: Down Arrow key
- `{LEFT}`: Left Arrow key
- `{RIGHT}`: Right Arrow key
- `{F1}` to `{F12}`: Function keys F1 to F12
- `{ESC}`: Escape key
- `{CTRL}` or `^`: Control key
- `{ALT}` or `%`: Alt key
- `{SHIFT}` or `+`: Shift key
- `{CAPSLOCK}`: Caps Lock key
- `{NUMLOCK}`: Num Lock key
- `{SCROLLLOCK}`: Scroll Lock key

# Step 6: Sending Multiple Keys

You can combine keys to simulate more complex keyboard commands, such as `Ctrl+Alt+Del`.

## Example: Simulate `Ctrl+Alt+Del`
```powershell
[System.Windows.Forms.SendKeys]::SendWait('^%{ESC}')
```

## Explanation
- `^` represents the `Ctrl` key, `%` represents the `Alt` key, and `{ESC}` represents the `Esc` key. This simulates pressing all three keys at the same time.