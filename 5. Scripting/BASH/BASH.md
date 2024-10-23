# Summary
BASH (Bourne Again SHell) is a command processor that typically runs in a text window where the user types commands that cause actions. BASH can also read commands from a file, called a script. It is the default shell on many Unix-like operating systems, including Linux and macOS. 

## Features of BASH
- **Command execution:** Executes commands typed in by the user or stored in scripts.
- **Scripting:** Allows the automation of tasks via shell scripts.
- **Job Control:** Manages multiple processes in the background or foreground.
- **Input/output redirection:** Redirects input and output from files, devices, or other commands.
- **Variable handling:** Allows the use of variables to store and manipulate data.
- **Control structures:** Supports conditionals, loops, and functions for more complex scripting.
- **Command history:** Maintains a history of executed commands for easy recall and editing.

## Typical Use Cases
- **System administration:** Automating routine tasks such as backups, updates, and monitoring.
- **Development environments:** Compiling code, running tests, and managing environments.
- **Security testing:** Running penetration testing tools, automating reconnaissance, and managing exploits.
- **File management:** Manipulating files and directories, including searching, editing, and transferring files.

# How BASH Works
1. **Command Input:** The user enters a command at the prompt. This command may involve built-in commands, scripts, or external programs.
2. **Parsing:** BASH interprets the command, checking for syntax errors and parsing arguments, options, and variables.
3. **Expansion:** BASH expands variables, wildcards, and command substitutions before execution.
4. **Execution:** BASH executes the command or script. This might involve running a built-in function, executing an external program, or performing a shell operation like looping or conditional branching.
5. **Redirection and Piping:** If specified, BASH redirects input and output streams or pipes the output of one command as the input to another.
6. **Process Management:** BASH manages processes, allowing commands to be run in the foreground or background, pausing, and resuming execution.
7. **Job Control:** BASH handles multiple jobs simultaneously, allowing the user to switch between different tasks or terminate them as necessary.
8. **Command History:** The command is stored in the command history, enabling the user to recall or edit it later.

# BASH Components
1. **Command Line Interface (CLI):** The primary interface where the user interacts with BASH. The CLI consists of a prompt where commands are entered.
2. **Shell Built-in Commands:** These are commands that are executed directly within the shell itself rather than as external programs (e.g., `cd`, `echo`, `alias`).
3. **Shell Variables:** These are variables managed by BASH to store data, such as strings, numbers, or command output. There are environment variables (global) and shell variables (local).
4. **Environment:** This includes environment variables and shell settings that configure how the shell behaves. Examples include `PATH`, `HOME`, and `USER`.
5. **Scripts:** Files containing a sequence of BASH commands. Scripts automate repetitive tasks and can be executed just like any other command.
6. **Job Control System:** A feature that allows users to manage multiple tasks (jobs) at the same time. Jobs can be in the foreground, background, or paused.
7. **Input/Output Redirection:** The system that manages where input comes from (keyboard, file) and where output goes (screen, file). This includes pipes (`|`), redirections (`>`, `>>`, `<`), and file descriptors.

# BASH Syntax Structure
The syntax structure of BASH includes several key elements that dictate how commands are interpreted and executed.

#### Basic Command Syntax
```bash
command [option(s)] [argument(s)]
```
**command:** The name of the program or built-in command to execute.
**option(s):** Flags or settings that modify the behavior of the command (e.g., `-l`, `--help`).
**argument(s):** The inputs to the command, such as files, directories, or other data.

#### Variable Assignment
```bash
variable_name=value
```
**Example:**
```bash
greeting="Hello, World!"
```

#### Command Substitution
```bash
variable_name=$(command)
```
**Example:**
```bash
current_date=$(date)
```

#### Conditional Statements
```bash
if [ condition ]; then
    # Commands to execute if condition is true
elif [ other_condition ]; then
    # Commands to execute if other_condition is true
else
    # Commands to execute if no condition is true
fi
```
**Example:**
```bash
if [ -f /etc/passwd ]; then
    echo "File exists"
else
    echo "File does not exist"
fi
```

#### Loops
```bash
# For loop
for variable in list; do
    # Commands to execute for each item in list
done

# While loop
while [ condition ]; do
    # Commands to execute while condition is true
done
```
**Example:**
```bash
for i in {1..5}; do
    echo "Iteration $i"
done
```

#### Functions
```bash
function_name () {
    # Commands that make up the function
}
```
**Example:**
```bash
greet() {
    echo "Hello, $1"
}
```

#### Piping and Redirection
```bash
command1 | command2     # Pipe output of command1 as input to command2
command > file          # Redirect output to a file
command >> file         # Append output to a file
command < file          # Use a file as input
```
**Example:**
```bash
ls -l | grep '^d' > directories.txt
```

# Commands and Usage

#### Common BASH Commands

1. **File and Directory Management:**
   - `ls`: List files and directories.
     ```bash
     ls -al
     ```
   - `cd`: Change directory.
     ```bash
     cd /path/to/directory
     ```
   - `mkdir`: Create a new directory.
     ```bash
     mkdir new_directory
     ```
   - `rm`: Remove files or directories.
     ```bash
     rm -rf directory_name
     ```
   - `cp`: Copy files or directories.
     ```bash
     cp source_file destination_file
     ```
   - `mv`: Move or rename files or directories.
     ```bash
     mv old_name new_name
     ```

2. **Text Processing:**
   - `cat`: Concatenate and display file content.
     ```bash
     cat file.txt
     ```
   - `grep`: Search for patterns in files.
     ```bash
     grep "search_term" file.txt
     ```
   - `awk`: Pattern scanning and processing language.
     ```bash
     awk '{print $1}' file.txt
     ```
   - `sed`: Stream editor for filtering and transforming text.
     ```bash
     sed 's/old/new/g' file.txt
     ```

3. **System Monitoring:**
   - `ps`: Display current processes.
     ```bash
     ps aux
     ```
   - `top`: Display real-time system statistics.
     ```bash
     top
     ```
   - `df`: Report disk space usage.
     ```bash
     df -h
     ```
   - `du`: Estimate file and directory space usage.
     ```bash
     du -sh *
     ```

4. **Networking:**
   - `ping`: Send ICMP ECHO_REQUEST to network hosts.
     ```bash
     ping <target_ip>
     ```
   - `netstat`: Display network connections, routing tables, interface statistics.
     ```bash
     netstat -an
     ```
   - `curl`: Transfer data from or to a server.
     ```bash
     curl -O http://example.com/file
     ```

5. **Process Management:**
   - `kill`: Terminate processes by PID.
     ```bash
     kill -9 <pid>
     ```
   - `jobs`: List active jobs.
     ```bash
     jobs
     ```
   - `fg`: Bring a job to the foreground.
     ```bash
     fg %1
     ```
   - `bg`: Send a job to the background.
     ```bash
     bg %1
     ```

6. **Scripting:**
   - Basic Script Example:
     ```bash
     #!/bin/bash
     echo "Hello, World!"
     ```
   - Running the script:
     ```bash
     ./script.sh
     ```

# Additional Information

### Advanced Topics
**BASH Aliases:** Shortcuts for longer commands.
  ```bash
  alias ll='ls -al'
  ```
**BASH Arrays:** Handling multiple values in a single variable.
  ```bash
  my_array=(val1 val2 val3)
  echo ${my_array[0]}
  ```
**BASH Trap Command:** Captures and handles signals and events.
  ```bash
  trap "echo 'Interrupted!'" SIGINT
  ```
**BASH Regular Expressions:** Powerful pattern matching with `[[ ]]` and `grep`.
  ```bash
  if [[ "$string" =~ ^[0-9]+
$ ]]; then
      echo "It's a number"
  fi  
  ```

#### File Structure
**.bashrc:** A file containing commands that are run whenever a new terminal session is started in interactive mode.
**.bash_profile:** A file executed for login shells, typically used for environment variable definitions.
**/etc/profile:** Global settings applied to all users.

#### Secondary Functions
**Command Completion:** BASH provides command auto-completion for built-in commands and user-defined ones.
**History Expansion:** Recall and modify previous commands using `!` and `^` operators.

#### Common Pitfalls
**Quoting:** Improper use of quotes can lead to unexpected command behavior.
**Whitespace Sensitivity:** Extra spaces can break command syntax, particularly in loops and conditionals.
**Script Permissions:** Scripts must have executable permissions (`chmod +x script.sh`) to be run directly.

# Resources

|**Website**|**URL**|
|-|-|
|GNU Bash Reference Manual|https://www.gnu.org/software/bash/manual/bash.html|
|Advanced Bash-Scripting Guide|https://tldp.org/LDP/abs/html/|
|Bash Hackers Wiki|https://wiki.bash-hackers.org/|
|Shell Scripting Tutorial|https://www.shellscript.sh/|
|Bash Guide for Beginners|https://tldp.org/LDP/Bash-Beginners-Guide/html/|
|The Linux Documentation Project (TLDP)|https://tldp.org/|
|SS64 Bash Reference|https://ss64.com/bash/|
|Explainshell|https://explainshell.com/|
|Bash-Snippets GitHub Repo|https://github.com/alexanderepstein/Bash-Snippets|
|Bash Pocket Reference by Arnold Robbins|https://www.oreilly.com/library/view/bash-pocket-reference/9781449388854/|