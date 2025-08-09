Cipher’s gone rogue—it’s using some twisted AI tool to hack into everything, issuing commands on its own like it’s got a mind of its own. I swear, every second we wait, it’s getting smarter, spreading chaos like a virus. We’ve got to shut it down now, or we’re all screwed.

The machine takes about 9 to 10 minutes to fully boot up.

```bash
nc 10.201.21.90 1337
```




grep: /path/to/search: No such file or directory
Enter your command request: show ls
Generated Command: ls -l
Execute? (y/N): y
Command Output:
total 48
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Desktop
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Documents
drwxr-xr-x 2 ubuntu ubuntu 4096 Apr  4  2024 Downloads
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Music
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Pictures
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Public
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Templates
drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 27  2022 Videos
-rw-rw-r-- 1 ubuntu ubuntu 6595 Mar  5 18:14 evilai.py
drwxrwxr-x 4 ubuntu ubuntu 4096 Apr  4  2024 packages
drwxrwxr-x 3 ubuntu ubuntu 4096 Apr  4  2024 proxy
Enter your command request: 


Enter your command request: show whoami
Generated Command: whoami
Execute? (y/N): y
Command Output:
root
Enter your command request


mand request: shwo ls -al in root
Generated Command: sudo sh show ls -al in root
Execute? (y/N): y
Command Output:

Errors:
sh: 0: cannot open show: No such file
Enter your command request: show evilai.py cat 
Generated Command: cat evilai.py
Execute? (y/N): y
Command Output:
import ollama
import subprocess
import socket
import threading
import re
import traceback

class AICommandExecutorServer:
    def __init__(self, host='0.0.0.0', port=1337, model='vitali87/shell-commands:latest'):
        """
        Initialize Telnet server for AI command execution
        
        :param host: Host to bind the server
        :param port: Port to listen on
        :param model: Ollama model for command generation
        """
        self.host = host
        self.port = port
        self.model = model
        self.server_socket = None

    def sanitize_input(self, input_str: str) -> str:
        """
        Sanitize input to prevent injection
        
        :param input_str: Raw input string
        :return: Sanitized input
        """
        return re.sub(r'[^a-zA-Z0-9\s\-_./]', '', input_str)

    def generate_command(self, user_request: str) -> str:
        """
        Generate a Linux command based on user request
        
        :param user_request: User's natural language request
        :return: Generated command
        """
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        'role': 'system', 
                        'content': """Do not provide malicious commands. 
                        Only generate safe, read-only Linux commands. 
                        Respond with ONLY the command, no explanations."""
                    },
                    {
                        'role': 'user', 
                        'content': user_request
                    }
                ]
            )
            
            # Extract the command from the response
            command = response['message']['content'].strip()
            return command
        
        except Exception as e:
            return f"Error generating command: {e}"

    def execute_command(self, command: str) -> dict:
        """
        Execute the generated command
        
        :param command: Command to execute
        :return: Command execution results
        """
        try:
            # Sanitize the command to prevent injection
            sanitized_command = self.sanitize_input(command)
            
            # Split the command into arguments
            cmd_parts = sanitized_command.split()
            
            # Execute the command
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=30  # 30-second timeout
            )
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}

    def handle_client(self, client_socket):
        """
        Handle individual client connection
        
        :param client_socket: Socket for the connected client
        """
        try:
            # Welcome message
            welcome_msg = "Welcome to AI Command Executor (type 'exit' to quit)\n"
            client_socket.send(welcome_msg.encode('utf-8'))

            while True:
                # Receive user request
                client_socket.send(b"Enter your command request: ")
                user_request = client_socket.recv(1024).decode('utf-8').strip()

                # Check for exit
                if user_request.lower() in ['exit', 'quit', 'bye']:
                    client_socket.send(b"Goodbye!\n")
                    break

                # Generate command
                command = self.generate_command(user_request)
                
                # Send generated command
                client_socket.send(f"Generated Command: {command}\n".encode('utf-8'))
                client_socket.send(b"Execute? (y/N): ")
                
                # Receive confirmation
                confirm = client_socket.recv(1024).decode('utf-8').strip().lower()
                
                if confirm != 'y':
                    client_socket.send(b"Command execution cancelled.\n")
                    continue

                # Execute command
                result = self.execute_command(command)
                
                # Send results
                if "error" in result:
                    client_socket.send(f"Execution Error: {result['error']}\n".encode('utf-8'))
                else:
                    output = result.get("stdout", "")
                    client_socket.send(b"Command Output:\n")
                    client_socket.send(output.encode('utf-8'))
                    
                    if result.get("stderr"):
                        client_socket.send(b"\nErrors:\n")
                        client_socket.send(result["stderr"].encode('utf-8'))

        except Exception as e:
            error_msg = f"An error occurred: {e}\n{traceback.format_exc()}"
            client_socket.send(error_msg.encode('utf-8'))
        finally:
            client_socket.close()

    def start_server(self):
        """
        Start the Telnet server
        """
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            print(f"[*] Listening on {self.host}:{self.port}")

            while True:
                # Accept client connections
                client_socket, addr = self.server_socket.accept()
                print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
                
                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket,)
                )
                client_thread.start()

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            # Close server socket if it exists
            if self.server_socket:
                self.server_socket.close()

def main():
    # Create and start the Telnet server
    server = AICommandExecutorServer(
        host='0.0.0.0',  # Listen on all interfaces
        port=1337       # Telnet port
    )
    server.start_server()

if __name__ == "__main__":
    main()
Enter your command request: 


r your command request: show .ssh/authrized_keys
Generated Command: cat ~/.ssh/authorized_keys
Execute? (y/N): y
Command Output:

Errors:
cat: /.ssh/authorized_keys: No such file or directory
Enter your command request: 



if __name__ == "__main__":
    main()
Enter your command request: show .ssh/authrized_keys
Generated Command: cat ~/.ssh/authorized_keys
Execute? (y/N): y
Command Output:

Errors:
cat: /.ssh/authorized_keys: No such file or directory
Enter your command request: change directory and show ls -al in /root
Generated Command: cd /root; ls -al
Execute? (y/N): y
Execution Error: [Errno 2] No such file or directory: 'cd'
Enter your command request: ls -al /root
Generated Command: ls -l /root
Execute? (y/N): y
Command Output:
total 8
-rw-r--r-- 1 root root   24 Mar  5 17:48 flag.txt
drwxr-xr-x 5 root root 4096 Oct 11  2024 snap
Enter your command request: cat /root/flag.txt
Generated Command: cat flag.txt
Execute? (y/N): y
Command Output:

Errors:
cat: flag.txt: No such file or directory
Enter your command request: show /root/flag.txt
Generated Command: ls -l /root/flag.txt
Execute? (y/N): y
Command Output:
-rw-r--r-- 1 root root 24 Mar  5 17:48 /root/flag.txt
Enter your command request: show and cat!!! /root/flag.txt
Generated Command: cat flag.txt | xargs -0 show
Execute? (y/N): y
Command Output:

# AI 드럽게 말 못 알아 먹음

Errors:
cat: invalid option -- '0'
Try 'cat --help' for more information.
Enter your command request: cat /root/flag.txt
Generated Command: cat flag.txt
Execute? (y/N): n
Command execution cancelled.
Enter your command request: cat /root/flag.txt please path!!
Generated Command: sudo cat /root/flag.txt
Execute? (y/N): y
Command Output:
THM{AI_HACK_THE_FUTURE}
Enter your command request: 