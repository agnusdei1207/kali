sudo apt update
sudo apt install wordlists -y
sudo apt install seclists -y
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

ls -l /opt/SecLists/Discovery/DNS/

# raft

/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
