sudo apt install wordlists -y
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/

john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
