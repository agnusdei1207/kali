# 10.65.171.83

![](https://velog.velcdn.com/images/agnusdei1207/post/448e522f-cf65-4bc4-89a5-ef80eb7bcc50/image.png)


┌──(kali㉿kali)-[~]
└─$ sudo docker run --rm --name rustscan --net=host rustscan/rustscan -a 10.65.171.83
Unable to find image 'rustscan/rustscan:latest' locally
latest: Pulling from rustscan/rustscan
582df0bcf6ab: Pull complete 
c6a83fedfae6: Pull complete 
d9bd24e2554c: Pull complete 
Digest: sha256:1a0137749007f12880c7174c65e9f16835106a787ebc952118c2f9f4ff7a1309
Status: Downloaded newer image for rustscan/rustscan:latest
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
To scan or not to scan? That is the question.

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.65.171.83:22
Open 10.65.171.83:80
Open 10.65.171.83:110
Open 10.65.171.83:143
Open 10.65.171.83:139
Open 10.65.171.83:445
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-30 07:26 UTC
Initiating Ping Scan at 07:26
Scanning 10.65.171.83 [2 ports]
Completed Ping Scan at 07:26, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:26
Completed Parallel DNS resolution of 1 host. at 07:26, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:26
Scanning 10.65.171.83 [6 ports]
Discovered open port 110/tcp on 10.65.171.83
Discovered open port 80/tcp on 10.65.171.83
Discovered open port 143/tcp on 10.65.171.83
Discovered open port 22/tcp on 10.65.171.83
Discovered open port 445/tcp on 10.65.171.83
Discovered open port 139/tcp on 10.65.171.83
Completed Connect Scan at 07:26, 0.20s elapsed (6 total ports)
Nmap scan report for 10.65.171.83
Host is up, received syn-ack (0.20s latency).
Scanned at 2025-11-30 07:26:47 UTC for 0s

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack
80/tcp  open  http         syn-ack
110/tcp open  pop3         syn-ack
139/tcp open  netbios-ssn  syn-ack
143/tcp open  imap         syn-ack
445/tcp open  microsoft-ds syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds