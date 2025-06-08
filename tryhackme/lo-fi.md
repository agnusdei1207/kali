Nmap 7.95 scan initiated Sun Jun 8 08:04:11 2025 as: /usr/lib/nmap/nmap -sC -sV -O -oN scan.txt -p- 10.10.148.214
Nmap scan report for 10.10.148.214
Host is up (0.21s latency).
Not shown: 65533 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 9d:3d:d7:e4:5f:88:2a:1a:7d:d3:be:ae:ed:ab:ce:89 (RSA)
| 256 ca:99:57:b7:88:38:f7:96:70:48:73:fa:c2:e0:c6:28 (ECDSA)
|\_ 256 7b:6f:41:2a:00:18:b6:a4:12:ce:e1:bd:f2:ce:67:45 (ED25519)
80/tcp open http Apache httpd 2.2.22 ((Ubuntu))
|\_http-title: Lo-Fi Music
|\_http-server-header: Apache/2.2.22 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Jun 8 08:30:16 2025 -- 1 IP address (1 host up) scanned in 1565.76 seconds

# ffuf

# -fs Response size 필터입니다. 응답 크기가 정확히 178바이트인 경우 결과에서 제외하겠다는 뜻입니다.

# -H 옵션은 HTTP 헤더 전체를 넣어야 하ㅂ니다

ffuf -u http://10.10.148.214 -H "Host: FUZZ.lofi" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50

# DNS 경로 검색 방식

ffuf -u http://10.10.148.214/FUZZ -w wordlist.txt

| 목적                          | 헤더 필요 여부 | 예시                              |
| ----------------------------- | -------------- | --------------------------------- |
| 🧠 **서브도메인 (Host 기반)** | ✅ 필요        | `-H "Host: FUZZ.lofi"`            |
| 📁 **경로, 파일 fuzzing**     | ❌ 불필요      | `-u http://target/FUZZ`           |
| 🧭 **DNS 직접 질의**          | ❌ 불필요      | `dig`, `dnsrecon`, `dnsenum` 사용 |
