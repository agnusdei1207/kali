cat scan.txt 
# Nmap 7.95 scan initiated Thu May 29 13:53:52 2025 as: /usr/lib/nmap/nmap -sV -sC -Pn -oN scan.txt -O --open 10.10.11.68
Nmap scan report for 10.10.11.68
Host is up (0.57s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 29 13:54:38 2025 -- 1 IP address (1 host up) scanned in 45.85 seconds
내부 도메인으로 변경

┌──(root㉿codespaces-38cdce)-[/]
└─# echo "10.10.11.68 planning.htb" >> /etc/hosts

┌──(root㉿codespaces-38cdce)-[/]
└─# curl http://planning.htb
탐색

# 1. detail.php 파라미터 테스트
curl -i "http://planning.htb/detail.php?id=1"

# 2. SQL 인젝션 의심 파라미터에 따옴표 넣기
curl -i "http://planning.htb/detail.php?id=1'"

# 3. XSS 테스트
curl -i "http://planning.htb/detail.php?id=<script>alert(1)</script>"

# 4. 다른 페이지 폼 확인 (contact.php 등)
curl -i "http://planning.htb/contact.php"

# 5. robots.txt 존재 여부 확인
curl -i "http://planning.htb/robots.txt"

# 6. 기본 디렉터리 리스팅 여부 확인
curl -i "http://planning.htb/uploads/"
# 1. 취약점 검색에 가장 많이 쓰이는 CLI 도구: 'searchsploit'
# Exploit-DB에 등록된 익스플로잇 및 취약점 정보를 검색 가능

# 설치 (Debian/Ubuntu 기준)
sudo apt update
sudo apt install exploitdb

# 설치 확인
searchsploit -v

# 사용법 예시: nginx 1.24.0 관련 취약점 검색
searchsploit nginx 1.24.0


# 1. GoBuster 설치 (Debian/Ubuntu)
sudo apt update
sudo apt install gobuster

# 워드리스트 설치
sudo apt update
sudo apt install wordlists

보통 설치하면 위치는
/usr/share/wordlists 에 설치됨

# 2. 디렉토리 브루트포싱 기본 명령어 예시
gobuster dir -u http://planning.htb/ -w /usr/share/wordlists/seclists -t 10 -o gobuster_result.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://planning.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

Error: error on running gobuster: failed to get number of lines: read /usr/share/wordlists/seclists: is a directory


# 설명:
# - dir      : 디렉토리 탐색 모드
# - -u       : 타겟 URL
# - -w       : 워드리스트 경로 (기본 디렉토리/파일 리스트)
# - -t       : 쓰레드 수 (속도 조절)
# - -o       : 결과 출력 파일 지정

# sqlMap OSCP 사용 전면 금지

# 1. 기본 SQL 인젝션 검사
# URL의 id 파라미터가 SQL 인젝션 취약한지 자동 검사
sqlmap -u "http://planning.htb/detail.php?id=1" --batch

# 2. 데이터베이스 목록 추출
# 취약점 발견 시 서버 내 모든 DB 이름 추출
sqlmap -u "http://planning.htb/detail.php?id=1" --dbs --batch

# 3. 특정 DB의 테이블 목록 추출
# 지정한 DB의 모든 테이블 이름 추출
sqlmap -u "http://planning.htb/detail.php?id=1" -D database_name --tables --batch

# 고부스터용 파일 합치기 서브도메인 DNS
cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/wordlists/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt \
    > /tmp/combined_subdomains.txt


# SQL 인젝션 사용 금지로 인해 자체 스크립트 사용
/vpn/scan/SQLi.sh -u "http://planning.htb/detail.php?id=1" --payloads /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/wordlists/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt



gobuster dns -d planning.htb -w /tmp/combined_subdomains.txt -t 50 -o subdomain_result.txt

##### 서브도메인 검색 결과


# 그라파나 서브도메인 발견
echo "10.10.11.68 grafana.planning.htb" >> /etc/hosts
curl -L http://grafana.planning.htb


# Exploit-DB 설치
apt update && apt install exploitdb
# update exploitdb 데이터베이스
searchsploit -u
mkdir -p ~/tools
cd ~/tools
git clone https://gitlab.com/exploit-database/exploitdb.git
cd exploitdb

# 위치 찾기
find / -type d -name exploitdb 2>/dev/null
/usr/share/doc/exploitdb
/usr/share/exploitdb
/exploitdb

# Exploit-DB에서 Grafana 관련 취약점 검색
grep -ri grafana exploits/


# 공식 CVE 자료도 연계하기
# grafana 검색 -> 11.0 검색
https://cve.mitre.org