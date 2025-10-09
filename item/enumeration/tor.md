apt install torsocks

torsocks ffuf -u http://10.10.178.114/FUZZ -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -o ffuf1.txt -t 20

---

tor: 인터넷 트래픽을 익명화하는 프록시 서비스. OSCP 시험에서 우회/익명성 확보용으로 사용. 기본적으로 127.0.0.1:9050 socks 프록시 제공.

torsocks: 일반 명령어(ssh, ffuf, dig 등)를 tor 네트워크로 우회시켜주는 래퍼. 명령어 앞에 torsocks 붙이면 해당 트래픽이 tor로 전달됨. 프록시 옵션 없는 툴에 필수.

실전: tor는 백그라운드 서비스, torsocks는 명령어 앞에 붙여서 사용.

# 1. tor 설치

```bash
sudo apt update
sudo apt install tor
```

- 필수: `tor` 패키지

# 2. tor 서비스 시작/중지/상태 확인

```bash
sudo systemctl start tor      # tor 서비스 시작 (필수: systemctl)
sudo systemctl stop tor       # tor 서비스 중지
sudo systemctl status tor     # tor 서비스 상태 확인
```

# 3. tor 프록시로 트래픽 우회 (socks5: 127.0.0.1:9050)

- 프록시 옵션: 대부분 프로그램에서 socks5 프록시로 사용
- 예시: curl, nmap, ffuf 등

## curl로 tor 프록시 사용

```bash
curl --socks5 127.0.0.1:9050 http://check.torproject.org/
```

- 필수: `--socks5 [IP:PORT]`
- 선택: URL

## nmap으로 tor 프록시 사용

```bash
nmap --proxy socks4://127.0.0.1:9050 -Pn -p 80 example.com
```

- 필수: `--proxy socks4://127.0.0.1:9050`
- 선택: `-Pn`, `-p [포트]`, `[타겟]`

# 4. torsocks로 명령어 프록시화

- torsocks: 명령어 앞에 붙여서 tor 네트워크로 트래픽 우회
- 설치: `sudo apt install torsocks`

## ffuf 예시

```bash
torsocks ffuf -u http://10.10.178.114/FUZZ -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -o ffuf1.txt -t 20
```

- 필수: `torsocks [명령어]`
- ffuf 옵션: `-u [URL]`, `-w [워드리스트 경로]`, `-o [출력파일]`, `-t [스레드수]`

## ssh 예시

```bash
torsocks ssh user@target
```

- 필수: `torsocks ssh [user@host]`

# 5. tor 연결 확인

```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org/
```

- tor 네트워크로 접속 시 "Congratulations" 메시지 확인

# 6. torrc 설정파일 경로 및 주요 옵션

- 경로: `/etc/tor/torrc`
- 주요 옵션:
  - SocksPort 9050 (기본값)
  - Log notice file /var/log/tor/notices.log (로그 경로)

# 7. tor 네트워크로 DNS 질의 우회

```bash
torsocks dig example.com
```

- 필수: `torsocks dig [도메인]`

---

실전 팁:

- tor 네트워크 느릴 수 있음, 스캔/브루트포스 시 스레드 수 조절
- 프록시 설정 안 되는 툴은 torsocks로 우회
- tor 서비스 항상 켜져 있는지 확인 (`systemctl status tor`)
- tor 네트워크로 우회 시 IP 변경됨, 익명성 확보 가능
