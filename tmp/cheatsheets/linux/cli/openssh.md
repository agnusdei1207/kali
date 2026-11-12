# OpenSSH 접속·터널링

- OpenSSH — ssh 클라이언트(openssh-client)와 서버(openssh-server). 키 기반 인증, 포트 포워딩(-L/-R/-D), scp/sftp 파일 전송을 제공하는 표준 원격 접속 도구다.
- 공격자 머신에서 타깃에 접속하거나, 타깃에 SSH 서비스를 띄워 새 접근로를 만들 때, -L/-R/-D 터널로 내부망 서비스를 우회할 때.
- apt로 openssh-client(클라이언트)와 openssh-server(sshd)를 설치하고, 서버는 sshd가 떠 있는지와 포트 개방 상태를 확인해야 접속된다.

## 설치와 서버 준비

```bash
sudo apt install openssh-client
sudo apt install openssh-server
sudo systemctl enable --now ssh
sudo ss -tlnp | grep :22
```

## 접속 기본

```bash
ssh user@10.10.10.10
ssh -p 2222 user@10.10.10.10
ssh -i ~/.ssh/id_rsa user@10.10.10.10
sshpass -p 'Passw0rd' ssh user@10.10.10.10
```

- `-p`: 포트 지정. `-i`: 개인 키 지정. 키 파일 권한이 600이 아니면 ssh가 키 사용을 거부한다.
- sshpass는 패스워드를 인자로 넘겨 자동화한다. 없으면 `sudo apt install sshpass`로 설치한다.

## 키 생성과 배포

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@10.10.10.10
```

- 패스프레이즈 없는 키는 자동화·피벗에 편하지만 유출 시 즉시 탈취된다는 점을 감안한다.
- 타깃의 authorized_keys에 공개키가 등록되면 패스워드 없이 접속된다.

## 터널링

```bash
# -L: 로컬 포트를 원격 쪽 서비스로 포워딩 (내부 DB 접근)
ssh -N -L 5432:192.168.1.20:5432 user@10.10.10.10

# -R: 원격(타깃) 포트를 내 쪽 리스너와 연결 (리버스 터널)
ssh -N -R 4444:127.0.0.1:4444 user@10.10.10.10

# -D: SOCKS5 동적 프록시 생성 (proxychains와 조합)
ssh -N -D 9050 user@10.10.10.10
```

- `-N`: 명령 실행 없이 터널만 유지한다. `-f`: 백그라운드로 전환한다.
- -D 터널은 `proxychains nmap -sT 192.168.1.0/24`처럼 proxychains와 함께 쓴다.

## 실전 예시

```bash
# 키 생성 -> 배포 -> SOCKS 터널 백그라운드 유지
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''
ssh-copy-id user@10.10.10.10
ssh -f -N -D 9050 user@10.10.10.10
proxychains curl http://192.168.1.20:8080
```

## 클라이언트 감사 포인트

```bash
cat ~/.ssh/known_hosts            # 접속 이력이 있는 호스트 목록
ls -l ~/.ssh/id_*                 # 유출 가능한 개인 키 목록
cat ~/.ssh/config                 # 별칭·자동 인증 설정
```

- 침해된 호스트를 조사할 때 known_hosts·config·개인 키는 다른 시스템으로의 횡이동 단서가 된다.

## 팁·트러블슈팅

1. sshd가 떠 있는데 접속이 안 되면 `sudo ufw status`와 `sudo ss -tlnp | grep :22`로 방화벽·리슨 상태부터 확인한다.
2. REMOTE HOST IDENTIFICATION HAS CHANGED 경고는 호스트 키가 바뀐 경우로, `ssh-keygen -R 10.10.10.10`으로 known_hosts 항목을 지운 뒤 재접속한다.
3. -R 터널이 외부에서 접근되지 않으면 sshd_config의 GatewayPorts 설정이 no일 가능성이 높다.
