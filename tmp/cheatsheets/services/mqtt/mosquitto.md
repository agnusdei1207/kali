# mosquitto_sub / mosquitto_pub MQTT 점검

- mosquitto_sub, mosquitto_pub — MQTT 브로커의 토픽을 구독·발행하는 클라이언트. 열린 1883 포트에서 익명 구독 가능 여부와 토픽 구조를 확인하는 데 쓴다.
- 1883/8883 포트 발견 직후 MQTT 브로커인지 확인할 때, allow_anonymous 누락으로 익명 접속이 되는지 점검할 때, $SYS 통계와 토픽 트래픽을 관찰할 때.
- apt install mosquitto-clients (mosquitto_sub, mosquitto_pub 바이너리 제공). 브로커 서버는 별도 패키지 mosquitto.

## 구독 — 익명 점검의 핵심

```bash
# 와일드카드 구독 - 익명으로 성공하면 finding
mosquitto_sub -h 10.10.10.10 -t '#' -v

# $SYS 통계 - 브로커 상태 공개 여부 확인
mosquitto_sub -h 10.10.10.10 -t '$SYS/#' -v -C 20
```

- `-t '#'`: 모든 토픽 구독. `-v`로 토픽명까지 함께 출력한다.
- `-C 20`: 20개 메시지를 받으면 종료한다. 관찰용으로 종료 조건을 걸어두는 습관이 좋다.
- 익명 구독이 성공하면 토픽 트래픽에서 기기 상태·측정값·경우에 따라 인증 정보가 그대로 보인다.

## 발행

```bash
mosquitto_pub -h 10.10.10.10 -t 'cmd/demo' -m 'hello'

# retained 메시지 확인
mosquitto_pub -h 10.10.10.10 -t 'cmd/demo' -m 'test' -r
```

- `-r`: retained 플래그. 브로커가 마지막 메시지를 저장해 나중에 구독한 클라이언트에게도 전달한다.
- 점검에서는 retained로 남아 있는 민감 메시지를 볼 수 있다. 구독해 두면 자기가 발행한 메시지가 되돌아와 발행 성공 여부도 판정된다.

## 인증·TLS

```bash
# 익명 (기본 포트)
mosquitto_sub -h 10.10.10.10 -p 1883 -t '#' -v

# TLS 포트
mosquitto_sub -h 10.10.10.10 -p 8883 -t '#' -v --cafile ca.crt

# 사용자명·비밀번호
mosquitto_sub -h 10.10.10.10 -t '#' -v -u user -P pass
```

- 인증서 검증 실패로 진단이 막히면 --insecure로 우회할 수 있다(진단 목적 한정).
- 익명 실패(NOAUTH·bad user name)가 나오면 -u/-P로 수집한 자격증명을 반복 적용한다.

## MQTT 열거 관점

```bash
# nmap으로 토픽 열거
nmap -p 1883 --script mqtt-subscribe-topics 10.10.10.10
```

- '#'는 전체 토픽, '+'는 단일 레벨 와일드카드다. 예: sensor/+/temp.
- 토픽 구조에서 기기 식별자와 명령 채널을 파악하면 mosquitto_pub로 명령 주입 가능성을 확인해 볼 수 있다.
- $SYS/#는 브로커 자체 통계다. 공개되어 있으면 버전·연결 수·토픽 수 등 열거 정보가 된다.

## 실전 점검 흐름

```text
1. nmap 1883 open 확인 (MQTT 판정)
2. mosquitto_sub -t '#' -v 익명 구독 시도
3. 성공: 트래픽 관찰 + $SYS/# 로 브로커 정보 수집
4. 실패: 수집 자격증명으로 -u/-P 재시도, 8883 TLS 점검
5. 명령 채널 파악 시 mosquitto_pub로 수용 여부 확인
```

## 팁·트러블슈팅

- 구독 출력이 없어도 접속은 성공한 것이다. 토픽이 조용할 뿐이다. -v와 retained 확인으로 구분한다.
- 최신 클라이언트가 MQTT v5 협상을 시도해 구형 브로커가 거절하면 -V mqttv311로 프로토콜 버전을 고정한다.
- mosquitto 패키지는 브로커(서버)다. 클라이언트만 필요하면 mosquitto-clients를 설치한다.
- 토픽에 공백·특수문자가 있으면 작은따옴표로 감싼다. $SYS의 $는 쉘 확장을 피하려 따옴표 필수다.
