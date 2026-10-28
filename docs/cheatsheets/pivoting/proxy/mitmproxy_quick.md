# mitmproxy quick (HTTP 가로채기)

## 개요

`mitmproxy`는 HTTP 요청/응답을 가로채 실습하는 GUI 도구다. Windows/Linux 리버스 쉘 테스트에서 웹 요청 확인에 유용하다. (피벗팅 전용이 아니다 — HTTP 분석용)

## 설치 및 실행

```bash
apt install mitmproxy -y

# 일반 모드로 실행 (8080 포트)
mitmproxy --mode regular -p 8080

# HTTP/2 문제 방지
mitmproxy --mode regular -p 8080 --no-http2
```

## 사용

```bash
# curl을 프록시 뒤로
curl -x 127.0.0.1:8080 http://10.10.10.10/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=admin&password=1234"
```

## 확인할 것

- 요청/응답 헤더에 실제로 전달된 값이 반영되어 있는지.
- 인코딩(응답이 `%XX`로 인코딩된 채 도착)되어 있는지.
- 이 값을 통해 SQLi/XSS 시도의 파라미터를 다시 만들 수 있다.

## 주의

- 이 도구는 웹 요청 분석용이다. 피벗팅(터널링)에는 `ligolo-ng`/`chisel`을 사용한다.
- mitmproxy 실행은 평소 연습 목적으로만.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
