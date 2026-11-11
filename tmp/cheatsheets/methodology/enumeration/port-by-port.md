# 포트별 열거

포트별 기본 스캔과 확인 절차를 정리했습니다.

## 스캔 흐름

1. 네트워크 범위 확인
   - IP 목록 준비
   - 대상 alive 확인 (ping, ARP)

2. 빠른 포트 스캔
   - Top 1000 포트 확인
   - 서비스 식별

3. 세부 스캔
   - 알고 있는 포트 상세 확인
   - 서비스 버전 확인

```bash
# alive 확인
nmap -sn 10.10.11.0/24 -oG alive.txt

# 빠른 포트 스캔
nmap -sS --top-ports 1000 -T4 -Pn -oG quick.txt 10.10.11.68
```
