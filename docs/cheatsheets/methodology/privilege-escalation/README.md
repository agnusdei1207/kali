# 권한 상승 (Privilege Escalation) 인덱스

셸 확보 후 root·SYSTEM으로 올라가기 위한 점검 문서 폴더. OS별 상세는 각 파일이 담당한다.

## 문서

- `linux.md` Linux 권한 상승 절차 — sudo·SUID·cron·경로·GTFOBins
- `windows.md` Windows 권한 상승 절차 — 특권·서비스·자동실행·자격증명

## 공통 절차

1. 현재 계정·권한 확인 — whoami, id, sudo -l / whoami /priv
2. OS·버전·패치 확인 — 커널·빌드 번호로 공개 익스플로잇 매칭
3. 자동화 열거 — linpeas(linux/privesc/linpeas), winPEAS(windows/privileges/winPEASany.exe.md)
4. 후보 경로 수동 검증 — 자동화 도구는 후보만 주고, 실제 상승은 수동 확인으로 확정한다
5. 상승 실행 — 도구·명령은 OS별 문서와 linux/privesc·windows/privileges 치트시트 참고

## 상세 치트시트 위치

```text
Linux   -> linux/privesc/          (sudo, suid, cron, gtfobins, linpeas ...)
Windows -> windows/privileges/     (SeDebug, SeImpersonate, PrintSpoofer, overview ...)
```
