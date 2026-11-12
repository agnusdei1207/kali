# Linux 인덱스

Linux CLI 명령과 권한 상승 문서 폴더.

## cli/ — 명령줄 도구

- `bash/` bash 셸 — overview·syntax·if·loop·brute_force
- 파일·텍스트: find, grep, echo, tr, xxd, hexdump, jq
- 압축: gzip, tar, zip_unzip, unrar
- 접속·기타: openssh, scp, which, vim, bat

## privesc/ — 권한 상승

- 절차: privilege_escalation_overview, information_gathering, linpeas/ (tip.md)
- sudo·권한: sudo_privesc, sudo_usage, su, chpasswd, chmod
- SUID·SGID: suid, sgid, gtfobins/ (gtfobinaries, xxd_gtfobin)
- 예약·서비스: crontab, process-monitoring/ (ps, process)
- 환경·기타: environment/ (shell_profile, tty), credentials/ (etc_passwd, shadow)
- 특정 벡터: pkexec, postgres_privesc, look, apparmor, analytics_binary_tip

## 관련 문서

- 전체 권한 상승 절차: methodology/privilege-escalation/ (linux.md)
- 자격증명 크래킹: cracking/ (hashcat, john)
- GTFOBins 원본 사본: util/ (최종 ZIP 내 workspace\util\GTFOBins)
