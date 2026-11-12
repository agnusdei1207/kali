# Shells 인덱스

리버스 셸·바인드 셸·웹셸·셸 업그레이드 문서 폴더.

## reverse-shell/ — 리버스 셸

- `listener_setup.md` 리스너(nc·rlwrap) 설정 — 가장 먼저 떠야 한다
- `linux_bash_reverse_shell.md` bash /dev/tcp 원라이너 (1순위)
- `linux_python_reverse_shell.md` python 원라이너 (pty 버전 권장)
- `linux_perl_reverse_shell.md` perl 원라이너 (구형 시스템)
- `linux_netcat_reverse_shell.md` nc 기반
- `linux_php_reverse_shell.md` php
- `linux_ruby_java_awk_reverse_shell.md` ruby·java·awk 변형
- `windows_powershell_reverse_shell.md` Windows PowerShell
- `icmp_reverse_shell.md` ICMP 기반
- `reverse_shell_delivery.md` 원라이너 전달 방법
- `reverse_shell_generator_revshells.md` revshells.com 생성기 활용
- `shell_basic_commands.md` 셸 기본 명령
- `scripts/send_powershell_reverse_shell_via_webshell.py` 웹셸 경유 PowerShell 리버스 셸 전송 스크립트

## shell-upgrade/ — 셸 업그레이드

- `python_pty.md` python pty로 TTY 붙이는 전체 절차

## web-shell/ — 웹셸

- `php_webshell.md` PHP 웹셸
- `php_filter_chain_webshell.md` PHP filter chain 기반
- `weevely.md` weevely 생성·접속
- `ftp_web_shell.md` FTP로 웹셸 올리기

## 루트 파일

- `bind-shell.md` 바인드 셸

## 흐름 정리

```text
1. 리스너 먼저: listener_setup.md
2. 타깃 언어·환경 확인: which bash python perl
3. 원라이너 실행: 언어별 문서
4. 안정화: shell-upgrade/python_pty.md
5. 웹셸이 필요하면: web-shell/
```

- 지속성(재부팅 후 유지)은 예약 작업·서비스가 담당한다: windows/cmd/schtasks.md, methodology/post-exploitation/
