# reverse shell

리버스 셸은 타깃에 무엇이 있는가가 곧 페이로드 선택이다.

> 관련 문서: [bind shell](../bind-shell.md) · [셸 안정화](../shell-upgrade/python_pty.md) · [웹셸](../web-shell/php_webshell.md)

## 진행 순서

```text
[공격자] 리스너 먼저       rlwrap nc -lvnp 4444   → listener_setup.md
[타깃]   도구 확인         which bash python3 nc ncat php perl ruby
[타깃]   상황 트리에서 파일 골라 페이로드 실행
[공격자] 셸 수신 → Linux면 TTY 안정화 → shell_basic_commands.md
```

## 상황 → 파일

```text
Linux
├─ bash 있음               → linux_bash_reverse_shell.md       가장 먼저 시도
├─ python3 있음            → linux_python_reverse_shell.md     pty 버전이면 안정화 생략
├─ nc 있음                 → linux_netcat_reverse_shell.md     -e 지원 여부로 2가지
├─ php 있음 / PHP 웹셸     → linux_php_reverse_shell.md
├─ perl 있음               → linux_perl_reverse_shell.md
└─ 위가 전부 없음          → linux_ruby_java_awk_reverse_shell.md

Windows (PowerShell)
└─ windows_powershell_reverse_shell.md

명령 실행 지점이 웹셸뿐 (요청 1건 = 명령 1건)
└─ reverse_shell_delivery.md   페이로드를 파일로 내려놓고 실행

TCP outbound 전부 막힘 (ICMP만 나감)
└─ icmp_reverse_shell.md
```

## 관례

- 페이로드의 `10.10.10.10` = 공격자 IP(LHOST), `4444` = 리스너 포트(LPORT). 자기 환경 tun0 IP·포트로 통째로 치환한다.
- 4444는 outbound 필터에 걸리기 쉽다. 실패하면 443, 80, 8080 순으로 바꾼다. → [listener_setup.md](./listener_setup.md)
- 페이로드 생성기: https://www.revshells.com/ — 실수 방지 노트는 [reverse_shell_generator_revshells.md](./reverse_shell_generator_revshells.md)
- 공용 문서: [shell_basic_commands.md](./shell_basic_commands.md) (셸 받자마자 기본 명령) · [reverse_shell_delivery.md](./reverse_shell_delivery.md) (웹셸 경유 전달) · [scripts/](./scripts/) (상황용 스크립트)
