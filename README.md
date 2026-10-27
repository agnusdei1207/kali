<div align="center">
  <img src="https://api.iconify.design/simple-icons/kalilinux.svg?color=%23FFFFFF" alt="Kali Linux 아이콘" width="150" />
</div>

# Kali Linux 침투 테스트 학습 기록

실습 환경, 롸잇업, 치트시트, OSCP 학습 경로를 한곳에 모은 저장소입니다.
모든 실습은 본인 소유 또는 허가받은 환경에서만 수행합니다.

## 문서 지도

| 문서 | 내용 |
|---|---|
| [AGENTS.md](AGENTS.md) | 작업 전 필독. 에이전트/기여자 규칙 (문서 작성, 이미지 업로드, 커밋) |
| [docs/WRITEUP_GUIDE.md](docs/WRITEUP_GUIDE.md) | 롸잇업 작성법 — 구조, 이미지 업로드 절차, 마무리 체크리스트 |
| [docs/write-ups/red/](docs/write-ups/red/README.md) | Red Team 롸잇업 인덱스 (33개) |
| [docs/cheatsheets/](docs/cheatsheets/README.md) | 단계별 치트시트 (정찰 → 취약점 분석 → 초기 침투 → 권한 상승 → 측면 이동 → 후속) |
| [docs/OSCP/](docs/OSCP/README.md) | OSCP 학습 경로와 진척도 |
| [Squid/](Squid/README.md) | Squid 프록시 피벗 실습 롸잇업 (루트 예외 폴더) |

## 롸잇업 인덱스

전체 목록과 요약은 [docs/write-ups/red/README.md](docs/write-ups/red/README.md) 에 있습니다. (총 33개)

- 웹: [CVE-2023-46818 ISPConfig RCE](docs/write-ups/red/CVE-2023-46818/README.md), [Cheese CTF](docs/write-ups/red/cheese-ctf/README.md), [Publisher](docs/write-ups/red/publisher/README.md), [SQLMap THM](docs/write-ups/red/sqlmap-thm/README.md), [SSRF](docs/write-ups/red/ssrf/README.md)
- AD/Windows: [Algernon](docs/write-ups/red/Algernon/README.md), [Attacktive Directory](docs/write-ups/red/attacktive-directory/README.md), [Blue](docs/write-ups/red/blue/README.md), [Billing](docs/write-ups/red/billing/README.md)
- Linux/권한 상승: [Skynet](docs/write-ups/red/skynet/README.md), [Smol](docs/write-ups/red/smol/README.md), [Startup](docs/write-ups/red/startup/README.md)
- 리버싱/Pwn: [Compiled](docs/write-ups/red/compiled/README.md), [Rev-Basic-0](docs/write-ups/red/rev-basic-0/README.md), [Off-by-One 001](docs/write-ups/red/off-by-one-001/README.md), [W1se Guy](docs/write-ups/red/w1se-guy/README.md)
- 프록시 피벗: [Squid](Squid/README.md)

## 이미지 업로드 규칙 (요약)

스크린샷은 저장소에 커밋하지 않습니다. `agnusdei1207/public` 리포지토리에 `[Writeup Figures] <이름>` 이슈를 만들고 이미지를 첨부한 뒤, GitHub이 발급한 `https://github.com/user-attachments/assets/...` URL만 본문에 씁니다. URL 추출 후 이슈는 닫고 로컬 png는 삭제합니다.

```bash
gh issue create -R agnusdei1207/public --title "[Writeup Figures] <이름>" --body "<설명>" --attach image_1.png
gh api repos/agnusdei1207/public/issues/<번호> --jq .body   # user-attachments URL 확인
gh issue close <번호> -R agnusdei1207/public
rm *.png
```

자세한 절차와 금지 사항: [docs/WRITEUP_GUIDE.md §3](docs/WRITEUP_GUIDE.md) · [AGENTS.md](AGENTS.md)

## 치트시트

- [01 정찰](docs/cheatsheets/01-reconnaissance)
- [02 취약점 분석](docs/cheatsheets/02-vulnerability-analysis)
- [03 초기 침투](docs/cheatsheets/03-initial-access)
- [04 권한 상승](docs/cheatsheets/04-privilege-escalation)
- [05 측면 이동](docs/cheatsheets/05-lateral-movement)
- [06 후속 공격](docs/cheatsheets/06-post-exploitation)
- [공통 도구·형식](docs/cheatsheets/common/README.md)

## 환경

- `compose.yml` — 실습용 Docker 구성
- `universal.ovpn` — VPN 접속 프로파일 (공개 랩 전용)
