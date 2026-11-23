<div align="center">
  <img src="https://api.iconify.design/simple-icons/kalilinux.svg?color=%23FFFFFF" alt="Kali Linux 아이콘" width="150" />
</div>

# Kali Linux 침투 테스트 학습 기록

실습 환경, 롸잇업, 치트시트를 한곳에 모은 저장소입니다.
모든 실습은 본인 소유 또는 허가받은 환경에서만 수행합니다.

## 문서 지도

| 문서 | 내용 |
|---|---|
| [AGENTS.md](AGENTS.md) | 작업 전 필독. 에이전트/기여자 규칙 (문서 작성, 이미지 업로드, 커밋) |
| [docs/WRITEUP_GUIDE.md](docs/WRITEUP_GUIDE.md) | 롸잇업 작성법 — 구조, 이미지 업로드 절차, 마무리 체크리스트 |
| [docs/IMAGE_UPLOAD.md](docs/IMAGE_UPLOAD.md) | 이미지 업로드·URL 교체·로컬 png 삭제 전체 절차 |
| [docs/write-ups/red/](docs/write-ups/red/README.md) | Red Team 롸잇업 인덱스 |
| [docs/cheatsheets/](docs/cheatsheets/README.md) | 연습장용 치트시트. 도구 사용법과 실습 절차까지 포함 (정찰 → 취약점 분석 → 초기 침투 → 권한 상승 → 측면 이동 → 후속) |
| [oscp-exam-reference/](oscp-exam-reference/README.md) | OSCP 시험 중 막혔을 때 보는 요약 레퍼런스. Hugo 정적 사이트 소스 |
| [Squid/](Squid/README.md) | Squid 프록시 피벗 실습 롸잇업 (루트 예외 폴더) |

## 롸잇업 인덱스

전체 목록과 요약은 [docs/write-ups/red/README.md](docs/write-ups/red/README.md) 에 있습니다.

- 웹: [CVE-2023-46818 ISPConfig RCE](docs/write-ups/red/CVE-2023-46818/README.md), [Cheese CTF](docs/write-ups/red/cheese-ctf/README.md), [Publisher](docs/write-ups/red/publisher/README.md), [SQLMap THM](docs/write-ups/red/sqlmap-thm/README.md), [SSRF](docs/write-ups/red/ssrf/README.md)
- AD/Windows: [Algernon](docs/write-ups/red/Algernon/README.md), [Attacktive Directory](docs/write-ups/red/attacktive-directory/README.md), [Blue](docs/write-ups/red/blue/README.md), [Billing](docs/write-ups/red/billing/README.md), [Monster](docs/write-ups/red/Monster/README.md)
- Linux/권한 상승: [Skynet](docs/write-ups/red/skynet/README.md), [Smol](docs/write-ups/red/smol/README.md), [Startup](docs/write-ups/red/startup/README.md)
- 리버싱/Pwn: [Compiled](docs/write-ups/red/compiled/README.md), [Rev-Basic-0](docs/write-ups/red/rev-basic-0/README.md), [Off-by-One 001](docs/write-ups/red/off-by-one-001/README.md), [W1se Guy](docs/write-ups/red/w1se-guy/README.md)
- 프록시 피벗: [Squid](Squid/README.md)

## 이미지 업로드 규칙 (요약)

스크린샷은 저장소에 커밋하지 않습니다. `agnusdei1207/public` 이슈에 첨부해 발급된 `https://github.com/user-attachments/assets/...` URL만 본문에 씁니다.
업로드 → URL 교체 → 200 응답 확인 → 로컬 png 삭제 전체 절차: [docs/IMAGE_UPLOAD.md](docs/IMAGE_UPLOAD.md)

## 치트시트

두 치트시트는 쓰임이 다르다.

- [docs/cheatsheets/](docs/cheatsheets/README.md): 연습장. 도구 사용법과 실습 절차까지 적어 둔 작업용 치트시트.
- [oscp-exam-reference/](oscp-exam-reference/README.md): OSCP 시험 중 막혔을 때 꺼내 보는 요약 레퍼런스. Hugo로 정적 사이트를 만들고 `https://agnusdei1207.github.io/kali/`에 배포한다.

사이트 소스는 `oscp-exam-reference/`에 독립 트리로 들어가 있고, 배포는 루트의 `.github/workflows/deploy-pages.yml`이 담당한다.

- 인덱스: [docs/cheatsheets/README.md](docs/cheatsheets/README.md)
- 폴더는 단계가 아니라 대상 기준: [active-directory](docs/cheatsheets/active-directory/README.md) · [bruteforce](docs/cheatsheets/bruteforce/README.md) · [common](docs/cheatsheets/common/README.md) · [cracking](docs/cheatsheets/cracking/README.md) · [cve](docs/cheatsheets/cve/README.md) · [forensics](docs/cheatsheets/forensics/README.md) · [linux](docs/cheatsheets/linux/README.md) · [metasploit](docs/cheatsheets/metasploit/README.md) · [methodology](docs/cheatsheets/methodology/README.md) · [mobile](docs/cheatsheets/mobile/README.md) · [pivoting](docs/cheatsheets/pivoting/README.md) · [python](docs/cheatsheets/python/README.md) · [recon](docs/cheatsheets/recon/README.md) · [scripts](docs/cheatsheets/scripts/README.md) · [services](docs/cheatsheets/services/README.md) · [shells](docs/cheatsheets/shells/README.md) · [util](docs/cheatsheets/util/README.md) · [web](docs/cheatsheets/web/README.md) · [windows](docs/cheatsheets/windows/README.md)

## 환경

- `compose.yml` — 실습용 Docker 구성
- `universal.ovpn` — VPN 접속 프로파일 (공개 랩 전용)
