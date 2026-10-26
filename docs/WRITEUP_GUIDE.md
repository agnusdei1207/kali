# 롸잇업 작성법

`docs/write-ups/red/` 아래의 모든 롸잇업이 따르는 규칙입니다.
목적은 하나입니다. **나중에 다시 봤을 때 "왜 그렇게 판단했는지"가 남아 있을 것.**

> 관련 문서: [루트 README](../README.md) · [AGENTS.md](../AGENTS.md) · [롸잇업 인덱스](write-ups/red/README.md) · [치트시트 인덱스](cheatsheets/README.md) · [OSCP 학습 경로](OSCP/README.md)

---

## 1. 단위와 위치

실습 단위는 **폴더명**입니다. 폴더명이 곧 CTF 이름이고, 그 안에 기록이 모입니다.

```text
docs/write-ups/red/<ctf-name>/
└── README.md      # 롸잇업 본문 (관찰 → 판단 → 실행 → 결과)
```

- 폴더명은 소문자-하이픈을 기본으로 합니다. (`attacktive-directory`, `hydra-base`)
- 루트에 따로 관리 중인 실습 폴더도 같은 규칙을 따릅니다. (예: `Squid/README.md`)
- 문서가 방대하면 `<ctf-name>/1.md`, `2.md` … 로 쪼개고 `README.md`를 인덱스로 씁니다. (`cve-2026-22200` 참고)
- 스크립트는 `<ctf-name>/tmp/` 에 두고 본문에서 상대경로로 링크합니다.
- 스크린샷(이미지)은 리포지토리에 두지 않습니다. `public` 이슈에 첨부해 받은 URL로만 참조합니다. → §3

---

## 2. 롸잇업 기본 원칙

- **관찰 → 판단 → 실행 → 결과** 순서로 씁니다.
- **장황하게 쓰지 않습니다.** 같은 말 반복, 배경 설명, 정리 안 된 생각은 넣지 않습니다.
- 각 단계는 1~3문장. 설명이 길어지면 그건 별도 문서로 빼야 한다는 신호입니다.
- 한 절에는 한 가지 주장만. 길어지면 덜어내고, 부연은 링크로 뺍니다.
- 명령은 **복붙 가능한 형태**로, 출력은 **판단에 쓴 줄만** 남깁니다.
- 실제로 친 명령과 실제 출력만 씁니다. 예상 결과를 실제 결과처럼 쓰지 않습니다.
- 민감 정보는 `REDACTED` 처리합니다. (패스워드, 개인키, 세션 토큰, 플래그)
- 표는 **비교·판정 기준**에만 씁니다. 그 외는 목록으로 풀어 씁니다.

---

## 3. 이미지(스크린샷) 관리

- 이미지는 **kali 리포지토리에 커밋하지 않습니다.**
- `agnusdei1207/public` 리포지토리에 `[Writeup Figures] <ctf-name>` 이슈를 만들고, 이미지를 이슈에 첨부합니다.
- GitHub이 첨부 시 발급하는 `user-attachments` URL만 본문에 씁니다. raw URL·로컬 경로는 쓰지 않습니다.
- URL을 모두 뽑은 뒤 이슈는 닫습니다. (첨부 URL은 이슈를 닫아도 유지됩니다.)
- 업로드가 끝나면 로컬 png는 삭제합니다.

```bash
# 1) public 리포지토리에 이슈 생성 + 이미지 첨부 (한 명령에 50개까지)
gh issue create -R agnusdei1207/public \
  --title "[Writeup Figures] Squid" --body "Squid 롸잇업 스크린샷" \
  --attach image.png --attach image_1.png --attach image_2.png

# 2) 이슈 본문에서 user-attachments URL 확인
gh api repos/agnusdei1207/public/issues/<번호> --jq .body

# 3) 이슈 닫기
gh issue close <번호> -R agnusdei1207/public

# 4) 로컬 png 삭제
rm *.png
```

```markdown
![8080 found](https://github.com/user-attachments/assets/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
```

- `--attach`는 이슈 본문에 `![파일명](https://github.com/user-attachments/assets/…)` 를 자동으로 추가합니다.
- alt 텍스트는 `--attach 'image_19.png#8080 found'` 형식으로 지정합니다.

---

## 4. 마무리 체크리스트

- [ ] 폴더명이 CTF 이름과 일치하는가
- [ ] `README.md`에 관찰 로그가 먼저 기록되어 있는가
- [ ] 추론과 확정이 구분되어 있는가
- [ ] 가설마다 확인 명령이 붙어 있는가
- [ ] 실패한 시도와 그 이유가 남아 있는가
- [ ] 오래 걸리는 작업에 예상 소요 시간이 적혀 있는가
- [ ] 패스워드·토큰·플래그가 `REDACTED` 처리되었는가
- [ ] 이미지가 public 이슈 첨부(`user-attachments`) URL로 참조되는가 (로컬 png·raw URL 없음)
