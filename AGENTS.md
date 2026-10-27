# AGENTS.md

이 저장소에서 문서를 작성·수정하는 에이전트와 기여자가 가장 먼저 읽는 문서입니다.
**작업 전에 [docs/WRITEUP_GUIDE.md](docs/WRITEUP_GUIDE.md)를 반드시 읽습니다.**

## 1. 최우선 규칙: 이미지(스크린샷)

| 금지 | 허용 |
|---|---|
| png 등을 이 저장소에 커밋 | `agnusdei1207/public` 이슈에 첨부 |
| `raw.githubusercontent.com/.../<폴더>/image.png` URL | `https://github.com/user-attachments/assets/...` URL |
| 로컬 상대경로 `![](image_1.png)` | 이슈 첨부 URL + alt 텍스트 유지 |
| 폴더째 업로드 | 이슈 단위 첨부 (이슈는 작업 후 close) |

절차:

```bash
# 1) public 리포지토리에 이슈 생성 + 이미지 첨부 (한 명령에 50개까지)
gh issue create -R agnusdei1207/public \
  --title "[Writeup Figures] Squid" --body "Squid 롸잇업 스크린샷" \
  --attach image.png --attach image_1.png --attach image_2.png

# 2) 본문에서 user-attachments URL 추출
gh api repos/agnusdei1207/public/issues/<번호> --jq .body

# 3) README 참조를 URL로 교체 (alt 텍스트 유지)
# 4) 이슈 close
gh issue close <번호> -R agnusdei1207/public

# 5) 첨부 URL이 실제로 열리는지(200) 확인한다 — 확인 전에는 png를 지우지 않는다
curl -s -o /dev/null -w "%{http_code}" -A "Mozilla/5.0" -L <URL>   # → 200 이어야 함 (HEAD는 403이 나올 수 있으므로 GET으로)

# 6) 200 확인 후 README 교체까지 끝났으면 로컬 png는 불필요하므로 반드시 삭제한다
#    - git이 추적 중이면 git rm 으로 삭제해 커밋에 반영
git rm --cached --ignore-unmatch *.png 2>/dev/null; rm -f *.png   # 추적 중이든 아니든 로컬에서 제거
# 7) 커밋/푸시 (삭제가 커밋에 포함되는지 git status로 확인)
```

- 첨부 URL은 이슈를 닫아도 유지됩니다.
- alt 텍스트는 `--attach 'image_19.png#8080 found'` 형식으로 지정합니다.

## 2. 문서 일괄 치환 금지

`sed`/`sed_replace` 등의 역참조(`\1`, `\2`)로 마크다운을 일괄 치환하지 않습니다. 과거에 이 방식으로 이미지 참조가 `![\1](.../\2)`로 깨져 문서와 이미지가 전부 404가 된 사고가 있습니다.

- 일괄 치환은 스크립트로 수행하고, **치환 건수·잔여 패턴·URL 응답을 검증**한 뒤 커밋합니다.
- 최소 검증: `grep '!\[\\1\]'`, 깨진 참조 0건, 참조 URL 샘플 200 응답.

## 3. 문서 지도

| 경로 | 역할 |
|---|---|
| `README.md` | 저장소 진입점, 전체 문서 인덱스 |
| `AGENTS.md` | 이 문서. 작업 규칙 |
| `docs/WRITEUP_GUIDE.md` | 롸잇업 작성법 (구조·이미지·체크리스트) |
| `docs/write-ups/red/README.md` | 롸잇업 목록 인덱스 (33개) |
| `docs/cheatsheets/README.md` | 치트시트 인덱스 |
| `docs/OSCP/README.md` | OSCP 학습 경로 |
| `Squid/README.md` | 루트 예외 실습 폴더 (프록시 피벗) |

## 4. 작성 위치

- 롸잇업: `docs/write-ups/red/<ctf-name>/README.md`
  - 분량이 크면 `<ctf-name>/1.md`, `2.md` … 로 쪼개고 `README.md`를 인덱스로 사용
- 스크립트·캡처: `<ctf-name>/tmp/` (본문에서 상대경로 링크)
- 루트 실습 폴더(`Squid/` 등)도 동일한 규칙 적용

## 5. 새 문서 추가 시

1. 해당 인덱스에 링크를 추가합니다.
   - 롸잇업 → `docs/write-ups/red/README.md` 표
   - 치트시트 → `docs/cheatsheets/README.md`
2. 루트 `README.md`의 문서 지도/요약과 중복·불일치가 없는지 확인합니다.
3. 커밋 메시지는 `docs(<범위>): <변경 요약>` 형식을 사용합니다.

## 6. 마무리 체크

- [ ] `docs/WRITEUP_GUIDE.md`의 체크리스트를 통과했는가
- [ ] 이미지가 전부 `user-attachments` URL인가 (로컬 png·raw URL 0건)
- [ ] 인덱스에 새 문서가 링크되어 있는가
- [ ] 민감 정보(패스워드·토큰·플래그)가 `REDACTED` 처리되었는가
