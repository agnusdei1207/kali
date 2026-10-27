# 이미지(스크린샷) 업로드 및 후처리

롸잇업을 작성하다 보면 스크린샷이 로컬 png로 쌓입니다. 이 문서는 그 png를 kali 리포지토리에 커밋하지 않고, `agnusdei1207/public` 이슈 첨부로 발급받은 `user-attachments` URL로 처리하는 절차의 단일 출처입니다. 다른 문서는 이 절차를 복사하지 않고 여기를 링크합니다.

> 관련 문서: [AGENTS.md](../AGENTS.md) · [롸잇업 작성법](WRITEUP_GUIDE.md)

## 1. 규칙

| 금지 | 허용 |
|---|---|
| png 등을 kali 리포지토리에 커밋 | `agnusdei1207/public` 이슈에 첨부 |
| `raw.githubusercontent.com/.../<폴더>/image.png` URL | `https://github.com/user-attachments/assets/...` URL |
| 로컬 상대경로 `![](image_1.png)` | 이슈 첨부 URL + alt 텍스트 유지 |
| 폴더째 업로드 | 이슈 단위 첨부 (이슈는 작업 후 close) |

- 첨부 URL은 이슈를 닫아도 유지됩니다.
- alt 텍스트는 `--attach 'image_19.png#8080 found'` 형식으로 지정합니다.
- `--attach`는 이슈 본문에 `![파일명](https://github.com/user-attachments/assets/…)` 를 자동으로 추가합니다.

## 2. 절차

```bash
# 1) public 리포지토리에 이슈 생성 + 이미지 첨부 (한 명령에 50개까지)
gh issue create -R agnusdei1207/public \
  --title "[Writeup Figures] Squid" --body "Squid 롸잇업 스크린샷" \
  --attach image.png --attach image_1.png --attach image_2.png

# 2) 이슈 본문에서 user-attachments URL 추출
gh api repos/agnusdei1207/public/issues/<번호> --jq .body

# 3) 본문의 로컬 png 참조를 URL로 교체 (alt 텍스트 유지)
# 4) 이슈 close
gh issue close <번호> -R agnusdei1207/public

# 5) 첨부 URL이 실제로 열리는지(200) 확인한다 — 확인 전에는 png를 지우지 않는다
curl -s -o /dev/null -w "%{http_code}" -A "Mozilla/5.0" -L <URL>   # → 200 이어야 함 (HEAD는 403이 나올 수 있으므로 GET으로)

# 6) 200 확인 후 본문 교체까지 끝났으면 로컬 png는 불필요하므로 반드시 삭제한다
#    - git이 추적 중이면 git rm 으로 삭제해 커밋에 반영
git rm --cached --ignore-unmatch *.png 2>/dev/null; rm -f *.png   # 추적 중이든 아니든 로컬에서 제거
# 7) 커밋/푸시 (삭제가 커밋에 포함되는지 git status로 확인)
```

본문 참조 형태:

```markdown
![8080 found](https://github.com/user-attachments/assets/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
```

## 3. 검증

- [ ] 본문의 이미지 참조가 전부 `user-attachments` URL인가 (로컬 경로·raw URL 0건)
- [ ] 깨진 참조(`![\1]`)가 0건인가
- [ ] 첨부 URL이 GET으로 200 응답하는가
- [ ] 로컬 png가 삭제되고 그 삭제가 커밋에 포함됐는가
- [ ] 처리한 이슈를 close했는가
