# 이미지(스크린샷) 업로드 및 후처리

롸잇업 작성 중뿐 아니라 작업 전반에서 png가 로컬로 쌓입니다. 대상은 이 저장소의 모든 png입니다. 롸잇업·치트시트·실습 폴더·`tmp/` 어디에 있든 예외는 없고, 본문에서 참조하지 않는 png도 남김 없이 처리합니다. 이 문서는 그 png를 kali 리포지토리에 커밋하지 않고, `agnusdei1207/public` 이슈 첨부로 발급받은 `user-attachments` URL로 처리하는 절차의 단일 출처입니다. 다른 문서는 이 절차를 복사하지 않고 여기를 링크합니다.

> 관련 문서: [AGENTS.md](../AGENTS.md) · [롸잇업 작성법](WRITEUP_GUIDE.md)

## 1. 규칙

| 금지 | 허용 |
|---|---|
| png 등을 kali 리포지토리에 커밋 | `agnusdei1207/public` 이슈에 첨부 |
| `raw.githubusercontent.com/.../<폴더>/image.png` URL | `https://github.com/user-attachments/assets/...` URL |
| 로컬 상대경로 `![](image_1.png)` | 이슈 첨부 URL + alt 텍스트 유지 |
| 폴더째 업로드 | 이슈 단위 첨부 (이슈는 작업 후 close) |

- 첨부 URL은 이슈를 닫아도 유지됩니다.
- png는 작업 중간중간 계속 생깁니다. 작업 도중에 로컬 png가 생기면 그때그때 같은 절차로 업로드하고 본문 참조를 URL로 교체합니다. 작업 끝에 몰아서 처리하다 남기는 일이 없도록 합니다.
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
#    - 한글이 포함된 문서는 반드시 UTF-8로 읽고 쓴다. PowerShell의
#      Get-Content/Set-Content는 기본 인코딩이 시스템 코드페이지(CP949)라
#      한글이 깨진다. 아래 방식을 쓴다.
#
#      $text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
#      # ... 치환 ...
#      [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
#
#    - 파일에 BOM이 있었으면 UTF8Encoding($true)로 유지한다.
#    - 검증: git diff에서 바뀐 줄이 이미지 참조 줄뿐인지 확인한다.
#      다른 줄이 하나라도 바뀌면 인코딩이 깨진 것이므로 되돌리고 다시 한다.
#      git diff --numstat 가 교체한 이미지 줄 수와 일치해야 한다.
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

```bash
# 잔여 png 스캔 — 추적 중이든 미추적이든 출력이 0줄이어야 한다
git ls-files --cached --others --exclude-standard '*.png'
```

- [ ] 본문의 이미지 참조가 전부 `user-attachments` URL인가 (로컬 경로·raw URL 0건)
- [ ] 한글 등 비ASCII 본문이 깨지지 않았는가 (git diff에서 바뀐 줄이 이미지 참조뿐인지 확인)
- [ ] 깨진 참조(`![\1]`)가 0건인가
- [ ] 첨부 URL이 GET으로 200 응답하는가
- [ ] 로컬 png가 삭제되고 그 삭제가 커밋에 포함됐는가
- [ ] 대상 폴더에 png가 0개 남았는가 (본문에서 참조하지 않는 png 포함)
- [ ] 잔여 png 스캔이 0줄인가 (작업 중간에 새로 생긴 png도 포함)
- [ ] 처리한 이슈를 close했는가
