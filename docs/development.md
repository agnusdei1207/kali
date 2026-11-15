# 치트시트 사이트 개발 가이드

이 저장소는 Hugo 기반 정적 사이트이며, 빌드·배포를 GitHub Actions(`deploy-pages`)가 담당한다.
`main` 브랜치에 커밋·푸시하면 자동으로 빌드된 뒤 `https://agnusdei1207.github.io/cheatsheet/`에 배포된다.

## 로컬 빌드를 하지 않는 이유

- 빌드와 배포는 GitHub Actions가 담당한다. 로컬에서 Hugo를 설치·실행하면
  `hugo.toml` 설정과 빌드 환경(버전·확장 기능) 차이로 화면이 달라질 수 있다.
- Windows에서는 Smart App Control / Device Guard가 winget으로 설치한 Hugo 실행
  파일을 차단하고, 서명되지 않은 실행 파일도 실행이 막힌다. Hugo를 다시 설치하거나
  고치려 하지 말고, Actions가 빌드를 하도록 둔다.

## 화면을 확인해야 할 때

1. `main`에 커밋·푸시한다.
2. `gh run watch -R agnusdei1207/cheatsheet`로 빌드가 성공하는지 확인한다.
3. 라이브 URL에서 빌드된 HTML을 내려받아 변경한 마크업을 grep으로 확인한다.

```bash
gh run watch -R agnusdei1207/cheatsheet
curl -s -A "Mozilla/5.0" https://agnusdei1207.github.io/cheatsheet/ | grep -o '<새 마크업>'
```

## Hugo 바이너리가 필요할 때

GitHub 릴리즈에서 릴리즈 아티팩트만 내려받아 스크래치 폴더에만 둔다.
커밋·푸시하지 않는다.

```bash
wget https://github.com/gohugoio/hugo/releases/download/v0.170.0/hugo_extended_0.170.0_windows-amd64.zip
# ... 스크래치 폴더에 압축 해제 ...
```

## 검증

- `git status --short`이 비어 있는지 확인한다.
- 새 커밋의 Actions 런이 성공인지 확인한다.
- 라이브 URL에 변경 마크업이 있는가(200 응답만이 아니라 실제 마크업 확인).
