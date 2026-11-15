# agnusdei207 — OSCP Notes

OSCP 준비를 위한 치트시트, 방법론, 도구 모음. heretek.dev 의 콘텐츠 구성을 참고해 한국어로 정리했고, UI 는 사이드바·본문·목차로 이어지는 문서형 레이아웃으로 새로 만들었다.

- 라이브: <https://agnusdei1207.github.io/cheetsheet/>
- 저장소: <https://github.com/agnusdei1207/cheetsheet>

> GitHub Pages 주소는 저장소 소유자 계정(`agnusdei1207`)을 따릅니다. `agnusdei207` 은 사이트 브랜드명입니다.

## 구조

| 경로 | 내용 |
|---|---|
| `content/oscp-cheatsheet/` | OSCP 치트시트 (20개 주제) |
| `content/methodology/` | AD 공격 방법론, 열거 워크플로 |
| `content/tools/` | BloodHound, Impacket 가이드 |
| `layouts/` | 사이트 전용 Hugo 레이아웃 |
| `assets/css/main.css` | 디자인 토큰, 레이아웃, 타이포그래피 |
| `assets/js/site.js` | 테마 전환, 모바일 사이드바, 코드 복사, TOC |
| `assets/js/search.js` | 클라이언트 사이드 검색 |

## 빌드

```bash
hugo --gc --minify --cleanDestinationDir
```

출력은 `public/` 에 생성된다. 로컬 미리보기는 `hugo server` 를 사용한다.

## 배포

`main` 브랜치에 푸시하면 GitHub Actions(`deploy-pages`)가 Hugo 로 빌드한 뒤 GitHub Pages 에 배포한다.
