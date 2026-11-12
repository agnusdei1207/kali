# exiftool로 메타데이터 열거

- exiftool — 이미지·문서·영상·오디오 등 수백 종 포맷의 EXIF/IPTC/XMP 메타데이터를 읽고 쓰는 펄 기반 CLI. 카메라·GPS·작성자·소프트웨어 정보를 한 번에 뽑는다.
- 이미지·문서의 출처 추적(촬영 장소, 기기, 편집 프로그램)을 할 때, 문서 작성자·회사 정보가 남아 있는지 확인할 때, 숨은 주석·댓글·썸네일 데이터를 살펴볼 때.
- Kali는 apt install libimage-exiftool-perl (PATH의 exiftool). Windows는 workspace\util\exiftool\exiftool.exe — 공식 배포본은 exiftool(-k).exe인데 오류 후 창을 유지하는 -k 버전이라 CLI용으로는 exiftool.exe로 이름을 바꿔 쓰는 게 편하다.

## 기본 명령어 구조

```bash
exiftool [옵션] <파일|디렉터리>
```

## 기본 사용

```bash
exiftool photo.jpg
exiftool -a -u -g1 photo.jpg
exiftool report.docx
exiftool image.png
```

- 인자 없이 실행하면 사람이 읽기 좋은 태그 목록을 출력한다.
- `-a`: 중복·숨은 태그까지 표시.
- `-u`: 알려지지 않은(unknown) 태그까지 표시.
- `-g1`: 태그를 IFD/EXIF/XMP 등 그룹별로 묶어 출력.

## 출처 추적에 유용한 태그

```bash
exiftool -GPS:all photo.jpg                     # 촬영 위치
exiftool -Make -Model -LensModel photo.jpg      # 촬영 기기
exiftool -Software -Creator -Author photo.jpg   # 편집 도구·작성자
exiftool -CreateDate -ModifyDate photo.jpg      # 생성·수정 시각
exiftool -Comment -Description photo.jpg        # 사용자 주석(숨은 데이터)
```

## 일괄 처리

```bash
exiftool -a -u -g1 -csv *.jpg > meta.csv
exiftool -r -a -u -g1 /mnt/evidence > all_meta.txt
```

- `-r`: 디렉터리 재귀. CSV로 내보내면 여러 파일을 비교하기 쉽다.

## Windows 사용

```powershell
workspace\util\exiftool\exiftool.exe -a -u -g1 photo.jpg
```

- exiftool(-k).exe를 그대로 쓰면 출력 후 키 입력을 기다려 스크립트에 부적합하다. 이름을 exiftool.exe로 바꿔 쓴다.

## 팁·트러블슈팅

1. GPS 좌표가 안 나오면 카메라가 기록을 안 했거나 SNS 업로드 과정에서 제거된 것이다.
2. 문서(docx, pdf)는 XMP·문서 속성의 Author, Company, Creator가 핵심 출처 단서다.
3. 태그를 지울 때는 -all= 를 쓴다(예: exiftool -all= photo.jpg). 원본 백업 _original이 자동 생성된다.
4. PDF 내장 이미지·첨부는 -b 옵션으로 바이너리 추출이 가능하다.
