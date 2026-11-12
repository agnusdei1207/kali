# foremost로 파일 카빙

- foremost — 헤더·푸터 시그니처 기반 파일 카빙 도구. 이미지·디스크 덤프에서 파일시스템 정보를 무시하고 jpg·png·pdf·doc 등을 복원해 out 디렉터리에 저장한다.
- 삭제된 사진·문서를 디스크 이미지에서 뽑아낼 때, binwalk가 놓친 조각난 파일을 복구할 때, SD카드·메모리 덤프를 처리할 때.
- Kali는 apt install foremost. Windows는 workspace\forensics\foremost\foremost.exe (또는 WSL) 사용. 시그니처 정의는 foremost.conf로 확장 가능.

## 기본 명령어 구조

```bash
foremost -i <입력파일> -o <출력디렉터리>
```

- `-i`: 입력 이미지(디스크 덤프, 단일 파일, RAW 사진 모두).
- `-o`: 출력 디렉터리. 실행 전에 존재하지 않거나 비어 있어야 한다.
- 결과는 out/jpg/ 처럼 타입별 하위 디렉터리에 저장되고 audit.txt에 복구 기록이 남는다.

## 기본 사용

```bash
sudo foremost -i disk.dd -o out
sudo foremost -i memory.dmp -o out_mem
foremost -i photo.jpg -o carved     # 단일 파일 안에 숨은 이미지도 카빗
```

## 유용한 옵션

- `-t jpg,png,pdf,zip`: 추출할 타입 지정(전체 시도보다 빠르고 노이즈가 적다).
- `-q`: 빠른 모드. 섹터 경계에서만 시그니처를 검사해 속도를 우선한다.
- `-w`: audit.txt만 생성하고 파일은 저장하지 않음(시그니처 분포 확인용).
- `-c /etc/foremost.conf`: 사용자 설정 파일로 헤더·푸터 시그니처 추가.
- `-s <섹터수>`: 스캔 시작 섹터 지정.

## 실전 예시

```bash
# 사진만 빠르게 복구
foremost -t jpg,png -i disk.dd -o out_pics

# audit 먼저 확인 후 타깃 타입만 추출
foremost -w -i disk.dd -o audit_only
head -30 audit_only/audit.txt

foremost -t pdf,doc,docx -i disk.dd -o out_docs

# 커스텀 시그니처 확인 (zip 예시)
grep -n "zip" /etc/foremost.conf
```

## binwalk와의 비교

- binwalk: 시그니처 스캔 + 자동 압축 해제. 펌웨어 내부 구조 파악에 강점.
- foremost: 파일 카빙 특화. 헤더/푸터 쌍 사이를 잘라 저장하므로 이미지·문서 복구가 직관적.
- 실무 흐름: binwalk -Me로 구조를 뜯고, 이미지·문서 복구는 foremost로 마무리한다.

## 팁·트러블슈팅

1. 출력 디렉터리가 이미 있으면 시작을 거부한다. 새 이름을 쓰거나 rm -rf out 후 실행한다.
2. 조각난 파일은 복구돼도 열리지 않을 수 있다. jpg라면 종료 마커 FF D9 유무와 사이즈를 확인한다.
3. 대형 이미지는 시간이 오래 걸리니 -q 또는 -t로 범위를 좁힌다.
