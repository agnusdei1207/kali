# Sleuth Kit으로 디스크 이미지 분석

- Sleuth Kit(TSK) — 디스크 이미지·볼륨·파일시스템을 파티션·inode 단위로 분석하는 CLI 모음. mmls(파티션), fls(파일목록), istat(inode), icat(파일추출) 등이 대표적.
- DD/E01 이미지에서 파티션 오프셋을 찾고 삭제된 파일을 복구할 때, 이미지를 마운트하지 않고 파일시스템을 열람할 때, 스크립트로 이미지를 자동 순회할 때.
- Kali는 apt install sleuthkit (기본 설치, PATH 사용). Windows는 workspace\forensics\sleuthkit\tools\ 아래 exe 사용. NTFS·FAT·exFAT·ext4 등 지원.

## 기본 명령어 구조

```bash
mmls disk.dd                        # 파티션 테이블 확인
fls -o <오프셋> disk.dd              # 파일 목록
istat -o <오프셋> disk.dd <inode>    # inode 상세
icat -o <오프셋> disk.dd <inode> > out.bin   # 파일 내용 추출
```

- `-o` 오프셋은 mmls 출력의 Start 열 값(섹터 단위)을 그대로 쓴다.

## 디스크 이미지 분석 흐름

```bash
# 1. 파티션 테이블 확인
mmls disk.dd

# 2. 출력의 NTFS 파티션 Start 값 확인 (예: 2048)

# 3. 파일 목록 (재귀 + 전체 경로 + 삭제 파일 포함)
fls -o 2048 -r -p disk.dd

# 4. 삭제된 파일만 찾기 (행 앞에 * 표시)
fls -o 2048 -r -p disk.dd | grep '\*'

# 5. inode 상세 (타임스탬프, 크기, 클러스터)
istat -o 2048 disk.dd 24576

# 6. 파일 추출
icat -o 2048 disk.dd 24576 > recovered.docx
```

- fls 행 맨 앞 숫자가 inode 번호이고, *가 붙으면 할당 해제(삭제) 상태다.

## 유용한 도구·옵션

- `fls -r`: 재귀, `-p`: 전체 경로, `-l`: 크기·시각 포함 롱 포맷.
- `tsk_recover -e -o 2048 disk.dd outdir`: 전체(-e) 또는 할당 파일만 자동 복구.
- `fsstat -o 2048 disk.dd`: 파일시스템 메타 정보 확인.

## 실전 예시

```bash
# 흔적 파일 검색
fls -o 2048 -r -p disk.dd | grep -i "password\|history\|rdp"

# 타임라인 생성 (bodyfile -> mactime)
fls -o 2048 -r -p -l disk.dd > timeline.body
mactime -b timeline.body -y 2026 > timeline.txt

# E01 이미지도 동일하게 처리
mmls evidence.E01
```

## 팁·트러블슈팅

1. mmls에 파티션이 안 보이면 GPT·LVM 여부를 확인한다. LVM이면 논리볼륨을 분리해 다시 분석한다.
2. icat 결과가 깨지면 inode를 잘못 쓴 경우가 많다. fls 출력의 inode 열을 정확히 복사한다.
3. 오프셋은 파티션마다 다르므로 볼륨마다 -o를 다시 잡아준다.
