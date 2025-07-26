```bash
# zip, unzip 설치 (없으면 먼저)
sudo apt update && sudo apt install zip unzip

# 파일 하나 압축하기 (memo.txt → archive.zip)
zip archive.zip memo.txt

# 여러 파일 압축하기 (file1.txt, file2.jpg, notes.pdf)
zip archive.zip file1.txt file2.jpg notes.pdf

# 폴더 전체 압축하기 (-r은 폴더 내부까지 재귀적으로 압축)
zip -r archive.zip myfolder/

# 압축 풀기 (현재 폴더에 풀림)
unzip archive.zip

# 특정 경로에 압축 풀기 (-d 옵션 뒤에 경로 지정)
unzip archive.zip -d /tmp/unzipped/

# 압축 내용만 확인하기 (풀지 않고 파일 리스트 보기)
unzip -l archive.zip

# 비밀번호 걸어서 압축하기 (-e 옵션, 압축할 때 비밀번호 입력)
zip -e secret.zip secret.txt

# 비밀번호 걸린 압축 풀기 (풀 때 비밀번호 입력 필요)
unzip secret.zip

```
