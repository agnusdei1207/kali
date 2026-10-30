# zip / unzip

## 개요

`zip`/`unzip`은 파일 압축/해제에 쓰인 도구다. 용량 비교와 증적 정리에 유용하다.

## 사용법

```bash
sudo apt install zip unzip -y

# 압축
zip archive.zip memo.txt
zip archive.zip file1.txt file2.jpg notes.pdf
zip -r archive.zip myfolder/

# 압축 풀기
unzip archive.zip
unzip archive.zip -d /tmp/unzipped/

# 내용 확인 (풀지 않고)
unzip -l archive.zip
```

## 비밀번호가 걸린 압축

```bash
zip -e secret.zip secret.txt      # 압축 시 비밀번호 설정
unzip secret.zip                # 풀 때 비밀번호 입력 필요
```

## 결과 해석

- `unzip -l`로 압축 목록을 먼저 본다.
- 압축 풀 위치(`-d`)를 지정하지 않으면 현재 폴더에 풀린다.
- OSCP 시험에서는 크게 쓸 일이 없다. 주로 증적 비교와 실습 용도다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
