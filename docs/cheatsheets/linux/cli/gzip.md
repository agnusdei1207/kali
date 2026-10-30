# gzip

## 개요

`gzip`은 파일 압축/해제에 쓰인 도구이고, 압축된 결과를 비교할 때 유용하다.

## 사용법

```bash
sudo apt install gzip -y

# 압축
gzip archive.tar

# 압축 해제
gunzip archive.tar.gz
tar -xf archive.tar
```

## 여러 파일 압축

```bash
# zip/unzip과는 별개. tar로 디렉터리 전체를 압축
tar -czf backup.tar.gz /home/user/data

# 압축 해제
tar -xzf backup.tar.gz
```

## 결과 확인

```bash
# 압축 파일 용량 비교
ls -lh backup.tar.gz
```

## 실전 팁

- OSCP 시험에서는 압축 도구 자체가 많이 등장하지 않는다. crontab 분석 때 확인하는 정도.
- 증적 비교 시 `md5sum`(common/cryptography/md5sum.md)과 함께 사용하면 좋다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
