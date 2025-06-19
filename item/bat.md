# bat - 구문 강조 cat 도구

## 설치
```bash
apt install bat    # Debian/Ubuntu/Kali
```

## 사용법
```bash
batcat file.txt             # 기본 사용법 (Ubuntu/Debian에서는 batcat)
bat file.txt                # 다른 배포판에서는 bat

bat --plain file.txt        # 라인 번호 없이 출력
bat -l php file.txt         # 특정 언어로 구문 강조
bat -A file.txt             # 공백 문자 표시
bat -n file.txt             # 항상 라인 번호 표시
```

## 파이프 활용
```bash
cat file.txt | bat         # 파이프에서 사용
find . -name "*.php" -exec bat {} \;  # find 결과 출력
diff -u file1 file2 | bat --language diff  # diff 결과 강조
```

## 유용한 팁
```bash
bat /etc/passwd               # 구성 파일 확인
bat /var/log/apache2/error.log  # 로그 파일 분석
PAGER='less -R' bat large_file.txt  # 대용량 파일 페이징
```
