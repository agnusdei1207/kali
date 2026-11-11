# Hashcat 문서 파일 해시 (PDF, MS Office)

- 암호 걸린 문서 파일 크래킹 모음 — PDF 1.1~1.7 버전별(-m 10400~10700), MS Office 2003/2007/2010/2013(-m 9700/9400/9500/9600), pdf2john·office2john 해시 추출 포함
- 침투 테스트에서 암호 보호된 PDF·DOCX 문서를 발견해 내용을 열어야 할 때
- hashcat 설치와 2john 계열 추출 도구 — Office 2013은 PBKDF2로 느림, PDF는 버전별 모드가 다르므로 pdf2john 출력 확인, 암호 없는 PDF는 qpdf --decrypt 가능

## PDF 1.1-1.3 (Acrobat 2-4) (-m 10400)

```bash
hashcat -m 10400 -a 0 pdf_old.txt wordlist.txt
```

## PDF 1.4-1.6 (Acrobat 5-8) (-m 10500)

```bash
hashcat -m 10500 -a 0 pdf.txt wordlist.txt
```

## PDF 1.7 Level 3 (Acrobat 9) (-m 10600)

```bash
hashcat -m 10600 -a 0 pdf9.txt wordlist.txt
```

## PDF 1.7 Level 8 (Acrobat 10-11) (-m 10700)

```bash
hashcat -m 10700 -a 0 pdf10.txt wordlist.txt
```

## MS Office 2007 (-m 9400)

```bash
hashcat -m 9400 -a 0 office2007.txt wordlist.txt
```

## MS Office 2010 (-m 9500)

```bash
hashcat -m 9500 -a 0 office2010.txt wordlist.txt
```

## MS Office 2013 (-m 9600)

```bash
hashcat -m 9600 -a 0 office2013.txt wordlist.txt
```

## MS Office <= 2003 (-m 9700)

```bash
hashcat -m 9700 -a 0 office_old.txt wordlist.txt
```

## 해시 추출

```bash
# PDF
pdf2john document.pdf > pdf.hash

# Office
office2john document.docx > office.hash
```

## 팁

- Office 2013은 PBKDF2로 느림
- PDF는 버전별 모드 다름. pdf2john 출력 확인
- 암호 없는 PDF도 있음: qpdf --decrypt