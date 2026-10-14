![](https://velog.velcdn.com/images/agnusdei1207/post/8096e6f7-f97e-44ba-9f6c-9079f32031f4/image.png)

apt update
apt install rizin

```bash
root㉿docker-desktop)-[/]
└─# ls
CVE-2024-9264                    bin   data  etc   lib    media  opt   root  sbin  sys       tmp  var
Compiled-1688545393558.Compiled  boot  dev   home  lib64  mnt    proc  run   srv   test.txt  usr  vpn

┌──(root㉿docker-desktop)-[/]
└─# rizin Compiled-1688545393558.Compiled
 -- Use +,-,*,/ to change the size of the block
[0x00001080]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls
[x] Analyze len bytes of instructions for references
[x] Check for classes
[x] Analyze local variables and arguments
[x] Type matching analysis for all functions
[x] Applied 0 FLIRT signatures via sigdb
[x] Propagate noreturn information
[x] Integrate dwarf function information.
[x] Resolve pointers to data sections
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00001080]> afl
0x00001000    3 23           sym._init
0x00001030    1 6            sym.imp.printf
0x00001040    1 6            sym.imp.strcmp
0x00001050    1 6            sym.imp.__isoc99_scanf
0x00001060    1 6            sym.imp.fwrite
0x00001070    1 6            sym.imp.__cxa_finalize
0x00001080    1 33           entry0
0x000010b0    4 41   -> 34   sym.deregister_tm_clones
0x000010e0    4 57   -> 51   sym.register_tm_clones
0x00001120    5 57   -> 54   sym.__do_global_dtors_aux
0x00001160    1 9            entry.init0
0x00001169    7 253          main
0x00001268    1 9            sym._fini
[0x00001080]> pdf @ main
            ; DATA XREF from entry0 @ 0x1094
┌ int main(int argc, char argv, char envp);
│           ; var int64_t var_48h @ stack - 0x48
│           ; var int64_t var_40h @ stack - 0x40
│           ; var int64_t var_38h @ stack - 0x38
│           ; var const char *s1 @ stack - 0x28
│           0x00001169      push  rbp
│           0x0000116a      mov   rbp, rsp
│           0x0000116d      sub   rsp, 0x40
│           0x00001171      movabs rax, 0x4973676e69727453             ; 'StringsI'
│           0x0000117b      movabs rdx, 0x626f6f4e726f4673             ; 'sForNoob'
│           0x00001185      mov   qword [var_48h], rax
│           0x00001189      mov   qword [var_40h], rdx
│           0x0000118d      mov   word [var_38h], 0x73                 ; 's'
│           0x00001193      mov   rax, qword [obj.stdout]              ; obj.__TMC_END
│                                                                      ; [0x4030:8]=0
│           0x0000119a      mov   rcx, rax                             ; FILE *stream
│           0x0000119d      mov   edx, 0xa                             ; size_t nitems
│           0x000011a2      mov   esi, 1                               ; size_t size
│           0x000011a7      lea   rax, str.Password:                   ; 0x2004 ; "Password: "
│           0x000011ae      mov   rdi, rax                             ; const void *ptr
│           0x000011b1      call  sym.imp.fwrite                       ; sym.imp.fwrite ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x000011b6      lea   rax, [s1]
│           0x000011ba      mov   rsi, rax
│           0x000011bd      lea   rax, str.DoYouEven_sCTF              ; 0x200f ; "DoYouEven%sCTF"
│           0x000011c4      mov   rdi, rax                             ; const char *format
│           0x000011c7      mov   eax, 0
│           0x000011cc      call  sym.imp.__isoc99_scanf               ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x000011d1      lea   rax, [s1]
│           0x000011d5      lea   rdx, str.dso_handle                  ; 0x201e ; "__dso_handle"
│           0x000011dc      mov   rsi, rdx                             ; const char *s2
│           0x000011df      mov   rdi, rax                             ; const char *s1
│           0x000011e2      call  sym.imp.strcmp                       ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
│           0x000011e7      test  eax, eax
│       ┌─< 0x000011e9      js    0x1205
│       │   0x000011eb      lea   rax, [s1]
│       │   0x000011ef      lea   rdx, str.dso_handle                  ; 0x201e ; "__dso_handle"
│       │   0x000011f6      mov   rsi, rdx                             ; const char *s2
│       │   0x000011f9      mov   rdi, rax                             ; const char *s1
│       │   0x000011fc      call  sym.imp.strcmp                       ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
│       │   0x00001201      test  eax, eax
│      ┌──< 0x00001203      jle   0x124b
│      │└─> 0x00001205      lea   rax, [s1]
│      │    0x00001209      lea   rdx, str.init                        ; 0x202b ; "_init"
│      │    0x00001210      mov   rsi, rdx                             ; const char *s2
│      │    0x00001213      mov   rdi, rax                             ; const char *s1
│      │    0x00001216      call  sym.imp.strcmp                       ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
│      │    0x0000121b      test  eax, eax
│      │┌─< 0x0000121d      jne   0x1235
│      ││   0x0000121f      lea   rax, str.Correct                     ; 0x2031 ; "Correct!"
│      ││   0x00001226      mov   rdi, rax                             ; const char *format
│      ││   0x00001229      mov   eax, 0
│      ││   0x0000122e      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│     ┌───< 0x00001233      jmp   0x125f
│     ││└─> 0x00001235      lea   rax, str.Try_again                   ; 0x203a ; "Try again!"
│     ││    0x0000123c      mov   rdi, rax                             ; const char *format
│     ││    0x0000123f      mov   eax, 0
│     ││    0x00001244      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│     ││┌─< 0x00001249      jmp   0x125f
│     │└──> 0x0000124b      lea   rax, str.Try_again                   ; 0x203a ; "Try again!"
│     │ │   0x00001252      mov   rdi, rax                             ; const char *format
│     │ │   0x00001255      mov   eax, 0
│     │ │   0x0000125a      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│     │ │   ; CODE XREFS from main @ 0x1233, 0x1249
│     └─└─> 0x0000125f      mov   eax, 0
│           0x00001264      leave
└           0x00001265      ret
[0x00001080]>
```

`0x4973676e69727453` 이 값은 문자열을 16진수로 표현한 것입니다.
단, 리틀 엔디안(Little Endian) 방식으로 저장되어 있으므로 역순으로 읽어야 합니다.

---

## 🔍 분석

원래 값:

```
0x4973676e69727453
```

16진수를 바이트 단위로 나누면:

```
49 73 67 6e 69 72 74 53
```

이를 아스키(ASCII) 문자로 바꾸면:

```
0x49 = I
0x73 = s
0x67 = g
0x6e = n
0x69 = i
0x72 = r
0x74 = t
0x53 = S
```

→ 즉, 바이트 순서대로 보면 `"IsgnirtS"`
하지만 이건 리틀엔디안으로 저장된 거라 역순으로 읽어야 합니다:

```
"Stringsi"
```

> 정확히는 `"Stringsi"` (마지막 `i`는 `"sForNoob"`와 결합되며 `"StringsForNoobs"`를 만들려는 의도일 가능성 높음)

---

## 🧠 결론

| 항목        | 설명                           |
| ----------- | ------------------------------ |
| 값          | `0x4973676e69727453`           |
| 저장 방식   | 리틀 엔디안 (낮은 바이트 먼저) |
| 문자열 해석 | `"Stringsi"`                   |

```bash
#!/bin/bash

# =================================================================
# OSCP 어셈블리 & 리버스 엔지니어링 현실적 학습 가이드
# =================================================================

echo "=== 2. OSCP에서 필요한 어셈블리 지식 수준 ==="

oscp_assembly_level() {
    echo "### OSCP 어셈블리 필수 지식 (80/20 법칙)"

    echo "## 💡 80%는 이것만 알면 됨:"
    echo "1. 기본 명령어 20개"
    echo "2. 레지스터 8개 역할"
    echo "3. 스택 동작 원리"
    echo "4. 함수 호출 규약"
    echo "5. 조건 분기 패턴"

    echo "## 🔧 20%는 상황별로:"
    echo "1. 시스템 콜 번호"
    echo "2. 복잡한 포인터 연산"
    echo "3. 구조체 접근 패턴"
    echo "4. 최적화된 코드 패턴"
}

echo "=== 3. 꼭 알아야 할 x86-64 어셈블리 핵심 20개 ==="

essential_x86_64() {
    echo "### 3-1. 기본 데이터 이동 (5개)"
    cat << 'EOF'
mov rax, rbx        # 레지스터 복사
mov rax, [rbx]      # 메모리에서 레지스터로
mov [rax], rbx      # 레지스터에서 메모리로
lea rax, [rbx+8]    # 주소 계산 (로드 없이)
xchg rax, rbx       # 두 값 교환
EOF

    echo "### 3-2. 산술 연산 (4개)"
    cat << 'EOF'
add rax, rbx        # 덧셈
sub rax, rbx        # 뺄셈
mul rbx             # 곱셈 (rax * rbx)
div rbx             # 나눗셈 (rax / rbx)
EOF

    echo "### 3-3. 스택 조작 (3개)"
    cat << 'EOF'
push rax            # 스택에 값 저장
pop rax             # 스택에서 값 로드
call func           # 함수 호출 (return address push)
EOF

    echo "### 3-4. 비교 및 분기 (4개)"
    cat << 'EOF'
cmp rax, rbx        # 비교 (플래그 설정)
test rax, rax       # AND 연산 후 플래그 설정
jmp addr            # 무조건 점프
je addr             # 같으면 점프 (Zero Flag)
EOF

    echo "### 3-5. 논리 연산 (2개)"
    cat << 'EOF'
and rax, rbx        # 비트 AND
or rax, rbx         # 비트 OR
EOF

    echo "### 3-6. 특수 명령어 (2개)"
    cat << 'EOF'
nop                 # 아무것도 안함 (패딩용)
ret                 # 함수 리턴
EOF
}

echo "=== 4. 핵심 레지스터 8개만 기억하면 됨 ==="

essential_registers() {
    echo "### x86-64 핵심 레지스터"
    cat << 'EOF'
rax  # 리턴값, 시스템콜 번호
rbx  # 범용 레지스터
rcx  # 루프 카운터, 4번째 인자
rdx  # 3번째 인자, 나눗셈 결과
rsi  # 2번째 인자, 소스 인덱스
rdi  # 1번째 인자, 목적지 인덱스
rsp  # 스택 포인터 (매우 중요!)
rbp  # 베이스 포인터 (스택 프레임)
EOF

    echo "### 📌 OSCP에서 가장 중요한 3개"
    echo "1. rsp (스택 포인터) - 버퍼 오버플로우 핵심"
    echo "2. rdi (첫 번째 인자) - 함수 인자 추적"
    echo "3. rax (리턴값) - 함수 결과 확인"
}

echo "=== 5. 실제 OSCP 바이너리 분석 패턴 ==="

oscp_analysis_patterns() {
    echo "### 5-1. 함수 프롤로그/에필로그 패턴"
    cat << 'EOF'
# 함수 시작 (프롤로그)
push rbp           # 이전 베이스 포인터 저장
mov rbp, rsp       # 새 스택 프레임 설정
sub rsp, 0x20      # 지역 변수 공간 할당

# 함수 끝 (에필로그)
leave              # mov rsp, rbp; pop rbp와 동일
ret                # 호출자로 리턴
EOF

    echo "### 5-2. 버퍼 오버플로우 취약점 패턴"
    cat << 'EOF'
# 위험한 패턴 1: 고정 크기 버퍼
sub rsp, 0x100     # 256바이트 버퍼 할당
mov rdi, rsp       # 버퍼 주소를 첫 번째 인자로
call gets          # 무제한 입력 받기 (취약!)

# 위험한 패턴 2: strcpy 사용
mov rsi, [rbp+0x8] # 두 번째 인자 (소스)
lea rdi, [rbp-0x20] # 첫 번째 인자 (목적지 - 스택 버퍼)
call strcpy        # 길이 체크 없이 복사 (취약!)
EOF

    echo "### 5-3. 인증 우회 패턴"
    cat << 'EOF'
# 전형적인 인증 체크
call check_password
test rax, rax      # 리턴값 확인
je auth_fail       # 0이면 실패로 점프
# 성공 코드
mov edi, success_msg
call puts
jmp end
auth_fail:
# 실패 코드
mov edi, fail_msg
call puts
end:
EOF
}

echo "=== 6. 아키텍처별 차이점 (OSCP 관점) ==="

architecture_differences() {
    echo "### 6-1. OSCP에서 만날 아키텍처"
    echo "🎯 x86-64 (Intel/AMD): 95% - 메인 타겟"
    echo "🎯 x86-32: 4% - 가끔 나옴"
    echo "🎯 ARM: 1% - 거의 없음 (모바일 앱 제외)"

    echo "### 6-2. Intel vs AMD CPU"
    echo "✅ 명령어 세트 동일 (x86-64 표준)"
    echo "✅ 어셈블리 코드 동일하게 보임"
    echo "✅ 차이점은 성능 최적화뿐"
    echo "🔍 OSCP에서는 구분할 필요 없음!"

    echo "### 6-3. 32bit vs 64bit 주요 차이"
    cat << 'EOF'
# 32bit (x86)
eax, ebx, ecx, edx    # 32비트 레지스터
push 0x41414141       # 4바이트 푸시
call [esp+4]          # 스택 기반 인자 전달

# 64bit (x86-64)
rax, rbx, rcx, rdx    # 64비트 레지스터
push 0x4141414141414141  # 8바이트 푸시
mov rdi, rax          # 레지스터 기반 인자 전달
EOF
}

echo "=== 7. 실무 어셈블리 읽기 전략 ==="

reading_strategy() {
    echo "### 7-1. 단계별 읽기 전략"
    echo "1️⃣ 함수 경계 찾기 (push rbp, leave, ret)"
    echo "2️⃣ 분기문 찾기 (cmp, test, jmp, je, jne)"
    echo "3️⃣ 함수 호출 찾기 (call)"
    echo "4️⃣ 문자열 참조 찾기 (mov edi, offset)"
    echo "5️⃣ 스택 조작 찾기 (push, pop, sub rsp)"

    echo "### 7-2. 패턴 인식 기법"
    cat << 'EOF'
# if-else 패턴
cmp rax, 0
je else_branch
# if 코드
jmp end_if
else_branch:
# else 코드
end_if:

# while 루프 패턴
jmp loop_condition
loop_start:
# 루프 본문
loop_condition:
cmp rax, 10
jl loop_start

# switch 패턴
cmp rax, 5
ja default_case
mov rax, qword [jump_table + rax*8]
jmp rax
EOF
}

echo "=== 8. OSCP 실전 어셈블리 분석 스크립트 ==="

analyze_assembly() {
    local file=$1
    echo "=== 실전 어셈블리 분석: $file ==="

    echo "## 1. 함수 목록 및 크기"
    objdump -t "$file" | grep -E "F .text" | while read line; do
        size=$(echo "$line" | awk '{print $5}')
        name=$(echo "$line" | awk '{print $6}')
        echo "함수: $name (크기: $((0x$size)) 바이트)"
    done

    echo "## 2. 위험 함수 호출 패턴"
    objdump -M intel -d "$file" | grep -B2 -A2 "call.*\(gets\|strcpy\|sprintf\|system\)"

    echo "## 3. 스택 버퍼 할당 패턴"
    objdump -M intel -d "$file" | grep -E "sub.*rsp.*0x[0-9a-f]+" | while read line; do
        size=$(echo "$line" | grep -o "0x[0-9a-f]*" | tail -1)
        echo "스택 버퍼: $((size)) 바이트"
    done

    echo "## 4. 조건 분기 패턴"
    objdump -M intel -d "$file" | grep -E "(cmp|test).*\n.*j[a-z]+" -A1

    echo "## 5. 문자열 참조 패턴"
    objdump -M intel -d "$file" | grep -E "mov.*0x[0-9a-f]+" | while read line; do
        addr=$(echo "$line" | grep -o "0x[0-9a-f]*" | tail -1)
        str=$(strings -t x "$file" | grep "$addr" | cut -d' ' -f2-)
        if [ -n "$str" ]; then
            echo "문자열: $str (주소: $addr)"
        fi
    done
}

echo "=== 9. 빠른 취약점 스캔 스크립트 ==="

quick_vuln_scan() {
    local file=$1
    echo "=== 빠른 취약점 스캔: $file ==="

    echo "## 🚨 버퍼 오버플로우 가능성"
    dangerous_funcs=$(objdump -T "$file" 2>/dev/null | grep -E "(gets|strcpy|strcat|sprintf)" | wc -l)
    if [ $dangerous_funcs -gt 0 ]; then
        echo "⚠️  위험 함수 $dangerous_funcs 개 발견"
        objdump -T "$file" 2>/dev/null | grep -E "(gets|strcpy|strcat|sprintf)"
    else
        echo "✅ 명백한 위험 함수 없음"
    fi

    echo "## 🚨 포맷 스트링 가능성"
    format_funcs=$(objdump -T "$file" 2>/dev/null | grep -E "(printf|sprintf|fprintf)" | wc -l)
    if [ $format_funcs -gt 0 ]; then
        echo "⚠️  포맷 함수 $format_funcs 개 발견"
        strings "$file" | grep -E "%[sdxp]" | head -5
    fi

    echo "## 🚨 시스템 명령 실행 가능성"
    system_funcs=$(objdump -T "$file" 2>/dev/null | grep -E "(system|exec)" | wc -l)
    if [ $system_funcs -gt 0 ]; then
        echo "⚠️  시스템 함수 $system_funcs 개 발견"
        strings "$file" | grep -E "(/bin/|sh|bash)" | head -5
    fi
}

echo "=== 10. 어셈블리 학습 로드맵 (OSCP 최적화) ==="

learning_roadmap() {
    echo "### 📚 1주차: 기초 (필수)"
    echo "- 레지스터 8개 외우기"
    echo "- 기본 명령어 20개 익히기"
    echo "- 스택 개념 이해"
    echo "- 함수 호출 규약 이해"

    echo "### 📚 2주차: 패턴 인식 (중요)"
    echo "- if-else 패턴 인식"
    echo "- 루프 패턴 인식"
    echo "- 함수 프롤로그/에필로그 인식"
    echo "- 버퍼 할당 패턴 인식"

    echo "### 📚 3주차: 취약점 분석 (핵심)"
    echo "- 버퍼 오버플로우 패턴"
    echo "- 포맷 스트링 패턴"
    echo "- 인증 우회 패턴"
    echo "- ROP 가젯 찾기"

    echo "### 📚 4주차: 실전 연습 (완성)"
    echo "- 실제 바이너리 분석"
    echo "- 익스플로잇 작성"
    echo "- 디버깅 기법"
    echo "- 자동화 스크립트 작성"
}

echo "=== 11. 실용적인 치트시트 ==="

cheat_sheet() {
    echo "### 🔧 자주 보는 어셈블리 패턴"
    cat << 'EOF'
# 함수 인자 확인 (x86-64)
mov rdi, ???    # 1번째 인자
mov rsi, ???    # 2번째 인자
mov rdx, ???    # 3번째 인자
mov rcx, ???    # 4번째 인자

# 리턴값 확인
mov rax, ???    # 리턴값 설정
test rax, rax   # 0인지 확인
je fail         # 0이면 실패

# 스택 버퍼
sub rsp, 0x100  # 256바이트 할당
lea rdi, [rsp]  # 버퍼 주소 전달

# 조건 분기
cmp rax, 0x10   # 16과 비교
jg greater      # 크면 점프
jl less         # 작으면 점프
je equal        # 같으면 점프
EOF

    echo "### 🔧 일반적인 컴파일러 패턴"
    cat << 'EOF'
# 변수 초기화
xor rax, rax    # rax = 0 (효율적)
mov rax, 0      # rax = 0 (직접적)

# 배열 접근
mov rax, [rbp-0x10+rcx*4]  # arr[i] (4바이트 원소)
mov rax, [rbp-0x10+rcx*8]  # arr[i] (8바이트 원소)

# 구조체 접근
mov rax, [rbp-0x10]        # struct.field1
mov rax, [rbp-0x10+0x8]    # struct.field2
EOF
}

echo "=== 사용법 ==="
echo "# 바이너리 분석"
echo "analyze_assembly ./target_binary"
echo ""
echo "# 취약점 스캔"
echo "quick_vuln_scan ./target_binary"
echo ""
echo "# 함수별 패턴 분석"
echo "objdump -M intel -d ./target_binary | sed -n '/<main>/,/^$/p'"

echo "=== 💡 핵심 메시지 ==="
echo """
1. 어셈블리 '작성'할 필요 없음 - '읽기'만 하면 됨
2. 모든 명령어 외울 필요 없음 - 패턴 인식이 핵심
3. 아키텍처별 차이 크지 않음 - x86-64만 집중
4. 도구 활용으로 90% 자동화 가능
5. 실전에서는 취약점 패턴 찾기가 목표
"""
```
