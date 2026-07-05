#include <stdio.h>   // 표준 입출력 함수(printf, puts 등)를 사용하기 위한 헤더 파일
#include <stdlib.h>  // 표준 라이브러리 함수(exit, system 등)를 사용하기 위한 헤더 파일
#include <signal.h>  // 시그널 처리 함수(signal, alarm 등)를 사용하기 위한 헤더 파일
#include <unistd.h>  // POSIX 운영체제 API(read 함수 등)를 사용하기 위한 헤더 파일

// 30초 제한 시간이 지났을 때 실행될 함수
void alarm_handler()
{
    puts("TIME OUT"); // 화면에 "TIME OUT" 출력
    exit(-1);        // 프로그램을 비정상 종료(-1)함
}

// 프로그램의 초기 설정을 담당하는 함수
void initialize()
{
    // 입력과 출력의 버퍼링(Buffering)을 제거하여, 
    // printf나 read 연산이 일어날 때 데이터가 버퍼에 머물지 않고 즉시 전송되도록 설정합니다.
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    // SIGALRM(알람 시그널)이 발생하면 alarm_handler 함수를 실행하도록 등록
    signal(SIGALRM, alarm_handler);
    alarm(30); // 30초 뒤에 알람 시그널이 발생하도록 설정 (해킹 제한 시간 30초)
}

// 문자열을 안전하게(?) 입력받으려고 만든 사용자 정의 함수
void read_str(char *ptr, int size)
{
    int len;
    // 표준 입력(0, 키보드)으로부터 ptr 주소에 최대 size 바이트만큼 데이터를 읽어옴
    len = read(0, ptr, size); 
    
    // 사용자가 실제 입력한 바이트 수를 화면에 숫자로 출력 (질문하셨던 숫자의 정체!)
    printf("%d", len);
    
    // [★ 치명적인 취약점 (Off-by-one) 발생 지점]
    // 입력받은 문자열의 맨 마지막에 문자열의 끝을 알리는 Null(널) 문자('\0')를 삽입합니다.
    // 만약 size가 20인데 사용자가 20바이트를 꽉 채워 입력하면, len은 20이 되고 ptr[20]에 '\0'을 넣게 됩니다.
    // ptr[0]부터 ptr[19]까지만 허용된 공간인데 ptr[20]을 건드리므로 '1바이트 침범'이 일어납니다.
    ptr[len] = '\0';
}

// 해커가 실행시켜야 하는 최종 목적지 함수
void get_shell()
{
    // 리눅스의 기본 셸(/bin/sh)을 실행합니다. 
    // 이 함수가 실행되면 서버의 주도권을 잡고 명령어를 내릴 수 있게 됩니다.
    system("/bin/sh");
}

int main()
{
    char name[20]; // 이름을 저장할 20바이트 크기의 문자 배열 (인덱스는 0 ~ 19까지 존재)
    int age = 1;   // 나이를 저장할 4바이트 정수형 변수 (초기값은 1)
                   // 메모리 구조상 대개 name[20] 배열 바로 뒤에 age 변수가 위치하게 됨

    initialize();  // 알람 설정 및 버퍼 초기화 함수 호출

    printf("Name: ");
    // name 배열(20바이트 크기)에 최대 20바이트만큼 입력을 받음
    // 여기서 20바이트를 꽉 채우면, read_str 내부에서 name[20] 영역('\0')을 건드리게 되고,
    // 이 name[20] 자리는 사실 바로 뒤에 붙어있던 변수인 'age'의 첫 번째 바이트 공간임!
    // 따라서 age 변수의 값이 강제로 0으로 변조됨
    read_str(name, 20);

    printf("Are you baby?");

    // age 변수가 0인지 확인 (기본값은 1이라 원래는 실행될 수 없는 영역)
    if (age == 0)
    {
        // 취약점을 통해 age를 0으로 만들면 이 조건문 안으로 들어와 셸을 획득함
        get_shell();
    }
    else
    {
        // 20바이트를 채우지 않아 age가 여전히 1이라면 실행되는 정상 흐름
        printf("Ok, chance: \n");
        read(0, name, 20); // 두 번째 기회를 주지만, 이미 기회는 무의미함
    }

    return 0; // 프로그램 정상 종료
}