#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
$ gcc vuln.c -fno-stack-protector -o vuln
$ sudo sysctl -w kernel.randomize_va_space=0
*/

int main(int argc, char *argv[])
{
    char buf[100];
    setvbuf(stdout, NULL, _IOLBF, 0);
    gets(buf);
    puts(buf);
    return 0;
}
