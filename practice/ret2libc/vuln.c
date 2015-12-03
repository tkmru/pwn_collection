#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
$ gcc vuln.c -m32 -fno-stack-protector -o vuln
$ sudo sysctl -w kernel.randomize_va_space=0

STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**4
      filesz 0x00000000 memsz 0x00000000 flags rw-

*/

int main(int argc, char *argv[])
{
    char buf[100];
    setvbuf(stdout, NULL, _IOLBF, 0);
    gets(buf);
    puts(buf);
    return 0;
}