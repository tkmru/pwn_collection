#include <stdio.h>
#include <string.h>

int main(int argc, char **argv){
    char buf[100];

    strncpy(buf, argv[1], 100);
    printf(buf);
    putchar('\n');

    return 0;
}
