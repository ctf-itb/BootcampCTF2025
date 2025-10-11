#include <stdio.h>
#include <stdlib.h>

int main()
{
    char s[256];
    FILE *fd = fopen("/flag","r");
    fgets(s, 256, fd);
    printf("%s\n", s);
    fclose(fd);
    return 0;
}