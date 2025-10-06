#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    FILE *fd = fopen("flag.txt", "r");
    char flag[64];
    if (fd) {
        fgets(flag, sizeof(flag), fd);
        printf("Yes\n %s\n", flag);
        fclose(fd);
    } else {
        printf("Could not open flag file.\n");
    }

}

int main() {
    setup();
    char buffer[64];
    printf("What ?\n");
    gets(buffer);
    return 0;
}
