#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

char buf[0x101];

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln(){
    for(;;){
        printf("Hoi: ");
        int n = read(0, buf, 0x101);
        buf[n] = 0;
        printf(buf);
    }
}

int main(){
    setup();
    int x = 0;
    int y = 1;
    if (x == y){
        int fd = syscall(SYS_openat, AT_FDCWD, "flag.txt", O_RDONLY, 0);
        syscall(SYS_read, fd, buf, sizeof buf);
        puts(buf);
    }
    vuln();
    return 0;
}