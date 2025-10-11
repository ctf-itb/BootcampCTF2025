#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    char buf[121];
    unsigned char key[8] = {0};
    char fname[9];

    setup();

    puts("First:");
    ssize_t n = read(0, buf, 8); if (n <= 0) return 1;
    buf[n] = 0;
    printf(buf);

    puts("Second:");
    n = read(0, buf, 120); if (n <= 0) return 1;
    buf[n] = 0;
    printf(buf);

    unsigned int s = 0x96;
    for (int i = 0; i < 8; i++) {
        s = (69u * s + 67u) & 0xFFu;
        fname[i] = (char)(key[i] ^ (unsigned char)s);
    }
    fname[8] = 0;

    FILE *fp = fopen(fname, "r");
    if (!fp) { perror("fopen"); return 1; }

    char out[512];
    size_t r = fread(out, 1, sizeof(out)-1, fp);
    out[r] = 0;
    fclose(fp);
    puts(out);
    return 0;
}
