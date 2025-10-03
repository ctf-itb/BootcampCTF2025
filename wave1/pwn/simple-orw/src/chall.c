#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

size_t input(const char *prompt, char *buffer, size_t size)
{
    printf("%s", prompt);
    fflush(stdout);
    size_t i;
    for (i = 0; i < size - 1; i++)
    {
        char c = getchar();
        if (c == '\n')
        {
            break;
        }
        buffer[i] = c;
    }
    buffer[i] = '\0';
    return i;
}

int main()
{
    char buffer[0x1000];

    FILE *file, *in_file, *out_file;

    input("1. read\n2. write\n> ", buffer, sizeof(buffer));
    int choice = atoi(buffer);
    if (choice < 1 || choice > 2)
    {
        printf("invalid option\n");
        exit(1);
    }

    input("file name: ", buffer, sizeof(buffer));
    if (choice == 1)
    {
        file = fopen(buffer, "r");
        in_file = file;
        out_file = stdout;
    }
    else
    {
        file = fopen(buffer, "w");
        in_file = stdin;
        out_file = file;
    }
    if (file == NULL)
    {
        printf("failed to open file: %s\n", strerror(errno));
        exit(1);
    }

    input("offset: ", buffer, sizeof(buffer));
    off_t offset = atol(buffer);

    input("size: ", buffer, sizeof(buffer));
    size_t size = MIN(atoi(buffer), sizeof(buffer));

    fseek(file, offset, SEEK_SET);
    fread(buffer, sizeof(char), size, in_file);
    fwrite(buffer, sizeof(char), size, out_file);
    fclose(file);

    return 0;
}
