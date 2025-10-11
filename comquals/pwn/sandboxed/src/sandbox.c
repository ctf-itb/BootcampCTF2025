#define _GNU_SOURCE

#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int install_seccomp(const char *arg)
{
    int rc = 0;
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        goto ret;
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)arg));
    if (rc < 0)
        goto ret;
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 1, SCMP_A1(SCMP_CMP_NE, (scmp_datum_t)arg));
    if (rc < 0)
        goto ret;
    rc = seccomp_load(ctx);
ret:
    seccomp_release(ctx);
    return rc;
}

pid_t child_pid;

void kill_child_process(int num)
{
    printf("Timeout!\n");
    kill(child_pid, SIGKILL);
}

int main(int argc, char *argv[], char *envp[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        exit(1);
    }

    child_pid = fork();
    if (child_pid < 0)
    {
        perror("fork");
        exit(1);
    }

    if (child_pid == 0)
    {
        if (install_seccomp(argv[1]) < 0)
        {
            perror("seccomp");
            _exit(1);
        }
        char *_argv[] = {argv[1], NULL};
        execve(argv[1], _argv, envp);

        _exit(127);
    }

    signal(SIGALRM, kill_child_process);
    alarm(5);

    int status;
    waitpid(child_pid, &status, 0);

    return WEXITSTATUS(status);
}
