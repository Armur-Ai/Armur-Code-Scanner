/* C testdata: intentionally vulnerable patterns for scanner testing. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* CWE-121: Stack-based buffer overflow */
void copy_input(char *input) {
    char buf[32];
    strcpy(buf, input);  /* no bounds check */
    printf("Input: %s\n", buf);
}

/* CWE-78: OS command injection */
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}

/* CWE-134: Uncontrolled format string */
void log_message(char *msg) {
    printf(msg);  /* format string vulnerability */
}

/* CWE-190: Integer overflow */
void allocate_buffer(int size) {
    int total = size * sizeof(int);  /* can overflow */
    int *buf = malloc(total);
    free(buf);
}

/* CWE-415: Double free */
void double_free() {
    char *p = malloc(10);
    free(p);
    free(p);  /* double free */
}

/* CWE-476: NULL pointer dereference */
void null_deref(char *p) {
    if (!p) {
        /* intentionally fall through */
    }
    printf("%s\n", p);  /* p may be NULL */
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        copy_input(argv[1]);
        run_command(argv[1]);
        log_message(argv[1]);
    }
    return 0;
}
