#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        return 3;
    }
    char input[4096] = {0};
    size_t size = fread(input, 1, sizeof(input) - 1, file);
    fclose(file);
    input[size] = '\0';
    if (strstr(input, "CRASH") != NULL) {
        volatile int *address = NULL;
        *address = 1;
    }
    return 0;
}

