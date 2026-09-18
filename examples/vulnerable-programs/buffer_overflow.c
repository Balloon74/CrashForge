#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains_overflow(const char *input, size_t size) {
    const char marker[] = "OVERFLOW";
    for (size_t index = 0; index + sizeof(marker) - 1 <= size; ++index) {
        if (memcmp(input + index, marker, sizeof(marker) - 1) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        return 3;
    }
    char input[4096] = {0};
    size_t size = fread(input, 1, sizeof(input), file);
    fclose(file);
    if (contains_overflow(input, size)) {
        char buffer[8];
        memcpy(buffer, input, size);
        return buffer[0];
    }
    return 0;
}
