#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains_binary_marker(const unsigned char *input, size_t size) {
    static const unsigned char marker[] = {0x43, 0x46, 0x00, 0x21};
    for (size_t index = 0; index + sizeof(marker) <= size; ++index) {
        if (memcmp(input + index, marker, sizeof(marker)) == 0) {
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
    unsigned char input[4096];
    size_t size = fread(input, 1, sizeof(input), file);
    fclose(file);

    /* The marker is the exact four-byte sequence 43 46 00 21, including NUL. */
    if (contains_binary_marker(input, size)) {
        abort();
    }
    return 0;
}
