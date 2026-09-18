#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains_ordered_markers(const unsigned char *input, size_t size) {
    static const unsigned char first[] = "LEFT";
    static const unsigned char second[] = "RIGHT";

    for (size_t first_index = 0; first_index + sizeof(first) - 1 <= size; ++first_index) {
        if (memcmp(input + first_index, first, sizeof(first) - 1) != 0) {
            continue;
        }
        for (size_t second_index = first_index + sizeof(first) - 1;
             second_index + sizeof(second) - 1 <= size;
             ++second_index) {
            if (memcmp(input + second_index, second, sizeof(second) - 1) == 0) {
                return 1;
            }
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

    /* Abort only when the complete LEFT marker occurs before RIGHT. */
    if (contains_ordered_markers(input, size)) {
        abort();
    }
    return 0;
}
