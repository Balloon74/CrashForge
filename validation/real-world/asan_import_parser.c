#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Standalone validation target, intentionally unrelated to CrashForge's
 * example fixtures. It models a legacy import path in a small C parser.
 */
static int read_file(const char *path, char **out, size_t *out_len) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "parser: %s: %s\n", path, strerror(errno));
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    long end = ftell(file);
    if (end < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 1;
    }

    size_t length = (size_t)end;
    char *buffer = malloc(length + 1);
    if (buffer == NULL) {
        fclose(file);
        return 1;
    }
    size_t read_count = fread(buffer, 1, length, file);
    fclose(file);
    if (read_count != length) {
        free(buffer);
        return 1;
    }
    buffer[length] = '\0';
    *out = buffer;
    *out_len = length;
    return 0;
}

static void parse_legacy_import(const char *input, size_t length) {
    size_t copied = length < 47 ? length : 47;
    char *record = malloc(48);
    if (record == NULL) {
        abort();
    }
    memset(record, 0, 48);
    memcpy(record, input, copied);

    /* Regression target: the retired record is still read by the decoder. */
    free(record);
    volatile unsigned char first_byte = (unsigned char)record[0];
    if (first_byte == 0xff) {
        fprintf(stderr, "parser: impossible legacy tag\n");
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: asan_import_parser INPUT\n");
        return 2;
    }

    char *input = NULL;
    size_t length = 0;
    if (read_file(argv[1], &input, &length) != 0) {
        return 2;
    }

    if (strstr(input, "CF_TRIGGER_LEGACY_IMPORT") != NULL) {
        parse_legacy_import(input, length);
    }

    free(input);
    return 0;
}
