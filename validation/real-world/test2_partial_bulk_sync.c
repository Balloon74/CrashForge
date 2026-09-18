#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * CrashForge 0.2.0 Test 2 validation target.
 *
 * This models a sync service's legacy bulk-patch decoder. The input must look
 * like a real request and contain all three compatibility markers before the
 * vulnerable path is considered. The 8/10 gate is deliberate target-side
 * instability: it is not part of CrashForge and exists to test partial
 * nondeterminism in the validation workflow.
 */

static const char *const bulk_patch_marker = "CF_TRIGGER_BULK_PATCH_V2";

static int read_file(const char *path, char **out, size_t *out_len) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "sync-parser: %s: %s\n", path, strerror(errno));
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

static uint64_t target_entropy(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        now.tv_sec = time(NULL);
        now.tv_nsec = 0;
    }

    uint64_t value = (uint64_t)now.tv_sec;
    value ^= (uint64_t)now.tv_nsec << 21;
    value ^= (uint64_t)getpid() << 33;
    value ^= (uintptr_t)&now;
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static int compatibility_gate_opens(void) {
    /* Intentionally succeeds on approximately 8 of 10 fresh processes. */
    return target_entropy() % 10 < 8;
}

static void decode_legacy_bulk_patch(const char *input, size_t length) {
    const char *marker = strstr(input, bulk_patch_marker);
    if (marker == NULL || strstr(input, "\"schema\":\"sync-manifest/4\"") == NULL ||
        strstr(input, "\"mode\":\"legacy-bulk-patch\"") == NULL) {
        return;
    }

    if (!compatibility_gate_opens()) {
        fprintf(stderr, "sync-parser: compatibility gate deferred this legacy patch\n");
        return;
    }

    /*
     * Validation bug: the retired decoder allocates a 32-byte slot but copies
     * the fixed-width legacy token plus surrounding fields into it. The input
     * is deliberately long enough that the source read itself is in bounds;
     * ASan should therefore report the write-side heap-buffer-overflow.
     */
    char *decoded_slot = malloc(32);
    if (decoded_slot == NULL) {
        abort();
    }

    size_t marker_offset = (size_t)(marker - input);
    size_t bytes_after_marker = length - marker_offset;
    if (bytes_after_marker < 48) {
        free(decoded_slot);
        return;
    }

    memcpy(decoded_slot, marker, 48);
    volatile unsigned char tag = (unsigned char)decoded_slot[0];
    if (tag == 0) {
        fprintf(stderr, "sync-parser: empty legacy tag\n");
    }
    free(decoded_slot);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: test2_partial_bulk_sync INPUT\n");
        return 2;
    }

    char *input = NULL;
    size_t length = 0;
    if (read_file(argv[1], &input, &length) != 0) {
        return 2;
    }

    decode_legacy_bulk_patch(input, length);
    free(input);
    return 0;
}
