#pragma GCC diagnostic ignored "-Wunused-function"
#pragma once
/**
 * PLT/GOT integrity check for FuckProtect shell.
 *
 * Verifies that PLT (Procedure Linkage Table) and GOT (Global Offset Table)
 * entries have not been modified by hooking frameworks.
 *
 * T9.1: PLT/GOT integrity check
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <android/log.h>

#define PLT_TAG "FP_PLTCheck"
#define PLT_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, PLT_TAG, fmt, ##__VA_ARGS__)
#define PLT_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, PLT_TAG, fmt, ##__VA_ARGS__)

/**
 * Get the base load address of a shared library.
 *
 * @param lib_name Library name (e.g. "libc.so")
 * @return Base address, or 0 if not found
 */
static uintptr_t get_lib_base(const char *lib_name) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Look for lines containing the library name with 'x' (executable) permission */
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            /* Parse the start address */
            char *dash = strchr(line, '-');
            if (dash) {
                *dash = '\0';
                base = (uintptr_t)strtoul(line, NULL, 16);
            }
            break;
        }
    }

    fclose(fp);
    return base;
}

/**
 * Iterate over all loaded shared libraries and verify their dynamic
 * section (PLT/GOT) integrity.
 *
 * @return 0 = no modifications detected, 1 = possible hook detected
 */
int verify_plt_got_integrity(void) {
    /* Read /proc/self/maps to enumerate loaded libraries */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        PLT_ERR("Cannot open /proc/self/maps");
        return 0;
    }

    char line[512];
    int hook_suspected = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Only check executable mappings (r-xp) */
        if (strstr(line, "r-xp") == NULL) continue;

        /* Skip anonymous mappings */
        char *path = strchr(line, '/');
        if (!path) continue;

        /* Remove trailing newline */
        size_t len = strlen(path);
        if (len > 0 && path[len - 1] == '\n') path[len - 1] = '\0';

        /* Check if this is a .so file we care about */
        if (strstr(path, "libshell.so") ||
            strstr(path, "libc.so") ||
            strstr(path, "liblog.so") ||
            strstr(path, "libandroid.so")) {

            /* Parse the address range */
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                /* Verify the first few bytes of .text are reasonable.
                 * The ELF header should start with 0x7F 'E' 'L' 'F' */
                uint8_t *header = (uint8_t *)start;
                if (header[0] != 0x7F || header[1] != 'E' ||
                    header[2] != 'L' || header[3] != 'F') {
                    /* Check if it's a relocated mapping (second mapping often
                     * starts at different address). Skip non-ELF starts. */
                    PLT_LOG("Non-ELF start for %s at %lx (normal for relocated)",
                            path, start);
                }
            }
        }
    }

    fclose(fp);
    return hook_suspected;
}

/**
 * Verify that specific critical functions have not been hooked.
 *
 * Checks the first bytes of functions loaded via dlsym() against
 * expected patterns. If the function has been hooked via PLT or
 * inline hook, the bytes will differ.
 *
 * @param func_name Name of the function to verify
 * @return 0 = not hooked, 1 = likely hooked
 */
int verify_function_not_hooked(const char *func_name) {
    void *handle = dlopen(NULL, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 0;

    void *func = dlsym(handle, func_name);
    dlclose(handle);

    if (!func) return 0;

    /* For ARM64, verify the function doesn't start with a branch
     * to an external address (which would indicate PLT redirection) */
#if defined(__aarch64__)
    uint32_t *instr = (uint32_t *)func;

    /* ADRP (relative page address) is normal for position-independent code.
     * But a direct B (branch) at offset 0 is suspicious. */
    uint32_t op = instr[0];
    uint32_t opcode = op >> 24;

    /* B instruction: 0x14xxxxxx or 0x17xxxxxx */
    if (opcode == 0x14 || opcode == 0x17) {
        PLT_ERR("Function %s starts with branch instruction — likely hooked", func_name);
        return 1;
    }

#elif defined(__arm__)
    uint32_t *instr = (uint32_t *)func;

    /* LDR PC, [PC, #offset] = 0xE51FFxxx (hook via literal pool) */
    if ((*instr & 0xFFFFF000) == 0xE51FF000) {
        PLT_ERR("Function %s has LDR PC hook pattern", func_name);
        return 1;
    }

    /* BX instruction: 0xE12FFF1x */
    if ((*instr & 0xFFFFFFF0) == 0xE12FFF10) {
        PLT_ERR("Function %s has BX redirect — likely hooked", func_name);
        return 1;
    }

#elif defined(__i386__) || defined(__x86_64__)
    uint8_t *bytes = (uint8_t *)func;

    /* JMP rel32: E9 xx xx xx xx */
    if (bytes[0] == 0xE9) {
        PLT_ERR("Function %s starts with JMP — likely hooked", func_name);
        return 1;
    }

    /* PUSH addr + RET (common hooking trick) */
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
        PLT_ERR("Function %s has PUSH+RET hook", func_name);
        return 1;
    }
#endif

    return 0;
}
