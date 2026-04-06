#pragma once
/**
 * Anti-hooking measures for FuckProtect shell.
 *
 * Detects and counters common hooking frameworks (Frida, Xposed, substrate)
 * and techniques (PLT/GOT hooking, inline hooking).
 *
 * For Phase 1/2, this provides the framework and basic detection.
 * Full implementation in Sprint 9.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <android/log.h>

#define ANTIHOOK_TAG "FP_AntiHook"
#define ANTIHOOK_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, ANTIHOOK_TAG, fmt, ##__VA_ARGS__)
#define ANTIHOOK_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, ANTIHOOK_TAG, fmt, ##__VA_ARGS__)

/* ─── Frida detection ──────────────────────────────────────────────── */

/**
 * Check for Frida-related files and libraries.
 *
 * @return 0 = no Frida detected, 1 = Frida detected
 */
int detect_frida(void) {
    /* Check for frida-gadget library */
    if (dlopen("libfrida-gadget.so", RTLD_NOW | RTLD_NOLOAD) != NULL) {
        ANTIHOOK_ERR("Frida gadget detected: libfrida-gadget.so");
        return 1;
    }

    /* Check for frida-agent in memory maps */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "frida") != NULL ||
                strstr(line, "gadget") != NULL) {
                ANTIHOOK_ERR("Frida detected in /proc/self/maps: %s", line);
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    /* Check for frida-server port (27042 is default) */
    fp = fopen("/proc/net/tcp", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            /* Port 27042 = 0x69A2 */
            if (strstr(line, ":69A2") != NULL &&
                strstr(line, " 0A ") != NULL) {  /* LISTEN state */
                ANTIHOOK_ERR("Frida server detected on port 27042");
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    return 0;
}

/* ─── Xposed detection ─────────────────────────────────────────────── */

/**
 * Check for Xposed framework indicators.
 *
 * @return 0 = no Xposed detected, 1 = Xposed detected
 */
int detect_xposed(void) {
    /* Check for Xposed installer package */
    const char *xposed_paths[] = {
        "/data/data/de.robv.android.xposed.installer",
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
    };

    for (size_t i = 0; i < sizeof(xposed_paths) / sizeof(xposed_paths[0]); i++) {
        if (access(xposed_paths[i], F_OK) == 0) {
            ANTIHOOK_ERR("Xposed detected: %s", xposed_paths[i]);
            return 1;
        }
    }

    return 0;
}

/* ─── Generic hook detection ───────────────────────────────────────── */

/**
 * Check if a specific function has been hooked by examining its
 * memory mapping and prologue.
 *
 * @param func_name Name of the function to check
 * @return 0 = not hooked, 1 = likely hooked
 */
int check_function_hooked(const char *func_name) {
    void *handle = dlopen(NULL, RTLD_NOW);
    if (!handle) return 0;

    void *func = dlsym(handle, func_name);
    dlclose(handle);

    if (!func) return 0;

    /* Check for inline hooks */
    uint8_t *bytes = (uint8_t *)func;

#if defined(__aarch64__)
    /* Check for B (branch) instruction at start */
    uint32_t instr = *(uint32_t *)bytes;
    if ((instr & 0xFC000000) == 0x14000000) {  /* B instruction */
        ANTIHOOK_ERR("Possible hook detected on: %s", func_name);
        return 1;
    }
#elif defined(__arm__)
    /* Check for LDR PC or BX instruction */
    uint32_t instr = *(uint32_t *)bytes;
    if (instr == 0xE51FF004 ||  /* LDR PC, [PC, #-4] */
        (instr & 0xFFFFFFF0) == 0xE12FFF10) {  /* BX */
        ANTIHOOK_ERR("Possible hook detected on: %s", func_name);
        return 1;
    }
#endif

    return 0;
}

/**
 * Initialize anti-hooking measures.
 *
 * Should be called after anti_debug_init() during shell startup.
 */
void anti_hook_init(void) {
    /* Check for Frida */
    if (detect_frida()) {
        ANTIHOOK_ERR("Hooking framework detected — Frida");
        /* In silent mode: corrupt data instead of exiting */
        /* _exit(1); */
    }

    /* Check for Xposed */
    if (detect_xposed()) {
        ANTIHOOK_ERR("Hooking framework detected — Xposed");
    }

    /* Verify critical functions haven't been hooked */
    check_function_hooked("dlopen");
    check_function_hooked("dlsym");
}
