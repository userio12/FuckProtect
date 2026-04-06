/**
 * Native hook framework for FuckProtect shell.
 *
 * This module provides ART method hooking capabilities used for:
 * - Reconstructing hollowed method bodies at runtime (Phase 3)
 * - Intercepting sensitive API calls for monitoring
 *
 * For Phase 1/2, this is a stub. Full implementation in Sprint 9.
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#define HOOK_TAG "FP_Hook"
#define HOOK_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, HOOK_TAG, fmt, ##__VA_ARGS__)

/**
 * Initialize the native hooking system.
 *
 * In Phase 3, this will set up:
 * - ART method interception (hooking art::ArtMethod)
 * - PLT hook detection and countermeasures
 * - Inline hook detection
 *
 * For now, this is a no-op stub.
 */
void native_hook_init(void) {
    /* Stub — full implementation in Sprint 9 */
}

/**
 * Hook a Java method by its class and method name.
 *
 * @param class_name  Fully qualified class name (e.g. "java/lang/String")
 * @param method_name Method name (e.g. "equals")
 * @param signature   JNI method signature (e.g. "(Ljava/lang/Object;)Z")
 * @param replacement Replacement function pointer
 * @return 0 on success, -1 on error
 */
int native_hook_method(const char *class_name, const char *method_name,
                       const char *signature, void *replacement) {
    (void)class_name;
    (void)method_name;
    (void)signature;
    (void)replacement;
    /* Stub */
    return -1;
}

/**
 * Unhook a previously hooked method.
 *
 * @param class_name  Fully qualified class name
 * @param method_name Method name
 * @return 0 on success, -1 on error
 */
int native_unhook_method(const char *class_name, const char *method_name) {
    (void)class_name;
    (void)method_name;
    /* Stub */
    return -1;
}

/**
 * Hook a native function by address.
 *
 * @param func_addr  Function address in memory
 * @param replacement Replacement function address
 * @param original   Output: pointer to store original function trampoline
 * @return 0 on success, -1 on error
 */
int native_hook_function(void *func_addr, void *replacement, void **original) {
    (void)func_addr;
    (void)replacement;
    (void)original;
    /* Stub */
    return -1;
}

/**
 * Detect inline hooks on a function.
 *
 * Checks the function prologue for common inline hook patterns:
 * - ARM: LDR PC, [PC, #offset]
 * - ARM64: ADRP + LDR + BR sequence
 * - x86: JMP relative (E9 xx xx xx xx)
 *
 * @param func_addr Function address to check
 * @return 0 = no hook detected, 1 = hook detected
 */
int detect_inline_hook(void *func_addr) {
    if (func_addr == NULL) return 0;

    uint8_t *bytes = (uint8_t *)func_addr;

#ifdef __arm__
    /* ARM: check for LDR PC, [PC, #offset] (0xE51FF004) */
    uint32_t instr = *(uint32_t *)bytes;
    if ((instr & 0xFFFFF000) == 0xE51FF000) {
        return 1;
    }

#elif defined(__aarch64__)
    /* ARM64: check for ADRP (0x90000000 range) + LDR + BR */
    uint32_t instr0 = *(uint32_t *)(bytes);
    uint32_t instr1 = *(uint32_t *)(bytes + 4);
    uint32_t instr2 = *(uint32_t *)(bytes + 8);

    /* ADRP: xddddddd dddddddd ddddddddd 010000 (0x90000000 range) */
    if ((instr0 & 0x9F000000) == 0x90000000 &&
        (instr1 & 0xFFC003FF) == 0xF9400010 &&  /* LDR */
        (instr2 & 0xFC0003FF) == 0xD61F0200) {   /* BR */
        return 1;
    }

#elif defined(__i386__)
    /* x86: check for JMP rel32 (E9) */
    if (bytes[0] == 0xE9) return 1;

#elif defined(__x86_64__)
    /* x86_64: check for JMP rel32 (E9) */
    if (bytes[0] == 0xE9) return 1;
    /* Also check for PUSH + RET trick */
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) return 1;
#endif

    return 0;
}

/**
 * Verify PLT/GOT entries haven't been modified.
 *
 * @return 0 = no hooks detected, 1 = hooks detected
 */
int verify_plt_integrity(void) {
    /* Stub — full implementation in Sprint 9 */
    return 0;
}
