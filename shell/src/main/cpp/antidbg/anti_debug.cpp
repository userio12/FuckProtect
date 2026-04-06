#pragma once
/**
 * Anti-debugging checks for FuckProtect shell.
 *
 * Implements four independent detection methods:
 * 1. ptrace(PTRACE_TRACEME) — fails if already traced
 * 2. TracerPid — reads /proc/self/status
 * 3. Timing analysis — detects single-stepping / breakpoints
 * 4. JDWP thread scan — detects debugger-attached threads
 *
 * All checks use raw syscalls where possible to avoid PLT hooking.
 * Checks are spread across multiple functions to make patching harder.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <android/log.h>

#define ADBG_TAG "FP_AntiDebug"
#define ADBG_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, ADBG_TAG, fmt, ##__VA_ARGS__)
#define ADBG_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, ADBG_TAG, fmt, ##__VA_ARGS__)

/* Use direct syscall for ptrace to avoid PLT hooks */
static long my_ptrace(long request, long pid, void *addr, void *data) {
    return syscall(SYS_ptrace, request, pid, addr, data);
}

/* ─── Check 1: ptrace self-attach (T6.1) ──────────────────────────── */

/**
 * Attempt to ptrace ourselves. If we're already being traced,
 * this will fail with EPERM.
 *
 * @return 0 = not traced, 1 = traced
 */
int check_ptrace_self_attach(void) {
    long ret = my_ptrace(PTRACE_TRACEME, 0, 0, 0);

    if (ret == -1) {
        /* Already being traced — debugger detected */
        return 1;
    }

    /* Detach ourselves so the process can continue normally */
    my_ptrace(PTRACE_DETACH, 0, 0, 0);
    return 0;
}

/* ─── Check 2: TracerPid via /proc/self/status (T6.2) ─────────────── */

/**
 * Read /proc/self/status and check if TracerPid > 0.
 * A non-zero TracerPid means another process is tracing us.
 *
 * @return 0 = not traced, 1 = traced
 */
int check_tracer_pid(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        /* Can't open — could be blocked, assume suspicious */
        return 0;  /* Don't fail on access issues */
    }

    char line[256];
    int traced = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:\t", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            if (tracer_pid > 0) {
                traced = 1;
            }
            break;
        }
    }

    fclose(fp);
    return traced;
}

/* ─── Check 3: Timing-based detection (T6.3) ──────────────────────── */

/**
 * Measure execution time of a known computation.
 * Debuggers (breakpoints, single-stepping) cause measurable delays.
 *
 * Uses a threshold calibrated for the target device class.
 *
 * @return 0 = normal, 1 = suspicious delay
 */
int check_timing(void) {
    struct timeval start, end;

    gettimeofday(&start, NULL);

    /* Perform a deterministic computation */
    volatile uint64_t sum = 0;
    for (uint64_t i = 0; i < 500000; i++) {
        sum += i * 7 + 3;
    }
    (void)sum;  /* Prevent optimization from removing the loop */

    gettimeofday(&end, NULL);

    long elapsed_us = (long)(end.tv_sec - start.tv_sec) * 1000000L +
                      (long)(end.tv_usec - start.tv_usec);

    /* Threshold: normal execution should complete in < 50ms (50000us).
     * Under a debugger with breakpoints, this can take 10x-100x longer. */
    const long THRESHOLD_US = 50000;

    if (elapsed_us > THRESHOLD_US) {
        return 1;  /* Suspicious delay detected */
    }

    return 0;
}

/**
 * Alternative timing check: measure wall-clock time across a syscall
 * boundary to detect step-over debugging.
 */
int check_timing_syscall(void) {
    struct timespec ts_before, ts_after;

    clock_gettime(CLOCK_MONOTONIC, &ts_before);

    /* Trigger a known-fast syscall */
    syscall(SYS_gettid);

    clock_gettime(CLOCK_MONOTONIC, &ts_after);

    long elapsed_ns = (ts_after.tv_sec - ts_before.tv_sec) * 1000000000L +
                      (ts_after.tv_nsec - ts_before.tv_nsec);

    /* Syscall should complete in < 1ms normally */
    if (elapsed_ns > 5000000L) {  /* 5ms threshold */
        return 1;
    }

    return 0;
}

/* ─── Check 4: JDWP thread scan (T6.4) ────────────────────────────── */

/**
 * Scan /proc/self/task/ for threads with JDWP-related status.
 * When a debugger attaches via JDWP, threads show debug-related state.
 *
 * @return 0 = no JDWP, 1 = JDWP detected
 */
int check_jdwp_threads(void) {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return 0;

    struct dirent *entry;
    int jdwp_found = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char status_path[256];
        snprintf(status_path, sizeof(status_path),
                 "/proc/self/task/%s/status", entry->d_name);

        FILE *fp = fopen(status_path, "r");
        if (!fp) continue;

        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            /* Look for Name field containing JDWP indicator */
            if (strstr(line, "Name:") != NULL) {
                if (strstr(line, "JDWP") != NULL ||
                    strstr(line, "Debugger") != NULL ||
                    strstr(line, "Debug") != NULL) {
                    jdwp_found = 1;
                }
            }
        }

        fclose(fp);
        if (jdwp_found) break;
    }

    closedir(dir);
    return jdwp_found;
}

/**
 * Check if the process is debuggable via the /proc/<pid>/attr/current
 * SELinux context or via the android:debuggable flag read from
 * /proc/self/cmdline and package manager state.
 *
 * @return 0 = not debuggable, 1 = debuggable environment
 */
int check_debuggable_flag(void) {
    /* Check /proc/self/cmdline for debuggable indicators */
    FILE *fp = fopen("/proc/self/cmdline", "r");
    if (!fp) return 0;

    char cmdline[1024];
    size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    cmdline[n] = '\0';
    fclose(fp);

    /* Nothing specific to check in cmdline — this is a framework for
     * additional checks. The android:debuggable flag is best checked
     * from Java via ApplicationInfo.FLAG_DEBUGGABLE. */
    return 0;
}

/**
 * Check for common debugger ports on localhost.
 * JDWP typically listens on port 8700.
 *
 * @return 0 = no debugger port, 1 = debugger port detected
 */
int check_debugger_ports(void) {
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) return 0;

    char line[512];
    int debugger_port_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* JDWP default port = 8700 = 0x21FC
         * Format: sl local_address rem_address ... */
        if (strstr(line, ":21FC") != NULL ||   /* 8700 in hex */
            strstr(line, ":1388") != NULL) {    /* 5000 in hex (some debuggers) */
            /* Check if it's in LISTEN state (0A) */
            if (strstr(line, " 0A ") != NULL) {
                debugger_port_found = 1;
                break;
            }
        }
    }

    fclose(fp);
    return debugger_port_found;
}

/* ─── Response actions ─────────────────────────────────────────────── */

/**
 * Response when debugging is detected.
 *
 * Strategy: exit immediately. In production with silent defense mode,
 * this would be replaced with data corruption or artificial delays.
 */
static void on_debug_detected(const char *check_name) {
    ADBG_ERR("[!] DEBUGGING DETECTED via: %s — terminating", check_name);

    /* Wipe any sensitive data in memory before exiting */
    /* In production: call key_wipe(), state_corrupt(), etc. */

    _exit(1);  /* Use _exit to avoid atexit handlers */
}

/* ─── Main entry point ────────────────────────────────────────────── */

/**
 * Run all anti-debugging checks.
 *
 * Should be called from nativeInit() BEFORE any DEX decryption.
 * If any check fails, the process is terminated.
 */
void anti_debug_init(void) {
    /* Check 1: ptrace self-attach */
    if (check_ptrace_self_attach()) {
        on_debug_detected("ptrace_self_attach");
    }

    /* Check 2: TracerPid */
    if (check_tracer_pid()) {
        on_debug_detected("tracer_pid");
    }

    /* Check 3: Timing */
    if (check_timing()) {
        on_debug_detected("timing_analysis");
    }

    /* Check 3b: Syscall timing */
    if (check_timing_syscall()) {
        on_debug_detected("syscall_timing");
    }

    /* Check 4: JDWP threads */
    if (check_jdwp_threads()) {
        on_debug_detected("jdwp_threads");
    }

    /* Check 5: Debugger ports */
    if (check_debugger_ports()) {
        on_debug_detected("debugger_ports");
    }
}

/**
 * Continuous monitoring: run anti-debugging checks periodically.
 *
 * Designed to be called from a background thread (pthread).
 * Loops indefinitely, checking every N seconds.
 */
void anti_debug_monitor_loop(int interval_seconds) {
    if (interval_seconds <= 0) interval_seconds = 5;

    while (1) {
        /* Sleep in small increments to allow quick response */
        for (int i = 0; i < interval_seconds; i++) {
            sleep(1);

            /* Quick ptrace check every second */
            if (check_tracer_pid()) {
                on_debug_detected("continuous_monitor:tracer_pid");
            }
        }

        /* Full check every interval_seconds */
        if (check_ptrace_self_attach()) {
            on_debug_detected("continuous_monitor:ptrace");
        }
        if (check_timing()) {
            on_debug_detected("continuous_monitor:timing");
        }
        if (check_debugger_ports()) {
            on_debug_detected("continuous_monitor:ports");
        }
    }
}
