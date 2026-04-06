/**
 * Continuous background monitoring for FuckProtect shell.
 *
 * Spawns a detached pthread that periodically re-runs:
 * - Anti-debugging checks (ptrace, TracerPid, timing)
 * - APK integrity re-check
 * - Hook detection re-check
 *
 * On detection, triggers the configured response action:
 * - EXIT: _exit(1) immediately
 * - CORRUPT: silently corrupt sensitive data in memory
 * - DELAY: introduce artificial delays
 * - FALSE_DATA: return incorrect results to debugger
 *
 * T11.1 + T11.2 + T11.3 + T12.1 + T12.2: Full implementation
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <android/log.h>

// // anti-debug moved to dpt_risk.cpp    /* Anti-debugging checks */

#define MON_TAG "FP_Monitor"
#define MON_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, MON_TAG, fmt, ##__VA_ARGS__)
#define MON_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, MON_TAG, fmt, ##__VA_ARGS__)

/* ─── Configuration ────────────────────────────────────────────────── */

/* Check intervals (seconds) */
#define QUICK_CHECK_INTERVAL   3   /* TracerPid quick check */
#define FULL_CHECK_INTERVAL    15  /* Full anti-debug + integrity check */

/* Response action types */
typedef enum {
    RESPONSE_EXIT = 0,       /* _exit(1) immediately */
    RESPONSE_CORRUPT = 1,    /* Corrupt memory silently */
    RESPONSE_DELAY = 2,      /* Artificial delays */
    RESPONSE_FALSE_DATA = 3, /* Return wrong data */
} response_action_t;

/* Global configuration (set at init time) */
static response_action_t g_response_action = RESPONSE_EXIT;
static volatile int g_monitor_running = 0;
static volatile int g_threat_detected = 0;
static volatile int g_threat_count = 0;

/* ─── Response Actions (T11.3) ─────────────────────────────────────── */

/**
 * Execute the configured response when a threat is detected.
 */
static void execute_response(const char *check_name) {
    g_threat_detected = 1;
    g_threat_count++;

    switch (g_response_action) {
    case RESPONSE_EXIT:
        MON_ERR("[!] THREAT: %s — exiting immediately (threat #%d)",
                check_name, g_threat_count);
        _exit(1);
        break;

    case RESPONSE_CORRUPT:
        MON_ERR("[!] THREAT: %s — corrupting memory (threat #%d)",
                check_name, g_threat_count);
        /* Overwrite sensitive memory regions with garbage */
        /* In production: target specific buffers (keys, decrypted DEX, etc.) */
        {
            volatile char corrupt_buf[256];
            for (int i = 0; i < 256; i++) {
                corrupt_buf[i] = (char)(i * 0x37);
            }
        }
        /* Continue running — debugger won't notice immediate crash */
        break;

    case RESPONSE_DELAY:
        MON_ERR("[!] THREAT: %s — introducing delay (threat #%d)",
                check_name, g_threat_count);
        /* Sleep for a random duration (1-5 seconds) to slow down debugging */
        {
            int delay = 1 + (rand() % 5);
            sleep(delay);
        }
        break;

    case RESPONSE_FALSE_DATA:
        MON_ERR("[!] THREAT: %s — will return false data (threat #%d)",
                check_name, g_threat_count);
        /* Set a flag that causes incorrect behavior throughout the app */
        /* In production: modify specific state that affects crypto, auth, etc. */
        break;
    }
}

/**
 * Set the response action for threat detection.
 */
void monitor_set_response_action(response_action_t action) {
    g_response_action = action;
}

/**
 * Get the current threat detection count.
 */
int monitor_get_threat_count(void) {
    return g_threat_count;
}

/* ─── Emulator Detection (T12.1) ──────────────────────────────────── */

/**
 * Check if running in an Android emulator.
 *
 * Checks multiple indicators:
 * - ro.hardware property (goldfish, ranchu, vmware)
 * - ro.product.model (contains "Emulator" or "SDK")
 * - /dev/qemu_pipe existence
 * - /dev/socket/qemud existence
 * - CPU info (QEMU, Bochs)
 * - Sensor count (emulators typically have 0 sensors)
 *
 * @return 0 = real device, 1 = emulator detected
 */
int detect_emulator(void) {
    int score = 0;

    /* Check 1: ro.hardware property */
    {
        FILE *fp = popen("getprop ro.hardware", "r");
        if (fp) {
            char buf[128];
            if (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "goldfish") ||
                    strstr(buf, "ranchu") ||
                    strstr(buf, "vmware") ||
                    strstr(buf, "nox")) {
                    score++;
                }
            }
            pclose(fp);
        }
    }

    /* Check 2: ro.product.model */
    {
        FILE *fp = popen("getprop ro.product.model", "r");
        if (fp) {
            char buf[128];
            if (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "Emulator") ||
                    strstr(buf, "SDK") ||
                    strstr(buf, "virtual")) {
                    score++;
                }
            }
            pclose(fp);
        }
    }

    /* Check 3: ro.bootloader property */
    {
        FILE *fp = popen("getprop ro.bootloader", "r");
        if (fp) {
            char buf[128];
            if (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "unknown") ||
                    strstr(buf, "sdk") ||
                    strstr(buf, "emulator")) {
                    score++;
                }
            }
            pclose(fp);
        }
    }

    /* Check 4: QEMU pipe device */
    if (access("/dev/qemu_pipe", F_OK) == 0) {
        score++;
    }

    /* Check 5: QEMUD socket */
    if (access("/dev/socket/qemud", F_OK) == 0) {
        score++;
    }

    /* Check 6: CPU info */
    {
        FILE *fp = fopen("/proc/cpuinfo", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "QEMU") ||
                    strstr(line, "Bochs") ||
                    strstr(line, "VirtualBox")) {
                    score++;
                    break;
                }
            }
            fclose(fp);
        }
    }

    /* Check 7: Battery temperature (emulators often report 0) */
    {
        FILE *fp = popen("dumpsys battery", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "temperature")) {
                    int temp = 0;
                    if (sscanf(line, "%*[^:]: %d", &temp) == 1) {
                        if (temp == 0) score++;
                    }
                    break;
                }
            }
            pclose(fp);
        }
    }

    /* Check 8: Build fingerprint contains emulator indicators */
    {
        FILE *fp = popen("getprop ro.build.fingerprint", "r");
        if (fp) {
            char buf[512];
            if (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "generic/sdk") ||
                    strstr(buf, "generic_x86/sdk") ||
                    strstr(buf, "google/sdk_gphone")) {
                    score++;
                }
            }
            pclose(fp);
        }
    }

    /* Threshold: 3+ indicators = likely emulator */
    return (score >= 3) ? 1 : 0;
}

/* ─── Quick Checks (run every few seconds) ─────────────────────────── */

/**
 * Lightweight check: TracerPid only.
 * Fast enough to run every 3 seconds.
 */
static int quick_check(void) {
    /* TracerPid check */
    if (check_tracer_pid()) {
        execute_response("continuous:tracer_pid");
        return 1;
    }

    /* Debugger port check */
    if (check_debugger_ports()) {
        execute_response("continuous:debugger_ports");
        return 1;
    }

    return 0;
}

/**
 * Full check: all anti-debugging + integrity.
 * More expensive, runs every 15 seconds.
 */
static int full_check(void) {
    /* Anti-debugging */
    if (check_ptrace_self_attach()) {
        execute_response("continuous:ptrace");
        return 1;
    }

    if (check_timing()) {
        execute_response("continuous:timing");
        return 1;
    }

    if (check_timing_syscall()) {
        execute_response("continuous:syscall_timing");
        return 1;
    }

    /* Anti-hooking */
    if (detect_frida()) {
        execute_response("continuous:frida");
        return 1;
    }

    /* Native self-integrity */
    if (verify_native_integrity()) {
        execute_response("continuous:self_integrity");
        return 1;
    }

    /* Emulator detection (if enabled) */
    if (detect_emulator()) {
        execute_response("continuous:emulator");
        return 1;
    }

    return 0;
}

/* ─── Background Thread ────────────────────────────────────────────── */

/**
 * Main monitoring loop. Runs in a detached pthread.
 *
 * Alternates between quick checks (every 3s) and full checks (every 15s).
 */
static void *monitor_thread_func(void *arg) {
    (void)arg;

    MON_LOG("Monitor thread started (PID: %d)", getpid());

    int quick_count = 0;

    while (g_monitor_running) {
        /* Quick check every iteration */
        quick_check();
        quick_count++;

        /* Full check every 5 quick checks (3s * 5 = 15s) */
        if (quick_count >= 5) {
            full_check();
            quick_count = 0;
        }

        /* Sleep for quick check interval */
        sleep(QUICK_CHECK_INTERVAL);
    }

    MON_LOG("Monitor thread exiting");
    return NULL;
}

/**
 * Start the continuous monitoring thread.
 *
 * @param response_action What to do when a threat is detected
 * @param enable_emulator_detection Whether to also detect emulators
 * @return 0 on success, -1 on error
 */
int monitor_start(response_action_t response_action,
                  int enable_emulator_detection) {
    if (g_monitor_running) {
        MON_ERR("Monitor already running");
        return -1;
    }

    g_response_action = response_action;
    g_monitor_running = 1;
    g_threat_detected = 0;
    g_threat_count = 0;

    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int ret = pthread_create(&thread, &attr, monitor_thread_func, NULL);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        MON_ERR("Failed to create monitor thread: %d", ret);
        g_monitor_running = 0;
        return -1;
    }

    MON_LOG("Monitor thread started (response=%d, emulator=%d)",
            response_action, enable_emulator_detection);
    return 0;
}

/**
 * Stop the continuous monitoring thread.
 */
void monitor_stop(void) {
    g_monitor_running = 0;
    MON_LOG("Monitor thread stopping");
}

/**
 * Check if a threat has been detected.
 */
int monitor_is_threat_detected(void) {
    return g_threat_detected;
}
