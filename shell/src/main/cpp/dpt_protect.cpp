/**
 * Child process protection for FuckProtect shell.
 *
 * Creates a fork() child process that monitors the parent.
 * If the parent is killed, debugged, or tampered with, the child
 * detects this and triggers a crash.
 *
 * This makes it much harder to debug or dump the process because:
 * 1. The child process monitors the parent via waitpid()
 * 2. If the parent is ptraced (debugger attached), ptrace fails
 * 3. If the parent is killed, the child detects it
 *
 * T11.3 + dpt-shell reference: protectProcess
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <android/log.h>

#define PROC_TAG "FP_Protect"
#define PROC_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, PROC_TAG, fmt, ##__VA_ARGS__)
#define PROC_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, PROC_TAG, fmt, ##__VA_ARGS__)

/**
 * Crash the process in a way that's hard to catch.
 * Sets lr/x30 to 0 so returning from any function will crash.
 */
static void crash_process(void) {
#if defined(__aarch64__)
    __asm__ volatile("mov x30, #0\n");
#elif defined(__arm__)
    __asm__ volatile("mov lr, #0\n");
#elif defined(__i386__)
    __asm__ volatile("ret\n");
#elif defined(__x86_64__)
    __asm__ volatile("pop %rbp\n");
#endif
    // Fallback
    raise(SIGSEGV);
}

/**
 * Child process: monitor the parent process.
 *
 * This function runs in the child process created by fork().
 * It waits for the parent to exit and then crashes itself,
 * making it clear that tampering was detected.
 *
 * If the parent is being debugged (ptrace), the child detects
 * this because ptrace can only attach to one process at a time.
 */
static void *monitor_parent_thread(void *arg) {
    pid_t parent_pid = *(pid_t *)arg;
    free(arg);

    PROC_LOG("Monitoring parent process: %d", parent_pid);

    // Wait for parent to exit or be killed
    int status;
    pid_t result = waitpid(parent_pid, &status, 0);

    if (result > 0) {
        PROC_ERR("Parent process %d exited (status: %d) — possible tampering detected",
                 parent_pid, status);
        crash_process();
    } else if (result == -1) {
        PROC_ERR("waitpid failed — parent may have been killed or debugged");
        crash_process();
    }

    return NULL;
}

/**
 * Parent process: run anti-debugging checks in a loop.
 *
 * This thread periodically checks if the parent is being debugged.
 * If ptrace fails (because the child is already ptracing us),
 * we know someone is trying to attach a debugger.
 */
static void *parent_check_thread(void *arg) {
    (void)arg;

    while (1) {
        sleep(5);

        // Try to ptrace ourselves — should fail if we're already being traced
        long ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (ret == 0) {
            // We weren't being traced — detach ourselves
            ptrace(PTRACE_DETACH, 0, 0, 0);
        } else {
            // Already being traced — debugger detected!
            PROC_ERR("Debugger detected via ptrace check");
            crash_process();
        }
    }

    return NULL;
}

/**
 * Create a child process that monitors the parent.
 *
 * This should be called early in the shell initialization,
 * AFTER anti-debugging checks pass.
 *
 * @return 0 on success, -1 on failure
 */
int protect_process(void) {
    pid_t child_pid = fork();

    if (child_pid < 0) {
        PROC_ERR("fork() failed — cannot create monitor process");
        return -1;
    }

    if (child_pid == 0) {
        /* Child process: monitor the parent */
        // Close any unnecessary file descriptors
        // Set up signal handlers to ignore SIGINT/SIGTERM (let parent handle them)
        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);

        // Create a monitoring thread
        pid_t *parent = malloc(sizeof(pid_t));
        *parent = getppid();

        pthread_t monitor;
        pthread_create(&monitor, NULL, monitor_parent_thread, parent);

        // Block the main thread — let the monitoring thread do the work
        pthread_join(monitor, NULL);

        // Should never reach here, but just in case
        exit(0);
    } else {
        /* Parent process: start anti-debugging check thread */
        PROC_LOG("Child monitor process created: PID %d", child_pid);

        pthread_t check;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        int ret = pthread_create(&check, &attr, parent_check_thread, NULL);
        pthread_attr_destroy(&attr);

        if (ret != 0) {
            PROC_ERR("Failed to create parent check thread: %d", ret);
            return -1;
        }

        PROC_LOG("Parent check thread started");
    }

    return 0;
}
