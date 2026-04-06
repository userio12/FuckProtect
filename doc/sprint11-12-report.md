# Sprint 11–12 Implementation Report

## Sprint 11: Continuous Monitoring (T11.1–T11.3)

### Files Created
| File | Purpose |
|---|---|
| `shell/.../antidbg/continuous_monitor.cpp` | Background pthread + emulator detection + response actions |

### Implementation Details

#### T11.1: Background Monitoring Thread
- `pthread_create()` with `PTHREAD_CREATE_DETACHED` — no join needed
- Quick check every **3 seconds**: TracerPid + debugger ports
- Full check every **15 seconds**: ptrace + timing + Frida + self-integrity + emulator
- Thread starts AFTER all initial checks pass in `nativeInitWithContext()`

#### T11.2: Periodic APK Integrity Re-check
- Full check includes `verify_native_integrity()` — re-hashes .text section
- TracerPid re-check on every quick cycle (every 3s)
- Frida detection re-check on every full cycle (every 15s)

#### T11.3: Response Actions
Four response modes configurable at init time:

| Mode | Behavior | Use Case |
|---|---|---|
| `RESPONSE_EXIT` | `_exit(1)` immediately | Default — maximum security |
| `RESPONSE_CORRUPT` | Overwrite memory with garbage, continue | Silent defense — debugger sees corruption |
| `RESPONSE_DELAY` | Sleep 1–5 seconds randomly | Slow down reverse engineering |
| `RESPONSE_FALSE_DATA` | Set flags that cause incorrect behavior | Debugger gets wrong results |

Global threat counter `g_threat_count` tracks all detections.

## Sprint 12: Emulator Detection & Silent Defense (T12.1–T12.2)

### T12.1: Emulator Detection
**8 checks**, threshold score ≥ 3 = emulator detected:

| # | Check | What it detects |
|---|---|---|
| 1 | `ro.hardware` property | goldfish, ranchu, vmware, nox |
| 2 | `ro.product.model` property | "Emulator", "SDK", "virtual" |
| 3 | `ro.bootloader` property | "unknown", "sdk", "emulator" |
| 4 | `/dev/qemu_pipe` existence | QEMU pipe device |
| 5 | `/dev/socket/qemud` existence | QEMUD socket |
| 6 | `/proc/cpuinfo` | QEMU, Bochs, VirtualBox |
| 7 | Battery temperature = 0 | Emulators report 0°C |
| 8 | `ro.build.fingerprint` | "generic/sdk", "google/sdk_gphone" |

Integrated into both initial checks AND continuous monitoring loop.

### T12.2: Silent Defense Mode
- Configurable via `monitor_set_response_action()`
- Default: `RESPONSE_EXIT` (crash on detection)
- Production: read from payload flags set by protector config
- When enabled:
  - No visible crash or error
  - Memory corruption, artificial delays, or false data returned
  - Debugger can't identify the defense mechanism

### Integration

```
nativeInitWithContext()
  │
  ├── anti_debug_init()           [initial checks]
  ├── signature verification      [initial check]
  ├── anti_hook_init()            [initial check]
  ├── verify_plt_got_integrity()  [initial check]
  ├── verify_native_integrity()   [initial check]
  │
  └── monitor_start()             [continuous background thread]
        │
        ├── Quick check (every 3s): TracerPid + ports
        └── Full check (every 15s): ptrace + timing + Frida + self-integrity + emulator
```
