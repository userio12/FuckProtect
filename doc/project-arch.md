# Project Architecture: FuckProtect

## 1. System Overview

FuckProtect is a **two-component** APK protection system:

1. **Protector Tool** (`protector` module) — A CLI/Gradle plugin that takes an APK as input and outputs a protected APK.
2. **Shell Runtime** (`shell` module) — Injected into the protected APK; handles decryption, class loading, anti-debugging, and anti-tampering at runtime.

```
┌─────────────────────────────────────────────────────┐
│                    Build Time                        │
│                                                     │
│  Original APK ──→ [Protector Tool] ──→ Protected APK │
│                     │                                │
│                     ├── Encrypt DEX                  │
│                     ├── Hollow methods               │
│                     ├── Inject shell DEX             │
│                     ├── Inject native .so            │
│                     ├── Modify manifest              │
│                     ├── Embed signature hash         │
│                     └── Repackage & re-sign           │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│                     Runtime                          │
│                                                     │
│  Protected APK ──→ [Shell Runtime]                  │
│                     │                                │
│                     ├── Anti-debugging checks        │
│                     ├── Integrity verification       │
│                     ├── Decrypt DEX to memory        │
│                     ├── Load classes dynamically     │
│                     ├── Reconstruct hollowed methods │
│                     └── Launch original Application  │
└─────────────────────────────────────────────────────┘
```

---

## 2. Module Structure

```
FuckProtect/
├── protector/                          # Build-time protector tool
│   ├── build.gradle.kts
│   └── src/main/java/com/fuckprotect/protector/
│       ├── Protector.kt                # Main entry point (CLI)
│       ├── apk/
│       │   ├── ApkParser.kt            # Parse APK structure
│       │   ├── ApkSigner.kt            # Re-sign protected APK
│       │   ├── ManifestEditor.kt       # Modify AndroidManifest.xml
│       │   └── ApkPackager.kt          # Repackage protected APK
│       ├── dex/
│       │   ├── DexParser.kt            # Parse DEX file format
│       │   ├── DexEncryptor.kt         # Encrypt DEX files
│       │   ├── MethodHollower.kt       # Hollow out method bodies
│       │   └── DexRebuilder.kt         # Rebuild DEX with stubs
│       ├── native/
│       │   ├── NativeLibInjector.kt    # Inject shell .so into APK
│       │   └── SignatureEmbedder.kt   # Embed signing cert hash
│       ├── config/
│       │   ├── ProtectorConfig.kt      # Configuration model
│       │   └── ExclusionRules.kt       # Class/method exclusion
│       └── utils/
│           ├── ZipUtils.kt             # APK zip manipulation
│           ├── AlignUtils.kt           # zipalign
│           └── CryptoUtils.kt          # AES/XXTEA utilities
│
├── shell/                              # Runtime shell (injected into protected APK)
│   ├── build.gradle.kts
│   └── src/main/
│       ├── java/com/fuckprotect/shell/
│       │   ├── ShellApplication.java   # Hijacked Application class
│       │   ├── loader/
│       │   │   ├── DexLoader.java      # DEX decryption & loading
│       │   │   ├── ClassLoaderProxy.java # ClassLoader hijacking
│       │   │   └── MemoryDexLoader.java # InMemoryDexClassLoader wrapper
│       │   ├── integrity/
│       │   │   ├── SignatureVerifier.java # APK signature check
│       │   │   ├── ApkIntegrity.java   # APK checksum verification
│       │   │   └── NativeIntegrity.java # Native lib integrity
│       │   └── utils/
│       │       ├── ReflectUtils.java   # Reflection helpers
│       │       └── Logger.java         # Obfuscated logging
│       └── cpp/
│           ├── CMakeLists.txt
│           ├── antidbg/
│           │   ├── anti_debug.cpp      # Anti-debugging checks
│           │   ├── anti_frida.cpp      # Frida/hook detection
│           │   └── anti_root.cpp       # Root detection
│           ├── crypto/
│           │   ├── aes.c               # AES-256-CBC implementation
│           │   ├── xxtea.c             # XXTEA for native libs
│           │   └── key_derive.c        # Key derivation
│           ├── integrity/
│           │   ├── self_check.cpp      # Native self-integrity
│           │   └── plt_check.cpp       # PLT/GOT hook detection
│           ├── hook/
│           │   ├── native_hook.cpp     # Method reconstruction hook
│           │   └── anti_hook.cpp       # Anti-hooking measures
│           ├── shell_native.cpp        # Main native entry point (JNI)
│           └── utils/
│               ├── string_obfuscate.cpp # String encryption
│               └── syscall_wrap.S      # Raw syscall wrappers
│
├── common/                             # Shared code between protector and shell
│   ├── build.gradle.kts
│   └── src/main/java/com/fuckprotect/common/
│       ├── Constants.kt                # Shared constants
│       ├── PayloadFormat.kt            # Payload layout definition
│       └── CryptoParams.kt             # Encryption parameters
│
├── app/                                # Test/dummy app (for development)
│   └── (existing test app)
│
├── doc/                                # Documentation
│   ├── research.md
│   ├── project-arch.md
│   ├── planning.md
│   └── todo.md
│
├── gradle/
│   └── libs.versions.toml
├── build.gradle.kts
├── settings.gradle.kts
└── gradle.properties
```

---

## 3. Data Flow

### 3.1 Protector Tool Flow

```
Input APK
    │
    ▼
┌─────────────────┐
│  1. Parse APK   │  Extract: DEX files, manifest, native libs, resources
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│  2. Extract Config  │  Read protector config (exclusions, encryption params)
└────────┬────────────┘
         │
         ▼
┌──────────────────────────┐
│  3. Parse DEX Files      │  Read DEX headers, class data, method lists
└────────┬─────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  4. Hollow Target Methods   │  Replace code_item with stubs for sensitive methods
└────────┬────────────────────┘
         │
         ▼
┌──────────────────────────┐
│  5. Encrypt DEX Payload  │  AES-256-CBC encrypt entire DEX (or hollowed DEX)
└────────┬─────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  6. Build Shell DEX/Classes  │  Compile shell runtime, inject config
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  7. Compile Native .so       │  Build shell native libs with O-LLVM
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  8. Modify Manifest          │  Replace Application with ShellApplication
│                              │  Store original Application name in metadata
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  9. Embed Signature Hash     │  Compute SHA-256 of signing cert, embed in native
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│ 10. Assemble Protected APK   │  Package: shell DEX + encrypted payload + native .so
│                              │  Run zipalign
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 11. Sign APK        │  Sign with provided keystore
└────────┬────────────┘
         │
         ▼
    Output Protected APK
```

### 3.2 Runtime Shell Flow

```
App Launch
    │
    ▼
┌──────────────────────────┐
│  ShellApplication.onCreate│  Entry point (replaces original Application)
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  1. Native Anti-Debugging    │  ptrace, TracerPid, timing checks
│     (runs BEFORE any decryption)
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  2. Signature Verification   │  Verify APK signing certificate
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  3. APK Integrity Check      │  Verify APK hasn't been modified
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  4. Extract Encrypted DEX    │  Read encrypted payload from assets/raw
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  5. Decrypt DEX              │  AES-256-CBC decrypt to memory (ByteBuffer)
└────────┬─────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  6. Load DEX                        │  InMemoryDexClassLoader (API 26+) or
│                                     │  DexClassLoader (temp file, delete after)
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  7. Replace ClassLoader             │  Hijack PathClassLoader with our loader
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  8. Reconstruct Hollowed Methods    │  Native hooks patch methods back in memory
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  9. Call Original Application       │  Reflect original Application.onCreate()
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ 10. Continuous Monitoring           │  Background thread: anti-debug, integrity
└─────────────────────────────────────┘
```

---

## 4. Payload Format

The encrypted payload appended to the protected APK follows this binary layout:

```
Offset  Size            Description
──────  ────            ───────────
0x00    4 bytes         Magic: "FUCK" (0x4655434B)
0x04    2 bytes         Version (uint16, current: 1)
0x06    2 bytes         Flags (uint16): 
                          bit 0 = has hollowed methods
                          bit 1 = has native protection
                          bit 2 = signature verification enabled
0x08    4 bytes         Encrypted DEX length (uint32, big-endian)
0x0C    4 bytes         Hollowed methods data length (uint32, big-endian)
0x10    4 bytes         Original Application class name length (uint32)
0x14    variable        Original Application class name (UTF-8)
0x14+N  variable        Encrypted DEX data (AES-256-CBC)
  ...   variable        Hollowed method bytecode (AES-256-CBC)
  ...   4 bytes         Payload footer: CRC32 of all preceding data
  ...   4 bytes         Total payload length (uint32, big-endian)
```

---

## 5. Native Library Architecture

### 5.1 `libshell.so` (Shell Native Library)

```
libshell.so
├── JNI Entry Point
│   └── Java_com_fuckprotect_shell_ShellApplication_nativeInit()
│
├── Anti-Debugging Module
│   ├── anti_debug_init()        — ptrace self-attach
│   ├── check_tracer_pid()       — /proc/self/status
│   ├── check_timing()           — timing analysis
│   ├── check_debuggable_flag()  — android:debuggable
│   └── continuous_monitor()     — background thread
│
├── Crypto Module
│   ├── aes_decrypt()            — AES-256-CBC decryption
│   ├── key_derive()             — Derive key from cert hash
│   └── string_decrypt()         — Runtime string decryption
│
├── Integrity Module
│   ├── verify_signature()       — APK signature check
│   ├── verify_apk_checksum()    — APK integrity
│   ├── verify_native_integrity() — .so self-check
│   └── plt_got_check()          — hook detection
│
├── Hook Module (for method reconstruction)
│   ├── hook_art_method()        — ART method hook
│   ├── patch_method_code()      — Reconstruct hollowed methods
│   └── anti_hook_detect()       — Detect if we're being hooked
│
└── Utilities
    ├── syscall()                — Raw syscalls (avoid libc hooks)
    ├── get_base_address()       — Find loaded .so base address
    └── find_symbol()            — Resolve symbols
```

### 5.2 Compilation (O-LLVM)

```cmake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -split")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -split")
```

---

## 6. Key Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Language** | Kotlin (protector) + Java/C++ (shell) | Kotlin for build tool; Java/C++ for runtime compatibility |
| **DEX encryption** | AES-256-CBC | Industry standard, fast, well-supported on Android |
| **DEX loading** | InMemoryDexClassLoader (API 26+), DexClassLoader fallback | Memory-only is ideal; fallback for older devices |
| **Method hollowing** | Optional, for critical methods only | Full hollowing is complex; start with full DEX encryption |
| **Anti-debugging** | Native-first (C++) | Java anti-debugging is trivially bypassed |
| **Native obfuscation** | O-LLVM | Best open-source native obfuscation |
| **Protector interface** | CLI + Gradle plugin | CLI for standalone use; Gradle plugin for CI/CD |
| **Key storage** | Derived from APK signing cert + build-time constant | No hardcoded keys; unique per build |

---

## 7. Build System

### 7.1 Protector as Gradle Plugin

```kotlin
// In protected app's build.gradle.kts
plugins {
    id("com.fuckprotect.protector") version "1.0.0"
}

fuckProtect {
    enabled = true
    encryption = "AES-256-CBC"
    antiDebug = true
    antiTamper = true
    signatureVerification = true
    methodHollowing = false  // opt-in for v1
    excludeClasses = listOf(
        "com.example.**.BuildConfig",
        "androidx.**"
    )
}
```

### 7.2 Protector CLI

```bash
# Standalone usage
java -jar protector.jar \
    --input app-release.apk \
    --output app-release-protected.apk \
    --keystore release.jks \
    --key-alias mykey \
    --key-pass mykeypass \
    --store-pass storepass \
    --anti-debug \
    --anti-tamper \
    --verify-sign
```

---

## 8. Security Model

### 8.1 Threat Model

| Threat | Mitigation |
|---|---|
| **Static analysis of DEX** | DEX fully encrypted; no plaintext DEX on disk |
| **Dynamic analysis (debugging)** | Native anti-debugging checks, distributed throughout lifecycle |
| **APK repackaging** | Signature verification + APK integrity checks |
| **Native code analysis** | O-LLVM obfuscation + string encryption + anti-hooking |
| **Memory dumping** | Hollowed methods + encrypted strings + runtime decryption |
| **Hooking (Frida, Xposed)** | Anti-Frida checks + PLT integrity + syscall wrappers |
| **Automated unpacking** | Custom payload format + method hollowing + silent defense |

### 8.2 Defense in Depth

```
Layer 1: Anti-debugging (native, pre-decryption)
Layer 2: Signature verification (native)
Layer 3: APK integrity check (native + Java)
Layer 4: DEX encryption (AES-256-CBC)
Layer 5: Method hollowing (for critical methods)
Layer 6: String encryption (native)
Layer 7: Native code obfuscation (O-LLVM)
Layer 8: Anti-hooking (PLT check, inline hook detection)
Layer 9: Continuous monitoring (background thread)
Layer 10: Silent defense (false data, not just crash)
```

---

## 9. Version Roadmap

| Version | Features |
|---|---|
| **v1.0** | Full DEX encryption, shell Application, native anti-debugging, signature verification |
| **v1.5** | InMemoryDexClassLoader support, O-LLVM native obfuscation, APK integrity checks |
| **v2.0** | Method hollowing, anti-Frida/hooking, string encryption, Gradle plugin |
| **v2.5** | Continuous monitoring, silent defense, emulator detection |
| **v3.0** | White-box cryptography, RASP engine, server-side verification |
