# Planning: FuckProtect Implementation

## Phase 1 — Foundation & DEX Encryption (Weeks 1-3)

### Goals
- Set up multi-module project structure
- Build DEX parser/encryptor
- Create shell Application class
- Implement basic APK repackaging
- End result: A protected APK that decrypts and loads DEX at runtime

### 1.1 Project Setup

**Actions:**
- Create three new modules: `protector`, `shell`, `common`
- Configure `settings.gradle.kts` to include all modules
- Set up `libs.versions.toml` with dependencies:
  - `commons-cli` or `picocli` for CLI argument parsing
  - `zip4j` for ZIP/APK manipulation
  - `bouncycastle` for cryptographic operations (signing)
- Configure NDK and CMake for `shell` module's native code

**Deliverables:**
- [ ] `protector/` module with `build.gradle.kts`
- [ ] `shell/` module with `build.gradle.kts` (Java + CMake)
- [ ] `common/` module with shared constants
- [ ] Updated root `settings.gradle.kts`
- [ ] Updated `libs.versions.toml`

### 1.2 Common Module

**Actions:**
- Define `PayloadFormat` — binary layout constants (magic, version, flags, offsets)
- Define `CryptoParams` — AES key size, IV size, algorithm names
- Define `ProtectorConfig` — serialization format for protector settings

**Files:**
```
common/src/main/java/com/fuckprotect/common/
├── Constants.kt          # MAGIC, VERSION, ALGORITHM constants
├── PayloadFormat.kt      # Payload header/footer definition
└── CryptoParams.kt       # AES-256-CBC parameters
```

**Deliverables:**
- [ ] All constant classes defined and documented
- [ ] Payload format matches architecture spec (see `project-arch.md`)

### 1.3 DEX Parser & Encryptor (Protector)

**Actions:**
- Implement DEX file parser:
  - Parse `dex_header` (magic, checksum, file size, header size, endian tag, etc.)
  - Parse `class_defs` section (class indices, method lists)
  - Parse `method_ids` and `code_item` structures
- Implement AES-256-CBC encryptor:
  - Use `javax.crypto.Cipher` with `AES/CBC/PKCS5Padding`
  - Generate IV randomly per encryption
  - Prepend IV to encrypted payload (needed for decryption)
- Implement payload builder:
  - Construct binary payload per `PayloadFormat` spec
  - Write: magic → version → flags → DEX length → app name → encrypted DEX → footer

**Files:**
```
protector/src/main/java/com/fuckprotect/protector/dex/
├── DexParser.kt          # Parse DEX file structure
├── DexEncryptor.kt       # AES-256-CBC encryption
└── PayloadBuilder.kt     # Build binary payload
```

**Technical Details:**
```kotlin
// DEX header structure (32 bytes minimum)
data class DexHeader(
    val magic: ByteArray,        // "dex\n035\0"
    val checksum: Int,           // adler32 checksum
    val signature: ByteArray,    // SHA-1 signature
    val fileSize: Int,
    val headerSize: Int,
    val endianTag: Int,
    // ... remaining fields
)

// Encryption
fun encryptDex(dexBytes: ByteArray, key: ByteArray): EncryptedPayload {
    val iv = SecureRandom().generateSeed(16)
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    val encrypted = cipher.doFinal(dexBytes)
    return EncryptedPayload(iv + encrypted) // IV prepended
}
```

**Deliverables:**
- [ ] DEX parser handles DEX 035 and 037 (Android 5.0+ / 8.0+)
- [ ] Encryption produces valid AES-256-CBC output with IV
- [ ] Payload builder produces correct binary layout
- [ ] Unit tests for DEX parsing and encryption

### 1.4 APK Parser & Repackager (Protector)

**Actions:**
- Implement APK parser:
  - Extract `classes.dex`, `AndroidManifest.xml`, `lib/` directory
  - Parse manifest XML to get original Application class name
  - Extract package name
- Implement repackager:
  - Create new APK with: shell DEX classes, encrypted payload, native .so
  - Modify manifest: replace Application with `ShellApplication`
  - Add `<meta-data>` for original Application class name
  - Run zipalign
  - Sign APK with provided keystore

**Files:**
```
protector/src/main/java/com/fuckprotect/protector/apk/
├── ApkParser.kt            # Extract APK contents
├── ManifestEditor.kt       # Modify AndroidManifest.xml
├── ApkPackager.kt          # Repackage protected APK
└── ApkSigner.kt            # Sign APK with keystore
```

**Technical Details:**
```kotlin
// Manifest modification
fun hijackApplication(manifestXml: String, originalApp: String): String {
    // Replace: android:name="com.example.MyApp"
    // With:    android:name="com.fuckprotect.shell.ShellApplication"
    // Add:     <meta-data android:name="FUCKPROTECT_APP_CLASS"
    //                    android:value="com.example.MyApp"/>
}
```

**Deliverables:**
- [ ] APK parser extracts all necessary components
- [ ] Manifest editor correctly replaces Application class
- [ ] Repackager produces valid APK (passes zipalign, apksigner verify)
- [ ] Integration test: protect a test APK → install → run

### 1.5 Shell Application (Runtime)

**Actions:**
- Create `ShellApplication` class:
  - Override `attachBaseContext()` (called before `onCreate()`)
  - Read encrypted payload from `assets/` or embedded in APK
  - Decrypt DEX using native JNI call
  - Create `DexClassLoader` with decrypted DEX
  - Replace `PathClassLoader` with our loader
  - Call original Application's `attachBaseContext()` and `onCreate()`
- Implement `DexLoader` class:
  - Write decrypted DEX to private directory (`/data/data/<pkg>/code_cache/`)
  - Create `DexClassLoader`
  - Delete decrypted file after loading (cleanup)

**Files:**
```
shell/src/main/java/com/fuckprotect/shell/
├── ShellApplication.java   # Entry point
└── loader/
    ├── DexLoader.java      # DEX decryption and loading
    └── ClassLoaderProxy.java  # ClassLoader replacement logic
```

**Technical Details:**
```java
public class ShellApplication extends Application {
    @Override
    protected void attachBaseContext(Context base) {
        // 1. Call native anti-debugging check
        nativeAntiDebugCheck();
        
        // 2. Read encrypted payload
        byte[] payload = readPayloadFromAssets(base);
        
        // 3. Decrypt DEX (native call)
        byte[] decryptedDex = nativeDecryptDex(payload);
        
        // 4. Write to temp file, create ClassLoader
        DexLoader dexLoader = new DexLoader(base, decryptedDex);
        dexLoader.initialize();
        
        // 5. Replace class loader
        ClassLoaderProxy.replaceClassLoader(base, dexLoader.getClassLoader());
        
        // 6. Get original Application class name from manifest
        String originalApp = ClassLoaderProxy.getOriginalAppClass(base);
        
        // 7. DON'T call super.attachBaseContext() yet
        //    First, we need to set up the class loader
        
        // 8. Create and call original Application
        Application realApp = ClassLoaderProxy.createApplication(originalApp);
        realApp.attachBaseContext(base);
        
        // 9. Store reference for onCreate forwarding
        this.realApplication = realApp;
        
        // 10. Clean up decrypted DEX file
        dexLoader.cleanup();
    }
    
    @Override
    public void onCreate() {
        super.onCreate();
        if (realApplication != null) {
            realApplication.onCreate();
        }
    }
    
    private native void nativeAntiDebugCheck();
    private native byte[] nativeDecryptDex(byte[] payload);
}
```

**Deliverables:**
- [ ] ShellApplication compiles as part of shell module
- [ ] DexLoader successfully loads a decrypted DEX
- [ ] ClassLoader proxy correctly replaces PathClassLoader
- [ ] Original Application's lifecycle methods are called
- [ ] Decrypted DEX file is cleaned up after loading

### 1.6 Native Crypto (Shell)

**Actions:**
- Implement AES-256-CBC decryption in C (for use by `DexLoader`)
- Use OpenSSL or a lightweight AES implementation
- Key derivation: SHA-256 of APK signing certificate (passed from Java)
- IV is extracted from payload (prepended during encryption)

**Files:**
```
shell/src/main/cpp/crypto/
├── aes.c                   # AES-256-CBC implementation (or use OpenSSL)
├── key_derive.c            # Derive AES key from cert hash
└── CMakeLists.txt          # Link against libcrypto if using OpenSSL
```

**Technical Details:**
```c
// Using OpenSSL
#include <openssl/aes.h>
#include <openssl/sha.h>

int decrypt_dex(const unsigned char* encrypted, int enc_len,
                const unsigned char* cert_hash, unsigned char* out) {
    // Derive key: SHA-256 of cert hash (32 bytes)
    unsigned char key[32];
    memcpy(key, cert_hash, 32);
    
    // IV is first 16 bytes of encrypted payload
    unsigned char iv[16];
    memcpy(iv, encrypted, 16);
    
    // Decrypt
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 256, &dec_key);
    AES_cbc_encrypt(encrypted + 16, out, enc_len - 16, &dec_key, iv, AES_DECRYPT);
    
    return 0;
}
```

**Deliverables:**
- [ ] Native AES decryption produces identical output to Java encryption input
- [ ] Unit test: encrypt in Java → decrypt in C → compare with original
- [ ] Key derivation is deterministic and correct

---

## Phase 2 — Anti-Debugging & Integrity (Weeks 4-5)

### Goals
- Implement native anti-debugging checks
- Implement APK signature verification
- Implement APK integrity (checksum) verification
- End result: Protected APK detects and resists debugging and tampering

### 2.1 Native Anti-Debugging

**Actions:**
- Implement `ptrace(PTRACE_TRACEME)` self-attach
- Implement `/proc/self/status` TracerPid check
- Implement timing-based detection
- Implement `/proc/self/task/` JDWP thread scan
- Combine into a single `anti_debug_init()` function
- Add continuous monitoring thread

**Files:**
```
shell/src/main/cpp/antidbg/
├── anti_debug.cpp          # Core anti-debugging
├── anti_frida.cpp          # Frida detection (optional, v2)
└── anti_root.cpp           # Root detection (optional, v2)
```

**Technical Details:**
```cpp
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

// Check 1: ptrace self-attach
int check_ptrace() {
    int ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (ret == -1) return 1; // Traced
    ptrace(PTRACE_DETACH, 0, 0, 0); // Detach ourselves
    return 0;
}

// Check 2: TracerPid
int check_tracer_pid() {
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return 0; // Can't check, assume OK
    
    char line[256];
    int traced = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:\t", 10) == 0) {
            int pid = atoi(line + 10);
            traced = (pid > 0);
            break;
        }
    }
    fclose(fp);
    return traced;
}

// Check 3: timing
int check_timing() {
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Do some computation
    volatile long sum = 0;
    for (long i = 0; i < 1000000; i++) {
        sum += i * i;
    }
    
    gettimeofday(&end, NULL);
    long elapsed = (end.tv_sec - start.tv_sec) * 1000000 + 
                   (end.tv_usec - start.tv_usec);
    
    // If it took >10x normal time, likely being debugged
    return (elapsed > 100000) ? 1 : 0; // 100ms threshold
}

// Main entry point
void anti_debug_init() {
    if (check_ptrace()) exit(1);
    if (check_tracer_pid()) exit(1);
    if (check_timing()) exit(1);
}
```

**Deliverables:**
- [ ] All three checks compile and run on target device
- [ ] Test: attaching jdb/Android Studio debugger triggers detection
- [ ] Test: app runs normally without debugger

### 2.2 Signature Verification

**Actions:**
- **Protector side:** Compute SHA-256 hash of APK signing certificate during protection, embed in native library
- **Shell side:** At runtime, compute SHA-256 of current APK's signing certificate, compare with embedded value

**Files:**
```
protector/
└── native/
    └── SignatureEmbedder.kt  # Embed cert hash in native .so

shell/
├── java/.../integrity/
│   └── SignatureVerifier.java
└── cpp/integrity/
    └── self_check.cpp
```

**Technical Details:**
```java
// Java side: get signing certificate SHA-256
public static byte[] getSigningCertHash(Context ctx) throws Exception {
    PackageInfo pi = ctx.getPackageManager().getPackageInfo(
        ctx.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
    Signature sig = pi.signingInfo.getApkContentsSigners()[0];
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    return md.digest(sig.toByteArray());
}
```

```c
// Native side: compare with embedded hash
// Embedded at build time by protector
static const unsigned char EXPECTED_CERT_HASH[32] = { 
    0xXX, 0xXX, ... // 32 bytes, replaced during protection
};

int verify_signature(const unsigned char* current_hash) {
    return memcmp(current_hash, EXPECTED_CERT_HASH, 32) == 0;
}
```

**Deliverables:**
- [ ] Protector embeds cert hash in native .so during protection
- [ ] Shell verifies cert hash at runtime before decrypting DEX
- [ ] Test: modifying APK and re-signing with different key triggers detection

### 2.3 APK Integrity Check

**Actions:**
- Protector computes SHA-256 (or CRC32) of the original APK file
- Embed hash in native library
- At runtime, recompute hash of the installed APK and compare

**Files:**
```
shell/src/main/java/com/fuckprotect/shell/integrity/
└── ApkIntegrity.java
```

**Technical Details:**
```java
public class ApkIntegrity {
    public static boolean verify(Context ctx) {
        try {
            String apkPath = ctx.getApplicationInfo().sourceDir;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream is = new FileInputStream(apkPath)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    md.update(buf, 0, n);
                }
            }
            byte[] currentHash = md.digest();
            
            // Compare with embedded hash (from native)
            byte[] expectedHash = nativeGetExpectedApkHash();
            return MessageDigest.isEqual(currentHash, expectedHash);
        } catch (Exception e) {
            return false;
        }
    }
}
```

**Deliverables:**
- [ ] APK hash computed and embedded during protection
- [ ] Runtime verification works correctly
- [ ] Test: modifying any file in APK triggers detection

---

## Phase 3 — Native Protection & Gradle Plugin (Weeks 6-8)

### Goals
- O-LLVM integration for native code obfuscation
- String encryption in native code
- Anti-hooking measures
- Gradle plugin for protector
- CLI tool packaging

### 3.1 O-LLVM Integration

**Actions:**
- Obtain O-LLVM (Obfuscator-LLVM) or use clang built-in obfuscation passes
- Configure CMake toolchain to use O-LLVM compiler
- Add obfuscation flags to CMakeLists.txt:
  - `-mllvm -fla` (control flow flattening)
  - `-mllvm -sub` (instruction substitution)
  - `-mllvm -bcf` (bogus control flow)
  - `-mllvm -split` (basic block splitting)
- Test: compiled .so should be significantly harder to reverse engineer

**Files to modify:**
```
shell/src/main/cpp/CMakeLists.txt
```

**CMake configuration:**
```cmake
# O-LLVM obfuscation flags
if(ENABLE_OBFUSCATION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
endif()
```

**Deliverables:**
- [ ] Native library compiles with O-LLVM flags
- [ ] Protected APK's native .so resists static analysis (verify with Ghidra/IDA)
- [ ] Performance impact is acceptable (< 20% slowdown)

### 3.2 Native String Encryption

**Actions:**
- Create a string encryption system:
  - All sensitive strings (error messages, file paths, class names) encrypted at compile time
  - Decrypted at runtime only when needed
  - Strings stored in an encrypted array in native code
- Protector rewrites string literals in native source before compilation

**Files:**
```
shell/src/main/cpp/utils/
└── string_obfuscate.cpp  # Encrypted string storage and decryption
```

**Technical Details:**
```cpp
// Strings encrypted with XOR key, stored as byte array
#define DECLARE_ENCRYPTED_STRING(var_name, plain_text) \
    static const uint8_t var_name##_enc[] = encrypt_string((const uint8_t*)plain_text, sizeof(plain_text)-1); \
    static const int var_name##_len = sizeof(plain_text)-1;

#define GET_STRING(var_name) decrypt_string(var_name##_enc, var_name##_len)

// Usage:
DECLARE_ENCRYPTED_STRING(SHELL_APP_CLASS, "com.fuckprotect.shell.ShellApplication");

void init() {
    const char* className = GET_STRING(SHELL_APP_CLASS);
    // ... use className ...
    memset((void*)className, 0, strlen(className)); // Wipe after use
}
```

**Deliverables:**
- [ ] All sensitive strings in native code are encrypted
- [ ] Strings are decrypted only when needed and wiped after use
- [ ] No plaintext strings visible in compiled .so binary

### 3.3 Anti-Hooking

**Actions:**
- PLT/GOT integrity check: verify function pointer tables haven't been modified
- Inline hook detection: check function prologues for jump instructions
- Self-integrity: hash our own .text section to detect patches

**Files:**
```
shell/src/main/cpp/hook/
├── anti_hook.cpp       # Anti-hooking measures
└── plt_check.cpp       # PLT/GOT integrity
```

**Deliverables:**
- [ ] Detects common hooking frameworks (Frida, substrate)
- [ ] Detects inline hooks on critical functions
- [ ] Test: Frida attach is detected and blocked

### 3.4 Gradle Plugin

**Actions:**
- Create a Gradle plugin that integrates the protector into the build process
- Plugin reads APK output from `assembleRelease`, runs protector, replaces output
- Configuration DSL in app's `build.gradle.kts`

**Files:**
```
protector/src/main/java/com/fuckprotect/protector/gradle/
├── FuckProtectPlugin.kt        # Gradle plugin entry
├── FuckProtectExtension.kt     # Configuration DSL
└── FuckProtectTask.kt          # Gradle task definition
```

**Deliverables:**
- [ ] Plugin applies to Android application projects
- [ ] `assembleRelease` produces protected APK automatically
- [ ] Configuration DSL works as documented

### 3.5 CLI Tool

**Actions:**
- Package protector as executable JAR
- CLI argument parsing with picocli or commons-cli
- Support all options: input, output, keystore, anti-debug, anti-tamper, etc.

**Deliverables:**
- [ ] `java -jar protector.jar --help` shows usage
- [ ] Full CLI interface works as documented in architecture

---

## Phase 4 — Advanced Features (Weeks 9-12)

### Goals
- Method hollowing (optional, for critical methods)
- Continuous monitoring (background anti-debugging thread)
- Emulator detection
- Silent defense mode
- Testing and hardening

### 4.1 Method Hollowing (Optional)

**Actions:**
- Implement DEX method body removal in protector
- Store hollowed method bytecode in encrypted payload
- At runtime, native code reconstructs methods in memory
- Uses ART method internals to patch code pointers

**Technical Complexity:** HIGH
- Requires deep understanding of ART method representation
- Different ART versions have different method layouts
- This is the most complex feature — may defer to v2.0

**Deliverables:**
- [ ] Protector can hollow specified methods from DEX
- [ ] Runtime reconstructs hollowed methods correctly
- [ ] Protected APK with hollowed methods runs identically to original

### 4.2 Continuous Monitoring

**Actions:**
- Spawn background thread in native code after initialization
- Periodically re-run anti-debugging checks
- Monitor for Frida/server injection throughout app lifecycle
- Check APK integrity periodically (not just at startup)

**Deliverables:**
- [ ] Background thread runs checks every N seconds
- [ ] Detection triggers appropriate response (exit, corrupt, etc.)
- [ ] Minimal performance impact (< 1% CPU)

### 4.3 Emulator Detection

**Actions:**
- Check for emulator-specific properties:
  - `ro.hardware` = `goldfish`, `ranchu`, `vmware`
  - `ro.product.model` contains `Emulator`, `SDK`
  - Presence of `/dev/qemu_pipe`
  - CPU info shows QEMU/Bochs
  - Limited sensor list
  - Missing Google Play Services

**Deliverables:**
- [ ] Detects common Android emulators
- [ ] Configurable: can whitelist known-good emulator fingerprints

### 4.4 Silent Defense Mode

**Actions:**
- Instead of crashing/exiting on detection:
  - Return false data to debugger
  - Introduce artificial delays
  - Corrupt sensitive data silently
  - Make the app "work" but not correctly
- Much harder for reverse engineer to identify the defense mechanism

**Deliverables:**
- [ ] Silent mode option in protector config
- [ ] App appears to work but returns incorrect data when tampering detected
- [ ] No obvious crash or error message

### 4.5 Testing & Hardening

**Actions:**
- Test against common reverse engineering tools:
  - **jdb / Android Studio debugger** — should be blocked by anti-debugging
  - **Frida** — should be detected by anti-Frida
  - **JADX / JEB** — should only see encrypted DEX, shell code
  - **Ghidra / IDA** — should see O-LLVM obfuscated native code
  - **APKiD** — should not be identified as a known packer (unique signature)
- Test protected APKs on various Android versions (5.0 - 15.0)
- Performance benchmarking

**Deliverables:**
- [ ] Test report: protection effectiveness against each tool
- [ ] Compatibility report: Android 5.0 through 15.0
- [ ] Performance report: startup time impact, runtime overhead

---

## Technical Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **InMemoryDexClassLoader not available on API 21-25** | High | Fall back to DexClassLoader with temp file + immediate deletion |
| **ART version differences break method loading** | Medium | Test on multiple Android versions; use reflection carefully |
| **O-LLVM incompatible with NDK Clang version** | Medium | Use pre-built O-LLVM binary or clang's built-in passes |
| **Anti-debugging causes false positives on some devices** | Low | Make checks configurable; add whitelist for known-safe scenarios |
| **Method hollowing breaks on complex DEX structures** | Medium | Start with full DEX encryption only; add hollowing incrementally |
| **APK integrity check fails on split APKs** | Medium | Handle app bundles and split APKs separately |
| **Protection adds significant APK size increase** | Low | Use efficient encryption; compress payload; size optimization flag |

---

## Success Criteria

1. **Protected APK cannot be decompiled to meaningful source code** — JADX shows only shell classes
2. **Protected APK detects and blocks debugger attachment** — jdb, Android Studio debugger
3. **Protected APK detects tampering** — modified APK or re-signed with different key
4. **Protected APK runs correctly on target devices** — Android 5.0+ (API 21+)
5. **Performance impact is minimal** — < 200ms startup overhead, < 1% runtime overhead
6. **Protector tool is easy to use** — CLI and Gradle plugin both functional
7. **Unique fingerprint** — Not identified by APKiD as a known packer
