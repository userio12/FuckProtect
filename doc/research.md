# Research: Android APK Protection Techniques

## 1. Overview

This document consolidates research from open-source APK protection projects (dpt-shell, JiGu 360 / Jiagu, SecShell, zShield, and others) and commercial solutions (DexGuard, AppSealing, LIAPP, DashO) to inform the design of **FuckProtect** — a self-built APK protector comparable to commercial-grade tools.

---

## 2. Referenced Projects

| Project | URL | Language | Core Technique |
|---|---|---|---|
| **dpt-shell** | github.com/luoyesiqiu/dpt-shell | Java 59%, C++ 34% | DEX method hollowing + runtime reconstruction |
| **JiGu 360 (Jiagu)** | 360.cn | Native + Java | AES-CBC DEX encryption + shell DEX wrapper |
| **SecShell** | Various analyses | Java + Native | RC4 + SM4 dual-cipher DEX encryption |
| **zShield** | Tencent | Java + Native | XXTEA encryption + ELF/DEX body protection |
| **dexVirgo** | Various | Java | DEX obfuscation + string encryption |
| **APKiD** | github.com/rednaga/APKiD | Python | Packer/protector detection (YARA rules) |

---

## 3. Core Protection Techniques

### 3.1 DEX Encryption

#### Techniques Observed

| Technique | Description | Used By |
|---|---|---|
| **AES-CBC + PKCS5** | First 512 bytes of payload encrypted with hardcoded key/IV | JiGu 360 |
| **XOR (single-byte)** | Secondary DEX first 112 bytes XORed with 0x66 | JiGu 360 |
| **RC4 + SM4 dual cipher** | Two layers of encryption for stronger protection | SecShell |
| **XXTEA** | Lightweight block cipher for ELF/DEX bodies | zShield |
| **White-box cryptography** | Embedded key tables in lookup tables | DexGuard |
| **Selective class encryption** | Only sensitive classes encrypted, not entire DEX | Various |

#### Recommended Approach for FuckProtect
- **Primary encryption:** AES-256-CBC with a key derived from a build-time constant (e.g., SHA-256 hash of the APK signing certificate)
- **Secondary obfuscation:** XOR with rotating 4-byte key on DEX header magic bytes
- **Optional:** XXTEA for native `.so` files

### 3.2 DEX Method Hollowing (dpt-shell approach)

Instead of encrypting the entire DEX, dpt-shell **removes method bytecode** from the DEX file and stores it externally. At runtime, native code reconstructs the methods in memory.

**Process:**
1. **Packing phase:** Parse DEX, identify target methods, replace their `code_item` with stubs, store original bytecode in an encrypted payload
2. **Runtime phase:** Native hook intercepts method execution, decrypts original bytecode, patches it back into memory via `Dobby`/`bhook`
3. **Advantage:** DEX on disk is non-functional; methods only exist decrypted in memory during execution

**Dependencies used by dpt-shell:**
- `Dobby` — dynamic binary instrumentation framework
- `bhook` — Android PLT hook library (ByteDance)
- `dexmaker` — runtime DEX generation
- `dx` — DEX compilation

### 3.3 Shell DEX Architecture (JiGu 360 approach)

The entire original DEX is encrypted and wrapped with a **shell DEX** that acts as the entry point.

**Payload Layout:**
```
[AES-CBC Encrypted Payload][Original App Name (1 byte length + UTF-8)]
[4-byte Big-Endian DEX Size Headers][classes.dex]
[Additional XOR-Encrypted DEXs][4-byte Shell DEX Length Footer]
```

**Process:**
1. Encrypt original `classes.dex` → append to shell
2. Replace `android:name` in `AndroidManifest.xml` with shell's Application class
3. Store original Application class name in payload header
4. Shell DEX decrypts payload → writes decrypted DEX to internal storage → loads via `DexClassLoader`

---

## 4. Class Loading Mechanisms

### 4.1 DexClassLoader (Disk-based)

```java
DexClassLoader classLoader = new DexClassLoader(
    decryptedDexPath,        // path to decrypted .dex file
    optimizedDirectory,       // /data/data/<pkg>/code_cache
    nativeLibraryPath,        // path to native .so libs
    parentClassLoader         // context.getClassLoader()
);
```

**Used by:** JiGu 360, most commercial packers

**Workflow:**
1. Shell Application's `attachBaseContext()` is called first
2. Decrypt DEX payload to private internal directory
3. Create `DexClassLoader` pointing to decrypted DEX
4. Use reflection to replace the app's `PathClassLoader` with the new `DexClassLoader`
5. Call the original Application's `attachBaseContext()` and `onCreate()`

### 4.2 InMemoryDexClassLoader (Android 8.0+)

```java
ByteBuffer dexBuffer = ...; // decrypted DEX in memory
InMemoryDexClassLoader classLoader = new InMemoryDexClassLoader(dexBuffer, parent);
```

**Advantage:** DEX never touches disk — exists only in memory
**Limitation:** Requires API 26+ (minSdk for FuckProtect is 21)

### 4.3 Class Loader Hijacking (PathClassLoader Replacement)

```java
// Get the current ActivityThread
Class<?> activityThread = Class.forName("android.app.ActivityThread");
Method currentActivityThread = activityThread.getMethod("currentActivityThread");
Object at = currentActivityThread.invoke(null);

// Replace the mPackages field's ClassLoader
Field mPackages = activityThread.getDeclaredField("mPackages");
mPackages.setAccessible(true);
// ... replace with our DexClassLoader
```

---

## 5. Anti-Debugging Techniques

### 5.1 Detection Methods

| Technique | Implementation | Detection Difficulty |
|---|---|---|
| **TracerPid check** | Read `/proc/self/status`, check if `TracerPid > 0` | Low |
| **ptrace self-attach** | Call `ptrace(PTRACE_TRACEME)` — fails if already traced | Medium |
| **Debug.isDebuggerConnected()** | Java API check | Very Low |
| **JDWP thread detection** | Scan `/proc/self/task/<tid>/status` for JDWP threads | Medium |
| **Timing analysis** | Measure execution time — debuggers cause delays | High |
| **Debug flags check** | Check `android:debuggable` flag at runtime | Low |
| **/proc/net/tcp scan** | Detect debugger ports (JDWP on port 8700) | Medium |
| **Frida detection** | Scan for frida-gadget, frida-server, suspicious ports | Medium |
| **Root detection** | Check for su binary, Magisk, rooted filesystems | Medium |

### 5.2 Recommended Implementation for FuckProtect

```cpp
// Native anti-debugging (harder to bypass than Java)

// 1. ptrace self-attach
int ptrace_result = ptrace(PTRACE_TRACEME, 0, 0, 0);
if (ptrace_result == -1) {
    // Debugger detected — exit or corrupt
    exit(1);
}

// 2. TracerPid check
FILE* fp = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int tracer_pid = atoi(line + 10);
        if (tracer_pid > 0) {
            exit(1);
        }
    }
}
fclose(fp);

// 3. Timing check
struct timeval start, end;
gettimeofday(&start, NULL);
// ... do some work ...
gettimeofday(&end, NULL);
long elapsed = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
if (elapsed > THRESHOLD) {
    exit(1); // Likely being debugged
}
```

### 5.3 Evasion Techniques

| Technique | Description |
|---|---|
| **Syscall wrapping** | Use raw syscalls instead of libc wrappers to bypass hooks |
| **Inline assembly** | Embed anti-debugging checks in inline asm to avoid PLT hooks |
| **Delayed checks** | Don't check at startup — spread checks throughout app lifecycle |
| **Silent corruption** | Instead of exiting, return false data to debugger |
| **Multi-threaded checks** | Run anti-debugging on a separate thread continuously |

---

## 6. Anti-Tampering Techniques

### 6.1 Signature Verification

```java
// Get the APK signing certificate
PackageInfo packageInfo = getPackageManager().getPackageInfo(
    getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
Signature[] signatures = packageInfo.signingInfo.getApkContentsSigners();

// Compute SHA-256 hash
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(signatures[0].toByteArray());

// Compare with known-good hash (stored obfuscated in native code)
byte[] expected = getExpectedSignature(); // from native
if (!MessageDigest.isEqual(hash, expected)) {
    // Tampered — exit or behave incorrectly
    exit(1);
}
```

**dpt-shell approach:** `-vs` flag computes SHA-256 of signing certificate and embeds it in the native runtime for runtime verification.

### 6.2 APK Integrity / Checksum Verification

```java
// Verify the APK hasn't been modified
String apkPath = getApplicationInfo().sourceDir;
File apkFile = new File(apkPath);

// Compute CRC32/SHA-256 of the APK file
// Compare with value stored in native code at build time
```

### 6.3 Native Code Integrity

```cpp
// Verify our own native library hasn't been patched
// Compute hash of .text section at runtime
ElfW(Ehdr)* elf = (ElfW(Ehdr)*)get_base_address("libmyapplication.so");
// Hash the code section, compare with build-time value
```

### 6.4 Manifest Tampering Detection

- Verify `AndroidManifest.xml` hasn't been modified
- Check `android:debuggable` is false
- Verify component names match expected values

---

## 7. Native Code Protection

### 7.1 O-LLVM Obfuscation

Use **Obfuscator-LLVM (O-LLVM)** to compile native code with:

| Flag | Technique | Effect |
|---|---|---|
| `-mllvm -fla` | Control Flow Flattening | Flattens if/switch/loop structures |
| `-mllvm -sub` | Instruction Substitution | Replaces instructions with equivalent complex sequences |
| `-mllvm -bcf` | Bogus Control Flow | Inserts dead code branches |
| `-mllvm -split` | Basic Block Split | Splits basic blocks to complicate CFG analysis |

### 7.2 String Encryption in Native Code

```cpp
// Encrypt all string literals at compile time
// Decrypt at runtime on first use
#define DECRYPT_STRING(id) decrypt_string(id)

// Strings stored encrypted in a separate section
static const uint8_t encrypted_strings[] = { 0x3a, 0x1f, ... };

const char* decrypt_string(int id) {
    // AES or XOR decrypt, return plaintext
    // Only decrypt when needed, not all at once
}
```

### 7.3 Anti-Hooking

| Technique | Description |
|---|---|
| **PLT/GOT integrity check** | Verify PLT/GOT entries haven't been modified |
| **Inline hook detection** | Check function prologues for jump instructions |
| **Self-checking** | Hash own `.text` section to detect patches |
| **bhook/Dobby counter** | Detect known hooking frameworks |

---

## 8. Packer Architecture Patterns

### 8.1 Pattern A: Full DEX Encryption (JiGu 360)

```
[Build Time]
Original APK → Encrypt classes.dex → Create shell.dex → 
Replace Application in manifest → Merge → Repackage → Sign

[Runtime]
shell.Application → decrypt payload → write to private dir →
DexClassLoader → call original Application
```

### 8.2 Pattern B: Method Hollowing (dpt-shell)

```
[Build Time]
Original APK → Parse DEX → hollow out method bodies →
Store bytecode in encrypted payload → Inject native loader →
Modify manifest → Repackage → Sign

[Runtime]
Native hook intercepts method calls → decrypts bytecode →
patches into memory → executes original method
```

### 8.3 Pattern C: Hybrid (Recommended for FuckProtect)

```
[Build Time]
1. Encrypt entire original DEX with AES-256-CBC
2. Hollow out critical methods (security-sensitive code)
3. Store both: encrypted DEX + hollowed method bytecode
4. Inject shell Application + native protection library
5. Embed signature hash, checksum, anti-debugging code
6. O-LLVM compile native code with obfuscation

[Runtime]
1. Shell Application starts
2. Native anti-debugging + integrity checks run
3. Decrypt DEX to memory (not disk if possible)
4. Load via InMemoryDexClassLoader / DexClassLoader
5. Reconstruct hollowed methods in memory
6. Call original Application
7. Continuous anti-tampering monitoring
```

---

## 9. Commercial Tool Analysis

### 9.1 What They Do

| Feature | DexGuard | 360 JiGu | AppSealing | LIAPP |
|---|---|---|---|---|
| DEX encryption | ✅ | ✅ | ✅ | ✅ |
| String encryption | ✅ | ✅ | ✅ | ✅ |
| Anti-debugging | ✅ | ✅ | ✅ | ✅ |
| Root detection | ✅ | ✅ | ✅ | ✅ |
| Anti-tampering | ✅ | ✅ | ✅ | ✅ |
| Anti-hooking | ✅ | ❌ | ✅ | ✅ |
| Emulator detection | ✅ | ✅ | ✅ | ✅ |
| RASP | ✅ | ❌ | ✅ | ✅ |
| White-box crypto | ✅ | ❌ | ❌ | ✅ |
| Native SO protection | ✅ | ✅ | ✅ | ✅ |

### 9.2 What Open Source Lacks

- **White-box cryptography** implementations
- **Sophisticated RASP** (Runtime Application Self-Protection)
- **Behavioral analysis** (detecting hooking frameworks at runtime)
- **Server-side token verification**

---

## 10. Key Takeaways for FuckProtect

1. **Use hybrid approach:** Full DEX encryption + selective method hollowing
2. **Native-first design:** Anti-debugging, anti-tampering, and decryption all in native code (harder to reverse)
3. **Multi-layer encryption:** AES-256 for DEX, XOR for headers, XXTEA for native libs
4. **Distributed checks:** Don't do all checks at startup — spread throughout app lifecycle
5. **Memory-only decryption:** Use InMemoryDexClassLoader when available (API 26+), fallback to DexClassLoader with immediate file deletion
6. **O-LLVM for native code:** Mandatory — unobfuscated native code is trivially reversed
7. **Silent defense:** Don't just crash — return false data, slow down, or behave incorrectly when tampering is detected
8. **Build tool design:** The protector should be a CLI/Gradle plugin that takes an APK and outputs a protected APK
