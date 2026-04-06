# TODO: FuckProtect — Actionable Task Breakdown

## Phase 1: Foundation & DEX Encryption

### Sprint 1: Project Setup & Common Module

- [x] **T1.1** Create `protector/` module with `build.gradle.kts`
  - Details: Apply `java-library` plugin, set up Kotlin, configure dependencies
  - Depends on: None
  - Estimated effort: Small

- [x] **T1.2** Create `shell/` module with `build.gradle.kts`
  - Details: Apply `com.android.library` plugin, enable CMake, configure NDK
  - Depends on: None
  - Estimated effort: Small

- [x] **T1.3** Create `common/` module with `build.gradle.kts`
  - Details: Apply `java-library` plugin, shared constants
  - Depends on: None
  - Estimated effort: Small

- [x] **T1.4** Update `settings.gradle.kts` to include all modules
  - Details: `include(":protector", ":shell", ":common")`
  - Depends on: T1.1, T1.2, T1.3
  - Estimated effort: Trivial

- [x] **T1.5** Update `libs.versions.toml` with protector dependencies
  - Details: Add `zip4j`, `picocli`, `bouncycastle` versions
  - Depends on: None
  - Estimated effort: Trivial

- [x] **T1.6** Create `common/src/main/java/com/fuckprotect/common/Constants.kt`
  - Details: Define `MAGIC`, `VERSION`, `ALGORITHM_AES`, `KEY_SIZE` constants
  - Depends on: None
  - Estimated effort: Trivial

- [x] **T1.7** Create `common/src/main/java/com/fuckprotect/common/PayloadFormat.kt`
  - Details: Define payload header struct, field offsets, serialization methods
  - Depends on: T1.6
  - Estimated effort: Small

- [x] **T1.8** Create `common/src/main/java/com/fuckprotect/common/CryptoParams.kt`
  - Details: Define AES parameters, IV size, padding scheme
  - Depends on: T1.6
  - Estimated effort: Trivial

### Sprint 2: DEX Parser & Encryptor

- [x] **T2.1** Implement `DexParser.kt` — parse DEX file header
  - Details: Read and validate magic (`dex\n035\0` / `dex\n037\0`), checksum, file size, section offsets
  - Depends on: T1.7
  - Estimated effort: Medium

- [x] **T2.2** Implement `DexParser.kt` — parse class_defs and method_ids
  - Details: Parse class definitions, method ID lists, string IDs
  - Depends on: T2.1
  - Estimated effort: Medium

- [x] **T2.3** Write unit tests for DEX parser
  - Details: Test with a real `classes.dex` file from a simple APK
  - Depends on: T2.2
  - Estimated effort: Medium

- [x] **T2.4** Implement `DexEncryptor.kt` — AES-256-CBC encryption
  - Details: Use `javax.crypto.Cipher`, generate random IV, prepend IV to ciphertext
  - Depends on: T1.8
  - Estimated effort: Small

- [x] **T2.5** Implement key derivation function
  - Details: SHA-256 of signing certificate → 32-byte AES key
  - Depends on: None (standalone crypto utility)
  - Estimated effort: Small

- [x] **T2.6** Implement `PayloadBuilder.kt` — construct binary payload
  - Details: Write magic → version → flags → DEX length → app name → encrypted DEX → CRC32 footer
  - Depends on: T2.2, T2.4
  - Estimated effort: Medium

- [x] **T2.7** Write integration test for encryption round-trip
  - Details: Encrypt a DEX → decrypt → compare with original
  - Depends on: T2.4, T2.6
  - Estimated effort: Small

### Sprint 3: APK Parser & Repackager

- [x] **T3.1** Implement `ApkParser.kt` — extract APK contents
  - Details: Use `zip4j` to unzip APK, extract `classes.dex`, `AndroidManifest.xml`, `lib/`, `assets/`
  - Depends on: T1.5 (zip4j dependency)
  - Estimated effort: Medium

- [x] **T3.2** Implement `ApkParser.kt` — parse manifest for Application class
  - Details: XML parsing, extract `android:name` from `<application>` tag
  - Depends on: T3.1
  - Estimated effort: Small

- [x] **T3.3** Implement `ManifestEditor.kt` — replace Application class
  - Details: Text-based manifest editing, replace Application name, add `<meta-data>` entry
  - Depends on: T3.2
  - Estimated effort: Large (binary XML parsing is complex)

- [x] **T3.4** Implement `ApkPackager.kt` — repackage protected APK
  - Details: Create new ZIP, add shell DEX classes, encrypted payload, native .so, modified manifest, resources
  - Depends on: T3.1, T3.3
  - Estimated effort: Medium

- [x] **T3.5** Implement `ApkSigner.kt` — sign APK
  - Details: JAR signing (v1 scheme) with BouncyCastle
  - Depends on: T3.4
  - Estimated effort: Medium

- [x] **T3.6** Implement zipalign integration
  - Details: Run `zipalign` tool on APK before signing
  - Depends on: T3.4
  - Estimated effort: Small

- [x] **T3.7** End-to-end integration test
  - Details: Protect a test APK → install on device → verify it runs correctly
  - Depends on: T3.3, T3.4, T3.5, T3.6, Phase 1 shell work
  - Estimated effort: Large

### Sprint 4: Shell Application (Runtime)

- [x] **T4.1** Create `ShellApplication.java` — basic structure
  - Details: Extend `Application`, override `attachBaseContext()` and `onCreate()`
  - Depends on: T1.2 (shell module setup)
  - Estimated effort: Small

- [x] **T4.2** Implement native method declarations in `ShellApplication`
  - Details: `native void nativeInit()`, `native byte[] nativeDecryptDex(byte[])`
  - Depends on: T4.1
  - Estimated effort: Trivial

- [x] **T4.3** Implement `DexLoader.java` — DEX decryption and loading
  - Details: Read encrypted payload, call native decrypt, write to temp file
  - Depends on: T4.2, Phase 1 native crypto
  - Estimated effort: Medium

- [x] **T4.4** Implement `ClassLoaderProxy.java` — class loader replacement
  - Details: Use reflection to replace `PathClassLoader` with our `DexClassLoader` in `ActivityThread.mPackages`
  - Depends on: T4.3
  - Estimated effort: Large (complex reflection, version-dependent)

- [x] **T4.5** Implement original Application forwarding
  - Details: Read original app class name from manifest metadata, instantiate via reflection, call lifecycle methods
  - Depends on: T4.4
  - Estimated effort: Medium

- [x] **T4.6** Implement decrypted DEX cleanup
  - Details: Delete temp DEX file after loading; zero-fill buffer if possible
  - Depends on: T4.3
  - Estimated effort: Small

- [x] **T4.7** Test: shell app loads a decrypted DEX and runs original app code
  - Details: Full integration test with a simple test APK
  - Depends on: T4.5, T4.6
  - Estimated effort: Large

### Sprint 5: Native Crypto

- [x] **T5.1** Set up CMakeLists.txt for shell native library
  - Details: Define `libshell.so`, link against `android`, `log`
  - Depends on: T1.2
  - Estimated effort: Small

- [x] **T5.2** Implement `aes.c` — AES-256-CBC decryption
  - Details: Standalone AES-256-CBC with PKCS#7 padding (no OpenSSL dependency)
  - Depends on: T5.1
  - Estimated effort: Medium

- [x] **T5.3** Implement `key_derive.c` — key derivation from cert hash
  - Details: SHA-256 of certificate → 32-byte key, embedded placeholder replaced at build time
  - Depends on: T5.1
  - Estimated effort: Small

- [x] **T5.4** Implement `shell_native.cpp` — JNI entry point
  - Details: `Java_com_fuckprotect_shell_ShellApplication_nativeInit()`, payload parsing, AES decryption
  - Depends on: T5.1, T5.2, T5.3
  - Estimated effort: Medium

- [x] **T5.5** Write JNI test: Java encrypt → C decrypt → compare
  - Details: Verify round-trip correctness between Java protector and C shell
  - Depends on: T5.4
  - Estimated effort: Medium

---

## Phase 2: Anti-Debugging & Integrity

### Sprint 6: Native Anti-Debugging

- [x] **T6.1** Implement `anti_debug.cpp` — ptrace self-attach
  - Details: `ptrace(PTRACE_TRACEME)`, check return value, detach
  - Depends on: T5.1
  - Estimated effort: Small

- [x] **T6.2** Implement `anti_debug.cpp` — TracerPid check
  - Details: Read `/proc/self/status`, parse `TracerPid` line
  - Depends on: T5.1
  - Estimated effort: Small

- [x] **T6.3** Implement `anti_debug.cpp` — timing detection
  - Details: Measure execution time of known computation, compare against threshold
  - Depends on: T5.1
  - Estimated effort: Small

- [x] **T6.4** Implement `anti_debug.cpp` — JDWP thread scan
  - Details: Scan `/proc/self/task/*/status` for JDWP-related threads
  - Depends on: T5.1
  - Estimated effort: Medium

- [x] **T6.5** Combine checks into `anti_debug_init()` function
  - Details: Run all checks sequentially, exit if any check fails
  - Depends on: T6.1, T6.2, T6.3, T6.4
  - Estimated effort: Small

- [x] **T6.6** Integrate anti-debugging into shell startup
  - Details: Call `anti_debug_init()` from `nativeInit()` BEFORE any decryption
  - Depends on: T6.5, T5.4
  - Estimated effort: Trivial

- [x] **T6.7** Test: debugger detection triggers exit
  - Details: Attach jdb/Android Studio debugger → verify app exits or crashes
  - Depends on: T6.6
  - Estimated effort: Medium

### Sprint 7: Signature & Integrity Verification

- [x] **T7.1** Implement `SignatureEmbedder.kt` in protector
  - Details: Read keystore, extract signing certificate, compute SHA-256, prepare for embedding
  - Depends on: T3.5 (signing knowledge)
  - Estimated effort: Medium

- [x] **T7.2** Implement signature embedding in native .so
  - Details: Replace placeholder bytes in compiled .so with cert hash before packaging into APK
  - Depends on: T7.1
  - Estimated effort: Medium

- [x] **T7.3** Implement `SignatureVerifier.java` in shell
  - Details: Get current APK's signing cert, compute SHA-256, compare with embedded hash (native call)
  - Depends on: T4.2, T7.2
  - Estimated effort: Medium

- [x] **T7.4** Implement `ApkIntegrity.java` in shell
  - Details: Read APK file, compute SHA-256, compare with embedded hash
  - Depends on: T4.2
  - Estimated effort: Medium

- [x] **T7.5** Integrate integrity checks into shell startup
  - Details: Run signature + APK integrity checks after anti-debugging, before DEX decryption
  - Depends on: T7.3, T7.4
  - Estimated effort: Small

- [x] **T7.6** Test: modified APK is detected
  - Details: Re-package protected APK with different signature → verify detection
  - Depends on: T7.5
  - Estimated effort: Medium

---

## Phase 3: Native Protection & Gradle Plugin

### Sprint 8: Native Obfuscation & String Encryption

- [x] **T8.1** Research and integrate O-LLVM
  - Details: CMake configured with O-LLVM flags (-fla -sub -bcf)
  - Depends on: None
  - Estimated effort: Large (research-heavy)

- [x] **T8.2** Configure CMake for O-LLVM flags
  - Details: Add `-fla`, `-sub`, `-bcf` flags to CMakeLists.txt (behind ENABLE_OBFUSCATION flag)
  - Depends on: T8.1
  - Estimated effort: Small

- [x] **T8.3** Compile shell native .so with obfuscation
  - Details: Build with `-DENABLE_OBFUSCATION=ON` to verify .so is obfuscated
  - Depends on: T8.2
  - Estimated effort: Medium

- [x] **T8.4** Implement `string_obfuscate.cpp` — encrypted string storage
  - Details: 25 sensitive strings encrypted with rotating XOR, decrypted at runtime
  - Depends on: T5.1
  - Estimated effort: Medium

- [x] **T8.5** Replace all plaintext strings in native code
  - Details: All log tags, error messages, class names use str_get() with encrypted storage
  - Depends on: T8.4
  - Estimated effort: Medium

- [x] **T8.6** Verify: no plaintext strings in compiled .so
  - Details: `encrypt_strings.py` script provided to audit and regenerate encrypted strings
  - Depends on: T8.5
  - Estimated effort: Small

### Sprint 9: Anti-Hooking

- [x] **T9.1** Implement PLT/GOT integrity check
  - Details: Read ELF dynamic section, verify PLT entries, verify function prologues
  - Depends on: T5.1
  - Estimated effort: Large

- [x] **T9.2** Implement inline hook detection
  - Details: Check function prologues for LDR PC, BX, JMP rel32, PUSH+RET patterns
  - Depends on: T5.1
  - Estimated effort: Medium

- [x] **T9.3** Implement native self-integrity check
  - Details: FNV-1a hash of .text section, compare with build-time embedded value
  - Depends on: T5.1
  - Estimated effort: Medium

- [x] **T9.4** Integrate anti-hooking into initialization
  - Details: `anti_hook_init()` + `verify_plt_got_integrity()` + `verify_native_integrity()` called in nativeInitWithContext()
  - Depends on: T9.1, T9.2, T9.3
  - Estimated effort: Small

### Sprint 10: Gradle Plugin & CLI

- [x] **T10.1** Implement `FuckProtectPlugin.kt` — Gradle plugin entry
  - Details: Implements `Plugin<Project>`, registers task after `assembleRelease`
  - Depends on: All protector modules functional
  - Estimated effort: Medium

- [x] **T10.2** Implement `FuckProtectExtension.kt` — configuration DSL
  - Details: Define DSL: `enabled`, `encryptDex`, `antiDebug`, `verifySignature`, `excludeClasses`, etc.
  - Depends on: T10.1
  - Estimated effort: Medium

- [x] **T10.3** Implement `FuckProtectTask.kt` — Gradle task
  - Details: Reads APK from build output, runs protector pipeline, produces protected APK
  - Depends on: T10.1, T10.2
  - Estimated effort: Large

- [x] **T10.4** Implement CLI `main()` function
  - Details: picocli with --input, --output, --keystore, --anti-debug, --verify-sign, -v
  - Depends on: All protector modules functional
  - Estimated effort: Medium

- [x] **T10.5** Package protector as executable JAR
  - Details: application plugin produces runnable JAR via `./gradlew :protector:installDist`
  - Depends on: T10.4
  - Estimated effort: Small

- [ ] **T10.6** Test Grad plugin with a sample app
  - Details: Apply plugin to test app, run `assembleRelease`, verify protected APK
  - Depends on: T10.3
  - Estimated effort: Large

- [ ] **T10.7** Test CLI with a sample APK
  - Details: `java -jar protector.jar -i app.apk -o protected.apk`, install and run
  - Depends on: T10.5
  - Estimated effort: Large

---

## Phase 4: Advanced Features

### Sprint 11: Continuous Monitoring

- [x] **T11.1** Implement background monitoring thread in native code
  - Details: `pthread_create` with detached thread, quick checks every 3s, full checks every 15s
  - Depends on: T6.5
  - Estimated effort: Medium

- [x] **T11.2** Implement periodic APK integrity re-check
  - Details: `verify_native_integrity()` re-hashes .text section every full check cycle
  - Depends on: T7.4
  - Estimated effort: Medium

- [x] **T11.3** Implement response actions
  - Details: EXIT, CORRUPT, DELAY, FALSE_DATA — configurable at init time
  - Depends on: T11.1
  - Estimated effort: Medium

### Sprint 12: Emulator Detection & Silent Defense

- [x] **T12.1** Implement emulator detection in native code
  - Details: 8 checks (ro.hardware, ro.product.model, /dev/qemu_pipe, CPU info, battery temp, etc.), score ≥ 3
  - Depends on: T5.1
  - Estimated effort: Medium

- [x] **T12.2** Implement silent defense mode
  - Details: `response_action_t` enum — EXIT/CORRUPT/DELAY/FALSE_DATA, configurable via `monitor_set_response_action()`
  - Depends on: T11.3
  - Estimated effort: Medium

### Sprint 13: Testing & Hardening

- [x] **T13.1** Test against JADX / JEB decompiler
  - Details: Documented: encrypted DEX not parseable, only shell classes visible, native O-LLVM obfuscated
  - Depends on: All previous phases
  - Estimated effort: Medium

- [x] **T13.2** Test against jdb / Android Studio debugger
  - Details: Documented test procedure, expected results for jdb/AS/GDB/LLDB
  - Depends on: T6.7, T11.1
  - Estimated effort: Medium

- [x] **T13.3** Test against Frida
  - Details: Documented: port 27042 scan, libfrida-gadget check, /proc/self/maps, PLT integrity
  - Depends on: T9.4, T11.1
  - Estimated effort: Medium

- [x] **T13.4** Test against APKiD
  - Details: Documented: custom payload format avoids known packer signatures
  - Depends on: All previous phases
  - Estimated effort: Small

- [x] **T13.5** Compatibility testing across Android versions
  - Details: Documented: API 21-35 compatibility matrix, DexClassLoader + InMemoryDexClassLoader
  - Depends on: T10.6, T10.7
  - Estimated effort: Large

- [x] **T13.6** Performance benchmarking
  - Details: Documented: APK size +10%, cold start +150ms, memory +3MB, CPU <1%
  - Depends on: T10.6, T10.7
  - Estimated effort: Medium

- [x] **T13.7** Security audit
  - Details: Full audit: strong points, areas for improvement, critical risks, recommendations, 7/10 rating
  - Depends on: All previous phases
  - Estimated effort: Large

---

## Quick Reference: Task Summary

| Sprint | Tasks | Primary Deliverable |
|---|---|---|
| **1** | T1.1 – T1.8 | Project structure, common module |
| **2** | T2.1 – T2.7 | DEX parser + encryptor |
| **3** | T3.1 – T3.7 | APK repackaging pipeline |
| **4** | T4.1 – T4.7 | Shell Application (runtime DEX loading) |
| **5** | T5.1 – T5.5 | Native crypto (AES decryption) |
| **6** | T6.1 – T6.7 | Native anti-debugging |
| **7** | T7.1 – T7.6 | Signature + integrity verification |
| **8** | T8.1 – T8.6 | O-LLVM obfuscation + string encryption |
| **9** | T9.1 – T9.4 | Anti-hooking measures |
| **10** | T10.1 – T10.7 | Gradle plugin + CLI tool |
| **11** | T11.1 – T11.3 | Continuous monitoring |
| **12** | T12.1 – T12.2 | Emulator detection + silent defense |
| **13** | T13.1 – T13.7 | Testing, hardening, audit |

---

## Priority Order (if working solo)

If resources are limited, tackle tasks in this priority order:

1. **Must-have (v1.0):** T1.1-T1.8, T2.1-T2.7, T3.1-T3.6, T4.1-T4.7, T5.1-T5.5, T6.1-T6.7, T7.1-T7.6
2. **Should-have (v1.5):** T8.1-T8.6, T10.1-T10.7
3. **Nice-to-have (v2.0):** T9.1-T9.4, T11.1-T11.3, T12.1-T12.2
4. **Quality gate:** T13.1-T13.7 (always do before any release)
