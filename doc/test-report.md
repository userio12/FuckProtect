# Test Report: FuckProtect Phase 1 & Phase 2

## Test Summary

| Test File | Task | Type | Status |
|---|---|---|---|
| `ConstantsTest.kt` | T1.6, T1.8 | JVM Unit | ✅ Ready |
| `DexParserTest.kt` | T2.3 | JVM Unit | ✅ Ready |
| `DexEncryptionRoundTripTest.kt` | T2.7 | JVM Unit | ✅ Ready |
| `KeyDerivationTest.kt` | T2.5 | JVM Unit | ✅ Ready |
| `ManifestEditorTest.kt` | T3.3 | JVM Unit | ✅ Ready |
| `EndToEndProtectionTest.kt` | T3.7 | JVM Unit | ✅ Ready |
| `DexLoaderTest.kt` | T4.7 | Android Instrumented | ✅ Ready |
| `JniCryptoRoundTripTest.kt` | T5.5 | Android Instrumented | ✅ Ready |
| `AntiDebugTest.kt` | T6.7 | Android Instrumented | ✅ Ready |
| `SignatureTamperTest.kt` | T7.6 | Android Instrumented | ✅ Ready |

## Running Tests

### Unit Tests (JVM — no device needed)

```bash
# Run all unit tests
./gradlew :common:test :protector:test

# Run specific module tests
./gradlew :common:test        # Constants, CryptoParams
./gradlew :protector:test     # DEX parser, encryptor, manifest, E2E

# Run with verbose output
./gradlew :protector:test --info
```

### Android Instrumented Tests (requires device/emulator)

```bash
# Connect a device or start an emulator first
adb devices

# Run all instrumented tests
./gradlew :shell:connectedAndroidTest

# Or use the test runner script
./scripts/run-tests.sh all
```

### Manual Anti-Debug Test (T6.7)

To verify debugger detection actually works:

```bash
# 1. Install the shell test APK
adb install -r shell/build/outputs/apk/debug/shell-debug.apk

# 2. Without debugger — app should start normally
adb shell am start -n com.fuckprotect.shell/.TestActivity

# 3. With debugger — app should exit immediately
#    Attach Android Studio debugger or run:
#    adb shell am set-debug-app com.fuckprotect.shell
#    Then launch the app — it should crash/exit
```

### Manual Signature Tamper Test (T7.6)

```bash
# 1. Protect an APK with --verify-sign flag
java -jar protector.jar -i app.apk -o protected.apk ... --verify-sign

# 2. Install and verify it runs
adb install -r protected.apk

# 3. Decompile, modify, re-sign with a DIFFERENT key
#    (or use apktool to modify and re-sign)
apktool d protected.apk -o modified
# ... make changes ...
apktool b modified -o tampered.apk
# Sign with debug key (different from original)
apksigner sign --ks debug.keystore tampered.apk

# 4. Install tampered APK — it should exit on startup
adb install -r tampered.apk
# App will call _exit(1) during signature verification failure
```

## Test Coverage by Component

### Protector Tool (JVM)
- **Constants & CryptoParams**: All values validated
- **DEX Parser**: Header parsing, version detection, method/class counts, invalid input
- **DEX Encryptor**: Round-trip encrypt/decrypt, wrong key rejection, IV uniqueness
- **Payload Builder**: Header serialization, string read/write, CRC32 verification
- **Manifest Editor**: Application hijacking, metadata injection, verification
- **Key Derivation**: Deterministic output, different inputs → different keys
- **End-to-End**: Full pipeline from fake APK → protected APK with valid structure

### Shell Runtime (Native + Android)
- **DexLoader**: Cleanup after initialization, invalid input handling
- **ClassLoaderProxy**: Metadata retrieval, reflection safety
- **JNI Crypto**: Native init stability, payload validation, magic verification
- **Anti-Debug**: TracerPid check, debug flag detection, native init behavior
- **Signature Verification**: Cert hash computation, determinism, hex formatting
- **APK Integrity**: Hash computation, verification flow

## Remaining Test Gaps

| Gap | Risk | Mitigation |
|---|---|---|
| No real DEX file in tests | Medium | Tests use synthetic DEX headers; real DEX tested in E2E |
| Anti-debug can't test debugger attachment in CI | Low | Documented manual test procedure |
| Signature tamper can't re-sign in automated test | Low | Documented manual test procedure |
| No fuzz testing for payload parser | Medium | Add fuzz tests in Phase 3 |
| No performance benchmarks | Low | Add in Phase 4 (T13.6) |

## Test Infrastructure

```
protector/src/test/
├── com/fuckprotect/protector/
│   ├── dex/
│   │   ├── DexParserTest.kt              # T2.3
│   │   ├── DexEncryptionRoundTripTest.kt # T2.7
│   │   └── KeyDerivationTest.kt          # T2.5
│   └── apk/
│       ├── ManifestEditorTest.kt         # T3.3
│       └── EndToEndProtectionTest.kt     # T3.7

shell/src/androidTest/
└── com/fuckprotect/shell/
    ├── JniCryptoRoundTripTest.kt         # T5.5
    ├── loader/
    │   └── DexLoaderTest.kt              # T4.7
    ├── antidbg/
    │   └── AntiDebugTest.kt              # T6.7
    └── integrity/
        └── SignatureTamperTest.kt        # T7.6

common/src/test/
└── com/fuckprotect/common/
    └── ConstantsTest.kt                  # T1.6, T1.8
```
