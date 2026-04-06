# FuckProtect — Setup & Usage Guide

A complete step-by-step guide to setting up, building, and using FuckProtect to protect Android APKs from reverse engineering.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Project Setup](#2-project-setup)
3. [Building the Protector Tool](#3-building-the-protector-tool)
4. [Building the Shell Runtime](#4-building-the-shell-runtime)
5. [Protecting Your First APK](#5-protecting-your-first-apk)
6. [Integrating as a Gradle Plugin](#6-integrating-as-a-gradle-plugin)
7. [Verifying Protection](#7-verifying-protection)
8. [Configuration Options](#8-configuration-options)
9. [Troubleshooting](#9-troubleshooting)
10. [Project Structure Reference](#10-project-structure-reference)

---

## 1. Prerequisites

### Required Software

| Tool | Minimum Version | How to Install |
|---|---|---|
| **JDK** | 17+ | `apt install openjdk-17-jdk` or download from [Adoptium](https://adoptium.net) |
| **Android SDK** | API 36 (compileSdk) | Install via Android Studio or `sdkmanager` |
| **Android NDK** | 27.3.13750724 | Install via `sdkmanager --install "ndk;27.3.13750724"` |
| **CMake** | 4.3.0+ | Bundled with Android Studio, or `apt install cmake` |
| **Git** | Any recent | `apt install git` |

### Recommended Tools

| Tool | Purpose |
|---|---|
| **Android Studio** | IDE for building and testing |
| **zipalign** | APK alignment (comes with Android SDK build-tools) |
| **apksigner** | APK signing (comes with Android SDK build-tools) |
| **JADX** | Verify protection quality by decompiling |
| **adb** | Install and test protected APKs on device |

### Verify Prerequisites

```bash
# Check Java
java -version
# Expected: openjdk version "17.x.x"

# Check Android SDK
echo $ANDROID_HOME
# Expected: path to your Android SDK

# Check NDK
ls $ANDROID_HOME/ndk/27.3.13750724/
# Expected: NDK files listed

# Check Gradle wrapper
./gradlew --version
# Expected: Gradle 9.0.0+
```

---

## 2. Project Setup

### Clone or Navigate to Project

```bash
cd /path/to/FuckProtect
```

### Sync Gradle Dependencies

```bash
# This downloads all dependencies defined in libs.versions.toml
./gradlew --refresh-dependencies
```

### Verify Project Structure

```bash
# Should show these top-level directories
ls -la
# Expected: app/ common/ protector/ shell/ doc/ gradle/ scripts/

# Should show 3 submodules
./gradlew projects
# Expected: Root project 'FuckProtect'
#           +--- Project ':app'
#           +--- Project ':common'
#           +--- Project ':protector'
#           \--- Project ':shell'
```

---

## 3. Building the Protector Tool

The protector tool is a standalone CLI application that takes an APK and outputs a protected version.

### Build the Protector

```bash
# Build and install the protector locally
./gradlew :protector:installDist
```

This produces an executable script at:
```
protector/build/install/protector/bin/protector
```

### Test the Protector CLI

```bash
# Show help
./protector/build/install/protector/bin/protector --help

# Expected output:
# Usage: fuckprotect [-hVv] [--disable-sign-check]
#                    [--work-dir=<workDir>] -i=<inputApk>
#                    -o=<outputApk> --keystore=<keystoreFile>
#                    --key-alias=<keyAlias> --key-pass=<keyPass>
#                    --store-pass=<storePass>
# Protect Android APKs from reverse engineering
```

### Verify All Components Compile

```bash
# Compile everything (skip actual APK building for now)
./gradlew :common:assemble :protector:assemble :shell:assembleDebug

# Expected: BUILD SUCCESSFUL
```

---

## 4. Building the Shell Runtime

The shell runtime is the code injected into protected APKs. It must be compiled for all target ABIs.

### Build Shell Native Libraries

```bash
# Build for all ABIs (armeabi-v7a, arm64-v8a, x86, x86_64)
./gradlew :shell:assembleDebug
```

This produces native libraries at:
```
shell/build/intermediates/cxx/Debug/
├── obj/arm64-v8a/libshell.so
├── obj/armeabi-v7a/libshell.so
├── obj/x86/libshell.so
└── obj/x86_64/libshell.so
```

### Enable O-LLVM Obfuscation (Optional)

For production builds, enable native code obfuscation:

```bash
# Build with O-LLVM flags (-fla -sub -bcf)
./gradlew :shell:assembleDebug \
    -PcmakeArgs="-DENABLE_OBFUSCATION=ON"
```

### Verify Native Libraries

```bash
# Check that strings are obfuscated (no plaintext "fuckprotect" visible)
strings shell/build/intermediates/cxx/Debug/obj/arm64-v8a/libshell.so \
    | grep -i "fuckprotect"

# Expected: NO output (strings are XOR-encrypted)
```

---

## 5. Protecting Your First APK

### Step 1: Prepare an Input APK

You need a release APK to protect. Build one from any Android project:

```bash
# From any Android project
cd /path/to/your-app
./gradlew assembleRelease

# Copy the release APK to a known location
cp app/build/outputs/apk/release/app-release.apk /tmp/my-app.apk
```

Or use the test APK included in this project:

```bash
./gradlew :app:assembleRelease
cp app/build/outputs/apk/release/app-release.apk /tmp/test-app.apk
```

### Step 2: Prepare a Keystore

You need a keystore to sign the protected APK. Use your release keystore or create a debug one:

```bash
# Create a debug keystore (for testing only)
keytool -genkeypair \
    -v \
    -keystore /tmp/debug.keystore \
    -alias androiddebugkey \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -storepass android \
    -keypass android \
    -dname "CN=Android Debug,O=Android,C=US"
```

### Step 3: Run the Protector

```bash
cd /storage/emulated/0/AndroidCSProjects/FuckProtect

./protector/build/install/protector/bin/protector \
    --input /tmp/test-app.apk \
    --output /tmp/protected-app.apk \
    --keystore /tmp/debug.keystore \
    --key-alias androiddebugkey \
    --key-pass android \
    --store-pass android \
    --verbose
```

### Expected Output

```
=== FuckProtect 1.0.0 ===

Phase 1: Parsing input APK...
  DEX files found: 1
  Original Application: com.fuckprotect.MainActivity
  Package: com.fuckprotect
Phase 2: Encrypting DEX files...
  AES key derived from signing certificate: a1b2c3d4e5f6...
  Primary DEX encrypted: 45320 -> 45368 bytes (with IV)
Phase 3: Building payload...
=== Payload Summary ===
  Magic:               FUCK
  Version:             1
  Flags:               0x6
  App Class:           com.fuckprotect.MainActivity
  Encrypted DEX size:  45368 bytes
  Hollowed methods:    0 bytes
  Total payload size:  45430 bytes
Phase 4: Modifying manifest...
  Manifest hijack valid: true
Phase 4b: Embedding signature hash into native library...
  arm64-v8a/libshell.so: OK
  armeabi-v7a/libshell.so: OK
Phase 5: Repackaging...
  Unsigned APK created: 5243820 bytes
Phase 6: Signing APK...
  Signed APK: 5245100 bytes

=== Protection complete ===
  Output: /tmp/protected-app.apk
  Original size: 4987650 bytes
  Protected size: 5245100 bytes

Next steps:
  1. Install: adb install -r /tmp/protected-app.apk
  2. Verify: adb logcat | grep FuckProtectShell
```

### Step 4: Install and Test

```bash
# Uninstall the original app first (if installed)
adb uninstall com.fuckprotect

# Install the protected APK
adb install -r /tmp/protected-app.apk

# Monitor the shell initialization
adb logcat -s FuckProtectShell &

# Launch the app
adb shell am start -n com.fuckprotect/.MainActivity

# Expected log output:
# FuckProtectShell: nativeInit: FuckProtect shell initializing...
# FuckProtectShell: nativeInit: anti-debugging checks passed
# FuckProtectShell: nativeInit: signature verification passed
# FuckProtectShell: nativeInit: anti-hooking checks passed
# FuckProtectShell: nativeInit: all initialization checks passed
# FuckProtectShell: nativeDecryptDex: decrypted 45352 bytes -> 45320 bytes (DEX)
```

---

## 6. Integrating as a Gradle Plugin

Instead of using the CLI, you can integrate FuckProtect directly into any Android project's build pipeline.

### Step 1: Publish the Plugin Locally

```bash
cd /storage/emulated/0/AndroidCSProjects/FuckProtect

# Publish to local Maven repository
./gradlew :protector:publishToMavenLocal
```

### Step 2: Add to Your App's Build

In your app project's `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        mavenLocal()  // Add this to find the local plugin
        google()
        mavenCentral()
    }
}
```

In your app's `build.gradle.kts`:

```kotlin
plugins {
    id("com.android.application")
    id("com.fuckprotect.protector") version "1.0.0"  // Add this
}

// Configure FuckProtect
fuckProtect {
    enabled = true
    antiDebug = true
    verifySignature = true
    verifyApkIntegrity = false  // Enable in Phase 3+
    methodHollowing = false     // Enable in Phase 3+
    continuousMonitoring = true
    silentDefense = false       // Enable for stealth mode
    emulatorDetection = true
    antiHooking = true

    // Exclude packages from protection
    excludeClasses.set(listOf(
        "com.example.BuildConfig",
        "androidx.**",
        "com.google.**",
    ))

    // Log level (0=quiet, 1=normal, 2=verbose)
    logLevel.set(1)
}
```

### Step 3: Build with Protection

```bash
# This will build AND protect in one step
./gradlew protectRelease

# The protected APK will be at:
# app/build/outputs/apk/release/app-release-protected.apk
```

### Maximum Protection Config

```kotlin
fuckProtect {
    maxProtection()  // Enables all protections at once
}
```

### Disabled (for debugging)

```kotlin
fuckProtect {
    disabled()  // Skips all protection
}
```

---

## 7. Verifying Protection

### 7.1 Check with JADX

```bash
# Open protected APK in JADX
jadx /tmp/protected-app.apk

# What you should see:
# ✅ AndroidManifest.xml shows ShellApplication as entry point
# ✅ classes.dex shows error or minimal shell classes only
# ✅ NO original source code visible
# ✅ libshell.so present but unreadable (O-LLVM obfuscated)
```

### 7.2 Check APK Structure

```bash
# List APK contents
unzip -l /tmp/protected-app.apk | head -30

# Expected structure:
# AndroidManifest.xml          ← Modified (ShellApplication)
# classes.dex                  ← ENCRYPTED (not a valid DEX)
# assets/fp_payload.dat        ← Encrypted original DEX
# lib/arm64-v8a/libshell.so    ← Protected native library
# lib/armeabi-v7a/libshell.so
# res/                         ← Unchanged
```

### 7.3 Verify DEX is Encrypted

```bash
# Extract and check the DEX magic
unzip -p /tmp/protected-app.apk classes.dex | xxd | head -1

# Expected: NOT "dex\n035\0" or "dex\n037\0"
# Instead: random-looking encrypted bytes
```

### 7.4 Test Anti-Debugging

```bash
# Install protected APK
adb install -r /tmp/protected-app.apk

# Try to set it as debuggable
adb shell am set-debug-app com.fuckprotect

# Launch — should exit immediately
adb shell am start -n com.fuckprotect/.MainActivity

# Check logcat for detection
adb logcat | grep -E "(FuckProtectShell|FP_AntiDebug)"

# Expected: App crashes/exits, log shows debugger detection
```

### 7.5 Test Signature Tampering

```bash
# Decompile the protected APK
apktool d /tmp/protected-app.apk -o /tmp/decompiled

# Modify something
echo "modified" >> /tmp/decompiled/smali/extra.txt

# Rebuild
apktool b /tmp/decompiled -o /tmp/tampered.apk

# Sign with DIFFERENT keystore
keytool -genkeypair -v -keystore /tmp/other.keystore \
    -alias other -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass other123 -keypass other123 \
    -dname "CN=Other,O=Other,C=US"

apksigner sign --ks /tmp/other.keystore \
    --ks-pass pass:other123 \
    --ks-key-alias other \
    --key-pass pass:other123 \
    /tmp/tampered.apk

# Install tampered APK
adb install -r /tmp/tampered.apk

# Launch — should fail signature verification
adb shell am start -n com.fuckprotect/.MainActivity

# Expected: App exits, log shows "SIGNATURE MISMATCH"
```

---

## 8. Configuration Options

### CLI Options

| Flag | Description | Default |
|---|---|---|
| `-i, --input <file>` | Input APK to protect | **Required** |
| `-o, --output <file>` | Output protected APK | **Required** |
| `--keystore <file>` | Keystore for signing | **Required** |
| `--key-alias <name>` | Keystore key alias | **Required** |
| `--key-pass <pass>` | Key password | **Required** |
| `--store-pass <pass>` | Keystore password | **Required** |
| `--work-dir <dir>` | Temp working directory | Auto-created |
| `--disable-sign-check` | Disable signature verification in shell | `false` |
| `-v, --verbose` | Verbose output | `false` |
| `-h, --help` | Show help | — |
| `-V, --version` | Show version | — |

### Gradle DSL Options

| Property | Type | Default | Description |
|---|---|---|---|
| `enabled` | Boolean | `true` | Enable/disable protection |
| `encryptDex` | Boolean | `true` | Encrypt DEX files |
| `antiDebug` | Boolean | `true` | Anti-debugging checks |
| `verifySignature` | Boolean | `true` | Signature verification |
| `verifyApkIntegrity` | Boolean | `false` | APK checksum verification |
| `methodHollowing` | Boolean | `false` | Hollow out method bodies |
| `continuousMonitoring` | Boolean | `true` | Background monitoring thread |
| `silentDefense` | Boolean | `false` | Don't crash, corrupt instead |
| `emulatorDetection` | Boolean | `false` | Detect emulators |
| `antiHooking` | Boolean | `false` | Anti-Frida/Xposed checks |
| `excludeClasses` | List\<String\> | See below | Classes to skip |
| `abiFilters` | List\<String\> | `["armeabi-v7a", "arm64-v8a"]` | Native ABIs to include |
| `logLevel` | Int | `1` | 0=quiet, 1=normal, 2=verbose |

### Default Excluded Packages

These are automatically excluded from protection:
```
*.BuildConfig
androidx.**
android.**
kotlin.**
com.google.**
org.jetbrains.**
java.**
javax.**
```

---

## 9. Troubleshooting

### Problem: Build fails with "NDK not found"

```bash
# Set NDK path explicitly
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.3.13750724

# Or in local.properties (project root):
echo "ndk.dir=$ANDROID_HOME/ndk/27.3.13750724" >> local.properties
```

### Problem: "Certificate hash placeholder not found"

The protector couldn't find the placeholder bytes in the compiled `.so` file.

```bash
# Verify the placeholder exists in source
grep -r "CERT_HASH_PLACEHOLDER" shell/src/main/cpp/

# If missing, check shell/src/main/cpp/crypto/key_derive.c
# The EMBEDDED_CERT_HASH constant should contain "CERT_HASH_PLACEHOLDER"
```

### Problem: Protected app crashes immediately on launch

This is **expected behavior** if:
1. A debugger is attached — anti-debugging triggers
2. The APK was re-signed with a different key — signature mismatch
3. The device is rooted and Frida is running — hooking detected

**To debug:**
```bash
# Check logcat for the reason
adb logcat | grep -E "FuckProtect|FP_"

# Common messages:
# "DEBUGGING DETECTED via: ptrace_self_attach"
# "SIGNATURE MISMATCH — exiting"
# "Frida gadget detected: libfrida-gadget.so"
```

### Problem: "Could not determine original Application class"

The protector couldn't find the `android:name` in your `AndroidManifest.xml`.

**Fix:** Ensure your manifest has an Application class:
```xml
<manifest package="com.example">
    <application android:name="com.example.MyApp">
        ...
    </application>
</manifest>
```

### Problem: Protected APK is significantly larger

Expected increase: **~5–15%** due to:
- Encrypted payload added to assets (`fp_payload.dat`)
- Native libraries for all ABIs (`libshell.so`)
- Shell classes added to the APK

**To reduce size:**
```kotlin
fuckProtect {
    // Only include specific ABIs
    abiFilters.set(listOf("arm64-v8a"))  // Removes 32-bit and x86
}
```

### Problem: Gradle plugin not found

```bash
# Make sure you published locally
./gradlew :protector:publishToMavenLocal

# Check it exists
ls ~/.m2/repository/com/fuckprotect/protector/

# In your app's settings.gradle.kts, ensure mavenLocal() is listed
dependencyResolutionManagement {
    repositories {
        mavenLocal()  // Must be before google() and mavenCentral()
        google()
        mavenCentral()
    }
}
```

---

## 10. Project Structure Reference

```
FuckProtect/
│
├── common/                          # Shared constants & types
│   └── src/main/java/.../common/
│       ├── Constants.kt             # Magic bytes, key sizes, class names
│       ├── CryptoParams.kt          # AES key/IV container
│       └── PayloadFormat.kt         # Binary payload serialization
│
├── protector/                       # Build-time protector tool
│   ├── build.gradle.kts             # java-gradle-plugin + application
│   └── src/main/java/.../protector/
│       ├── Protector.kt             # CLI entry point (picocli)
│       ├── config/
│       │   ├── ProtectorConfig.kt   # Protection configuration
│       │   └── ExclusionRules.kt    # Class/method exclusion
│       ├── dex/
│       │   ├── DexParser.kt         # DEX file parsing
│       │   ├── DexEncryptor.kt      # AES-256-CBC encryption
│       │   ├── KeyDerivation.kt     # SHA-256 → AES key
│       │   └── PayloadBuilder.kt    # Binary payload construction
│       ├── apk/
│       │   ├── ApkParser.kt         # APK extraction via zip4j
│       │   ├── ManifestEditor.kt    # Application class hijacking
│       │   ├── ApkPackager.kt       # APK repackaging
│       │   └── ApkSigner.kt         # JAR signing
│       ├── embedder/
│       │   └── SignatureEmbedder.kt # Cert hash → native .so
│       ├── utils/
│       │   └── ZipAlignUtils.kt     # zipalign integration
│       └── gradle/
│           ├── FuckProtectPlugin.kt      # Gradle plugin entry
│           ├── FuckProtectExtension.kt   # Configuration DSL
│           └── FuckProtectTask.kt        # Protection task
│
├── shell/                           # Runtime (injected into APK)
│   ├── build.gradle.kts             # Android library + CMake
│   └── src/main/
│       ├── java/.../shell/
│       │   ├── ShellApplication.java     # Hijacked entry point
│       │   ├── loader/
│       │   │   ├── DexLoader.java        # DEX decryption/loading
│       │   │   └── ClassLoaderProxy.java # ClassLoader replacement
│       │   ├── integrity/
│       │   │   ├── SignatureVerifier.java # Cert hash verification
│       │   │   └── ApkIntegrity.java      # APK checksum check
│       │   └── utils/
│       │       ├── ReflectUtils.java      # Reflection helpers
│       │       └── Logger.java            # Obfuscated logging
│       └── cpp/
│           ├── CMakeLists.txt             # Native build config
│           ├── shell_native.cpp           # JNI entry point
│           ├── crypto/
│           │   ├── aes.c                  # AES-256-CBC (no OpenSSL)
│           │   └── key_derive.c           # Embedded cert hash
│           ├── antidbg/
│           │   ├── anti_debug.cpp         # 6 anti-debug checks
│           │   └── continuous_monitor.cpp # Background monitoring
│           ├── hook/
│           │   ├── anti_hook.cpp          # Frida/Xposed detection
│           │   ├── plt_check.cpp          # PLT/GOT integrity
│           │   └── native_hook.cpp        # ART method hooking
│           ├── integrity/
│           │   ├── self_check.cpp         # Signature JNI
│           │   └── self_integrity.cpp     # .text self-hash
│           └── utils/
│               └── string_obfuscate.cpp   # Encrypted strings
│
├── app/                             # Test/dummy app (for development)
├── doc/                             # Documentation
│   ├── research.md                  # Open-source research findings
│   ├── project-arch.md              # System architecture
│   ├── planning.md                  # Implementation plan
│   ├── todo.md                      # Task breakdown (all 76 tasks)
│   ├── test-report.md               # Test infrastructure
│   ├── sprint11-12-report.md        # Monitoring & emulator detection
│   └── sprint13-report.md           # Security audit
├── scripts/
│   ├── run-tests.sh                 # Test runner
│   └── encrypt_strings.py           # String encryption tool
└── gradle/
    └── libs.versions.toml           # Dependency versions
```

---

## Quick Reference Card

```bash
# ─── Build Everything ──────────────────────────────
./gradlew clean assemble

# ─── Build Protector CLI ───────────────────────────
./gradlew :protector:installDist

# ─── Build Shell Native Libs ───────────────────────
./gradlew :shell:assembleDebug

# ─── Protect an APK (CLI) ──────────────────────────
./protector/build/install/protector/bin/protector \
    -i input.apk -o output.apk \
    --keystore release.jks --key-alias mykey \
    --key-pass pass --store-pass pass -v

# ─── Protect an APK (Gradle Plugin) ────────────────
./gradlew protectRelease

# ─── Run Unit Tests ────────────────────────────────
./gradlew :common:test :protector:test

# ─── Run Instrumented Tests ────────────────────────
./gradlew :shell:connectedAndroidTest

# ─── Run All Tests ─────────────────────────────────
./scripts/run-tests.sh all

# ─── Encrypt New Strings for Native Code ───────────
python3 scripts/encrypt_strings.py "new string here"

# ─── Verify Protected APK ──────────────────────────
jadx protected.apk
unzip -l protected.apk
adb install -r protected.apk
adb logcat | grep FuckProtectShell
```
