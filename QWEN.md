# Project Context: FuckProtect

## Project Overview

**FuckProtect** is an Android application written in Java with native C++ code via JNI (Java Native Interface). The project follows a standard Android Studio project structure using Gradle (Kotlin DSL) as its build system.

### Key Details
- **Package Name:** `com.fuckprotect`
- **Min SDK:** 21 (Android 5.0 Lollipop)
- **Target SDK:** 34
- **Compile SDK:** 36
- **NDK Version:** 27.3.13750724
- **CMake Version:** 4.3.0
- **Java Version:** 17

### Architecture
The project is a minimal Android app with a single `MainActivity` that uses **View Binding** and displays text generated from native C++ code. The architecture consists of:

- **Java Layer:** `MainActivity` — an `AppCompatActivity` that loads a native library and displays the result via View Binding.
- **Native Layer:** `native-lib.cpp` — a C++ JNI function (`stringFromJNI`) that returns the string `"Hello from C++"`.
- **UI:** A simple `ConstraintLayout` with a centered `TextView`.

### Dependencies
| Library | Version |
|---|---|
| AndroidX Core | 1.17.0 |
| AndroidX AppCompat | 1.7.1 |
| Material Components | 1.13.0 |
| AndroidX ConstraintLayout | 2.2.1 |

## Project Structure

```
FuckProtect/
├── app/
│   ├── build.gradle.kts          # Module-level build config
│   ├── proguard-rules.pro         # ProGuard rules (mostly default)
│   └── src/main/
│       ├── AndroidManifest.xml    # App manifest
│       ├── cpp/
│       │   ├── CMakeLists.txt     # CMake build script for native code
│       │   └── native-lib.cpp     # JNI implementation
│       ├── java/com/fuckprotect/
│       │   └── MainActivity.java  # Main activity
│       └── res/                   # Resources (layouts, themes, drawables)
├── gradle/
│   └── libs.versions.toml         # Version catalog for dependencies
├── build.gradle.kts               # Root-level build config
├── settings.gradle.kts            # Project settings
└── gradle.properties              # Gradle daemon/JVM settings
```

## Building and Running

### Prerequisites
- Android SDK with API level 36 installed
- Android NDK 27.3.13750724
- CMake 4.3.0+
- JDK 17+

### Commands

```bash
# Build the debug APK
./gradlew assembleDebug

# Build the release APK
./gradlew assembleRelease

# Run all checks (lint, etc.)
./gradlew check

# Clean build outputs
./gradlew clean

# Install on a connected device
./gradlew installDebug
```

Alternatively, open the project in **Android Studio** and use the built-in build/run functionality.

## Development Conventions

- **Build System:** Gradle with Kotlin DSL (`.kts` files).
- **Dependency Management:** Uses Gradle Version Catalog (`libs.versions.toml`) for centralized dependency versions.
- **View Binding:** Enabled; binding classes are used instead of `findViewById`.
- **Native Code:** C++ JNI code is built with CMake and linked via `target_link_libraries` against `android` and `log`.
- **Kotlin Code Style:** Set to `official` in `gradle.properties` (standard for Android projects, even Java-only ones).
- **Resource Naming:** Standard Android conventions (e.g., `ic_launcher`, `activity_main`).

## Notes

- The project name and package (`com.fuckprotect`) suggest this may be an anti-tampering / anti-obfuscation research or experimental project, given the combination of "FuckProtect" and the presence of `proguard-rules.pro`.
- The native library is named `myapplication` (as defined in `CMakeLists.txt`), loaded via `System.loadLibrary("myapplication")` in `MainActivity`.
- The `foregroundServiceDataSync` permission is declared but not currently used in the manifest.
