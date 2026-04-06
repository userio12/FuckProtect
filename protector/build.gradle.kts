plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-gradle-plugin`
    application
}

application {
    mainClass.set("com.fuckprotect.protector.Protector")
}

dependencies {
    implementation(project(":common"))
    implementation(libs.picocli)
    implementation(libs.zip4j)
    implementation(libs.bouncycastle)
    implementation(libs.kotlinx.coroutines)
    // dexlib2 for proper DEX manipulation (same as dpt-shell)
    implementation(libs.dexlib2)
    implementation(libs.commons.lang3)
    implementation(libs.commons.io)
    // Only pull in the Gradle API types we need, not the full runtime
    compileOnly(gradleApi())

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    useJUnitPlatform()
}

// ─── Fix Gradle 9.0 duplicate JAR issue ─────────────────────────────
tasks.withType<Sync>().configureEach {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

// Fix duplicate kotlin-stdlib in distributions
configurations {
    runtimeClasspath {
        exclude(group = "org.jetbrains.kotlin", module = "kotlin-stdlib")
    }
}

// ─── Gradle Plugin Registration ─────────────────────────────────────
gradlePlugin {
    plugins {
        create("fuckProtect") {
            id = "com.fuckprotect.protector"
            implementationClass = "com.fuckprotect.protector.gradle.FuckProtectPlugin"
            displayName = "FuckProtect APK Protector"
            description = "Protects Android APKs from reverse engineering"
        }
    }
}
