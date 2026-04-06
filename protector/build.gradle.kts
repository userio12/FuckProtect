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
    implementation(gradleApi())

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
