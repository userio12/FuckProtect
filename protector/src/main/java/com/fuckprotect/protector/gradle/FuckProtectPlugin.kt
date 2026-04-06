package com.fuckprotect.protector.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Gradle plugin that integrates FuckProtect APK protection into the
 * Android build pipeline.
 *
 * When applied, it:
 * 1. Registers a `protectApk` task after `assembleRelease`
 * 2. Reads configuration from the `fuckProtect {}` DSL block
 * 3. Runs the protection pipeline on the output APK
 *
 * Usage in app's build.gradle.kts:
 * ```
 * plugins {
 *     id("com.fuckprotect.protector")
 * }
 *
 * fuckProtect {
 *     enabled = true
 *     antiDebug = true
 *     verifySignature = true
 * }
 * ```
 *
 * T10.1: Gradle plugin entry point
 */
class FuckProtectPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        // Only apply to Android application projects
        val androidExtension = project.extensions.findByName("android")
            ?: run {
                project.logger.warn("FuckProtect: 'android' extension not found. Skipping.")
                return
            }

        // Create the DSL extension
        val extension = project.extensions.create(
            "fuckProtect",
            FuckProtectExtension::class.java,
            project,
        )

        // Register the protection task after the project is evaluated
        project.afterEvaluate {
            val variant = findReleaseVariant(project)
                ?: run {
                    project.logger.warn("FuckProtect: No release variant found. Skipping.")
                    return@afterEvaluate
                }

            val assembleTask = variant.assembleProvider.get()

            val protectTask = project.tasks.register(
                "protect${variant.name.capitalize()}",
                FuckProtectTask::class.java,
            ) { task ->
                task.description = "Protect the ${variant.name} APK with FuckProtect"
                task.group = "fuckprotect"
                task.extension.set(extension)

                // Get the output APK from the assemble task
                task.inputApkProvider = {
                    assembleTask.outputs.files.files.find { f ->
                        f.name.endsWith(".apk", ignoreCase = true)
                    }
                }

                task.outputApkProvider = {
                    val input = task.inputApkProvider?.invoke()
                    if (input != null) {
                        project.file(
                            input.path.replace(
                                ".apk",
                                "-protected.apk",
                            ),
                        )
                    } else {
                        null
                    }
                }

                task.dependsOn(assembleTask)
            }

            project.logger.info("FuckProtect: Registered task ${protectTask.name}")
        }
    }

    private fun findReleaseVariant(project: Project): Any? {
        val android = project.extensions.findByName("android") ?: return null

        // Try applicationVariants (for app projects)
        try {
            val variants = android.javaClass.getMethod("getApplicationVariants")
                .invoke(android) as? Iterable<*>
            return variants?.find { v ->
                v.javaClass.getMethod("getName").invoke(v) == "release"
            }
        } catch (_: Exception) {
        }

        return null
    }
}
