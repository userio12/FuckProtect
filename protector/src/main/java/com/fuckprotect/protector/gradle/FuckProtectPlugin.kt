package com.fuckprotect.protector.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.TaskProvider

/**
 * Gradle plugin that integrates FuckProtect APK protection into the
 * Android build pipeline.
 *
 * T10.1: Gradle plugin entry point
 */
class FuckProtectPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val androidExtension = project.extensions.findByName("android")
            ?: run {
                project.logger.warn("FuckProtect: 'android' extension not found. Skipping.")
                return
            }

        val extension = project.extensions.create(
            "fuckProtect",
            FuckProtectExtension::class.java,
            project,
        )

        project.afterEvaluate {
            val appExt = try {
                project.extensions.findByType(
                    com.android.build.gradle.AppExtension::class.java
                )
            } catch (_: Exception) {
                project.extensions.findByName("android") as? com.android.build.gradle.AppExtension
            } ?: run {
                project.logger.warn("FuckProtect: AppExtension not found. Skipping.")
                return@afterEvaluate
            }

            appExt.applicationVariants.all { variant ->
                if (variant.name != "release" && !variant.name.endsWith("Release")) return@all

                val assembleTask = variant.assembleProvider.get()

                val protectTask = project.tasks.register(
                    "protect${variant.name.replaceFirstChar { it.uppercaseChar() }}",
                    FuckProtectTask::class.java,
                ) { task ->
                    task.description = "Protect the ${variant.name} APK with FuckProtect"
                    task.group = "fuckprotect"
                    task.extension.set(extension)
                    task.dependsOn(assembleTask)
                }

                project.logger.info("FuckProtect: Registered task $protectTask")
            }
        }
    }
}
