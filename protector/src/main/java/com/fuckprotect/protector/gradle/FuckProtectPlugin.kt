package com.fuckprotect.protector.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Gradle plugin that integrates FuckProtect APK protection into the
 * Android build pipeline.
 *
 * T10.1: Gradle plugin entry point
 */
class FuckProtectPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        // Create the DSL extension
        val extension = project.extensions.create(
            "fuckProtect",
            FuckProtectExtension::class.java,
            project,
        )

        project.afterEvaluate {
            // Use reflection to find applicationVariants on the android extension
            val androidExt = project.extensions.findByName("android")
                ?: run {
                    project.logger.warn("FuckProtect: 'android' extension not found. Skipping.")
                    return@afterEvaluate
                }

            try {
                val variantsMethod = androidExt.javaClass.getMethod("getApplicationVariants")
                @Suppress("UNCHECKED_CAST")
                val variants = variantsMethod.invoke(androidExt) as Iterable<Any>

                variants.forEach { variant ->
                    val variantName = variant.javaClass.getMethod("getName").invoke(variant) as String
                    if (!variantName.endsWith("Release", ignoreCase = true)) return@forEach

                    val assembleProvider = variant.javaClass.getMethod("getAssembleProvider").invoke(variant)
                    val assembleTask = assembleProvider.javaClass.getMethod("get").invoke(assembleProvider) as org.gradle.api.Task

                    val protectTask = project.tasks.register(
                        "protect${variantName.replaceFirstChar { it.uppercaseChar() }}",
                        FuckProtectTask::class.java,
                    ) { task ->
                        task.description = "Protect the $variantName APK with FuckProtect"
                        task.group = "fuckprotect"
                        task.extension.set(extension)
                        task.dependsOn(assembleTask)
                    }

                    project.logger.info("FuckProtect: Registered task $protectTask")
                }
            } catch (e: Exception) {
                project.logger.warn("FuckProtect: Could not register protection tasks: ${e.message}")
            }
        }
    }
}
