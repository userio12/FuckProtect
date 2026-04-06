package com.fuckprotect.protector.apk

import java.io.File

/**
 * Utility to run zipalign on an APK file.
 *
 * zipalign ensures all uncompressed data starts at a particular
 * alignment (typically 4 bytes), which allows Android to read
 * resources with mmap() instead of copying into RAM.
 *
 * T3.6: zipalign integration
 */
object ZipAlignUtils {

    /**
     * Run zipalign on the given APK.
     *
     * @param inputApk Input APK file
     * @param outputApk Output aligned APK file
     * @param alignment Byte alignment (default 4)
     * @param zipalignPath Path to zipalign binary (auto-detected if null)
     * @return true if zipalign succeeded
     */
    fun align(
        inputApk: File,
        outputApk: File,
        alignment: Int = 4,
        zipalignPath: String? = null,
    ): Boolean {
        require(inputApk.exists()) { "Input APK not found: ${inputApk.absolutePath}" }

        val zipalign = zipalignPath ?: findZipalign()
            ?: run {
                System.err.println("WARNING: zipalign not found. Skipping alignment.")
                inputApk.copyTo(outputApk, overwrite = true)
                return true
            }

        // Remove output if exists
        if (outputApk.exists()) outputApk.delete()

        val process = ProcessBuilder(
            zipalign,
            "-p",             // Do not compress (preserve existing compression)
            "-f",             // Overwrite existing file
            alignment.toString(),
            inputApk.absolutePath,
            outputApk.absolutePath,
        )
            .redirectErrorStream(true)
            .start()

        val exitCode = process.waitFor()
        if (exitCode != 0) {
            val output = process.inputStream.bufferedReader().readText()
            System.err.println("zipalign failed with exit code $exitCode: $output")
            return false
        }

        return true
    }

    /**
     * Verify that an APK is properly zipaligned.
     */
    fun verify(apkFile: File, alignment: Int = 4, zipalignPath: String? = null): Boolean {
        require(apkFile.exists()) { "APK not found: ${apkFile.absolutePath}" }

        val zipalign = zipalignPath ?: findZipalign()
            ?: run {
                System.err.println("WARNING: zipalign not found. Skipping verification.")
                return true
            }

        val process = ProcessBuilder(
            zipalign,
            "-c",             // Check alignment
            "-v",             // Verbose
            alignment.toString(),
            apkFile.absolutePath,
        )
            .redirectErrorStream(true)
            .start()

        val exitCode = process.waitFor()
        return exitCode == 0
    }

    /**
     * Find the zipalign binary in common locations and PATH.
     */
    private fun findZipalign(): String? {
        // Check PATH first
        val envPath = System.getenv("PATH")
        if (envPath != null) {
            for (dir in envPath.split(File.pathSeparatorChar)) {
                val candidate = File(dir, "zipalign")
                if (candidate.canExecute()) return candidate.absolutePath
            }
        }

        // Common Android SDK locations
        val androidHome = System.getenv("ANDROID_HOME")
            ?: System.getenv("ANDROID_SDK_ROOT")
            ?: return null

        val buildToolsBase = File("$androidHome/build-tools")
        if (buildToolsBase.exists()) {
            // Find the latest build-tools version
            val versions = buildToolsBase.listFiles()
                ?.filter { it.isDirectory }
                ?.sortedWith(compareByDescending { it.name })
                ?: return null

            for (versionDir in versions) {
                val candidate = File(versionDir, "zipalign")
                if (candidate.canExecute()) return candidate.absolutePath
            }
        }

        return null
    }
}
