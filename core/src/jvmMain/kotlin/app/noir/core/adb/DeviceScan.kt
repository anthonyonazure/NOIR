/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.core.adb

import app.noir.core.apk.ApkScan
import java.io.File

data class PackagePath(val pkg: String, val path: String)

/**
 * Collects URL strings from every installed APK.
 *
 * The fast path runs entirely on the device (unzip + strings), so only a few KB
 * cross the USB link. Progress is streamed per package: the shell script prints
 * one marker after each APK, which lets the CLI redraw its bar for every app
 * instead of every batch.
 *
 * If the device's `unzip` cannot read an APK at all, the script reports it and
 * the host pulls that file and parses it locally.
 */
object DeviceScan {

    private const val FALLBACK = "F "
    private const val RESULT = "R "
    private const val PROGRESS = "P "

    /** Every file NOIR ever writes on the phone. All of it lives in /data/local/tmp. */
    private const val DEVICE_SCRIPT = "/data/local/tmp/noir_scan.sh"
    private const val DEVICE_TARGETS = "/data/local/tmp/noir_targets.txt"
    private const val DEVICE_DEX = "/data/local/tmp/noir_dex.bin"
    private const val CLEANUP = "rm -f $DEVICE_SCRIPT $DEVICE_TARGETS $DEVICE_DEX"

    /** Removes anything NOIR left on the phone, including leftovers from an interrupted run. */
    fun cleanDevice(adb: Adb, serial: String) {
        runCatching { adb.shell(serial, CLEANUP, timeoutSec = 30) }
    }

    fun packagePaths(adb: Adb, serial: String): Map<String, String> {
        val out = adb.shell(serial, "pm list packages -f").output
        val map = HashMap<String, String>()
        out.lineSequence().forEach { line ->
            if (!line.startsWith("package:")) return@forEach
            val body = line.removePrefix("package:")
            val idx = body.lastIndexOf('=')
            if (idx <= 0) return@forEach
            val path = body.substring(0, idx)
            val pkg = body.substring(idx + 1).trim()
            if (pkg.isNotEmpty()) map[pkg] = path
        }
        return map
    }

    fun hasDeviceTools(adb: Adb, serial: String): Boolean {
        val out = adb.shell(serial, "which unzip strings").output
        return out.contains("unzip") && out.contains("strings")
    }

    fun urls(
        adb: Adb,
        serial: String,
        targets: List<PackagePath>,
        workDir: File,
        onProgress: (Int, Int) -> Unit = { _, _ -> }
    ): Map<String, List<String>> {
        if (targets.isEmpty()) return emptyMap()
        workDir.mkdirs()

        if (!hasDeviceTools(adb, serial)) {
            return urlsByPulling(adb, serial, targets, workDir, onProgress)
        }

        // Clear leftovers from any earlier run that was interrupted.
        cleanDevice(adb, serial)

        // If the user hits Ctrl+C mid-scan, still wipe the phone on the way out.
        val hook = Thread { cleanDevice(adb, serial) }
        runCatching { Runtime.getRuntime().addShutdownHook(hook) }

        val list = File(workDir, "targets.txt")
        val script = File(workDir, "scan.sh")
        try {
            return deviceSideScan(adb, serial, targets, workDir, list, script, onProgress)
        } finally {
            cleanDevice(adb, serial)
            list.delete()
            script.delete()
            runCatching { Runtime.getRuntime().removeShutdownHook(hook) }
        }
    }

    private fun deviceSideScan(
        adb: Adb,
        serial: String,
        targets: List<PackagePath>,
        workDir: File,
        list: File,
        script: File,
        onProgress: (Int, Int) -> Unit
    ): Map<String, List<String>> {
        val result = HashMap<String, List<String>>()
        val pendingFallback = ArrayList<String>()

        list.writeText(targets.joinToString("\n", postfix = "\n") { "${it.pkg} ${it.path}" })

        script.writeText(
            """
            #!/system/bin/sh
            TMP=$DEVICE_DEX
            while read p f; do
              # Explicit entry names: some vendor `unzip` builds do not expand 'classes*.dex'.
              : > ${'$'}TMP
              for d in classes.dex classes2.dex classes3.dex classes4.dex classes5.dex \
                       classes6.dex classes7.dex classes8.dex classes9.dex classes10.dex \
                       classes11.dex classes12.dex classes13.dex classes14.dex classes15.dex; do
                unzip -p "${'$'}f" "${'$'}d" 2>/dev/null >> ${'$'}TMP
              done
              if [ ! -s ${'$'}TMP ]; then
                echo "F ${'$'}p"
              else
                u=${'$'}(strings < ${'$'}TMP | grep -oE 'https?://[A-Za-z0-9._~:/?#@!&()*+,;=%-]+' \
                    | sort -u | head -400 | tr '\n' ' ')
                [ -n "${'$'}u" ] && echo "R ${'$'}p|${'$'}u"
              fi
              rm -f ${'$'}TMP
              echo "P ${'$'}p"
            done < $DEVICE_TARGETS
            echo "#DONE"
            """.trimIndent()
        )

        adb.push(serial, script, DEVICE_SCRIPT)
        adb.push(serial, list, DEVICE_TARGETS)

        var done = 0
        val total = targets.size

        val execution = adb.execStreaming(
            listOf("-s", serial, "shell", "sh $DEVICE_SCRIPT"),
            timeoutSec = 0
        ) { line ->
            when {
                line.startsWith(RESULT) -> {
                    val body = line.removePrefix(RESULT)
                    val pkg = body.substringBefore('|')
                    val found = body.substringAfter('|', "").split(' ').filter { it.isNotBlank() }
                    if (pkg.isNotEmpty() && found.isNotEmpty()) result[pkg] = found
                }
                line.startsWith(FALLBACK) -> pendingFallback.add(line.removePrefix(FALLBACK).trim())
                line.startsWith(PROGRESS) -> {
                    done++
                    onProgress(done, total)
                }
            }
        }

        if (done == 0 && targets.isNotEmpty()) {
            // The script never ran. Fall back to pulling everything rather than
            // returning a plausible-looking empty report.
            println("  ! device-side scan produced no progress; pulling ${targets.size} APKs instead")
            return urlsByPulling(adb, serial, targets, workDir, onProgress)
        }

        if (execution.code != 0) {
            println("  ! device-side scan exited with ${execution.code}; results may be partial")
        }

        if (pendingFallback.isNotEmpty()) {
            println("  ! ${pendingFallback.size} APK(s) could not be read by the device's unzip; pulling instead")
            val fallbackTargets = targets.filter { it.pkg in pendingFallback }
            result.putAll(
                urlsByPulling(adb, serial, fallbackTargets, workDir) { index, count ->
                    print("\r  pulling $index/$count")
                    System.out.flush()
                }
            )
            println()
        }

        return result
    }

    private fun urlsByPulling(
        adb: Adb,
        serial: String,
        targets: List<PackagePath>,
        workDir: File,
        onProgress: (Int, Int) -> Unit = { _, _ -> }
    ): Map<String, List<String>> {
        val result = HashMap<String, List<String>>()
        val apkDir = File(workDir, "apks").apply { mkdirs() }
        targets.forEachIndexed { index, target ->
            val local = File(apkDir, "${target.pkg}.apk")
            adb.pull(serial, target.path, local)
            if (local.exists()) {
                val found = runCatching { ApkScan.urls(local) }.getOrDefault(emptyList())
                if (found.isNotEmpty()) result[target.pkg] = found
                local.delete()
            }
            onProgress(index + 1, targets.size)
        }
        apkDir.delete()
        return result
    }
}
