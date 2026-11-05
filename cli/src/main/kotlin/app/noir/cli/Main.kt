/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.cli

import app.noir.core.ActionType
import app.noir.core.Advisor
import app.noir.core.AppEntry
import app.noir.core.Cache
import app.noir.core.Category
import app.noir.core.Classifier
import app.noir.core.Domains
import app.noir.core.Device
import app.noir.core.Recommendation
import app.noir.core.Report
import app.noir.core.ReportMeta
import app.noir.core.Rules
import app.noir.core.Tui
import app.noir.core.adb.Adb
import app.noir.core.adb.DeviceScan
import app.noir.core.adb.Dumpsys
import app.noir.core.adb.PackagePath
import app.noir.core.apk.ApkScan
import app.noir.core.apk.ManifestAnalyzer
import app.noir.core.apk.ManifestFacts
import app.noir.core.apk.Trackers
import app.noir.core.jadx.Jadx
import app.noir.core.platform.Platform
import app.noir.core.platform.Setup
import java.io.File
import java.time.OffsetDateTime
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.system.exitProcess

private val VERSION: String =
    Guidance::class.java.`package`?.implementationVersion ?: "0.1.0-dev"

private val BOOLEAN_FLAGS = setOf(
    "apply", "yes", "verbose", "help", "ascii", "color", "no-color", "quiet", "no-clear",
    "all", "purge"
)

private var QUIET = false

private fun say(message: String) {
    if (!QUIET) println(message)
}

private class NoirException(message: String, val hint: String? = null) : Exception(message)

fun main(args: Array<String>) {
    QUIET = args.contains("--quiet")
    try {
        runMain(args)
    } catch (e: NoirException) {
        System.err.println()
        System.err.println(Guidance.error(e.message ?: "Something went wrong", e.hint))
        exitProcess(1)
    } catch (e: Exception) {
        System.err.println()
        System.err.println(
            Guidance.error(
                e.message ?: e::class.simpleName ?: "Unknown error",
                "Add --verbose to see the full stack trace, or run noir doctor first to check your setup."
            )
        )
        if (args.contains("--verbose")) e.printStackTrace()
        exitProcess(1)
    }
}

private fun runMain(args: Array<String>) {
    if (args.isEmpty()) {
        if (isInteractive()) guided() else usage()
        return
    }
    when (val command = args[0]) {
        "devices" -> cmdDevices(args.drop(1))
        "scan" -> cmdScan(args.drop(1))
        "auto" -> cmdAuto(args.drop(1))
        "ui" -> cmdUi(args.drop(1))
        "deep" -> cmdDeep(args.drop(1))
        "deepscan" -> cmdDeepScan(args.drop(1))
        "block" -> cmdBlock(args.drop(1))
        "setup" -> cmdSetup(args.drop(1))
        "doctor" -> cmdDoctor(args.drop(1))
        "-h", "--help", "help" -> usage()
        "-v", "--version", "version" -> println("NOIR $VERSION")
        "--about", "about" -> println(Guidance.about(VERSION))
        else -> {
            System.err.println("Unknown command: $command")
            usage()
            exitProcess(2)
        }
    }
}

private fun usage() {
    println(
        """
        NOIR — audit what your phone can leak, from the desktop.
        runs on Windows 10/11, macOS and Debian/Ubuntu.

        First time? Just run `noir` (no arguments) to start the wizard.
        Want to know what it is first? noir --about

        usage:
          noir                                guided setup + scan (interactive)
          noir --about                        what this is, what it writes, license
          noir --version                      print the version
          noir doctor                         check adb / jadx / device
          noir setup                          download missing tools into ~/.noir/tools
          noir devices                        list connected devices
          noir scan [options]                 inventory apps, permissions and endpoints
          noir auto [options]                 scan + classify + plan
          noir ui [options]                   same, rendered as a dashboard
          noir deep <package> [options]       pull one APK, run jadx, grep for red flags
          noir deepscan [options]             decompile the riskiest apps, then offer cleanup
          noir block <package...> [options]   print (or apply) neutralisation commands

        options:
          --serial <id>      target a specific device
          --out <dir>        output directory (default: noir-out)
          --min <score>      only keep apps at or above this score
          --limit <n>        cap reported apps (default 500)
          --only <regex>     restrict scanning to matching package names
          --adb <path>       override adb binary
          --jadx <path>      override jadx binary

        auto / deepscan:
          --apply            execute the safe, reversible app-ops actions
          --yes              skip confirmation prompts (automation)

        deepscan only:
          --top <n>          how many apps to decompile (default 15)
          --all              decompile every flagged app (slow, lots of disk)
          --jobs <n>         parallel jadx processes (default: cpu/2, max 6)
          --purge            also offer to uninstall risky user apps

        display:
          --ascii            plain ASCII borders (legacy Windows console)
          --color            force ANSI colour (auto-detected on a TTY)
          --no-color         disable ANSI colour
          --quiet            suppress scan progress
          --no-clear         do not clear the screen before the dashboard
        """.trimIndent()
    )
}

// ── guided first run ───────────────────────────────────────────────────────

private fun bannerSmall() {
    println(
        """
        |  ███╗   ██╗ ██████╗ ██╗██████╗
        |  ████╗  ██║██╔═══██╗██║██╔══██╗
        |  ██╔██╗ ██║██║   ██║██║██████╔╝
        |  ██║╚██╗██║██║   ██║██║██╔══██╗
        |  ██║ ╚████║╚██████╔╝██║██║  ██║
        |  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
        """.trimMargin()
    )
}

private fun guided() {
    bannerSmall()
    println("  First-run wizard · Ctrl+C to quit anytime")
    println()

    val adb = ensureAdbInteractive()
    val device = awaitDevice(adb, null, interactive = true)

    println()
    println("  Device: ${device.model.ifBlank { device.serial }}  (${device.serial})")
    print("  Start scan and write report? [Y/n] ")
    val proceed = readLine()?.trim()?.lowercase()
    if (proceed == "n" || proceed == "no") {
        println("  Cancelled.")
        return
    }

    val args = Args(emptyList())
    val result = performScan(args)
    val recommendations = Advisor.advise(result.apps)
    writeReports(result, recommendations)

    println()
    print(renderDashboard(args, result, recommendations))

    val planned = plannedActions(recommendations)
    println()
    println("  ${planned.size} actions can be applied safely (appops, reversible)")
    if (planned.isEmpty()) {
        println("  Nothing needs automatic handling.")
        return
    }
    print("  Apply now? [y/N] ")
    val apply = readLine()?.trim()?.lowercase()
    if (apply == "y" || apply == "yes") {
        applyCommands(adb, result, planned)
    } else {
        println("  Skipped. You can run this later: noir auto --apply")
    }
}

private fun ensureAdbInteractive(): Adb {
    Platform.findAdb()?.let { return Adb(it) }

    println("  adb not found.")
    println(Guidance.adbMissing())
    print("  Download Android platform-tools now (about 15 MB)? [Y/n] ")
    val answer = readLine()?.trim()?.lowercase()
    if (answer == "n" || answer == "no") {
        throw NoirException("adb is required to continue.", Guidance.adbMissing())
    }

    print("  Downloading ")
    val path = Setup.installAdb { read, total -> renderDownload(read, total) }
    println()
    if (path == null) throw NoirException("adb download failed.", "Check your network and try again, or install adb manually.")
    println("  Installed: $path")
    return Adb(path)
}

private fun renderDownload(read: Long, total: Long) {
    if (QUIET) return
    if (total > 0) {
        print("\r  ${read * 100 / total}%  ${read / 1_048_576}/${total / 1_048_576} MB   ")
    } else {
        print("\r  ${read / 1_048_576} MB   ")
    }
    System.out.flush()
}

// ── commands ───────────────────────────────────────────────────────────────

private fun cmdDevices(raw: List<String>) {
    val args = Args(raw)
    val adb = connectAdb(args)
    val filter = args.value("serial")
    val devices = adb.devices().let { all -> if (filter == null) all else all.filter { it.serial == filter } }
    if (devices.isEmpty()) {
        println(Guidance.deviceGuide())
        return
    }
    println("%-22s %-14s %-22s %s".format("SERIAL", "STATE", "MODEL", "PRODUCT"))
    devices.forEach {
        println("%-22s %-14s %-22s %s".format(it.serial, it.state, it.model, it.product))
    }
    if (devices.any { it.state == "unauthorized" }) {
        println()
        println(Guidance.unauthorizedGuide())
    }
}

internal data class ScanResult(
    val device: Device,
    val apps: List<AppEntry>,
    val outDir: File,
    val android: String,
    val installed: Int,
    val paths: Map<String, String>,
    val meta: ReportMeta
)

private fun cmdScan(raw: List<String>) {
    val args = Args(raw)
    val result = performScan(args)
    writeReports(result, emptyList())

    println()
    println("%5s  %-12s %-10s %-44s %s".format("SCORE", "CATEGORY", "VENDOR", "PACKAGE", "PERM/UPLOAD/CMD"))
    result.apps.take(40).forEach { a ->
        println(
            "%5d  %-12s %-10s %-44s %d/%d/%d".format(
                a.score, a.category.label, a.vendor ?: "—", a.pkg,
                a.permissions.size, a.uploadEndpoints.size, a.commandEndpoints.size
            )
        )
    }
    println()
    println(Tui.clip("[+] ${result.outDir.absolutePath}"))
}

private fun cmdAuto(raw: List<String>) {
    val args = Args(raw)
    val result = performScan(args)
    val recommendations = Advisor.advise(result.apps)
    writeReports(result, recommendations)

    println()
    print(renderDashboard(args, result, recommendations))
    println()
    println("== Recommended actions (top 15) ==")
    recommendations.take(15).forEach { r ->
        println("  %-5s %-16s %-46s %s".format(r.risk, r.action.label, r.pkg, r.reason))
    }

    val planned = plannedActions(recommendations)
    println()
    println("== Will apply (${planned.size} actions, all reversible) ==")
    planned.forEach { println("  ${it.setCommand(result.meta.user)}") }
    println()
    println(Tui.clip("[+] ${result.outDir.absolutePath}"))

    if (!args.flag("apply")) {
        println()
        println("[*] dry run: add --apply to run these ${planned.size} actions")
        return
    }

    if (!args.flag("yes")) {
        if (!isInteractive()) {
            println("[!] --apply in a non-interactive environment also requires --yes")
            return
        }
        print("Apply ${planned.size} appops actions? [y/N] ")
        val answer = readLine()?.trim()?.lowercase()
        if (answer != "y" && answer != "yes") {
            println("aborted")
            return
        }
    }
    applyCommands(connectAdb(args), result, planned)
}

private fun cmdUi(raw: List<String>) {
    val args = Args(raw)
    val result = performScan(args)
    val recommendations = Advisor.advise(result.apps)
    writeReports(result, recommendations)

    if (!args.flag("no-clear") && System.console() != null) {
        print("\u001b[2J\u001b[H")
    }
    println()
    print(renderDashboard(args, result, recommendations))
    println()
    println(Tui.clip("  report  ${result.outDir.absolutePath}"))
    println()
}

private fun cmdDeep(raw: List<String>) {
    val args = Args(raw)
    val pkg = args.positional.firstOrNull()
        ?: throw NoirException("Missing package name.", "Usage: noir deep <package> [--serial S] [--out DIR]")

    val adb = connectAdb(args)
    val device = awaitDevice(adb, args.value("serial"), interactive = isInteractive())
    val outDir = File(args.value("out") ?: "noir-out/deep-${pkg.replace('.', '_')}").apply { mkdirs() }

    val remote = adb.shell(device.serial, "pm path $pkg").output
        .lineSequence()
        .firstOrNull { it.startsWith("package:") }
        ?.removePrefix("package:")
        ?.trim()
        ?: throw NoirException("$pkg is not installed on this device.", "Run noir scan first to see the actual package names.")

    val apk = File(outDir, "$pkg.apk")
    println("[*] pulling $remote")
    adb.pull(device.serial, remote, apk)
    println("[*] apk: ${apk.length() / 1024} KiB")

    val urls = ApkScan.urls(apk)
    println("[*] endpoints: ${urls.size}")
    urls.filter { Rules.isUpload(it) || Rules.isCommand(it) }.forEach { println("    ! $it") }

    val jadxBin = Platform.findJadx(args.value("jadx"))
        ?: throw NoirException("jadx not found.", Guidance.jadxMissing())

    println("[*] decompiling with $jadxBin ...")
    val src = File(outDir, "src")
    val code = Jadx(jadxBin).decompile(apk, src)
    println("[*] jadx exit=$code")

    val hits = Jadx(jadxBin).grep(
        src,
        listOf(
            "Runtime\\.exec", "ProcessBuilder", "setApplicationEnabledSetting",
            "enabled_accessibility_services", "DexClassLoader", "loadLibrary",
            "https?://", "verify\\(", "Cipher", "getInstalledPackages",
            "getRunningTasks", "MediaProjection"
        )
    )
    println("[*] hits: ${hits.size}")
    hits.take(40).forEach { println("    ${it.file}:${it.line}  ${it.text}") }
    println("[+] sources: ${src.absolutePath}")
}

private fun cmdBlock(raw: List<String>) {
    val args = Args(raw)
    val pkgs = args.positional
    if (pkgs.isEmpty()) throw NoirException("Missing package name.", "Usage: noir block <package...> [--apply]")

    val adb = connectAdb(args)
    val device = awaitDevice(adb, args.value("serial"), interactive = isInteractive())

    val actions = ArrayList<String>()
    pkgs.forEach { pkg ->
        actions += "pm uninstall --user 0 $pkg"
        actions += "cmd appops set $pkg PROJECT_MEDIA ignore"
        actions += "cmd appops set $pkg GET_USAGE_STATS ignore"
    }

    println("# rollback")
    pkgs.forEach { println("#   adb -s ${device.serial} shell pm install-existing --user 0 $it") }
    println()
    actions.forEach { println("adb -s ${device.serial} shell $it") }

    if (!args.flag("apply")) {
        println()
        println("# dry run: add --apply to execute")
        return
    }

    println()
    actions.forEach { action ->
        print("> $action ... ")
        val result = adb.shell(device.serial, action)
        println(if (result.ok) "ok" else "failed (${result.code}) ${result.output.trim().take(120)}")
    }
}

private fun cmdSetup(raw: List<String>) {
    val args = Args(raw)
    val autoYes = args.flag("yes")

    println("NOIR setup")
    println("  platform  ${Platform.describe()}")

    val adb = Platform.findAdb(args.value("adb"))
    if (adb != null) {
        println("  adb       $adb")
    } else {
        println("  adb       not found")
        if (!autoYes && !confirm("  Download Android platform-tools (about 15 MB)? [Y/n] ")) {
            println(Guidance.adbMissing())
        } else {
            print("  Downloading ")
            val path = Setup.installAdb { read, total -> renderDownload(read, total) }
            println()
            if (path == null) throw NoirException("adb download failed.", "Check your network and try again.")
            println("  adb       $path")
        }
    }

    val jadx = Platform.findJadx(args.value("jadx"))
    if (jadx != null) {
        println("  jadx      $jadx")
    } else {
        println("  jadx      not found (only needed for the deep command)")
        if (!autoYes && !confirm("  Download jadx (about 73 MB)? [Y/n] ")) {
            println(Guidance.jadxMissing())
        } else {
            print("  Downloading ")
            val path = Setup.installJadx { read, total -> renderDownload(read, total) }
            println()
            if (path == null) throw NoirException("jadx download failed.", "Check your network and try again.")
            println("  jadx      $path")
        }
    }

    println()
    println("Done. Next step: noir doctor")
}

private fun cmdDoctor(raw: List<String>) {
    val args = Args(raw)
    println("NOIR doctor")
    println("  platform  ${Platform.describe()}")
    println("  java      ${System.getProperty("java.version")}")

    val adbPath = Platform.findAdb(args.value("adb"))
    if (adbPath == null) {
        println("  adb       not found")
        println(Guidance.adbMissing())
        return
    }
    val adb = Adb(adbPath)
    println("  adb       $adbPath")
    adb.exec(listOf("version"), timeoutSec = 15).output.lineSequence()
        .firstOrNull { it.startsWith("Version") }
        ?.let { println("            $it") }

    val devices = adb.devices()
    if (devices.isEmpty()) {
        println("  device    not connected")
        println()
        println(Guidance.deviceGuide())
    } else {
        devices.forEach { println("  device    ${it.serial}  ${it.state}  ${it.model}") }
        if (devices.any { it.state == "unauthorized" }) {
            println()
            println(Guidance.unauthorizedGuide())
        }
    }

    val jadx = Platform.findJadx(args.value("jadx"))
    if (jadx == null) println("  jadx      not found (only needed for deep)") else println("  jadx      $jadx")
}

private fun confirm(prompt: String): Boolean {
    print(prompt)
    val answer = readLine()?.trim()?.lowercase()
    return answer != "n" && answer != "no"
}

// ── scan pipeline ──────────────────────────────────────────────────────────

private fun performScan(args: Args): ScanResult {
    val adb = connectAdb(args)
    val device = awaitDevice(adb, args.value("serial"), interactive = isInteractive())
    val outDir = File(args.value("out") ?: "noir-out").apply { mkdirs() }
    val minScore = args.value("min")?.toIntOrNull() ?: 0
    val limit = args.value("limit")?.toIntOrNull() ?: 500

    say("[*] host: ${Platform.describe()}")
    say("[*] device: ${device.serial} (${device.model})")

    val paths = DeviceScan.packagePaths(adb, device.serial)
    say("[*] packages: ${paths.size}")

    if (!QUIET) print("[*] reading dumpsys package ... ")
    val dump = adb.shell(device.serial, "dumpsys package", timeoutSec = 600)
    say("${dump.output.length / 1024} KiB")

    val meta = Dumpsys.parse(dump.output)
    say("[*] parsed: ${meta.size}")

    val only = args.value("only")?.let { runCatching { Regex(it) }.getOrNull() }
    val candidates = meta.entries.filter { (pkg, m) ->
        m.perms.contains("INTERNET") &&
            m.perms.count { it in Rules.SENSITIVE } > 0 &&
            paths.containsKey(pkg) &&
            (only == null || only.containsMatchIn(pkg))
    }
    say("[*] candidates (internet + sensitive): ${candidates.size}")

    val android = adb.shell(device.serial, "getprop ro.build.version.release").output.trim()
    val reportMeta = readReportMeta(adb, device, android)

    val targets = candidates.map { PackagePath(it.key, paths.getValue(it.key)) }
    val endpoints = HashMap<String, List<String>>()
    val missing = ArrayList<PackagePath>()

    targets.forEach { target ->
        val hit = Cache.get(target.pkg, target.path)
        if (hit != null) endpoints[target.pkg] = hit else missing += target
    }

    if (missing.isNotEmpty()) {
        say("[*] analysing ${missing.size} new/changed APKs (cache hits: ${targets.size - missing.size})")
        val started = System.currentTimeMillis()
        val fresh = DeviceScan.urls(adb, device.serial, missing, File(outDir, "work")) { done, total ->
            if (!QUIET) {
                print(progressLine(started, done, total))
                System.out.flush()
            }
        }
        if (!QUIET) println()
        missing.forEach { target -> Cache.put(target.pkg, target.path, fresh[target.pkg].orEmpty()) }
        Cache.flush()
        endpoints.putAll(fresh)
    } else {
        say("[*] all endpoints served from cache")
    }

    val apps = candidates.map { (pkg, m) ->
        val perms = m.perms.filter { it in Rules.SENSITIVE }
        val urls = endpoints[pkg].orEmpty()
        AppEntry(
            pkg = pkg,
            uid = m.appId,
            isSystem = m.isSystem,
            debuggable = m.debuggable,
            installer = m.installer,
            permissions = perms,
            endpoints = urls,
            score = Rules.score(perms, urls, m.isSystem, m.debuggable),
            category = Classifier.category(pkg, urls, perms, m.isSystem),
            vendor = Classifier.vendor(pkg, urls),
            sharedUid = m.sharedUser
        )
    }
        .filter { it.score >= minScore }
        .sortedByDescending { it.score }
        .take(limit)

    return ScanResult(device, apps, outDir, android, paths.size, paths, reportMeta)
}

private fun readReportMeta(adb: Adb, device: Device, android: String): ReportMeta {
    fun prop(key: String): String =
        adb.shell(device.serial, "getprop $key", timeoutSec = 15).output.trim()

    val userOut = adb.shell(device.serial, "am get-current-user", timeoutSec = 15).output
    val user = userOut.lineSequence()
        .map { it.trim() }
        .firstOrNull { it.toIntOrNull() != null }
        ?: "0"

    return ReportMeta(
        tool = "NOIR $VERSION",
        host = Platform.describe(),
        android = android,
        sdk = prop("ro.build.version.sdk"),
        build = prop("ro.build.display.id").ifBlank { prop("ro.build.id") },
        fingerprint = prop("ro.build.fingerprint"),
        user = user,
        generatedAt = OffsetDateTime.now().toString()
    )
}

private fun writeReports(result: ScanResult, recommendations: List<Recommendation>) {
    File(result.outDir, "report.json").writeText(Report.json(result.device, result.apps, recommendations, result.meta))
    File(result.outDir, "report.md").writeText(Report.markdown(result.device, result.apps, recommendations, result.meta))
    writeDomainFiles(result.outDir, result.apps)
    File(result.outDir, "plan.txt").writeText(
        plannedCommands(recommendations, result.meta.user).joinToString("\n", postfix = "\n")
    )
    File(result.outDir, "rollback.txt").writeText(
        rollbackLines(recommendations, result.meta.user).joinToString("\n", postfix = "\n")
    )
}

private fun writeDomainFiles(outDir: File, apps: List<AppEntry>) {
    val export = Domains.export(apps)
    val date = java.time.LocalDate.now().toString()

    fun render(title: String, note: String, hosts: List<String>): String =
        buildString {
            append("# NOIR — ").append(title).append('\n')
            append("# generated ").append(date).append(" · ").append(hosts.size).append(" hosts\n")
            append("# ").append(note).append('\n')
            append("#\n")
            hosts.forEach { append(it).append('\n') }
        }

    val trackers = render(
        "tracker domains",
        "analytics / ads / crash reporting. Safe to block: these do not carry user-facing features.",
        export.trackers
    )
    val review = render(
        "unclassified domains",
        "review before blocking: these may be app APIs, maps, security updates or third-party SDKs.",
        export.review
    )
    val functional = render(
        "functional domains",
        "DO NOT BLOCK: push, login, updates, payments, app stores, cloud sync and connectivity checks.",
        export.functional
    )

    File(outDir, "domains-trackers.txt").writeText(trackers)
    File(outDir, "domains-other.txt").writeText(review)
    File(outDir, "domains-functional.txt").writeText(functional)

    // Backwards-compatible name, now containing only the safe tier.
    File(outDir, "domains.txt").writeText(trackers)
}

internal data class AppOpAction(val pkg: String, val op: String) {
    fun setCommand(user: String?): String =
        "cmd appops set${userArg(user)} $pkg $op ignore"

    fun getCommand(user: String?): String =
        "cmd appops get${userArg(user)} $pkg $op"

    fun rollbackCommand(user: String?, mode: String = "default"): String =
        "adb shell cmd appops set${userArg(user)} $pkg $op ${mode.ifBlank { "default" }}"

    private fun userArg(user: String?): String =
        if (user.isNullOrBlank()) "" else " --user $user"
}

private fun plannedActions(recommendations: List<Recommendation>): List<AppOpAction> =
    recommendations.filter { it.autoSafe }.mapNotNull { r ->
        when (r.action) {
            ActionType.APPOP_PROJECT_MEDIA -> AppOpAction(r.pkg, "PROJECT_MEDIA")
            ActionType.APPOP_USAGE_STATS -> AppOpAction(r.pkg, "GET_USAGE_STATS")
            else -> null
        }
    }.distinct()

private fun plannedCommands(recommendations: List<Recommendation>, user: String? = null): List<String> =
    plannedActions(recommendations).map { it.setCommand(user) }

private fun rollbackLines(recommendations: List<Recommendation>, user: String? = null): List<String> =
    plannedActions(recommendations).map { it.rollbackCommand(user) }

private fun parseAppOpMode(output: String, op: String): String? {
    val match = Regex("(?m)^\\s*${Regex.escape(op)}:\\s*([a-zA-Z_]+)").find(output)
    return match?.groupValues?.get(1)
}

private fun flatOutput(output: String): String =
    output.trim().replace("\n", " | ").ifBlank { "(no output)" }

private fun classifyAppOpFailure(output: String): String = when {
    output.contains("device offline", ignoreCase = true) ||
        output.contains("no devices", ignoreCase = true) ||
        output.contains("device not found", ignoreCase = true) -> "adb connection"
    output.contains("SecurityException", ignoreCase = true) ||
        output.contains("Permission Denial", ignoreCase = true) ||
        output.contains("not allowed", ignoreCase = true) -> "system permission"
    output.contains("Unknown operation", ignoreCase = true) ||
        output.contains("Unknown op", ignoreCase = true) -> "unknown AppOp"
    output.contains("No such package", ignoreCase = true) ||
        (output.contains("package", ignoreCase = true) && output.contains("not found", ignoreCase = true)) -> "package/user"
    else -> "rejected"
}

internal fun applyCommands(adb: Adb, result: ScanResult, planned: List<AppOpAction>) {
    if (planned.isEmpty()) return
    val user = result.meta.user.ifBlank { null }
    val applied = ArrayList<String>()
    val rollback = ArrayList<String>()
    var failed = 0
    var permissionFailures = 0

    applied.add("# NOIR applied commands")
    applied.add("# generated: ${result.meta.generatedAt}")
    applied.add("# tool: ${result.meta.tool}")
    applied.add("# host: ${result.meta.host}")
    applied.add("# device: ${result.device.model} (${result.device.serial}) · ${result.device.product}")
    applied.add("# android: ${result.meta.android} (SDK ${result.meta.sdk})")
    applied.add("# build: ${result.meta.build}")
    applied.add("# fingerprint: ${result.meta.fingerprint}")
    applied.add("# user: ${result.meta.user.ifBlank { "unknown (default user)" }}")
    applied.add("#")

    println()
    planned.forEach { action ->
        val before = adb.shell(result.device.serial, action.getCommand(user), timeoutSec = 30)
        val res = adb.shell(result.device.serial, action.setCommand(user), timeoutSec = 30)
        val after = adb.shell(result.device.serial, action.getCommand(user), timeoutSec = 30)
        val status = when {
            res.timedOut -> "timeout (${res.code})"
            res.ok -> "ok (0)"
            else -> "failed (${res.code})"
        }
        val kind = if (!res.ok) classifyAppOpFailure(res.output) else ""
        if (!res.ok) {
            failed++
            if (kind == "system permission") permissionFailures++
        }

        applied.add("${action.setCommand(user)}\t$status${if (kind.isNotBlank()) " [$kind]" else ""}")
        applied.add("  before: ${flatOutput(before.output)}")
        applied.add("  after:  ${flatOutput(after.output)}")
        if (res.output.isBlank()) {
            applied.add("  output: (empty)")
        } else {
            applied.add("  output:")
            res.output.trimEnd().lineSequence().forEach { applied.add("    $it") }
        }

        println("  %-72s %s%s".format(action.setCommand(user), status, if (kind.isNotBlank()) " [$kind]" else ""))
        if (!res.ok) {
            val lines = res.output.trim().lineSequence().filter { it.isNotBlank() }.toList()
            lines.take(4).forEach { println("      $it") }
            if (lines.size > 4) println("      ... (${lines.size - 4} more lines in applied.txt)")
        }

        if (res.ok) {
            val prior = parseAppOpMode(before.output, action.op) ?: "default"
            rollback.add(action.rollbackCommand(user, prior))
        }
    }

    File(result.outDir, "applied.txt").writeText(applied.joinToString("\n", postfix = "\n"))

    val rollbackText = buildString {
        appendLine("# NOIR rollback")
        appendLine("# generated: ${result.meta.generatedAt}")
        appendLine("# tool: ${result.meta.tool}")
        appendLine("# only commands that succeeded in this run are listed")
        appendLine("# device: ${result.device.model} (${result.device.serial}) · user ${result.meta.user.ifBlank { "unknown" }}")
        if (rollback.isEmpty()) {
            appendLine("# no appops changes were applied")
        } else {
            rollback.forEach { appendLine(it) }
        }
    }
    File(result.outDir, "rollback.txt").writeText(rollbackText)
    File(result.outDir, "applied.txt").let { println("\n[*] applied: ${it.absolutePath}") }
    println("[*] rollback: ${File(result.outDir, "rollback.txt").absolutePath}")
    println("[*] ${planned.size - failed}/${planned.size} appops commands applied")

    if (failed > 0) {
        println("[!] $failed command(s) failed — full stdout/stderr is in applied.txt")
        if (permissionFailures > 0) {
            println("[i] The device rejected shell-level AppOps changes. On ColorOS/OPPO/OnePlus,")
            println("    check Developer options → Permission monitoring, or use Shizuku.")
        }
    }
}

private fun renderDashboard(args: Args, result: ScanResult, recommendations: List<Recommendation>): String {
    val color = (args.flag("color") || System.console() != null) &&
        !args.flag("no-color") &&
        !args.flag("ascii")
    return Tui.dashboard(
        device = result.device,
        apps = result.apps,
        recommendations = recommendations,
        android = result.android,
        host = Platform.describe(),
        installed = result.installed,
        ascii = args.flag("ascii"),
        color = color
    )
}

private fun progressLine(startedMs: Long, done: Int, total: Int): String {
    val elapsed = (System.currentTimeMillis() - startedMs).coerceAtLeast(1)
    val perItem = elapsed.toDouble() / done.coerceAtLeast(1)
    val eta = ((total - done) * perItem / 1000).toLong().coerceAtLeast(0)
    val width = 26
    val pct = done * 100 / total
    val filled = (done.toLong() * width / total).toInt().coerceIn(0, width)
    val bar = "█".repeat(filled) + "░".repeat(width - filled)
    val spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[done % 10]
    return "\r  " + bar + " " + pct + "%  " + done + "/" + total +
        "  ·  ETA " + (eta / 60) + ":" + (eta % 60).toString().padStart(2, '0') + "  " + spin
}


// ── deep scan ──────────────────────────────────────────────────────────────

private data class DeepFinding(
    val pkg: String,
    val score: Int,
    val codeRisk: Int,
    val signals: Map<String, Int>,
    val trackers: Set<String>,
    val manifest: ManifestFacts?,
    val src: File?,
    val error: String?
)

private val DEEP_SIGNALS: Map<String, Pair<Regex, Int>> = linkedMapOf(
    "exec" to (Regex("Runtime\\.exec|ProcessBuilder") to 4),
    "dynamic-load" to (Regex("DexClassLoader|PathClassLoader|loadLibrary") to 3),
    "disable-app" to (Regex("setApplicationEnabledSetting") to 5),
    "a11y-hijack" to (Regex("enabled_accessibility_services") to 5),
    "screen-capture" to (Regex("MediaProjection|createScreenCaptureIntent") to 4),
    "reflection" to (Regex("Class\\.forName|getDeclaredMethod") to 1),
    "crypto" to (Regex("Cipher\\.getInstance|MessageDigest") to 1),
    "network" to (Regex("HttpURLConnection|OkHttpClient|openConnection") to 1),
    "set-prop" to (Regex("SystemProperties\\.set|Settings\\.(Global|Secure)\\.put") to 5),
    "sms" to (Regex("SmsManager|sendTextMessage|content://sms") to 4),
    "device-id" to (Regex("getDeviceId|getImei|getSubscriberId|getAndroidId|getSerial") to 3),
    "webview-bridge" to (Regex("addJavascriptInterface") to 3),
    "accessibility" to (Regex("AccessibilityService") to 4),
    "notification-listener" to (Regex("NotificationListenerService") to 3),
    "device-admin" to (Regex("DeviceAdminReceiver") to 4)
)

private val DEEP_SKIP = listOf(
    "androidx/", "kotlin/", "kotlinx/", "org/intellij/", "org/jetbrains/",
    "com/google/gson/", "okhttp3/", "retrofit2/", "com/google/protobuf/"
)

private fun cmdDeepScan(raw: List<String>) {
    val args = Args(raw)
    val adb = connectAdb(args)
    val scan = performScan(args)
    val outDir = File(scan.outDir, "deepscan").apply { mkdirs() }

    val top = args.value("top")?.toIntOrNull() ?: 15
    val jobs = (args.value("jobs")?.toIntOrNull()
        ?: (Runtime.getRuntime().availableProcessors() / 2).coerceAtLeast(2)).coerceIn(1, 6)
    val targets = if (args.flag("all")) scan.apps else scan.apps.take(top)

    if (targets.isEmpty()) {
        println("No flagged apps, DeepScan not needed.")
        return
    }

    val jadxBin = Platform.findJadx(args.value("jadx"))
        ?: throw NoirException("jadx not found.", Guidance.jadxMissing())

    println()
    println("== DeepScan ==")
    println("  targets  ${targets.size} apps (${scan.apps.size} flagged in total)")
    println("  jobs     $jobs jadx processes")
    println("  output   ${outDir.absolutePath}")
    if (args.flag("all")) println("  note     --all decompiles every flagged app; this can take hours and use several GB")
    println()

    val pool = Executors.newFixedThreadPool(jobs)
    val done = AtomicInteger()
    val started = System.currentTimeMillis()

    val findings = targets.map { app ->
        pool.submit<DeepFinding> {
            val result = try {
                analyzeOne(adb, scan, outDir, jadxBin, app)
            } catch (e: Exception) {
                DeepFinding(app.pkg, app.score, 0, emptyMap(), emptySet(), null, null, e.message ?: e::class.simpleName)
            }
            val n = done.incrementAndGet()
            val elapsed = (System.currentTimeMillis() - started) / 1000
            println("  [$n/${targets.size}] ${app.pkg}  code-risk=${result.codeRisk}  (${elapsed}s)")
            result
        }
    }.map { future ->
        try {
            future.get()
        } catch (e: Exception) {
            DeepFinding("unknown", 0, 0, emptyMap(), emptySet(), null, null, e.message)
        }
    }
    pool.shutdown()

    val ranked = findings.sortedByDescending { it.codeRisk }
    writeDeepReports(outDir, ranked)

    println()
    println("%5s %5s  %-44s %s".format("RISK", "SCAN", "PACKAGE", "SIGNALS"))
    ranked.take(20).forEach { f ->
        val signals = f.signals.entries.sortedByDescending { it.value }.take(3)
            .joinToString(", ") { "${it.key}x${it.value}" }
            .ifBlank { f.error ?: "-" }
        println("%5d %5d  %-44s %s".format(f.codeRisk, f.score, f.pkg, signals))
    }
    println()
    println("[+] ${File(outDir, "deepscan.md").absolutePath}")
    println("[+] ${File(outDir, "deepscan.tsv").absolutePath}")

    offerCleanup(args, adb, scan, ranked)
}

private fun analyzeOne(adb: Adb, scan: ScanResult, outDir: File, jadxBin: String, app: AppEntry): DeepFinding {
    val remote = scan.paths[app.pkg]
        ?: return DeepFinding(app.pkg, app.score, 0, emptyMap(), emptySet(), null, null, "no apk path")

    val apk = File(outDir, "apks/${app.pkg}.apk")
    if (!apk.exists()) {
        apk.parentFile?.mkdirs()
        adb.pull(scan.device.serial, remote, apk)
    }
    if (!apk.exists()) {
        return DeepFinding(app.pkg, app.score, 0, emptyMap(), emptySet(), null, null, "pull failed")
    }

    val src = File(outDir, "src/${app.pkg}")
    val marker = File(src, ".noir-ok")
    val cached = marker.exists() && marker.readText().trim() == remote
    if (!cached) {
        src.deleteRecursively()
        src.mkdirs()
    }

    val exit = if (cached) 0 else Jadx(jadxBin).decompile(apk, src)
    val sources = File(src, "sources")
    if (exit != 0 && !sources.isDirectory) {
        return DeepFinding(app.pkg, app.score, 0, emptyMap(), emptySet(), ManifestAnalyzer.analyze(apk), null, "jadx exit $exit")
    }
    runCatching { marker.writeText(remote) }

    val signals = countSignals(src)
    var risk = DEEP_SIGNALS.entries.sumOf { (key, def) ->
        (signals[key] ?: 0).coerceAtMost(3) * def.second
    }
    val manifest = ManifestAnalyzer.analyze(apk)
    manifest?.let { facts ->
        risk += facts.riskyCount.coerceAtMost(4)
        if (facts.cleartext == true && app.uploadEndpoints.isNotEmpty()) risk += 2
        if (facts.allowBackup == true) risk += 1
        if (facts.debuggable == true) risk += 3
    }

    return DeepFinding(
        app.pkg, app.score, risk.coerceAtMost(40), signals,
        Trackers.fromEndpoints(app.endpoints) + Trackers.fromSources(src),
        manifest, src, null
    )
}

private fun countSignals(dir: File): Map<String, Int> {
    val counts = HashMap<String, Int>()
    if (!dir.exists()) return counts

    // jadx writes decompiled classes under <out>/sources; skip bundled libraries by
    // their path relative to that root, not the output root.
    val root = File(dir, "sources").takeIf { it.isDirectory } ?: dir
    var budget = 40L * 1024 * 1024
    val files = root.walkTopDown()
        .filter { it.isFile && (it.extension == "java" || it.extension == "kt") }
        .filter { file ->
            val path = file.relativeTo(root).path
            DEEP_SKIP.none { path.startsWith(it) }
        }
        .take(8000)

    for (file in files) {
        if (budget <= 0) break
        val text = try {
            file.readText()
        } catch (e: Exception) {
            continue
        }
        budget -= text.length
        DEEP_SIGNALS.forEach { (key, def) ->
            val hits = def.first.findAll(text).count()
            if (hits > 0) counts[key] = (counts[key] ?: 0) + hits
        }
    }
    return counts
}

private fun writeDeepReports(outDir: File, findings: List<DeepFinding>) {
    val tsv = StringBuilder("code_risk\tscan_score\tpackage\tsignals\ttrackers\texported_no_perm\terror\n")
    findings.forEach { f ->
        val signals = f.signals.entries.joinToString(";") { "${it.key}=${it.value}" }
        tsv.append(f.codeRisk).append('\t')
            .append(f.score).append('\t')
            .append(f.pkg).append('\t')
            .append(signals).append('\t')
            .append(f.trackers.joinToString(",")).append('\t')
            .append(f.manifest?.exportedWithoutPermission?.size ?: 0).append('\t')
            .append(f.error ?: "").append('\n')
    }
    File(outDir, "deepscan.tsv").writeText(tsv.toString())

    val md = StringBuilder()
    md.append("# DeepScan\n\n")
    md.append("| code risk | scan score | package | signals | trackers | error |\n")
    md.append("|---:|---:|---|---|---|---|\n")
    findings.forEach { f ->
        val signals = f.signals.entries.sortedByDescending { it.value }
            .joinToString(", ") { "${it.key} ×${it.value}" }
        md.append("| ").append(f.codeRisk)
            .append(" | ").append(f.score)
            .append(" | `").append(f.pkg).append("`")
            .append(" | ").append(signals.ifBlank { "—" })
            .append(" | ").append(f.trackers.joinToString(", ").ifBlank { "—" })
            .append(" | ").append(f.error ?: "")
            .append(" |\n")
    }
    md.append("\n## details\n")
    findings.forEach { f ->
        md.append("\n### ").append(f.pkg).append("\n\n")
        md.append("- code risk: ").append(f.codeRisk).append("\n")
        md.append("- scan score: ").append(f.score).append("\n")
        if (f.signals.isNotEmpty()) {
            md.append("- signals: ").append(f.signals.entries.joinToString(", ") { "${it.key}=${it.value}" }).append("\n")
        }
        if (f.trackers.isNotEmpty()) {
            md.append("- trackers: ").append(f.trackers.joinToString(", ")).append("\n")
        }
        f.manifest?.let { m ->
            md.append("- targetSdk: ").append(m.targetSdk ?: "?").append("\n")
            md.append("- cleartext: ").append(m.cleartext ?: "unset")
                .append(" · allowBackup: ").append(m.allowBackup ?: "unset")
                .append(" · debuggable: ").append(m.debuggable ?: "false")
                .append(" · networkSecurityConfig: ").append(m.networkSecurityConfig).append("\n")
            if (m.exportedWithoutPermission.isNotEmpty()) {
                md.append("- exported without permission (").append(m.exportedWithoutPermission.size).append("):\n")
                m.exportedWithoutPermission.take(10).forEach { c ->
                    md.append("  - ").append(c.kind).append(" `").append(c.name).append("`")
                    c.authorities?.let { md.append(" (").append(it).append(")") }
                    md.append("\n")
                }
            }
        }
        f.src?.let { md.append("- sources: `").append(it.absolutePath).append("`\n") }
        if (f.error != null) md.append("- error: ").append(f.error).append("\n")
    }
    File(outDir, "deepscan.md").writeText(md.toString())
}

private fun offerCleanup(args: Args, adb: Adb, scan: ScanResult, findings: List<DeepFinding>) {
    val high = findings.filter { it.codeRisk >= 8 && it.error == null }
    if (high.isEmpty()) {
        println()
        println("No code-level high-risk findings, no extra cleanup needed.")
        return
    }

    val highPkgs = high.map { it.pkg }.toSet()
    val appsByPkg = scan.apps.associateBy { it.pkg }
    val planned = plannedActions(Advisor.advise(scan.apps).filter { it.pkg in highPkgs })

    println()
    println("== ${high.size} code-level high-risk apps ==")
    high.forEach { f ->
        val system = appsByPkg[f.pkg]?.isSystem ?: true
        println("  %-44s risk %2d  %s".format(f.pkg, f.codeRisk, if (system) "system" else "user"))
    }
    println("  Safe appops available: ${planned.size}")

    if (!args.flag("apply")) {
        println()
        println("[*] dry run: add --apply to run safe cleanup; add --purge to also uninstall high-risk user apps")
        return
    }

    if (!args.flag("yes")) {
        if (!isInteractive()) {
            println("[!] --apply in a non-interactive environment also requires --yes")
            return
        }
        print("Apply these ${planned.size} appops? [y/N] ")
        val answer = readLine()?.trim()?.lowercase()
        if (answer != "y" && answer != "yes") {
            println("Skipped.")
            return
        }
    }
    applyCommands(adb, scan, planned)

    if (!args.flag("purge")) return

    val userHigh = high.filter { appsByPkg[it.pkg]?.isSystem == false }
    if (userHigh.isEmpty()) {
        println("No user apps among the high-risk findings, nothing to uninstall.")
        return
    }
    println()
    println("== Uninstall high-risk user apps ==")
    println("# Restore command: adb shell pm install-existing --user 0 <package>")
    userHigh.forEach { f ->
        if (!args.flag("yes") && isInteractive()) {
            print("  Uninstall ${f.pkg}? [y/N] ")
            val answer = readLine()?.trim()?.lowercase()
            if (answer != "y" && answer != "yes") return@forEach
        }
        val result = adb.shell(scan.device.serial, "pm uninstall --user 0 ${f.pkg}")
        println("  %-44s %s".format(f.pkg, if (result.ok) "uninstalled" else "failed (${result.code})"))
    }
}

// ── plumbing ───────────────────────────────────────────────────────────────

private fun isInteractive(): Boolean =
    System.console() != null || System.getenv("NOIR_INTERACTIVE") == "1"

private fun connectAdb(args: Args): Adb {
    val explicit = args.value("adb")
    if (explicit != null && !File(explicit).exists()) {
        throw NoirException("The specified adb does not exist: $explicit", "Check the path, or run noir setup to install it automatically.")
    }
    val bin = Platform.findAdb(explicit)
        ?: throw NoirException("adb not found.", Guidance.adbMissing())
    return Adb(bin)
}

private fun awaitDevice(adb: Adb, requested: String?, interactive: Boolean): Device {
    var waited = 0
    var printed = false

    while (true) {
        val devices = adb.devices()
        val online = devices.filter { it.state == "device" }

        if (requested != null) {
            online.firstOrNull { it.serial == requested }?.let { return it }
            if (online.isNotEmpty()) {
                throw NoirException(
                    "Device $requested not found.",
                    "Currently connected: " + online.joinToString { "${it.serial} (${it.model})" }
                )
            }
        } else if (online.size == 1) {
            return online.first()
        } else if (online.size > 1) {
            // Prefer a physical device over an emulator when both are attached.
            val physical = online.filterNot { it.serial.startsWith("emulator-") }
            if (physical.size == 1) return physical.first()

            if (interactive) {
                println("Multiple devices detected:")
                online.forEachIndexed { index, device ->
                    println("  ${index + 1}) ${device.serial}  ${device.model}")
                }
                print("Choose a device [1-${online.size}] ")
                val choice = readLine()?.trim()?.toIntOrNull()
                if (choice != null && choice in 1..online.size) return online[choice - 1]
                throw NoirException("No device selected.", "Use --serial <id> to choose which device to scan.")
            }

            val chosen = physical.firstOrNull() ?: online.first()
            println("Note: ${online.size} devices detected, using ${chosen.serial}. Use --serial to choose.")
            return chosen
        }

        val unauthorized = devices.any { it.state == "unauthorized" }
        if (!printed) {
            println(if (unauthorized) Guidance.unauthorizedGuide() else Guidance.deviceGuide())
            printed = true
        }

        if (!interactive) {
            throw NoirException(
                "No usable device.",
                if (unauthorized) Guidance.unauthorizedGuide() else "Plug in your phone and run again, or run noir doctor first."
            )
        }
        if (waited >= 180) throw NoirException("Waited 180 seconds and still no device.", Guidance.deviceGuide())

        print("\r  Waiting for a device ... ${180 - waited}s   ")
        System.out.flush()
        Thread.sleep(2000)
        waited += 2
    }
}

private class Args(raw: List<String>) {
    val positional = ArrayList<String>()
    val flags = HashSet<String>()
    val values = HashMap<String, String>()

    init {
        var i = 0
        while (i < raw.size) {
            val arg = raw[i]
            if (arg.startsWith("--")) {
                val name = arg.substring(2)
                val takesValue = name !in BOOLEAN_FLAGS && i + 1 < raw.size && !raw[i + 1].startsWith("--")
                if (takesValue) {
                    values[name] = raw[i + 1]
                    i++
                } else {
                    flags.add(name)
                }
            } else {
                positional.add(arg)
            }
            i++
        }
    }

    fun flag(name: String): Boolean = name in flags
    fun value(name: String): String? = values[name]
}
