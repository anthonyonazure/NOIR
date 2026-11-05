/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.cli

import app.noir.core.Tui

/** Human-friendly text blocks: every failure should end with an action. */
object Guidance {


    fun about(version: String): String {
        val total = (Tui.terminalColumns() - 2).coerceIn(50, 100)
        val inner = total - 4

        fun row(text: String) = "│ " + pad(text, inner) + " │"

        val sb = StringBuilder()
        sb.append("╭").append("─".repeat(total - 2)).append("╮").append('\n')

        val logo = listOf(
            "  ███╗   ██╗ ██████╗ ██╗██████╗ ",
            "  ████╗  ██║██╔═══██╗██║██╔══██╗",
            "  ██╔██╗ ██║██║   ██║██║██████╔╝",
            "  ██║╚██╗██║██║   ██║██║██╔══██╗",
            "  ██║ ╚████║╚██████╔╝██║██║  ██║",
            "  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝"
        )
        if (inner >= 40) {
            logo.forEach { sb.append(row(it)).append('\n') }
        } else {
            sb.append(row("  NOIR")).append('\n')
        }

        sb.append(row("")).append('\n')

        fun field(label: String, value: String) {
            val prefix = "  " + label.padEnd(10)
            val lines = wrap(value, inner - prefix.length)
            if (lines.isEmpty()) {
                sb.append(row(prefix.trimEnd())).append('\n')
                return
            }
            sb.append(row(prefix + lines.first())).append('\n')
            lines.drop(1).forEach { sb.append(row(" ".repeat(prefix.length) + it)).append('\n') }
        }

        field("version", "$version · android leak audit")
        field("what", "inventories what installed apps can collect, and where they send it")
        field("not", "a root tool · not a malware scanner · not a firewall")
        field("writes", "nothing by default; --apply only sets reversible app-ops")
        field("license", "MIT")
        field("author", "Verlintas")
        field("repo", "github.com/Verlintas/NOIR")
        field("runs on", "Windows 10/11 · macOS · Debian/Ubuntu")

        sb.append(row("")).append('\n')
        sb.append(row("  commands")).append('\n')
        listOf(
            "noir" to "guided first run",
            "noir doctor" to "environment check",
            "noir scan" to "inventory + report",
            "noir ui" to "dashboard",
            "noir auto" to "plan (+ --apply)",
            "noir deep <pkg>" to "jadx dive",
            "noir setup" to "download adb / jadx"
        ).forEach { (cmd, desc) ->
            sb.append(row("    " + cmd.padEnd(18) + desc)).append('\n')
        }

        sb.append('╰').append("─".repeat(total - 2)).append('╯')
        return sb.toString()
    }

    fun deviceGuide(): String = """
        |╭─ No device detected ──────────────────────────────────────────╮
        |│                                                              │
        |│  1. Turn on developer mode                                   │
        |│     Xiaomi / HyperOS: Settings → My device → All specs       │
        |│       → tap "MIUI version" 7 times                           │
        |│     Stock Android: Settings → About phone                    │
        |│       → tap "Build number" 7 times                           │
        |│                                                              │
        |│  2. Turn on USB debugging                                    │
        |│     Settings → System → Developer options → USB debugging    │
        |│     Xiaomi only: also turn on                                │
        |│       USB debugging (Security settings)                      │
        |│                                                              │
        |│  3. After plugging in, the phone asks "Allow USB debugging?" │
        |│     Check "Always allow from this computer" → Allow          │
        |│                                                              │
        |│  4. Still not working? Try another cable                     │
        |│     (many cables are charge-only)                            │
        |╰──────────────────────────────────────────────────────────────╯
    """.trimMargin()

    fun unauthorizedGuide(): String = """
        |The device is connected but not authorized.
        |
        |  • Check the phone screen: there should be an "Allow USB debugging?" prompt
        |  • No prompt: Developer options → Revoke USB debugging authorizations → unplug and replug
        |  • Still nothing: Developer options → turn USB debugging off and on again
    """.trimMargin()

    fun adbMissing(): String = """
        |  • macOS: brew install --cask android-platform-tools
        |  • Windows: scoop install adb  or  https://developer.android.com/tools/releases/platform-tools
        |  • Debian/Ubuntu: sudo apt install adb
        |  • Or let NOIR download it for you: noir setup
    """.trimMargin()

    fun jadxMissing(): String = """
        |  • macOS: brew install jadx
        |  • Windows: scoop install jadx
        |  • Debian/Ubuntu: apt install jadx
        |  • Or let NOIR download it for you: noir setup
    """.trimMargin()

    fun error(title: String, hint: String? = null): String {
        val total = (Tui.terminalColumns() - 2).coerceIn(50, 100)
        val inner = total - 4

        fun row(text: String) = "│ " + pad(text, inner) + " │"

        val sb = StringBuilder()
        sb.append("╭─ ERROR ").append("─".repeat(total - 10)).append("╮").append('\n')
        wrap(title, inner).forEach { sb.append(row(it)).append('\n') }
        if (hint != null) {
            sb.append('├').append("─".repeat(total - 2)).append('┤').append('\n')
            wrap(hint, inner).forEach { sb.append(row(it)).append('\n') }
        }
        sb.append('╰').append("─".repeat(total - 2)).append('╯')
        return sb.toString()
    }

    /**
     * Greedy wrap that prefers spaces (English) but still breaks anywhere when a
     * run of CJK text has no spaces to break on.
     */
    private fun wrap(text: String, width: Int): List<String> {
        val out = ArrayList<String>()
        text.lines().forEach { line ->
            if (line.isEmpty()) {
                out.add("")
                return@forEach
            }
            var start = 0
            while (start < line.length) {
                var i = start
                var used = 0
                var lastSpace = -1
                while (i < line.length) {
                    val cw = charWidth(line[i])
                    if (used + cw > width) break
                    if (line[i] == ' ') lastSpace = i
                    used += cw
                    i++
                }
                if (i >= line.length) {
                    out.add(line.substring(start))
                    break
                }
                if (lastSpace > start) {
                    out.add(line.substring(start, lastSpace))
                    start = lastSpace + 1
                } else {
                    out.add(line.substring(start, i))
                    start = i
                }
            }
        }
        return out
    }

    private fun pad(s: String, width: Int) = s + " ".repeat(maxOf(0, width - width(s)))

    private fun width(s: String) = s.sumOf { charWidth(it) }

    private fun charWidth(c: Char): Int = when {
        c.code in 0x1100..0x115F -> 2
        c.code in 0x2E80..0xA4CF -> 2
        c.code in 0xAC00..0xD7A3 -> 2
        c.code in 0xF900..0xFAFF -> 2
        c.code in 0xFE30..0xFE4F -> 2
        c.code in 0xFF00..0xFF60 -> 2
        c.code in 0xFFE0..0xFFE6 -> 2
        else -> 1
    }
}
