/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.core

enum class ActionType(val label: String) {
    APPOP_PROJECT_MEDIA("Block screen capture"),
    APPOP_USAGE_STATS("Block usage stats"),
    UNINSTALL_USER("Uninstall for current user"),
    REVIEW("Manual review"),
    BLOCK_DNS("DNS block")
}

data class Recommendation(
    val pkg: String,
    val action: ActionType,
    val risk: String,
    val reason: String,
    val autoSafe: Boolean
)

/**
 * Turns findings into a small, ordered set of actions.
 *
 * Two deliberate restraints:
 *  - screen-capture is only flagged on system components that also ship upload
 *    endpoints, never on apps where screen sharing is a real feature;
 *  - NOIR never proposes uninstalling a user app. Those become REVIEW, because
 *    "WeChat uploads a lot" is not a reason to uninstall WeChat.
 */
object Advisor {

    private val CORE = setOf(
        "com.miui.securitycenter",
        "com.miui.guardprovider",
        "com.xiaomi.xmsf",
        "com.xiaomi.digitalkey",
        "com.android.systemui",
        "com.miui.home",
        "com.android.settings",
        "com.android.phone",
        "com.android.mms",
        "com.android.incallui"
    )

    /** Apps where screen capture is a legitimate, user-facing feature. */
    private val MEDIA_KEEP = setOf(
        "com.miui.screenrecorder",
        "com.milink.service",
        "com.miui.carlink",
        "com.miui.accessibility",
        "com.xiaomi.mirror",
        "com.android.chrome",
        "com.google.android.youtube",
        "com.tencent.mm",
        "com.tencent.mobileqq",
        "com.eg.android.AlipayGphone",
        "tv.danmaku.bili",
        "com.verlintas.baic2",
        "com.verlintas.baic2.devtest",
        "bin.mt.plus"
    )

    fun advise(apps: List<AppEntry>): List<Recommendation> {
        val out = ArrayList<Recommendation>()

        apps.forEach { app ->
            if (app.pkg == "android") return@forEach

            val mediaWorthFlagging =
                "FOREGROUND_SERVICE_MEDIA_PROJECTION" in app.permissions &&
                    app.pkg !in MEDIA_KEEP &&
                    app.isSystem &&
                    (
                        app.category in setOf(Category.SECURITY, Category.AI_VOICE, Category.TELEMETRY) ||
                            app.uploadEndpoints.isNotEmpty()
                        )

            if (mediaWorthFlagging) {
                out += Recommendation(
                    app.pkg,
                    ActionType.APPOP_PROJECT_MEDIA,
                    "MED",
                    "System component that declares screen capture and has reporting endpoints",
                    autoSafe = true
                )
            }

            if ("PACKAGE_USAGE_STATS" in app.permissions &&
                app.category == Category.TELEMETRY &&
                app.isSystem
            ) {
                out += Recommendation(
                    app.pkg,
                    ActionType.APPOP_USAGE_STATS,
                    "MED",
                    "Telemetry system app can read app usage stats",
                    autoSafe = true
                )
            }

            if ((app.category == Category.TELEMETRY || app.category == Category.ADS) && app.pkg !in CORE) {
                out += Recommendation(
                    app.pkg,
                    ActionType.REVIEW,
                    if (app.isSystem) "HIGH" else "MED",
                    if (app.isSystem) "Telemetry/ads system component; can't be uninstalled, block at the DNS level" else "Heavy telemetry/ads; evaluate whether to keep it",
                    autoSafe = false
                )
            }

            if (app.uploadEndpoints.size >= 2 &&
                app.category in setOf(Category.TELEMETRY, Category.LOCATION, Category.ADS)
            ) {
                out += Recommendation(
                    app.pkg,
                    ActionType.BLOCK_DNS,
                    "LOW",
                    "Multiple reporting endpoints; can be blocked at the DNS level",
                    autoSafe = false
                )
            }
        }

        return out
            .distinctBy { it.pkg to it.action }
            .sortedWith(compareBy({ riskRank(it.risk) }, { it.action.ordinal }))
    }

    private fun riskRank(risk: String): Int = when (risk) {
        "HIGH" -> 0
        "MED" -> 1
        else -> 2
    }
}
