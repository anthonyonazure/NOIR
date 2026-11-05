```
  ███╗   ██╗ ██████╗ ██╗██████╗
  ████╗  ██║██╔═══██╗██║██╔══██╗
  ██╔██╗ ██║██║   ██║██║██████╔╝
  ██║╚██╗██║██║   ██║██║██╔══██╗
  ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
```

# NOIR

[![build](https://github.com/Verlintas/NOIR/actions/workflows/build.yml/badge.svg)](https://github.com/Verlintas/NOIR/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/Verlintas/NOIR)](https://github.com/Verlintas/NOIR/releases)
[![license](https://img.shields.io/github/license/Verlintas/NOIR)](LICENSE)
![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux-2ea44f)
[![AtomGit](https://img.shields.io/badge/AtomGit-Verlintas%2FNOIR-2f81f7)](https://atomgit.com/Verlintas/NOIR)

**Turn "what can this phone actually leak?" into a reproducible report.**

NOIR is an audit tool that runs on your computer. Over `adb`, it reads the app list, permissions, and network endpoints inside the APKs on a connected Android device, then gives you categories, risk scores, and actionable fixes. When needed, it can also call `jadx` to decompile a single app and search it for keywords.

> Purpose: **auditing and self-protection**. For your own devices, your own apps, and authorized security research.

> This is an English translation of [Verlintas/NOIR](https://github.com/Verlintas/NOIR). The CLI output, labels, and docs have been translated from Chinese.

**Website:** https://verlintas.dev/noir/ · [中文](https://verlintas.dev/noir/zh/)

**AtomGit mirror:** https://atomgit.com/Verlintas/NOIR

---

## What it does

1. **Inventory:** lists every app that has network permission plus sensitive permissions, and what each one was granted.
2. **Endpoint extraction:** runs `unzip + strings` on the device to pull URLs out of each APK's dex files. Only a few KB come back; the full APK is never copied to your computer.
3. **Classification and scoring:** identifies the vendor (Xiaomi / Google / Tencent / Amap ...) and category (telemetry, ads, location, keyboard ...) from package and domain names, then calculates a risk score from permissions and reporting endpoints.
4. **Data mapping:** translates permissions into "what data it can get" (location / contacts / SMS / call log / mic / camera / screen / app list / device IDs / files / calendar / accounts), then pairs that with reporting domains to show "which data may flow where."
5. **Shared UID:** detects shared users like `android.uid.system` and lists which packages actually share the same combined permission set.
6. **Manifest layer:** parses the binary AXML `AndroidManifest.xml` to find exported components with no permission protection, cleartext traffic, backup, debuggable, and targetSdk.
7. **Recommendations:** sorts actions into "safe to auto-run," "needs manual review," and "don't touch," and generates a rollback command for each.
8. **Deep dive when needed:** `deep` pulls a single APK locally, decompiles it with `jadx`, and searches for high-risk calls like `Runtime.exec`, `setApplicationEnabledSetting`, `DexClassLoader`, and `MediaProjection`.

## What it doesn't do

- No internet access, no data uploads, no account needed.
- Doesn't modify the system partition, no root required.
- Never auto-uninstalls anything unless you explicitly add `--aggressive` (and even then it asks before each app unless you also pass `--yes`).
- Leaves nothing behind on the phone: its temporary files are wiped after every scan, even if you press Ctrl+C.

---

## First run

```bash
noir
```

With no arguments it starts a wizard:

1. Checks for `adb`. If missing, it **asks whether to auto-download it** (to `~/.noir/tools`)
2. Checks for a device. If none, it prints **steps to enable developer mode / USB debugging**, then **waits for you to plug in** (up to 180 seconds)
3. Asks "Start scan?" and shows the dashboard when done
4. Asks "Apply these 19 safe fixes?" Answer `y` and it runs them and writes a rollback file

You only answer two or three y/n questions. Everything else is automatic.

## Environment check

```bash
noir doctor
```

```
NOIR doctor
  platform  Mac OS X aarch64
  java      17.0.19
  adb       /opt/homebrew/.../platform-tools/adb
            Version 37.0.1-15733141
  device    178b0d2f  device  2509FPN0BC
  jadx      /opt/homebrew/bin/jadx
```

```bash
noir setup          # download whatever is missing
noir setup --yes    # no prompts, good for scripts
```

## When something goes wrong

Every error tells you what to do instead of dumping a stack trace:

```
╭─ ERROR ──────────────────────────────────────────────────────────╮
│ The specified adb does not exist: /nonexistent/adb              │
├──────────────────────────────────────────────────────────────────┤
│ Check the path, or run noir setup to install it automatically.   │
╰──────────────────────────────────────────────────────────────────╯
```

With no device, you get actionable steps:

```
╭─ No device detected ──────────────────────────────────────────╮
│  1. Turn on developer mode                                   │
│     Xiaomi / HyperOS: Settings → My device → All specs       │
│     → tap "MIUI version" 7 times                             │
│  2. Turn on USB debugging: Settings → System →               │
│     Developer options → USB debugging                        │
│  3. Plug in; when the phone asks "Allow USB debugging?"      │
│     check "Always allow"                                     │
│  4. Still not working? Try another cable (many are           │
│     charge-only)                                             │
╰──────────────────────────────────────────────────────────────╯
```

If the device is connected but not authorized, it separately tells you to "revoke USB debugging authorizations and reconnect."

## Supported platforms

| OS | Status |
|---|---|
| macOS (Intel / Apple Silicon) | ✅ |
| Windows 10 / 11 | ✅ |
| Debian / Ubuntu | ✅ |

Dependencies:

- **JDK 17+**
- **Android platform-tools** (`adb`)
- **jadx** (only needed for the `deep` command)

NOIR looks for `adb` and `jadx` in common install locations automatically. If it can't find them, point to them with `--adb` / `--jadx`.

```bash
# macOS
brew install --cask android-platform-tools jadx

# Debian / Ubuntu
sudo apt install adb
# jadx: https://github.com/skylot/jadx/releases

# Windows (scoop)
scoop install adb jadx
```

---

## Install

**Option 1: download and run (recommended)**

Grab the portable package for your platform from [Releases](https://github.com/Verlintas/NOIR/releases):

```
noir-v0.1.1-macOS-portable.zip
noir-v0.1.1-Windows-portable.zip
noir-v0.1.1-Linux-portable.zip
SHA256SUMS.txt
```

Unzip and **double-click the launcher**. A runtime is bundled, so **you don't need Java installed**:

| OS | Double-click | If blocked |
|---|---|---|
| macOS | `Start NOIR.command` | Right-click → Open; or `xattr -dr com.apple.quarantine "Start NOIR.command" NOIR.app` |
| Windows | `Start NOIR.bat` | SmartScreen → More info → Run anyway (the batch file switches to UTF-8 and uses the bundled JRE) |
| Linux | `Start-NOIR.sh` | Run `chmod +x Start-NOIR.sh` first, or start it from a terminal |

The launcher opens a terminal window, runs the wizard, and pauses at the end so it doesn't just flash and close.

`adb` and `jadx` aren't included in the package. On first run it asks whether to download them to `~/.noir/tools`.

> Note: the prebuilt Releases come from the upstream Chinese project. To get the English version, build from source (option 2).

**Option 2: build from source**

```bash
git clone https://github.com/anthonyonazure/NOIR
cd NOIR
./gradlew :cli:installDist
./cli/build/install/noir/bin/noir --about
```

## Build

```bash
git clone <repo> && cd NOIR
./gradlew :cli:installDist
```

Output:

```
cli/build/install/noir/bin/noir        # macOS / Linux
cli/build/install/noir/bin/noir.bat    # Windows
```

Or run directly:

```bash
./gradlew :cli:run --args="devices"
```

---

## Interface

![NOIR dashboard on a Xiaomi 17 Pro Max](docs/screenshot.png)

Real-device output (macOS Terminal): gradient logo, CJK-aligned tables, risk-colored scores,
and a progress bar that updates after each APK.

`noir ui` renders results as a monospace dashboard. Colors and borders downgrade automatically based on what your terminal supports:

- `--ascii`: plain ASCII borders, for old Windows consoles
- `--no-color` / `--color`: turn off or force ANSI color (default: auto, based on whether output is a TTY)
- `--quiet`: dashboard only, no scan progress
- `--no-clear`: don't clear the screen (handy when redirecting output to a file)

## Usage

```bash
noir --about              # what it is, what it writes, license
noir --version
noir devices
noir scan                 # full scan, outputs JSON / Markdown / domain lists
noir ui                   # scan and render the dashboard
noir auto                 # scan + classify + build a fix plan (dry run)
noir auto --apply         # run safe appops actions (reversible)
noir auto --apply --aggressive   # also uninstall flagged user apps (asks per app)
noir deep com.example.app # pull APK + jadx + keyword search
noir block com.example.app        # print fix commands
noir block com.example.app --apply   # asks once, then saves restore commands
```

Common options:

| Option | Meaning |
|---|---|
| `--serial <id>` | Target a specific device |
| `--out <dir>` | Output folder (default `noir-out`) |
| `--min <score>` | Only keep apps scoring ≥ N |
| `--limit <n>` | Output at most N entries |
| `--only <regex>` | Only scan matching package names, e.g. `--only 'com\.miui\.'` |
| `--adb <path>` / `--jadx <path>` | Set tool paths manually |
| `--yes` | Skip confirmations in automated runs |

## DeepScan: decompile and fix in one command

```bash
noir deepscan                  # decompile the 15 highest-risk apps
noir deepscan --top 30         # more
noir deepscan --all            # every flagged app (slow, uses a lot of disk)
noir deepscan --jobs 4         # number of parallel jadx jobs
```

The flow: scan → sort by risk → `adb pull` + `jadx` each one → count code-level signals
(`Runtime.exec`, `DexClassLoader`, `setApplicationEnabledSetting`,
`enabled_accessibility_services`, `MediaProjection`, `SystemProperties.set`,
SMS / device IDs, WebView bridges, accessibility / notification listener / device admin ...) → parse the manifest
(exported components, cleartext traffic, backup, debuggable) → identify SDKs (Umeng / Firebase / AppsFlyer ...)
→ write `deepscan.md` / `deepscan.tsv` → ask whether to clean up.

```bash
noir deepscan --apply          # run safe appops after analysis
noir deepscan --apply --purge  # then confirm uninstalls of high-risk user apps one by one
```

Decompiled results are cached by `package name + APK path`, so a second run on the same app reuses them.

## Output

```
noir-out/
├── report.json               # structured results (apps, permissions, endpoints, recommendations)
├── report.md                 # human-readable report
├── domains-trackers.txt      # analytics / ads / crash reporting, safe to import whole
├── domains-other.txt         # unclear purpose, review each before importing
├── domains-functional.txt    # push / login / updates / payments / store / cloud sync, do NOT block
├── domains.txt               # same as trackers (for old scripts)
├── plan.txt                  # appops actions available this run
├── applied.txt               # commands actually run, exit codes, full stdout/stderr
├── rollback.txt              # rollback commands (pre-change AppOps modes, written on success)
└── uninstall-rollback.txt    # one restore command per app NOIR uninstalled (only if any were)
```

## Privacy

- The tool itself **never goes online**: no telemetry, no update checks, no crash reporting
- Scan results are only written to the `--out` folder you choose
- The only external requests happen in `noir setup` (downloading adb/jadx). `noir deep` runs jadx as a local process
- Reports may contain package names and endpoints from your device. Review them before sharing
- Nothing is left on the phone. The scan pushes a small script and app list to `/data/local/tmp`, and deletes them (plus any leftovers from an interrupted earlier run) when the scan ends, fails, or is cancelled with Ctrl+C
- Temporary files on your computer (the scan script and any APKs pulled for the fallback scan) are deleted as soon as they're used. What stays is the report folder, the endpoint cache in `~/.noir/`, and, for `deep`/`deepscan`, the APKs and decompiled sources you asked for
- Downloads only follow HTTPS links. The jadx download is checked against the official SHA-256 fingerprint, and archives are unpacked with a guard that blocks files from escaping the tools folder

## Cache

Scan results are cached by `package name + APK path` in `~/.noir/endpoints.tsv`. When an app updates, its path changes and it gets re-analyzed automatically. Repeat scans usually take a few seconds.

---

## Architecture

```
adb ──▶ pm / dumpsys ──▶ Dumpsys parser ──┐
                                          ├─▶ cache (pkg + apk path)
adb ──▶ unzip/strings ──▶ endpoints ──────┘        │
                                                   ▼
                                          Classifier ─▶ score ─▶ Advisor
                                                   │              │
                                                   ▼              ▼
                                              report.json    plan.txt
                                              report.md      rollback.txt
                                                   │
                                                   ▼
                                                 Tui / CLI
```

`deep` takes a separate path: `adb pull` → `jadx` → grep the source.

## Design tradeoffs

- **Endpoint extraction happens on the device:** runs `unzip | strings | grep` inside `adb shell` to avoid pulling hundreds of APKs to the computer. If the device lacks `unzip`/`strings`, it falls back to local parsing.
- **Shared UID handling:** on Android, apps under `android.uid.system` (often 50+) have their permissions recorded in the `Shared users` section at the end of `dumpsys package`. The parser merges those back into each package; otherwise the apps you most need to see would disappear.
- **Tiered recommendations:** only appops-level actions are marked as auto-runnable. Uninstalling must be turned on explicitly.
- **No telemetry:** the program contains no reporting code.

## FAQ

**Does it need root?**
No. Everything runs with `adb` shell permissions. Uninstalls are only `--user 0` level; the APK stays on the system partition.

**Can it break my phone?**
It's fully read-only by default. `--apply` only changes app-ops. It checks the original mode before running, and successful actions are written to
`rollback.txt` so you can restore them. Full stdout/stderr and exit codes go to `applied.txt`.
Every uninstall (`--aggressive`, `--purge`, or `noir block`) writes its `pm install-existing` restore command to `uninstall-rollback.txt`.

**Why do some apps only get "Manual review"?**
System apps can't truly be uninstalled (a `--user 0` uninstall gets put back by an OTA update or factory reset), so it only suggests
app-ops or DNS-level blocking.

**Why are DNS blocks only exported, not applied?**
Changing DNS across platforms can easily knock a device offline (we hit this during development), so it only exports lists:

- `domains-trackers.txt`: analytics / ads / crash reporting, safe to import whole
- `domains-other.txt`: unclear purpose, review each before importing
- `domains-functional.txt`: push, login, updates, payments, app stores, cloud sync. **Blocking these breaks features**
- `domains.txt`: now contains only trackers, for old scripts

IPs, `localhost`, and domains containing `test`/`staging` are removed automatically.

**iOS support?**
No. `core` is organized as Kotlin Multiplatform, but the audit logic depends on Android's
`dumpsys` and the APK format.

## Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, where the rules live
- [SECURITY.md](SECURITY.md): how to report vulnerabilities (please don't open a public issue)
- [Issues](https://github.com/Verlintas/NOIR/issues): for bugs, include your `noir doctor` output

## Roadmap

- [x] Monospace dashboard (`noir ui`)
- [x] DeepScan (batch decompile + code-level signals)
- [x] Double-click packages with a bundled runtime (jpackage)
- [ ] GUI (Compose Multiplatform)
- [ ] Configurable rule files (YAML), with community rule packs
- [ ] Batch pipeline with `apktool` / `jadx`
- [ ] Export of on-device DNS/VPN blocking setups
- [ ] Signed scan results and version comparison

## Disclaimer

Use NOIR only on **your own devices** or devices you're explicitly authorized to test. It provides static evidence
("this app has this capability, and this endpoint is in its code"). It **can't prove** that any specific transmission happened.
Combine it with network-layer evidence to draw your own conclusions.

## License

MIT © 2026 Verlintas
