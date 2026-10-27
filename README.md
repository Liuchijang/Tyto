<div align="center">

<img src="docs/assets/tyto-interactive-progress.png" alt="Tyto's interactive mode partway through a collection, showing live per-module status" width="860">

# Tyto — Windows artifact collection and triage for incident response

<p>
<a href="https://github.com/Liuchijang/Tyto/stargazers"><img src="https://img.shields.io/github/stars/Liuchijang/Tyto?style=for-the-badge" alt="GitHub stars"></a>
<a href="https://github.com/Liuchijang/Tyto/network"><img src="https://img.shields.io/github/forks/Liuchijang/Tyto?style=for-the-badge" alt="GitHub forks"></a>
<a href="https://github.com/Liuchijang/Tyto/issues"><img src="https://img.shields.io/github/issues/Liuchijang/Tyto?style=for-the-badge" alt="GitHub issues"></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/Liuchijang/Tyto?style=for-the-badge" alt="License"></a>
</p>
<p>
<a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.26+"></a>
<img src="https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server%202016+-0078D4?style=for-the-badge" alt="Windows 10, 11, Server 2016+">
<img src="https://img.shields.io/badge/Single%20binary-no%20runtime%20deps-555555?style=for-the-badge" alt="Single binary, no runtime dependencies">
</p>

Tyto collects Windows forensic artifacts from a running machine, parses them into CSV,<br>
and packages the run with a SHA-256 per file. Collection happens on the affected host;<br>
<code>tyto analyze --input</code> parses that run later on the investigator's machine, with no access to the live system.

<p>
<strong>Collects</strong><br>
<a href="https://github.com/Liuchijang/Tyto/wiki/MFT">$MFT</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/USN-Journal">$UsnJrnl:$J</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Secure-SDS">$Secure:$SDS</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Event-Log">Event logs</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Prefetch">Prefetch</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Amcache">Amcache</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Jump-Lists">Jump lists</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Recent-Files">Recent links</a> ·
Registry hives ·
<a href="https://github.com/Liuchijang/Tyto/wiki/SRUM">SRUM</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/WMI">WMI</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Browsers">Browsers</a> ·
<a href="#ram-acquisition">Memory</a>
</p>
<p>
<strong>Captures live</strong><br>
<a href="https://github.com/Liuchijang/Tyto/wiki/Autoruns">Autoruns</a> ·
<a href="https://github.com/Liuchijang/Tyto/wiki/Process-Explorer">Processes, modules and connections</a>
</p>

</div>

## Quick Start

Requires **Windows 10/11 or Windows Server 2016+**, and **Go 1.26+** to build from source.

```powershell
git clone https://github.com/Liuchijang/Tyto.git
cd Tyto
go build -trimpath -buildvcs=false -ldflags "-s -w" -o tyto.exe .
```

Then, from an **elevated** terminal:

```powershell
.\tyto.exe                                   # interactive: pick modules, watch them run
.\tyto.exe collect --artifact all            # everything, zipped when finished
```

And later, on the investigator's machine — no Administrator needed:

```powershell
.\tyto.exe analyze --input D:\evidence\HOST_20260812_134006.zip
```

Interactive mode and `tyto collect` exit immediately if not run elevated. `tyto analyze --input`
is the exception: it reads files the operator already holds.

## Features

<table>
<tr>
<td width="33%" valign="top">🖥️ <a href="#usage"><b>Three ways to run</b></a><br>Interactive TUI, <code>tyto collect</code> for automation, <code>tyto analyze</code> for a run collected earlier.</td>
<td width="33%" valign="top">🧳 <a href="#usage"><b>Collect here, analyze there</b></a><br><code>analyze --input</code> re-hashes every artifact against the source manifest and names the output after the subject, not the machine parsing it.</td>
<td width="33%" valign="top">💽 <b>Native acquisition</b><br>Backup semantics, registry hive save APIs, and raw NTFS reads of <code>$MFT</code>, <code>$UsnJrnl:$J</code> and <code>$Secure:$SDS</code> from every fixed drive.</td>
</tr>
<tr>
<td valign="top">🔓 <b>Locked files get three attempts</b><br>Plain copy, then backup semantics, then a raw NTFS read of the file.</td>
<td valign="top">🧩 <a href="#available-modules"><b>15 collectors, 18 analyzers</b></a><br>NTFS, event logs, execution artifacts, jump lists, shell links, the registry, WMI, SRUM and browsers.</td>
<td valign="top">🛡️ <a href="https://github.com/Liuchijang/Tyto/wiki/Event-Log"><b>Reads evidence without changing it</b></a><br>Event logs are parsed from a staged copy, because opening a dirty <code>.evtx</code> makes Windows rewrite it. Hives are parsed from the file, not mounted.</td>
</tr>
<tr>
<td valign="top">⚠️ <a href="https://github.com/Liuchijang/Tyto/wiki#missing-is-not-the-same-as-failed"><b>Nothing is lost quietly</b></a><br>A partial result warns, a file that copies as all zeroes is flagged, and a record that will not parse still gets a row saying why.</td>
<td valign="top">🚫 <a href="#usage"><b>No fallback to the live host</b></a><br>An analyzer that cannot read the collected artifact reports <code>SKIPPED</code> or <code>FAILED</code> instead of answering from somewhere else.</td>
<td valign="top">🕒 <a href="#timestamps"><b>One timestamp rule</b></a><br>Every timestamp column is RFC3339 in UTC and holds the artifact's own instant — or is empty.</td>
</tr>
<tr>
<td valign="top">#️⃣ <b>Hashed on the way out</b><br>Artifacts are SHA-256'd as they are written, the ZIP included.</td>
<td valign="top">⚙️ <b>No worker knob</b><br>Workers are derived from the storage topology per phase; CPU and disk caps go through a Job Object, so child processes are covered too.</td>
<td valign="top">🔍 <a href="https://github.com/Liuchijang/Tyto/wiki/Jump-Lists"><b>Cross-checked against JLECmd</b></a><br>27 of 35 shared fields identical across 2,133 jump list entries.</td>
</tr>
</table>

Tyto does not decrypt browser secrets: cookie values and saved passwords are exported as hex
beside the scheme that wrapped them, and the encrypted stores are collected intact.

## How It Works

Every collector finishes before any analyzer starts, so volatile state is captured first and
analyzers only ever read what the run already holds.

<details>
<summary>The pipeline as text</summary>

```
tyto / tyto collect ──► collectors ══barrier══► analyzers ──► manifest + summary ──► zip
                            │                       │
                   <run>/<category>/          <run>/Analyzer/<name>/*.csv

tyto analyze --input <run|zip> ──► verify SHA-256 ──► analyzers ──► <SUBJECT>_<timestamp>_analysis/
```

</details>

A run directory looks like this:

```
HOSTNAME_YYYYMMDD_HHMMSS/
  manifest.json      per-file SHA-256, sizes, source timestamps, the subject's timezone
  summary.txt        per-module outcome, with warnings
  collector.log      what happened, in order
  <category>/        the collected artifacts
  Analyzer/<name>/   the CSVs
```

## Usage

There are three ways to run Tyto, and they differ in **where an analyzer reads its sample
from**. That decides which machine the CSVs describe.

| How it is run | Analyzers read from | Administrator |
|---|---|---|
| `collect --artifact <category> --analyze` | the artifacts this run just collected | required |
| `analyze` with no `--input` | the live machine | required |
| `analyze --input <run\|zip>` | only the input, never the live machine | not required |

There is no fallback between them, so a CSV never describes a source other than the one
`manifest.json` names.

### Interactive

Run `.\tyto.exe` without a subcommand to select modules, review the runtime configuration,
watch live module status, and read the final collection summary.

### tyto collect

Acquires artifacts from the machine it runs on. Collector modules only by default — analyzers
(`*_parser`) are skipped even if a category or `all` would include them, and `--analyze` opts
into them. `autoruns` and `process_explorer` are collectors, so they run without it.

```powershell
.\tyto.exe collect --artifact registry,eventlog,prefetch     # by module name
.\tyto.exe collect --artifact ntfs,execution                 # by category
.\tyto.exe collect --artifact ntfs --analyze                 # collect, then parse what was collected
.\tyto.exe collect --artifact registry --output C:\triage --timeout 10m
.\tyto.exe collect --artifact all --output E:\evidence --cpu-limit 60 --disk-io 80MB
.\tyto.exe collect --artifact ntfs --no-compress
```

> [!NOTE]
> **`--analyze` follows categories, not module names.** `--artifact ntfs --analyze` adds
> `mft_parser`, `usnjrnl_parser` and `secure_sds_parser` because `ntfs` is a category;
> `--artifact mft --analyze` adds nothing, because `mft` names one collector. List the parsers
> explicitly instead: `--artifact mft,mft_parser --analyze`.

<details>
<summary>All <code>collect</code> flags</summary>

| Flag | Description |
|---|---|
| `-a, --artifact` | Comma-separated modules or categories, or `list` to print every module with its description. Required |
| `--analyze` | Also run the analyzers for the selected categories. Off by default |
| `-o, --output` | Base directory the run directory is created in. Defaults to `.` |
| `-t, --timeout` | Timeout per module; `0` (the default) disables it |
| `--cpu-limit` | CPU cap for Tyto and every process it spawns, via a Windows Job Object. Defaults to 60, clamped to 10–80 |
| `--disk-io` | Disk bandwidth cap for Tyto and every process it spawns, e.g. `80MB`. No cap by default |
| `--compress` / `--no-compress` | Zip the run directory when finished. **On** by default |
| `-v, --verbose` | Verbose/debug output |

</details>

### tyto analyze

Runs analyzer modules. `--input` decides which machine they describe, and that is the only
difference between the two ways to call it.

```powershell
# Offline: parse a run collected earlier, on the investigator's machine.
.\tyto.exe analyze --input D:\evidence\HOST_20260812_134006.zip        # a compressed run, what collect leaves by default
.\tyto.exe analyze --input D:\evidence\HOST_20260812_134006 -o D:\cases\1234
.\tyto.exe analyze --input HOST_20260812_134006.zip --artifact ntfs,eventlog

# Live: no --input, so the analyzers read this machine. Requires Administrator.
.\tyto.exe analyze --artifact shimcache_parser,prefetch_parser
.\tyto.exe analyze --artifact wmi_parser                               # carve the live OBJECTS.DATA, plus a CIM query
```

<details>
<summary>All <code>analyze</code> flags</summary>

| Flag | Description |
|---|---|
| `-i, --input` | The run directory or `.zip` to analyze. Omit it to analyze the live machine instead |
| `-a, --artifact` | Comma-separated analyzers or categories, or `list` to print every module with its description. Defaults to `all` |
| `--keep-extracted` | Keep the directory an input archive was extracted into, instead of removing it when the run ends |
| `-o, --output` | Base directory the analysis run directory is created in. Defaults to `.` |
| `-t, --timeout` | Timeout per analyzer; `0` (the default) disables it |
| `--cpu-limit` | CPU cap for Tyto and every process it spawns, via a Windows Job Object. Defaults to 60, clamped to 10–80 |
| `--disk-io` | Disk bandwidth cap for Tyto and every process it spawns, e.g. `80MB`. No cap by default |
| `--compress` | Zip the analysis output when finished. **Off** by default, unlike collection — the output is CSV an analyst opens straight away |
| `-v, --verbose` | Verbose/debug output |

There is no `--no-compress` here; compression is already off unless `--compress` asks for it.

</details>

## Available Modules

Use a category — `browser`, `eventlog`, `execution`, `live`, `memory`, `ntfs`, `registry`,
`system` — or `all` to select every module in it, collectors and analyzers alike. `live` holds
only collectors, so `collect --artifact live` runs both and `analyze --artifact live` has
nothing to run.

The same lists come from the binary, generated from the module registry: `tyto collect --help`
prints each category with its modules, and `--artifact list` prints every module with its
description.

<details>
<summary><b>Collectors</b> (15)</summary>

| Name | Category | Description |
|---|---|---|
| `browser` | `browser` | Collects browser artifacts from Chromium and Firefox profiles: history, cookies, credential stores, bookmarks, preferences, session files, the flat LevelDB stores (Local Storage, Session Storage, Platform Notifications, Service Worker, Sync Data), and extension manifests without the extension payloads. `IndexedDB` and the HTTP cache are left out — hundreds of megabytes per profile for artifacts nothing here parses yet |
| `eventlog` | `eventlog` | Collects Windows Event Log files (`.evtx`) |
| `amcache` | `execution` | Collects `Amcache.hve` and transaction logs |
| `prefetch` | `execution` | Collects Windows Prefetch files (`.pf`) |
| `jumplist` | `execution` | Collects jump lists per user profile: both `AutomaticDestinations` and `CustomDestinations`, including the `.temp` files Windows leaves behind mid-write — on one measured host those held 155 embedded links against 120 in the finished files |
| `recentfiles` | `execution` | Collects the shell links a user leaves when opening a document, from **two** folders: `Windows\Recent` and `Office\Recent`. Office keeps its own MRU, and only that copy survives a user clearing the shell's list |
| `ram` | `memory` | Acquires physical memory using `winpmem` |
| `mft` | `ntfs` | Collects the `$MFT` via raw disk access, from every fixed drive |
| `secure_sds` | `ntfs` | Collects the `$Secure:$SDS` stream, from every fixed drive |
| `usnjrnl` | `ntfs` | Collects the `$UsnJrnl:$J` USN Change Journal, from every fixed drive |
| `autoruns` | `live` | Captures autostart configuration from the running system: services, run keys per machine and per user SID, scheduled tasks with their actions and triggers, and every startup folder. **Live state, not an artifact** |
| `process_explorer` | `live` | Captures running processes with command lines and owners, every loaded module, and TCP/UDP connections joined to the owning process. Falls back to `netstat -ano` where the `Get-Net*` cmdlets are unavailable. **Live state, not an artifact** |
| `registry` | `registry` | Collects primary registry hives and transaction logs (excludes `SECURITY`, which requires `SYSTEM`, not just Administrator) |
| `srum` | `system` | Collects the SRUM database (`SRUDB.dat`) |
| `wmi` | `system` | Collects WMI repository files |

</details>

<details>
<summary><b>Analyzers</b> (18)</summary>

Every analyzer reads an artifact, so each works against a collected run or the live machine
and is available to `analyze --input`.

`autoruns` and `process_explorer` are **collectors**. They acquire state that exists only
while the machine is running, and the runner finishes every collector before it starts any
analyzer — as analyzers they would capture the most volatile data in a run only after every
artifact had been copied, a memory image included. Use `collect` for them, not `analyze`.

| Name | Category | Description |
|---|---|---|
| `amcache_parser` | `execution` | Parses Amcache artifacts |
| `browser_history_parser` | `browser` | Parses visits and downloads from Chromium `History` and Firefox `places.sqlite`. Downloads carry the redirect chain and the decoded Safe Browsing verdict |
| `browser_cookies_parser` | `browser` | Parses cookie metadata — host, path, creation, expiry, last access, `Secure`/`HttpOnly`/`SameSite` — from every cookie store a profile has |
| `browser_credentials_parser` | `browser` | Parses saved-login metadata and autofill from `Login Data`, `Web Data`, `logins.json` and `formhistory.sqlite`. Separate from the other browser analyzers so a triage can skip the most sensitive artifacts |
| `browser_profile_parser` | `browser` | Parses bookmarks with folder paths, installed extensions with their permissions and content scripts, selected profile settings, omnibox shortcuts, media history and DIPS bounce records |
| `eventlog_parser` | `eventlog` | Parses EVTX logs |
| `jumplist_parser` | `execution` | Parses jump lists: the DestList of each automatic file and the LNK bodies both kinds wrap. Reports what was opened, in what order, on which machine, from which volume, and the target's own size, timestamps and `$MFT` position. Three CSVs: a row per file (including the empty ones), a row per DestList entry, and a row per link in a custom destinations file |
| `mft_parser` | `ntfs` | Parses `$MFT` into CSV, streaming one row per record with resolved full paths |
| `prefetch_parser` | `execution` | Parses Prefetch records, decompressing the Windows 10/11 container first. Reports up to **eight execution timestamps** per program with the run count, the volumes it touched with their serials and creation times, and every file and directory the traced runs loaded. Versions 17 through 31 (XP to Windows 11). Four CSVs: per-record summary, a run-time timeline, volumes, and path references |
| `recentdocs_parser` | `registry` | Parses RecentDocs entries |
| `recentfiles_parser` | `execution` | Parses Recent and Office Recent shell links. Carries the link file's own creation and modification times — the first and last time that document was opened — alongside everything the link records about the target, including the serial and label of a volume that has since been unplugged |
| `runmru_parser` | `registry` | Parses RunMRU entries |
| `secure_sds_parser` | `ntfs` | Parses Secure SDS data |
| `shimcache_parser` | `registry` | Parses ShimCache |
| `srum_parser` | `system` | Parses the SRUM database into one CSV per provider table, resolving application and user IDs through `SruDbIdMapTable`, network adapter types out of the interface LUID, and Wi-Fi profile names from the `SOFTWARE` hive |
| `userassist_parser` | `registry` | Parses UserAssist |
| `usnjrnl_parser` | `ntfs` | Parses USN records, joining in each record's `$MFT` name, path and timestamps when `mft` or `mft_parser` is part of the run |
| `wmi_parser` | `system` | Reports WMI event-subscription persistence from two sources. It carves `__FilterToConsumerBinding`, `__EventFilter` and the consumer records out of `OBJECTS.DATA` — the run's collected copy, or the live host's file — which is what makes it work offline and what lets it recover subscriptions already deleted from the repository. When analyzing the live machine it additionally queries `root\subscription` for the authoritative current view plus the namespace tree. The two sets of CSVs keep separate names because they are separate evidence |

</details>

What every CSV column means, and when it is blank, is documented per artifact in the
[wiki](https://github.com/Liuchijang/Tyto/wiki).

## Timestamps

**Every timestamp column in every CSV is RFC3339 in UTC, and the value is the artifact's
own.** Nothing is re-based on the way out: a FILETIME, a WebKit microsecond count and a PE
`TimeDateStamp` are already UTC where they are stored. Most column names carry a `UTC` suffix
to say so.

- **A timestamp column holds an instant or it is empty** — never the raw integer, never `N/A`.
  Importers bind such a column to a date type and reject the *whole file* over one cell that
  will not convert, so a value Tyto cannot resolve costs one blank cell rather than the artifact.
- **Sub-second precision survives.** The layout is RFC3339 *Nano*: a FILETIME carries 100ns and
  a USN journal records many events inside one second. A whole second renders with no fraction,
  so both forms parse as plain RFC3339.

<details>
<summary>Timestamp columns per module</summary>

| Module | Timestamp columns | What the artifact stores |
|---|---|---|
| `mft_parser` | `SI_CreatedUTC`, `SI_ModifiedUTC`, `SI_MFTModifiedUTC`, `SI_AccessedUTC`, and the four `FN_*UTC` equivalents | FILETIME — 100ns ticks since 1601-01-01 UTC |
| `usnjrnl_parser` | `TimestampUTC`, plus the `$MFT` times joined in when `mft`/`mft_parser` is in the run | FILETIME |
| `secure_sds_parser` | none — `$Secure:$SDS` carries no timestamps | — |
| `prefetch_parser` | `LastRunUTC`, `PreviousRun1..7UTC`, `RunUTC`, `VolumeCreatedUTC` | FILETIME, read from **inside the record**. That is the point: the execution times are in the file's bytes, so a collected copy carries them intact. The `.pf` file's own filesystem timestamps are not reported: everything they carried is inside the record |
| `jumplist_parser` | `LastModifiedUTC` | FILETIME in the DestList entry — when that item was last opened |
| | `DroidCreatedUTC`, `TrackerCreatedUTC` | The timestamp inside a version 1 UUID, counted in 100ns from **1582-10-15**. It dates the identifier, not the file — it has been observed tracking the machine's boot time — which is why neither column is named after a creation |
| `recentfiles_parser` | `LinkCreatedUTC`, `LinkModifiedUTC` | The `.lnk` file's own timestamps: the first and last time the document was opened. See *An artifact's own timestamps* below |
| both, from the embedded link | `TargetCreatedUTC`, `TargetModifiedUTC`, `TargetAccessedUTC` | FILETIME in the link header, describing the **target** as it was when the link was last written |
| `eventlog_parser` | `TimeCreatedUTC` | EVTX record `SystemTime` (FILETIME), rendered through .NET's round-trip `"o"` format under the invariant culture so the column never depends on the operator's regional settings |
| `amcache_parser` | `KeyLastWriteTimestamp`, `FileKeyLastWriteTimestamp` | Hive key last-write FILETIME |
| | `DriverTimeStamp` | A `REG_DWORD` holding the driver's PE `TimeDateStamp` — Unix epoch **seconds**, not a FILETIME |
| | `DriverVerDate`, `Date`, `DriverLastWriteTime`, `LinkDate` | Text values inside the hive |
| `shimcache_parser` | `LastModifiedUTC`, `LastUpdateUTC` | FILETIME inside the cache entry |
| `userassist_parser` | `LastExecutedUTC`, `KeyLastWriteTimestamp` | FILETIME in the value blob and on the hive key. `FocusTimeMS` beside them is a **duration** in milliseconds, not an instant |
| `recentdocs_parser`, `runmru_parser` | `KeyLastWriteTimestamp` | Hive key last-write FILETIME |
| `srum_parser` | per provider table — `ConnectStartTime`, `*TimeStamp`, … | FILETIME for most columns and an ESE `DateTime` for others; both are accepted. `ConnectedTime` is a **duration** in seconds and is added to the row's start time rather than printed |
| `browser_*_parser`, Chromium | `VisitTimeUTC`, `LastVisitUTC`, `CreationUTC`, `ExpiresUTC`, `DateAddedUTC`, … | Microseconds since **1601-01-01** (the WebKit epoch) |
| `browser_*_parser`, Firefox | the same columns | Microseconds since **1970-01-01** — except `logins.json`, which uses **milliseconds** |
| `browser_profile_parser` | the Media History columns | Unix epoch **seconds** |
| `autoruns`, `process_explorer` (collectors) | `LastRunTimeUTC`, `NextRunTimeUTC`, `LastWriteTimeUTC`, `CreationDateUTC`, `CreationTimeUTC` | A .NET `DateTime` in **local** time, converted by `ConvertTo-TytoUtc`. Along with `eventlog_parser` these are the only paths that convert rather than re-render, because .NET hands the script local time |
| `wmi_parser` | none | The object store keeps no creation time for a subscription and the CIM query selects no date-bearing property, so no column is named after one |

</details>

<details>
<summary>An artifact's own timestamps</summary>

Copying a file does not preserve its timestamps, so a collected artifact carries the moment
Tyto wrote it rather than the moment the subject's machine did. For most artifacts that costs
nothing — the evidence is inside the file. For a Recent folder's `.lnk` it is the evidence: the
link is created the first time a document is opened and rewritten every time after.

So the collector records the source's own creation and modification times as it copies, and
`manifest.json` carries them per file:

```json
{
  "path": "users\\alice\\Recent\\report.docx.lnk",
  "sha256": "…",
  "size": 1234,
  "source_created": "2026-03-31T09:05:01.8065995Z",
  "source_modified": "2026-09-03T06:47:06.0013361Z"
}
```

An analyzer reads them back from that record offline, and stats the file directly when it is
reading the live host — both render identically, so a row does not say which mode produced it.
The access time is deliberately not recorded: Windows updates it inconsistently and disables it
outright for many operations.

The copy itself still does not preserve times, and that is deliberate. Collected files carrying
*collection* times is what made it possible to prove that a parser was rewriting artifacts after
the collector had hashed them, by showing the two mtime windows did not overlap.

</details>

## RAM Acquisition

Tyto does not bundle `winpmem`. To enable RAM acquisition, place `winpmem_mini_x64.exe` in the
same directory as `tyto.exe`, the current working directory, or a directory on `PATH`. If it is
not found, the `ram` module fails gracefully and records the error in the run summary.

## Built With

<p>
<img src="https://img.shields.io/badge/Cobra-CLI-6415ff?style=for-the-badge" alt="Cobra">
<img src="https://img.shields.io/badge/Bubble_Tea-TUI-FF75B7?style=for-the-badge" alt="Bubble Tea">
<img src="https://img.shields.io/badge/Lip_Gloss-Terminal_UI-7D56F4?style=for-the-badge" alt="Lip Gloss">
<img src="https://img.shields.io/badge/golang.org%2Fx%2Fsys-Windows_APIs-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="golang.org/x/sys">
<img src="https://img.shields.io/badge/modernc.org%2Fsqlite-Embedded_SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="modernc.org/sqlite">
<img src="https://img.shields.io/badge/go--ese-ESE%2FJET_Blue-4B8BBE?style=for-the-badge" alt="go-ese">
</p>

`modernc.org/sqlite` reads browser databases and `www.velocidex.com/golang/go-ese` reads the SRUM
database's ESE format. Both are pure Go, so a release build stays a single static `tyto.exe` with
no runtime dependencies.

## Resources

- 📚 [Artifact and output reference (wiki)](https://github.com/Liuchijang/Tyto/wiki)
- 🕒 [Conventions that hold across every output file](https://github.com/Liuchijang/Tyto/wiki#conventions-that-hold-across-every-output-file)
- 🔗 [Shell link columns, shared by jump lists and Recent files](https://github.com/Liuchijang/Tyto/wiki/Shell-Link-Columns)
- 🧩 [Available modules](#available-modules)
- 🐛 [Issues](https://github.com/Liuchijang/Tyto/issues)

## Security and Legal Notice

Tyto is intended for authorized forensic investigation and incident response only. Run it only on
systems where you have explicit permission to collect artifacts.

## Contributing

Fork the repository, create a feature or fix branch, keep changes focused and aligned with the
module structure, update documentation when behavior changes, and open a pull request.

## License

[MIT](LICENSE).

---

<div align="center">

**Star this repository if Tyto is useful for your incident response workflow.**

Made by [Liuchijang](https://github.com/Liuchijang)

</div>
