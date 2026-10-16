package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eventlogpkg "github.com/Liuchijang/Tyto/internal/collectors/eventlog"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/utils"
)

func init() { module.RegisterAnalyzer(&eventLogParser{}) }

type eventLogParser struct{ offlineCapable }

func (c *eventLogParser) Name() string     { return "eventlog_parser" }
func (c *eventLogParser) Category() string { return "eventlog" }
func (c *eventLogParser) Description() string {
	return "Parse EVTX logs"
}

func (c *eventLogParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create eventlog parser output dir: %w", err))
	}

	sourceDir, live, err := resolveArtifactSource(req, "eventlog")
	if err != nil {
		return skippedNoSource(outDir, "collected EVTX files")
	}
	if live {
		sourceDir = filepath.Join(platform.SystemRoot(), "System32", "winevt", "Logs")
	}
	selectedFiles, err := eventlogpkg.ResolveSelectedOrAllLogs(sourceDir)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("resolve selected EVTX files: %w", err))
	}
	if len(selectedFiles) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no selected or available EVTX files found in %s", sourceDir)}
	}

	// The C# helper prefixes every path with \\?\, which only means anything on an
	// absolute one — a relative --input or -o would otherwise reach it as is.
	if sourceDir, err = filepath.Abs(sourceDir); err != nil {
		return analyzerError(outDir, fmt.Errorf("resolve EVTX source dir: %w", err))
	}
	csvDir, err := filepath.Abs(outDir)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("resolve eventlog parser output dir: %w", err))
	}

	// Staged under the analyzer's own output directory rather than %TEMP%, for the
	// same reason stageLiveAmcacheHive is: %TEMP% is on the volume being investigated,
	// and a run killed mid-parse would leave copies of the subject's event logs there.
	// Here they sit inside the run and are removed before it finishes.
	stageDir := filepath.Join(csvDir, "_staging")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return analyzerError(outDir, fmt.Errorf("create eventlog staging dir: %w", err))
	}

	// The file list goes to the script through a file, not inline. The script travels
	// on powershell.exe's command line, which Windows caps at 32,767 characters, and
	// inlined it grew with the run: 386 log names were 21,589 of the ~30,000
	// characters on a real run, so a host with a few more channels failed the whole
	// analyzer with "The filename or extension is too long".
	listFile := filepath.Join(stageDir, "files.txt")
	outCsv := filepath.Join(csvDir, "eventlog_records.csv")
	if err := os.WriteFile(listFile, []byte(strings.Join(selectedFiles, "\n")), 0o644); err != nil {
		return analyzerError(outDir, fmt.Errorf("write eventlog file list: %w", err))
	}

	// The per-event work runs in a compiled helper rather than in PowerShell: a
	// [pscustomobject] per event piped into Export-Csv spends most of its time in
	// PowerShell's object pipeline and Export-Csv's per-property reflection. On a
	// 3-file, 86,694-event corpus this went from 19.1s to 1.7s, byte-for-byte
	// identical output. EventLogReader yields the same EventRecord objects
	// Get-WinEvent wraps, and the writer reproduces Export-Csv's format exactly:
	// UTF-8 with BOM, CRLF, every field quoted and embedded quotes doubled. The
	// header is written with the first row on purpose: an empty pipeline left
	// Export-Csv with a BOM-only file and a successful result, which a zero-event
	// run must still produce.
	//
	// Values are rendered with the invariant culture rather than the session's.
	// Export-Csv used the current one, which made TimeCreated whatever the
	// operator's regional settings happened to say — "8/12/2026 1:52:11 AM" on one
	// host, "12/08/2026 01:52:11" on another, and neither joinable against the
	// RFC3339 every other analyzer writes. The round-trip "o" format is that same
	// RFC3339, and it is taken in UTC because a local-time column silently
	// misorders events across a DST boundary.
	//
	// Do not reintroduce $event.LevelDisplayName here: it resolves the severity
	// string from the provider's message-table resources per event, which is far
	// slower than mapping the numeric Level enum.
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$sourceDir = ` + utils.PSQuote(sourceDir) + `
$stageDir = ` + utils.PSQuote(stageDir) + `
$outCsv = ` + utils.PSQuote(outCsv) + `
$listFile = ` + utils.PSQuote(listFile) + `

Add-Type -ReferencedAssemblies 'System.Core','System.Xml','System.Xml.Linq' -TypeDefinition @'
using System;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;

public static class FirEvtx
{
    // Every file this helper touches goes through Win32 with an extended-length
    // path, never through System.IO's path APIs. powershell.exe runs .NET Framework
    // with legacy path handling, which enforces MAX_PATH on every path and rejects
    // the \\?\ prefix too — measured, a StreamWriter on a prefixed path throws
    // PathTooLongException. So with -o 197 characters deep the CSV path itself
    // passed 260 and the analyzer failed outright. A CreateFileW handle wrapped in
    // a FileStream, CopyFileW and EvtQuery all accept the prefix: measured, a
    // 353-character staged copy was copied and read in full.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CopyFileW(string source, string target, bool failIfExists);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool DeleteFileW(string name);

    const uint GenericRead = 0x80000000, GenericWrite = 0x40000000, ShareRead = 1;
    const uint CreateAlways = 2, OpenExisting = 3, FileAttributeNormal = 0x80;
    const int ErrorFileNotFound = 2, ErrorPathNotFound = 3;

    // Long prefixes a path Go has already made absolute and clean.
    static string Long(string path)
    {
        if (path.StartsWith(@"\\?\")) return path;
        if (path.StartsWith(@"\\")) return @"\\?\UNC\" + path.Substring(2);
        return @"\\?\" + path;
    }

    static string Join(string dir, string name)
    {
        return dir.TrimEnd('\\') + "\\" + name;
    }

    static FileStream Open(string path, bool write)
    {
        var handle = CreateFileW(Long(path), write ? GenericWrite : GenericRead, ShareRead, IntPtr.Zero,
            write ? CreateAlways : OpenExisting, FileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException(path + ": " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
        return new FileStream(handle, write ? FileAccess.Write : FileAccess.Read);
    }

    public static string[] ReadList(string path)
    {
        using (var r = new StreamReader(Open(path, false), Encoding.UTF8))
        {
            return r.ReadToEnd().Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }
    }

    static readonly string[] LevelNames = { "LogAlways", "Critical", "Error", "Warning", "Information", "Verbose" };

    static void Field(StringBuilder sb, string value, bool last)
    {
        sb.Append('"');
        if (value != null)
        {
            if (value.IndexOf('"') >= 0) sb.Append(value.Replace("\"", "\"\""));
            else sb.Append(value);
        }
        sb.Append('"');
        if (!last) sb.Append(',');
    }

    static string Num(long? value)
    {
        return value.HasValue ? value.Value.ToString(CultureInfo.InvariantCulture) : null;
    }

    // Utc renders an event's timestamp as RFC3339 in UTC, the one layout every
    // Tyto analyzer writes. "o" keeps the 100ns precision an EVTX record carries,
    // which is what keeps events inside the same second in the order they
    // happened.
    static string Utc(DateTime? value)
    {
        return value.HasValue
            ? value.Value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)
            : null;
    }

    // Export parses each log from a throwaway copy in stageDir, never in place.
    //
    // A .evtx copied out of a running system is marked dirty, and opening a dirty log
    // through EvtQuery makes the Event Log service recover it and write the repaired
    // header back. Measured: a collect --analyze run rewrote 113 of the 382 EVTX files
    // it had just collected — the large active ones — 37 seconds after the collector
    // finished, so every later integrity check reported those artifacts as not
    // matching the hash recorded at collection. The event data was intact and the
    // sizes were unchanged, but the run had invalidated its own evidence record and
    // the alert read as tampering.
    //
    // Staging also keeps the live path honest: without it, analyzing a machine
    // directly writes to that machine's own event logs.
    //
    // A log that cannot be staged is skipped and named on stdout rather than parsed in
    // place. Losing one log's events is recoverable by re-running; silently altering
    // evidence is not.
    public static long Export(string sourceDir, string outCsv, string[] files, string stageDir)
    {
        long rows = 0;
        using (var w = new StreamWriter(Open(outCsv, true), new UTF8Encoding(true)))
        {
            w.NewLine = "\r\n";

            var sb = new StringBuilder(512);
            for (int i = 0; i < files.Length; i++)
            {
                var fileName = files[i];
                var source = Join(sourceDir, fileName);

                // The staged copy is numbered, not named after its log, and that is
                // the difference between parsing a run's event logs and skipping
                // them. Channel names run to 90 characters
                // ("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Operational.evtx"),
                // and while the copy went through File.Copy, which enforces
                // MAX_PATH, a run whose -o sat 60 characters deeper left 11 of this
                // machine's logs unstaged and unread. CopyFileW has since lifted
                // the limit; the short name still keeps the staged path well inside
                // it. Nothing downstream sees this name: SourceFile in the CSV is
                // written from fileName above.
                //
                // A log that is not there is skipped silently, as the File.Exists
                // check this replaced did; any other failure is named.
                var path = Join(stageDir, i.ToString(CultureInfo.InvariantCulture) + ".evtx");
                if (!CopyFileW(Long(source), Long(path), false))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == ErrorFileNotFound || err == ErrorPathNotFound) continue;
                    Console.WriteLine("TYTO-STAGE-FAILED\t" + fileName + "\t" + new Win32Exception(err).Message.Replace('\t', ' '));
                    continue;
                }

                EventLogReader reader;
                try
                {
                    var query = new EventLogQuery(Long(path), PathType.FilePath);
                    query.ReverseDirection = false;
                    reader = new EventLogReader(query);
                }
                catch { TryDelete(path); continue; }

                using (reader)
                {
                    while (true)
                    {
                        EventRecord rec;
                        try { rec = reader.ReadEvent(); }
                        catch { break; }
                        if (rec == null) break;

                        using (rec)
                        {
                            try
                            {
                                int level = rec.Level.HasValue ? rec.Level.Value : 0;
                                string levelName = level < LevelNames.Length
                                    ? LevelNames[level]
                                    : "Level" + level.ToString(CultureInfo.InvariantCulture);

                                if (rows == 0)
                                {
                                    w.WriteLine("\"SourceFile\",\"LogName\",\"ProviderName\",\"Id\",\"Level\",\"TimeCreatedUTC\",\"RecordId\",\"ProcessId\",\"ThreadId\",\"MachineName\",\"UserId\",\"Message\"");
                                }

                                sb.Length = 0;
                                Field(sb, fileName, false);
                                Field(sb, rec.LogName, false);
                                Field(sb, rec.ProviderName, false);
                                Field(sb, rec.Id.ToString(CultureInfo.InvariantCulture), false);
                                Field(sb, levelName, false);
                                Field(sb, Utc(rec.TimeCreated), false);
                                Field(sb, Num(rec.RecordId), false);
                                Field(sb, Num(rec.ProcessId), false);
                                Field(sb, Num(rec.ThreadId), false);
                                Field(sb, rec.MachineName, false);
                                Field(sb, rec.UserId != null ? rec.UserId.ToString() : null, false);
                                Field(sb, Payload(rec), true);
                                w.WriteLine(sb.ToString());
                                rows++;
                            }
                            catch { }
                        }
                    }
                }
                // The staged copy is deleted as soon as its log is parsed, so peak
                // extra disk is one log rather than the whole winevt\Logs directory.
                TryDelete(path);
            }
        }
        return rows;
    }

    // Payload renders the event's own EventData or UserData as Name=Value pairs
    // joined by " | ", and that is what the Message column carries.
    //
    // It is not rec.FormatDescription(), the sentence Event Viewer shows. That text
    // is resolved per event from the provider's message-table resources — the same
    // lookup LevelDisplayName is refused for above — and against the providers
    // installed on the machine doing the parsing, so an offline analysis would
    // render different text, or none, for the identical event. ToXml() renders only
    // what the record itself stores, so live and offline output are the same. The
    // sentence is a template over exactly these fields.
    //
    // Classic events carry unnamed <Data> elements; they are numbered by position.
    //
    // EvtRender passes control characters a provider logged straight into the XML,
    // which XML 1.0 forbids: measured, 3 of 361,508 events on a real run (0x14 in
    // Host-Network-Service 1024) were otherwise unreadable. They are escaped to
    // character references, which CheckCharacters = false accepts, so the value is
    // kept as logged. Whitespace-only values ("ExtraInfo" = "\n") are kept too;
    // XElement.Parse would drop them.
    static readonly XmlReaderSettings LenientXml = new XmlReaderSettings { CheckCharacters = false };

    static string EscapeControlChars(string xml)
    {
        StringBuilder sb = null;
        for (int i = 0; i < xml.Length; i++)
        {
            char c = xml[i];
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
            {
                if (sb == null) sb = new StringBuilder(xml, 0, i, xml.Length + 16);
                sb.Append("&#x").Append(((int)c).ToString("X", CultureInfo.InvariantCulture)).Append(';');
            }
            else if (sb != null) sb.Append(c);
        }
        return sb == null ? xml : sb.ToString();
    }

    static string Payload(EventRecord rec)
    {
        XElement root;
        try
        {
            using (var r = XmlReader.Create(new StringReader(EscapeControlChars(rec.ToXml())), LenientXml))
                root = XElement.Load(r);
        }
        catch (Exception ex) { return "(event data unreadable: " + ex.Message + ")"; }

        var sb = new StringBuilder();
        foreach (var section in root.Elements())
        {
            var name = section.Name.LocalName;
            if (name == "EventData")
            {
                int index = 0;
                foreach (var e in section.Elements())
                {
                    string key = e.Name.LocalName;
                    if (key == "Data")
                    {
                        var attr = e.Attribute("Name");
                        key = attr != null && attr.Value.Length > 0
                            ? attr.Value
                            : "Data[" + index.ToString(CultureInfo.InvariantCulture) + "]";
                    }
                    Pair(sb, key, e.Value);
                    index++;
                }
            }
            else if (name == "UserData")
            {
                // UserData is one provider-defined element whose leaves are the fields.
                foreach (var e in section.Descendants())
                {
                    if (!e.HasElements && e.Parent != section) Pair(sb, e.Name.LocalName, e.Value);
                }
            }
        }
        return sb.ToString();
    }

    static void Pair(StringBuilder sb, string key, string value)
    {
        if (sb.Length > 0) sb.Append(" | ");
        sb.Append(key).Append('=').Append(value);
    }

    static void TryDelete(string path)
    {
        DeleteFileW(Long(path));
    }
}
'@

# Test-Path is held to MAX_PATH as well, so success is the helper returning rather
# than the CSV being visible to PowerShell. SilentlyContinue does not reach inside
# try, so a helper that failed to compile or threw still fails the script.
try {
    [FirEvtx]::Export($sourceDir, $outCsv, [FirEvtx]::ReadList($listFile), $stageDir) | Out-Null
} catch {
    Write-Output ('no selected EVTX records could be parsed: ' + $_.Exception.Message)
    exit 1
}
`

	output, runErr := utils.RunPowerShellOutput(ctx, script)
	// Removed whether the run succeeded or not: a staged copy left behind would be
	// swept into the archive as if it were collected evidence.
	var warnings []string
	if removeErr := os.RemoveAll(stageDir); removeErr != nil {
		warnings = append(warnings, fmt.Sprintf("staging directory %s was left behind: %v", stageDir, removeErr))
	}
	if skipped := describeStagingFailures(output); skipped != "" {
		warnings = append(warnings, skipped)
	}

	if runErr != nil {
		files, fileErr := utils.CollectGeneratedCSVs(outDir)
		if fileErr == nil && len(files) > 0 {
			return module.AnalyzeResult{Files: files, OutputPath: outDir, Error: fmt.Errorf("parse event logs: %w", runErr).Error()}
		}
		return analyzerError(outDir, fmt.Errorf("parse event logs: %w", runErr))
	}

	files, err := utils.CollectGeneratedCSVs(outDir)
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{
		Files:      files,
		OutputPath: outDir,
		// A log that could not be staged was not parsed, and the CSV cannot show its
		// own absence.
		Error: strings.Join(warnings, "; "),
	}
}

// stageFailureMarker is what the embedded C# prints for a log it could not copy.
const stageFailureMarker = "TYTO-STAGE-FAILED\t"

// describeStagingFailures turns those lines into one warning for the run summary.
func describeStagingFailures(output string) string {
	var skipped []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, stageFailureMarker) {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(line, stageFailureMarker), "\t", 2)
		if len(parts) == 2 {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", parts[0], parts[1]))
			continue
		}
		skipped = append(skipped, parts[0])
	}
	if len(skipped) == 0 {
		return ""
	}
	return fmt.Sprintf("%d event log(s) could not be copied for parsing and were not read: %s",
		len(skipped), strings.Join(skipped, "; "))
}
