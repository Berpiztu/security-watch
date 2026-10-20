#:property PublishAot=false

// Not AOT, as a file-based app is by default: the JSON read and written here
// goes by reflection.
//
// security-watch: the inventories the projects send (inventories/<project>/<ref>.json),
// each library in them checked once however many projects use it, against
// the known vulnerabilities and the newest versions. Writes libraries.json,
// status/<project>.json, history.json and HISTORY.md, and opens an issue for
// each blocking finding first seen. Run from the repository's root:
//
//     dotnet run watch/watch.cs
//
// Issues are opened only with GH_TOKEN set (the workflow), never on a run by hand.

using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

var root = Directory.GetCurrentDirectory();
var today = DateTime.UtcNow.ToString("yyyy-MM-dd");
var token = Environment.GetEnvironmentVariable("GH_TOKEN");
var web = new Web();

var inventories = Inventories.Load(Path.Combine(root, "inventories"));
Console.WriteLine($"{inventories.Count} inventories from {inventories.Select(i => i.Project).Distinct().Count()} projects");

var catalog = await Catalog.BuildAsync(inventories, web);
catalog.Write(Path.Combine(root, "libraries.json"));

var history = History.Load(Path.Combine(root, "history.json"));
var statusFolder = Path.Combine(root, "status");
Directory.CreateDirectory(statusFolder);
foreach (var stale in Directory.GetFiles(statusFolder, "*.json").Where(f => inventories.All(i => i.Project != Path.GetFileNameWithoutExtension(f))))
{
    // A project that sends no inventory any more is no longer watched.
    File.Delete(stale);
}

foreach (var project in inventories.GroupBy(i => i.Project).OrderBy(g => g.Key))
{
    var findings = catalog.FindingsOf(project);
    var opened = history.Record(project.Key, findings, today);
    Status.Write(Path.Combine(statusFolder, $"{project.Key}.json"), project, catalog, history);
    foreach (var finding in opened.Where(f => Severity.Blocks(f.Severity)))
    {
        await Issues.OpenAsync(project.Key, finding, token);
    }

    Console.WriteLine($"  {project.Key}: {findings.Count} findings, {opened.Count} new");
}

history.Save(Path.Combine(root, "history.json"));
File.WriteAllText(Path.Combine(root, "HISTORY.md"), history.Markdown());

// ------------------------------------------------------------- inventories --

/// <summary>What a project sends for one of its branches or releases: every library it uses at its exact version, its .NET SDK and its images.</summary>
sealed class Inventory
{
    public string Project { get; set; } = "";
    public string Ref { get; set; } = "";
    public string Type { get; set; } = "branch";
    public string Commit { get; set; } = "";
    public string Sent { get; set; } = "";
    public List<Package> Packages { get; set; } = [];
    public string? DotnetSdk { get; set; }
    public List<string> Images { get; set; } = [];
}

/// <summary>One library: its ecosystem as OSV.dev names it (NuGet, PyPI, npm, Maven…), its name and version, and whether the project asks for it itself.</summary>
sealed class Package
{
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public bool Direct { get; set; }
}

static class Inventories
{
    /// <summary>How many releases of a project are kept: the ones people may still have installed.</summary>
    const int Releases = 3;

    /// <summary>Every inventory sent; of each project's releases only the latest few, the older files deleted.</summary>
    public static List<Inventory> Load(string folder)
    {
        var loaded = new List<(Inventory Inventory, string File)>();
        foreach (var file in Directory.Exists(folder) ? Directory.GetFiles(folder, "*.json", SearchOption.AllDirectories) : [])
        {
            if (JsonSerializer.Deserialize<Inventory>(File.ReadAllText(file), Json.Options) is { Project.Length: > 0, Ref.Length: > 0 } inventory)
            {
                loaded.Add((inventory, file));
            }
        }

        foreach (var old in loaded.Where(l => l.Inventory.Type == "release").GroupBy(l => l.Inventory.Project)
            .SelectMany(g => g.OrderByDescending(l => l.Inventory.Sent).Skip(Releases)).ToList())
        {
            File.Delete(old.File);
            loaded.Remove(old);
        }

        return [.. loaded.Select(l => l.Inventory)];
    }
}

// ----------------------------------------------------------------- catalog --

/// <summary>A known vulnerability of one library at one version.</summary>
sealed record Vulnerability(string Advisory, string Cve, string Severity, string Summary, string FixedIn, string Url);

/// <summary>One library at one version, checked once for everyone who uses it.</summary>
sealed class Library(string ecosystem, string name, string version)
{
    public string Ecosystem { get; } = ecosystem;
    public string Name { get; } = name;
    public string Version { get; } = version;
    public string? Latest { get; set; }
    public List<Vulnerability> Vulnerabilities { get; } = [];
    public SortedSet<string> UsedBy { get; } = [];

    public static string KeyOf(string ecosystem, string name, string version) => $"{ecosystem}|{name.ToLowerInvariant()}|{version}";
}

/// <summary>A finding: a library's vulnerability, at the refs of one project that use it.</summary>
sealed record Finding(string Ecosystem, string Package, string Version, Vulnerability Vulnerability, List<string> Where)
{
    public string Key => $"{Ecosystem}|{Package}|{Version}|{Vulnerability.Advisory}";

    public string Severity => Vulnerability.Severity;
}

sealed class Catalog
{
    /// <summary>The ecosystem a .NET SDK is kept under: it is checked against .NET's own release metadata, not OSV.</summary>
    public const string DotnetSdk = "dotnet-sdk";

    readonly Dictionary<string, Library> _libraries = [];

    public Library Of(string ecosystem, string name, string version) => _libraries[Library.KeyOf(ecosystem, name, version)];

    /// <summary>
    /// Every library of every inventory, once: one OSV.dev question for each
    /// version, one registry question for each name, one .NET release check
    /// for each SDK.
    /// </summary>
    public static async Task<Catalog> BuildAsync(List<Inventory> inventories, Web web)
    {
        var catalog = new Catalog();
        foreach (var inventory in inventories)
        {
            var user = $"{inventory.Project}@{inventory.Ref}";
            foreach (var package in inventory.Packages)
            {
                catalog.Add(package.Ecosystem, package.Name, package.Version).UsedBy.Add(user);
            }

            if (inventory.DotnetSdk is { Length: > 0 } sdk)
            {
                catalog.Add(DotnetSdk, ".NET SDK", sdk).UsedBy.Add(user);
            }
        }

        var packages = catalog._libraries.Values.Where(l => l.Ecosystem != DotnetSdk).ToList();
        Console.WriteLine($"{packages.Count} unique libraries, {packages.Select(l => $"{l.Ecosystem}|{l.Name.ToLowerInvariant()}").Distinct().Count()} unique names");
        await Osv.CheckAsync(packages, web);
        foreach (var name in packages.GroupBy(l => $"{l.Ecosystem}|{l.Name.ToLowerInvariant()}"))
        {
            var latest = await web.LatestAsync(name.First().Ecosystem, name.First().Name);
            foreach (var library in name)
            {
                library.Latest = latest;
            }
        }

        foreach (var sdk in catalog._libraries.Values.Where(l => l.Ecosystem == DotnetSdk))
        {
            await Dotnet.CheckAsync(sdk, web);
        }

        return catalog;
    }

    Library Add(string ecosystem, string name, string version)
    {
        var key = Library.KeyOf(ecosystem, name, version);
        if (!_libraries.TryGetValue(key, out var library))
        {
            library = _libraries[key] = new Library(ecosystem, name, version);
        }

        return library;
    }

    /// <summary>A project's findings: each vulnerability of a library it uses, with the refs that use it.</summary>
    public List<Finding> FindingsOf(IGrouping<string, Inventory> project)
    {
        var findings = new Dictionary<string, Finding>();
        foreach (var inventory in project)
        {
            foreach (var library in LibrariesOf(inventory))
            {
                foreach (var vulnerability in library.Vulnerabilities)
                {
                    var finding = new Finding(library.Ecosystem, library.Name, library.Version, vulnerability, []);
                    if (!findings.TryGetValue(finding.Key, out var known))
                    {
                        known = findings[finding.Key] = finding;
                    }

                    if (!known.Where.Contains(inventory.Ref))
                    {
                        known.Where.Add(inventory.Ref);
                    }
                }
            }
        }

        return [.. findings.Values];
    }

    public IEnumerable<Library> LibrariesOf(Inventory inventory)
    {
        foreach (var package in inventory.Packages)
        {
            yield return Of(package.Ecosystem, package.Name, package.Version);
        }

        if (inventory.DotnetSdk is { Length: > 0 } sdk)
        {
            yield return Of(DotnetSdk, ".NET SDK", sdk);
        }
    }

    /// <summary>libraries.json: every library watched, with its vulnerabilities, its newest version and who uses it.</summary>
    public void Write(string path) => File.WriteAllText(path, JsonSerializer.Serialize(new
    {
        @checked = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        libraries = _libraries.Values.OrderBy(l => l.Ecosystem).ThenBy(l => l.Name, StringComparer.OrdinalIgnoreCase).ThenBy(l => l.Version, Versions.Comparer)
            .Select(l => new { ecosystem = l.Ecosystem, name = l.Name, version = l.Version, latest = l.Latest, vulnerabilities = l.Vulnerabilities, usedBy = l.UsedBy }),
    }, Json.Options) + "\n");
}

static class Severity
{
    static readonly string[] Order = ["unknown", "low", "moderate", "high", "critical", "security-release"];

    /// <summary>
    /// What stops a build: moderate and worse, and a .NET security release
    /// newer than the runtime an SDK bundles (Microsoft gives no single
    /// severity to a release, and an app published with that runtime inside
    /// carries every one of its fixes undone). Low and unknown only warn.
    /// </summary>
    public static bool Blocks(string severity) => Rank(severity) >= Rank("moderate");

    public static int Rank(string severity) => Array.IndexOf(Order, severity);

    public static string Of(string? text) => (text ?? "").Trim().ToLowerInvariant() switch
    {
        "medium" => "moderate",
        var known when Order.Contains(known) => known,
        _ => "unknown",
    };
}

// -------------------------------------------------------------------- OSV --

static class Osv
{
    /// <summary>OSV.dev's answer for every library, in batches; each advisory read once for its severity, its CVE and the version that fixed it.</summary>
    public static async Task CheckAsync(List<Library> libraries, Web web)
    {
        foreach (var batch in libraries.Chunk(500))
        {
            var answer = await web.OsvBatchAsync(new
            {
                queries = batch.Select(l => new { package = new { name = l.Name, ecosystem = l.Ecosystem }, version = l.Version }),
            });
            var results = answer?["results"]?.AsArray() ?? [];
            for (var i = 0; i < results.Count && i < batch.Length; i++)
            {
                foreach (var id in (results[i]?["vulns"]?.AsArray() ?? []).Select(v => (string?)v?["id"]).OfType<string>())
                {
                    batch[i].Vulnerabilities.Add(Read(await web.OsvVulnAsync(id), id, batch[i]));
                }
            }
        }
    }

    static Vulnerability Read(JsonNode? vuln, string id, Library library)
    {
        var aliases = (vuln?["aliases"]?.AsArray() ?? []).Select(a => (string?)a).OfType<string>().ToList();
        var ghsa = id.StartsWith("GHSA-") ? id : aliases.FirstOrDefault(a => a.StartsWith("GHSA-")) ?? id;
        var fixedIn = (vuln?["affected"]?.AsArray() ?? [])
            .Where(a => string.Equals((string?)a?["package"]?["name"], library.Name, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a?["ranges"]?.AsArray() ?? [])
            .SelectMany(r => r?["events"]?.AsArray() ?? [])
            .Select(e => (string?)e?["fixed"]).OfType<string>()
            .Where(v => Versions.Compare(v, library.Version) > 0)
            .OrderBy(v => v, Versions.Comparer).FirstOrDefault() ?? "";
        return new Vulnerability(ghsa, aliases.FirstOrDefault(a => a.StartsWith("CVE-")) ?? "",
            Severity.Of((string?)vuln?["database_specific"]?["severity"]), (string?)vuln?["summary"] ?? "", fixedIn,
            $"https://osv.dev/vulnerability/{id}");
    }
}

// ------------------------------------------------------------- .NET SDK --

static class Dotnet
{
    /// <summary>
    /// The runtime an SDK bundles, from .NET's release metadata: an app
    /// published with the runtime inside carries it, so every .NET security
    /// release after it is a vulnerability, with the CVEs it fixed. Its
    /// newest version is the newest SDK of the same band.
    /// </summary>
    public static async Task CheckAsync(Library sdk, Web web)
    {
        var channel = string.Join('.', sdk.Version.Split('.').Take(2));
        var releases = (await web.GetAsync($"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json"))?["releases"]?.AsArray() ?? [];
        var index = releases.ToList().FindIndex(r => (r?["sdks"]?.AsArray() ?? []).Any(s => (string?)s?["version"] == sdk.Version));
        if (index < 0)
        {
            return;
        }

        var band = sdk.Version[..^2];
        var newest = (releases[0]?["sdks"]?.AsArray() ?? []).Select(s => (string?)s?["version"] ?? "").FirstOrDefault(v => v.StartsWith(band)) ?? "";
        sdk.Latest = newest.Length > 0 ? newest : sdk.Version;
        var runtime = (string?)releases[index]?["runtime"]?["version"] ?? "";
        foreach (var later in releases.Take(index).Where(r => (bool?)r?["security"] == true))
        {
            var version = (string?)later?["release-version"] ?? "";
            var cves = (later?["cve-list"]?.AsArray() ?? []).Select(c => (string?)c?["cve-id"]).OfType<string>().ToList();
            sdk.Vulnerabilities.Add(new Vulnerability($"dotnet-{version}", string.Join(", ", cves), "security-release",
                $"The SDK bundles runtime {runtime}; .NET {version}, a security release, fixed {cves.Count} CVEs after it", $"SDK {newest}",
                (string?)later?["release-notes"] ?? ""));
        }
    }
}

// ---------------------------------------------------------------- versions --

static class Versions
{
    public static readonly IComparer<string> Comparer = Comparer<string>.Create(Compare);

    /// <summary>A stable version above another; a prerelease (a dash) is never offered as an update.</summary>
    public static bool Newer(string? candidate, string current) => candidate is { Length: > 0 } && !candidate.Contains('-') && Compare(candidate, current) > 0;

    public static int Compare(string a, string b)
    {
        var x = Parts(a);
        var y = Parts(b);
        for (var i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            var difference = (i < x.Length ? x[i] : 0).CompareTo(i < y.Length ? y[i] : 0);
            if (difference != 0)
            {
                return difference;
            }
        }

        return 0;
    }

    static long[] Parts(string version) =>
        [.. version.Split('-', '+')[0].Split('.').Select(p => long.TryParse(p, out var n) ? n : 0)];
}

// -------------------------------------------------------------------- web --

sealed class Web
{
    readonly HttpClient _http = new();
    readonly Dictionary<string, JsonNode?> _cache = [];

    public Web() => _http.DefaultRequestHeaders.UserAgent.ParseAdd("security-watch");

    /// <summary>The newest stable version of a library in its registry; null for an ecosystem not read yet, or a name the registry does not know.</summary>
    public async Task<string?> LatestAsync(string ecosystem, string name)
    {
        switch (ecosystem)
        {
            case "NuGet":
                var index = await GetAsync($"https://api.nuget.org/v3-flatcontainer/{name.ToLowerInvariant()}/index.json");
                return (index?["versions"]?.AsArray() ?? []).Select(v => (string?)v).OfType<string>().LastOrDefault(v => !v.Contains('-'));
            case "PyPI":
                return (string?)(await GetAsync($"https://pypi.org/pypi/{name}/json"))?["info"]?["version"];
            case "npm":
                return (string?)(await GetAsync($"https://registry.npmjs.org/{name}"))?["dist-tags"]?["latest"];
            case "Maven" when name.Split(':') is [var group, var artifact]:
                return (string?)(await GetAsync($"https://search.maven.org/solrsearch/select?q=g:%22{group}%22+AND+a:%22{artifact}%22&rows=1&wt=json"))?["response"]?["docs"]?[0]?["latestVersion"];
            default:
                return null;
        }
    }

    public async Task<JsonNode?> OsvBatchAsync(object query)
    {
        using var response = await _http.PostAsJsonAsync("https://api.osv.dev/v1/querybatch", query);
        response.EnsureSuccessStatusCode();
        return JsonNode.Parse(await response.Content.ReadAsStringAsync());
    }

    public Task<JsonNode?> OsvVulnAsync(string id) => GetAsync($"https://api.osv.dev/v1/vulns/{id}");

    /// <summary>A public JSON document, read once per run; null when it is not there.</summary>
    public async Task<JsonNode?> GetAsync(string url)
    {
        if (_cache.TryGetValue(url, out var known))
        {
            return known;
        }

        using var response = await _http.GetAsync(url);
        var node = response.IsSuccessStatusCode ? JsonNode.Parse(await response.Content.ReadAsStringAsync()) : null;
        _cache[url] = node;
        return node;
    }
}

static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

// ----------------------------------------------------------------- output --

static class Status
{
    /// <summary>
    /// What a project asks before it builds: each of its refs with whether it
    /// is blocking, its worst severity, its findings (and since when), the
    /// newer versions of the libraries it asks for itself, and its images.
    /// </summary>
    public static void Write(string path, IGrouping<string, Inventory> project, Catalog catalog, History history)
    {
        var findings = catalog.FindingsOf(project);
        var refs = project.OrderBy(i => i.Type).ThenByDescending(i => i.Sent).Select(inventory =>
        {
            var mine = findings.Where(f => f.Where.Contains(inventory.Ref)).OrderByDescending(f => Severity.Rank(f.Severity)).ToList();
            return new
            {
                @ref = inventory.Ref,
                type = inventory.Type,
                commit = inventory.Commit,
                sent = inventory.Sent,
                blocking = mine.Any(f => Severity.Blocks(f.Severity)),
                worst = mine.FirstOrDefault()?.Severity,
                findings = mine.Select(f => new
                {
                    ecosystem = f.Ecosystem, package = f.Package, version = f.Version, advisory = f.Vulnerability.Advisory, cve = f.Vulnerability.Cve,
                    severity = f.Severity, summary = f.Vulnerability.Summary, fixedIn = f.Vulnerability.FixedIn, url = f.Vulnerability.Url,
                    since = history.Since(project.Key, f),
                }),
                updates = inventory.Packages.Where(p => p.Direct)
                    .Select(p => catalog.Of(p.Ecosystem, p.Name, p.Version))
                    .Concat(catalog.LibrariesOf(inventory).Where(l => l.Ecosystem == Catalog.DotnetSdk))
                    .Where(l => Versions.Newer(l.Latest, l.Version))
                    .Select(l => new { ecosystem = l.Ecosystem, package = l.Name, version = l.Version, latest = l.Latest }),
                images = inventory.Images,
            };
        });
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            project = project.Key,
            @checked = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            refs,
        }, Json.Options) + "\n");
    }
}

/// <summary>Every finding ever made, by the day it was first seen and the day it was gone.</summary>
sealed class History
{
    public List<Entry> Entries { get; set; } = [];

    public static History Load(string path) =>
        File.Exists(path) ? JsonSerializer.Deserialize<History>(File.ReadAllText(path), Json.Options) ?? new() : new();

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, Json.Options) + "\n");

    /// <summary>Today's findings for a project: the open ones kept, the new ones opened, the gone ones closed. Returns the new ones.</summary>
    public List<Finding> Record(string project, List<Finding> findings, string today)
    {
        var opened = new List<Finding>();
        var seen = new HashSet<Entry>();
        foreach (var finding in findings)
        {
            var entry = Open(project, finding.Key);
            if (entry is null)
            {
                entry = new Entry
                {
                    Project = project, Key = finding.Key, Ecosystem = finding.Ecosystem, Package = finding.Package, Version = finding.Version,
                    Advisory = finding.Vulnerability.Advisory, Cve = finding.Vulnerability.Cve, Severity = finding.Severity,
                    FixedIn = finding.Vulnerability.FixedIn, Url = finding.Vulnerability.Url, Opened = today,
                };
                Entries.Add(entry);
                opened.Add(finding);
            }

            entry.LastSeen = today;
            entry.Where = [.. finding.Where.Order()];
            seen.Add(entry);
        }

        foreach (var gone in Entries.Where(e => e.Project == project && e.Closed is null && !seen.Contains(e)))
        {
            gone.Closed = today;
        }

        return opened;
    }

    public string? Since(string project, Finding finding) => Open(project, finding.Key)?.Opened;

    Entry? Open(string project, string key) => Entries.FirstOrDefault(e => e.Project == project && e.Key == key && e.Closed is null);

    public string Markdown()
    {
        var text = new StringBuilder("# History\n\nEvery known vulnerability found in a watched project, newest first. ")
            .Append("Open ones are still in at least one of the branches or releases its project sent; ")
            .Append("an old release stays open until it is no longer among the latest kept.\n\n")
            .Append("| Opened | Closed | Project | Library | Version | Advisory | Severity | Where | Fixed in |\n")
            .Append("|---|---|---|---|---|---|---|---|---|\n");
        foreach (var e in Entries.OrderByDescending(e => e.Opened).ThenBy(e => e.Project).ThenBy(e => e.Package))
        {
            var advisory = e.Cve.Length > 0 && !e.Cve.Contains(',') ? $"[{e.Cve}]({e.Url})" : $"[{e.Advisory}]({e.Url})";
            text.Append($"| {e.Opened} | {e.Closed ?? "open"} | {e.Project} | {e.Package} | {e.Version} | {advisory} | {e.Severity} | {string.Join(", ", e.Where)} | {e.FixedIn} |\n");
        }

        return text.ToString();
    }

    public sealed class Entry
    {
        public string Project { get; set; } = "";
        public string Key { get; set; } = "";
        public string Ecosystem { get; set; } = "";
        public string Package { get; set; } = "";
        public string Version { get; set; } = "";
        public string Advisory { get; set; } = "";
        public string Cve { get; set; } = "";
        public string Severity { get; set; } = "";
        public string FixedIn { get; set; } = "";
        public string Url { get; set; } = "";
        public string Opened { get; set; } = "";
        public string LastSeen { get; set; } = "";
        public string? Closed { get; set; }
        public List<string> Where { get; set; } = [];
    }
}

static class Issues
{
    /// <summary>One issue for a blocking finding first seen: the mail GitHub sends for it is the alarm.</summary>
    public static async Task OpenAsync(string project, Finding finding, string? token)
    {
        if (token is not { Length: > 0 })
        {
            return;
        }

        var v = finding.Vulnerability;
        var body = $"""
            **{finding.Package} {finding.Version}** ({finding.Ecosystem}) in {project}, at {string.Join(", ", finding.Where)}.

            - Advisory: [{v.Advisory}]({v.Url}) {v.Cve}
            - Severity: {v.Severity}
            - Fixed in: {(v.FixedIn.Length > 0 ? v.FixedIn : "not yet")}

            {v.Summary}
            """;
        var title = $"{project}: {finding.Package} {finding.Version}, {v.Severity} ({v.Advisory})";
        // One open issue per finding, whatever the history says: a history
        // started over does not mail the same finding twice.
        if ((await GhAsync("issue", "list", "--state", "open", "--limit", "500", "--json", "title", "--jq", ".[].title")).Split('\n').Contains(title))
        {
            return;
        }

        await GhAsync("issue", "create", "--title", title, "--body", body);
    }

    static async Task<string> GhAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo("gh") { RedirectStandardOutput = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        return output;
    }
}
