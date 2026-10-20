#:package YamlDotNet@16.2.1
#:property PublishAot=false

// Not AOT, as a file-based app is by default: YamlDotNet and the JSON
// written here are read and written by reflection.
//
// security-watch: each project in projects/*.yml, read from its own files at
// the branches and releases it names, checked against the known
// vulnerabilities and the newest versions. Writes status/<project>.json,
// history.json and HISTORY.md, and opens an issue for each high, critical or
// security-release finding first seen today. Run from the repository's root:
//
//     dotnet run watch/watch.cs
//
// Issues are opened only with GH_TOKEN set (the workflow), never on a run by hand.

using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

var root = Directory.GetCurrentDirectory();
var work = Path.Combine(root, "work");
var today = DateTime.UtcNow.ToString("yyyy-MM-dd");
var token = Environment.GetEnvironmentVariable("GH_TOKEN");
Directory.CreateDirectory(work);
Directory.CreateDirectory(Path.Combine(root, "status"));

var web = new Web(token);
var history = History.Load(Path.Combine(root, "history.json"));
var yaml = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).IgnoreUnmatchedProperties().Build();
var failed = false;

foreach (var file in Directory.GetFiles(Path.Combine(root, "projects"), "*.yml").Order())
{
    var project = yaml.Deserialize<ProjectFile>(File.ReadAllText(file));
    Console.WriteLine($"== {project.Name} ({project.Repository})");
    try
    {
        var status = await Watcher.CheckAsync(project, work, web);
        var opened = history.Record(project.Name, status.Findings, today);
        status.Write(Path.Combine(root, "status", $"{project.Name}.json"), history, today);
        foreach (var finding in opened.Where(f => Severity.Blocks(f.Severity)))
        {
            await Issues.OpenAsync(project, finding, token);
        }
    }
    catch (Exception error)
    {
        // A project that could not be read keeps its history as it was: nothing
        // is closed on a day it was not looked at.
        failed = true;
        Console.WriteLine($"   failed: {error.Message}");
        Status.WriteFailure(Path.Combine(root, "status", $"{project.Name}.json"), project, error.Message);
    }
}

history.Save(Path.Combine(root, "history.json"));
File.WriteAllText(Path.Combine(root, "HISTORY.md"), history.Markdown());
return failed ? 1 : 0;

// ------------------------------------------------------------------ input --

sealed class ProjectFile
{
    public string Name { get; set; } = "";
    public string Repository { get; set; } = "";
    public WatchSpec Watch { get; set; } = new();
    public List<SourceSpec> Sources { get; set; } = [];
}

sealed class WatchSpec
{
    public List<string> Branches { get; set; } = [];
    public int Releases { get; set; }
}

sealed class SourceSpec
{
    public string File { get; set; } = "";
    public string Kind { get; set; } = "";
}

// --------------------------------------------------------------- findings --

/// <summary>A known vulnerability in one package at one version, found at the refs in Where.</summary>
sealed record Finding(string Kind, string Package, string Version, string Advisory, string Cve, string Severity, string Summary, string FixedIn, string Url)
{
    public SortedSet<string> Where { get; } = [];

    public string Key => $"{Kind}|{Package}|{Version}|{Advisory}";
}

/// <summary>A dependency with a newer version than the one used.</summary>
sealed record Update(string Kind, string Package, string Version, string Latest)
{
    public SortedSet<string> Where { get; } = [];
}

/// <summary>A container image a project builds from or runs.</summary>
sealed record Image(string Reference, string File)
{
    public SortedSet<string> Where { get; } = [];
}

static class Severity
{
    /// <summary>
    /// What stops a project's release: high and critical advisories, and a .NET
    /// security release newer than the runtime an SDK bundles (Microsoft gives
    /// no single severity to a release, and an agent published with that
    /// runtime inside carries every one of its fixes undone).
    /// </summary>
    public static bool Blocks(string severity) => severity is "high" or "critical" or "security-release";

    public static string Of(string? text) => (text ?? "").Trim().ToLowerInvariant() switch
    {
        "" => "unknown",
        "medium" => "moderate",
        var known => known,
    };
}

// ----------------------------------------------------------------- watch --

static class Watcher
{
    public static async Task<Status> CheckAsync(ProjectFile project, string work, Web web)
    {
        var clone = Path.Combine(work, project.Name);
        if (!Directory.Exists(Path.Combine(clone, ".git")))
        {
            Git.Run(work, "clone", "--quiet", "--filter=blob:none", $"https://github.com/{project.Repository}.git", clone);
        }

        Git.Run(clone, "fetch", "--quiet", "--force", "--tags", "origin");
        var refs = new List<(string Name, string Commit)>();
        foreach (var branch in project.Watch.Branches)
        {
            refs.Add((branch, Git.Run(clone, "rev-parse", $"origin/{branch}").Trim()));
        }

        foreach (var tag in await web.ReleasesAsync(project.Repository, project.Watch.Releases))
        {
            refs.Add((tag, Git.Run(clone, "rev-parse", $"{tag}^{{commit}}").Trim()));
        }

        var status = new Status(project);
        // Refs whose dependency files are the same are read once: main and its
        // last release usually are, and so are develop and its preview.
        foreach (var group in refs.GroupBy(r => Fingerprint(clone, r.Commit, project.Sources)))
        {
            var names = group.Select(r => r.Name).ToList();
            Console.WriteLine($"   {string.Join(", ", names)}");
            Git.Run(clone, "checkout", "--quiet", "--force", group.First().Commit);
            foreach (var source in project.Sources)
            {
                var path = Path.Combine(clone, source.File);
                if (!File.Exists(path))
                {
                    continue;
                }

                await Sources.ReadAsync(source, clone, path, web, status, names);
            }
        }

        status.Refs.AddRange(refs.Select(r => r.Name));
        return status;
    }

    /// <summary>The dependency files' contents at a commit, and every project file's for NuGet: what the result depends on.</summary>
    static string Fingerprint(string clone, string commit, List<SourceSpec> sources)
    {
        var text = new StringBuilder();
        foreach (var source in sources)
        {
            text.Append(Git.TryShow(clone, commit, source.File));
            if (source.Kind == "nuget")
            {
                foreach (var csproj in Git.Run(clone, "ls-tree", "-r", "--name-only", commit).Split('\n').Where(p => p.EndsWith(".csproj")))
                {
                    text.Append(Git.TryShow(clone, commit, csproj));
                }
            }
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }
}

static class Sources
{
    public static Task ReadAsync(SourceSpec source, string clone, string path, Web web, Status status, List<string> where) => source.Kind switch
    {
        "nuget" => NuGet.ReadAsync(clone, path, web, status, where),
        "dotnet-sdk" => DotnetSdk.ReadAsync(path, web, status, where),
        "pip" => Pip.ReadAsync(path, web, status, where),
        "dockerfile" => Images.ReadDockerfile(source.File, path, status, where),
        "compose" => Images.ReadCompose(source.File, path, status, where),
        _ => throw new InvalidOperationException($"{source.File}: unknown kind {source.Kind}"),
    };
}

// ------------------------------------------------------------------ NuGet --

static class NuGet
{
    /// <summary>
    /// The central versions (Directory.Packages.props) asked of OSV, which
    /// covers the packages of every project, the MAUI client's too; then each
    /// project that restores without workloads, restored and listed by dotnet
    /// itself, which adds the transitive packages.
    /// </summary>
    public static async Task ReadAsync(string clone, string props, Web web, Status status, List<string> where)
    {
        var central = XDocument.Load(props).Descendants("PackageVersion")
            .Select(p => (Id: (string?)p.Attribute("Include") ?? "", Version: (string?)p.Attribute("Version") ?? ""))
            .Where(p => p.Id.Length > 0 && p.Version.Length > 0)
            .ToList();

        foreach (var finding in await Osv.QueryAsync("NuGet", "nuget", central, web))
        {
            status.Add(finding, where);
        }

        foreach (var (id, version) in central)
        {
            if (await web.LatestNuGetAsync(id) is { } latest && Versions.Newer(latest, version))
            {
                status.Add(new Update("nuget", id, version, latest), where);
            }
        }

        foreach (var project in Directory.GetFiles(clone, "*.csproj", SearchOption.AllDirectories))
        {
            if (File.ReadAllText(project).Contains("<UseMaui>true</UseMaui>", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Restored without the audit, which stops a restore on a vulnerable
            // package: here finding them is the point.
            if (Process("dotnet", clone, "restore", project, "-p:NuGetAudit=false", "-p:EnableWindowsTargeting=true", "-v", "q").Exit != 0)
            {
                throw new InvalidOperationException($"{Path.GetRelativePath(clone, project)} did not restore.");
            }

            var listed = Process("dotnet", clone, "list", project, "package", "--vulnerable", "--include-transitive", "--format", "json");
            var start = listed.Output.IndexOf('{');
            if (listed.Exit != 0 || start < 0)
            {
                throw new InvalidOperationException($"{Path.GetRelativePath(clone, project)}: dotnet list gave no answer.");
            }

            var json = JsonNode.Parse(listed.Output[start..]);
            foreach (var package in (json?["projects"]?.AsArray() ?? [])
                .SelectMany(p => p?["frameworks"]?.AsArray() ?? [])
                .SelectMany(f => (f?["topLevelPackages"]?.AsArray() ?? []).Concat(f?["transitivePackages"]?.AsArray() ?? [])))
            {
                var id = (string?)package?["id"] ?? "";
                var version = (string?)package?["resolvedVersion"] ?? "";
                foreach (var vulnerability in package?["vulnerabilities"]?.AsArray() ?? [])
                {
                    var url = (string?)vulnerability?["advisoryurl"] ?? "";
                    var ghsa = url[(url.LastIndexOf('/') + 1)..];
                    var advisory = await web.AdvisoryAsync(ghsa);
                    status.Add(new Finding("nuget", id, version, ghsa, advisory.Cve, Severity.Of((string?)vulnerability?["severity"]),
                        advisory.Summary, advisory.FixedIn(id), url), where);
                }
            }
        }
    }

    static (int Exit, string Output) Process(string file, string directory, params string[] arguments)
    {
        var start = new ProcessStartInfo(file) { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = System.Diagnostics.Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            Console.WriteLine(output.Result + errors.Result);
        }

        return (process.ExitCode, output.Result);
    }
}

// ------------------------------------------------------------- .NET SDK --

static class DotnetSdk
{
    /// <summary>
    /// The SDK global.json asks for, and the runtime it bundles: an app
    /// published with the runtime inside carries that runtime, so a .NET
    /// security release after it is a finding, with the CVEs it fixed.
    /// </summary>
    public static async Task ReadAsync(string path, Web web, Status status, List<string> where)
    {
        var sdk = (string?)JsonNode.Parse(File.ReadAllText(path))?["sdk"]?["version"] ?? "";
        var channel = string.Join('.', sdk.Split('.').Take(2));
        var releases = (await web.DotnetReleasesAsync(channel))?["releases"]?.AsArray() ?? [];
        var index = releases.ToList().FindIndex(r => (r?["sdks"]?.AsArray() ?? []).Any(s => (string?)s?["version"] == sdk));
        if (index < 0)
        {
            return;
        }

        var runtime = (string?)releases[index]?["runtime"]?["version"] ?? "";
        var band = sdk[..^2];
        var newest = releases[0];
        var newestSdk = (newest?["sdks"]?.AsArray() ?? []).Select(s => (string?)s?["version"] ?? "").FirstOrDefault(v => v.StartsWith(band)) ?? (string?)newest?["sdk"]?["version"] ?? "";
        foreach (var later in releases.Take(index).Where(r => (bool?)r?["security"] == true))
        {
            var version = (string?)later?["release-version"] ?? "";
            var cves = (later?["cve-list"]?.AsArray() ?? []).Select(c => (string?)c?["cve-id"]).OfType<string>().ToList();
            status.Add(new Finding("dotnet-sdk", $"Microsoft.NETCore.App (bundled by SDK {sdk})", runtime, $"dotnet-{version}",
                string.Join(", ", cves), "security-release", $".NET {version} security release: {cves.Count} CVEs fixed after runtime {runtime}",
                $"SDK {newestSdk}", (string?)later?["release-notes"] ?? ""), where);
        }

        if (newestSdk.Length > 0 && Versions.Newer(newestSdk, sdk))
        {
            status.Add(new Update("dotnet-sdk", ".NET SDK", sdk, newestSdk), where);
        }
    }
}

// -------------------------------------------------------------------- pip --

static class Pip
{
    static readonly Regex Pinned = new(@"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s;#]+)", RegexOptions.Compiled);

    /// <summary>The pinned lines of a requirements file (name==version): an unpinned one has no version to check.</summary>
    public static async Task ReadAsync(string path, Web web, Status status, List<string> where)
    {
        var pinned = File.ReadAllLines(path).Select(l => Pinned.Match(l)).Where(m => m.Success)
            .Select(m => (Id: Regex.Replace(m.Groups[1].Value, @"\[.*\]", ""), Version: m.Groups[2].Value)).ToList();

        foreach (var finding in await Osv.QueryAsync("PyPI", "pip", pinned, web))
        {
            status.Add(finding, where);
        }

        foreach (var (id, version) in pinned)
        {
            if (await web.LatestPyPIAsync(id) is { } latest && Versions.Newer(latest, version))
            {
                status.Add(new Update("pip", id, version, latest), where);
            }
        }
    }
}

// ----------------------------------------------------------------- images --

static class Images
{
    static readonly Regex From = new(@"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex ComposeImage = new(@"^\s*image:\s*[""']?([^""'\s#]+)", RegexOptions.Compiled);

    /// <summary>The base images, without the build's own stages, scratch, or a reference made of build arguments.</summary>
    public static Task ReadDockerfile(string file, string path, Status status, List<string> where)
    {
        var stages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var match in File.ReadAllLines(path).Select(l => From.Match(l)).Where(m => m.Success))
        {
            var image = match.Groups[1].Value;
            if (match.Groups[2].Success)
            {
                stages.Add(match.Groups[2].Value);
            }

            if (image != "scratch" && !image.Contains('$') && !stages.Contains(image))
            {
                status.Add(new Image(image, file), where);
            }
        }

        return Task.CompletedTask;
    }

    public static Task ReadCompose(string file, string path, Status status, List<string> where)
    {
        foreach (var match in File.ReadAllLines(path).Select(l => ComposeImage.Match(l)).Where(m => m.Success && !m.Groups[1].Value.Contains('$')))
        {
            status.Add(new Image(match.Groups[1].Value, file), where);
        }

        return Task.CompletedTask;
    }
}

// -------------------------------------------------------------------- OSV --

static class Osv
{
    /// <summary>OSV.dev's answer for these packages, each advisory read for its severity, its CVE and the version that fixed it.</summary>
    public static async Task<List<Finding>> QueryAsync(string ecosystem, string kind, List<(string Id, string Version)> packages, Web web)
    {
        var found = new List<Finding>();
        if (packages.Count == 0)
        {
            return found;
        }

        var answer = await web.OsvBatchAsync(new
        {
            queries = packages.Select(p => new { package = new { name = p.Id, ecosystem }, version = p.Version }),
        });
        var results = answer?["results"]?.AsArray() ?? [];
        for (var i = 0; i < results.Count; i++)
        {
            foreach (var id in (results[i]?["vulns"]?.AsArray() ?? []).Select(v => (string?)v?["id"]).OfType<string>())
            {
                var vuln = await web.OsvVulnAsync(id);
                var aliases = (vuln?["aliases"]?.AsArray() ?? []).Select(a => (string?)a).OfType<string>().ToList();
                var ghsa = id.StartsWith("GHSA-") ? id : aliases.FirstOrDefault(a => a.StartsWith("GHSA-")) ?? id;
                var fixedIn = (vuln?["affected"]?.AsArray() ?? [])
                    .Where(a => string.Equals((string?)a?["package"]?["name"], packages[i].Id, StringComparison.OrdinalIgnoreCase))
                    .SelectMany(a => a?["ranges"]?.AsArray() ?? [])
                    .SelectMany(r => r?["events"]?.AsArray() ?? [])
                    .Select(e => (string?)e?["fixed"]).OfType<string>()
                    .Where(v => Versions.Newer(v, packages[i].Version))
                    .OrderBy(v => v, Versions.Comparer).FirstOrDefault() ?? "";
                found.Add(new Finding(kind, packages[i].Id, packages[i].Version, ghsa,
                    aliases.FirstOrDefault(a => a.StartsWith("CVE-")) ?? "",
                    Severity.Of((string?)vuln?["database_specific"]?["severity"]),
                    (string?)vuln?["summary"] ?? "", fixedIn, $"https://osv.dev/vulnerability/{id}"));
            }
        }

        return found;
    }
}

// ---------------------------------------------------------------- versions --

static class Versions
{
    public static readonly IComparer<string> Comparer = Comparer<string>.Create(Compare);

    /// <summary>A stable version above another; a prerelease (a dash) is never offered as an update.</summary>
    public static bool Newer(string candidate, string current) => !candidate.Contains('-') && Compare(candidate, current) > 0;

    static int Compare(string a, string b)
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
    readonly Dictionary<string, Advisory> _advisories = [];
    readonly Dictionary<string, JsonNode?> _cache = [];

    public Web(string? token)
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("security-watch");
        _token = token;
    }

    readonly string? _token;

    public async Task<List<string>> ReleasesAsync(string repository, int count)
    {
        if (count <= 0)
        {
            return [];
        }

        var list = await GitHubAsync($"repos/{repository}/releases?per_page=30");
        return [.. (list?.AsArray() ?? []).Where(r => (bool?)r?["draft"] != true)
            .OrderByDescending(r => (string?)r?["published_at"])
            .Select(r => (string?)r?["tag_name"]).OfType<string>().Take(count)];
    }

    public async Task<Advisory> AdvisoryAsync(string ghsa)
    {
        if (!_advisories.TryGetValue(ghsa, out var advisory))
        {
            var json = await GitHubAsync($"advisories/{ghsa}");
            advisory = _advisories[ghsa] = new Advisory((string?)json?["cve_id"] ?? "", (string?)json?["summary"] ?? "", json?["vulnerabilities"]?.AsArray());
        }

        return advisory;
    }

    public async Task<string?> LatestNuGetAsync(string id)
    {
        var index = await GetAsync($"https://api.nuget.org/v3-flatcontainer/{id.ToLowerInvariant()}/index.json");
        return (index?["versions"]?.AsArray() ?? []).Select(v => (string?)v).OfType<string>().Where(v => !v.Contains('-')).LastOrDefault();
    }

    public async Task<string?> LatestPyPIAsync(string id) =>
        (string?)(await GetAsync($"https://pypi.org/pypi/{id}/json"))?["info"]?["version"];

    public Task<JsonNode?> DotnetReleasesAsync(string channel) =>
        GetAsync($"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json");

    public async Task<JsonNode?> OsvBatchAsync(object query)
    {
        using var response = await _http.PostAsJsonAsync("https://api.osv.dev/v1/querybatch", query);
        response.EnsureSuccessStatusCode();
        return JsonNode.Parse(await response.Content.ReadAsStringAsync());
    }

    public Task<JsonNode?> OsvVulnAsync(string id) => GetAsync($"https://api.osv.dev/v1/vulns/{id}");

    async Task<JsonNode?> GitHubAsync(string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/{path}");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        if (_token is { Length: > 0 })
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        }

        using var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return JsonNode.Parse(await response.Content.ReadAsStringAsync());
    }

    /// <summary>A public JSON document, read once per run; null when it is not there (a package unknown to its registry).</summary>
    async Task<JsonNode?> GetAsync(string url)
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

sealed record Advisory(string Cve, string Summary, JsonArray? Vulnerabilities)
{
    /// <summary>The first version of this package the advisory names as patched.</summary>
    public string FixedIn(string package) => (Vulnerabilities ?? [])
        .Where(v => string.Equals((string?)v?["package"]?["name"], package, StringComparison.OrdinalIgnoreCase))
        .Select(v => (string?)v?["first_patched_version"]).OfType<string>()
        .OrderBy(v => v, Versions.Comparer).FirstOrDefault() ?? "";
}

static class Git
{
    public static string Run(string directory, params string[] arguments)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"git {string.Join(' ', arguments)}: {errors.Result.Trim()}");
        }

        return output.Result;
    }

    /// <summary>A file at a commit; empty when it is not there.</summary>
    public static string TryShow(string clone, string commit, string file)
    {
        try
        {
            return Run(clone, "show", $"{commit}:{file}");
        }
        catch (InvalidOperationException)
        {
            return "";
        }
    }
}

// ----------------------------------------------------------------- output --

sealed class Status(ProjectFile project)
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    readonly Dictionary<string, Finding> _findings = [];
    readonly Dictionary<string, Update> _updates = [];
    readonly Dictionary<string, Image> _images = [];

    public List<string> Refs { get; } = [];

    public IReadOnlyCollection<Finding> Findings => _findings.Values;

    public void Add(Finding finding, List<string> where)
    {
        if (!_findings.TryGetValue(finding.Key, out var known))
        {
            known = _findings[finding.Key] = finding;
        }

        known.Where.UnionWith(where);
    }

    public void Add(Update update, List<string> where)
    {
        var key = $"{update.Kind}|{update.Package}|{update.Version}";
        if (!_updates.TryGetValue(key, out var known))
        {
            known = _updates[key] = update;
        }

        known.Where.UnionWith(where);
    }

    public void Add(Image image, List<string> where)
    {
        var key = $"{image.Reference}|{image.File}";
        if (!_images.TryGetValue(key, out var known))
        {
            known = _images[key] = image;
        }

        known.Where.UnionWith(where);
    }

    /// <summary>
    /// What a project asks for: each ref with whether something there stops a
    /// release, the findings with the day each was first seen, the updates and
    /// the images.
    /// </summary>
    public void Write(string path, History history, string today)
    {
        var document = new
        {
            project = project.Name,
            repository = project.Repository,
            @checked = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            refs = Refs.Select(r => new { @ref = r, blocking = _findings.Values.Any(f => f.Where.Contains(r) && Severity.Blocks(f.Severity)) }),
            vulnerable = _findings.Values.OrderBy(f => f.Package).Select(f => new
            {
                where = f.Where, kind = f.Kind, package = f.Package, version = f.Version, advisory = f.Advisory, cve = f.Cve,
                severity = f.Severity, summary = f.Summary, fixedIn = f.FixedIn, url = f.Url, since = history.Since(project.Name, f) ?? today,
            }),
            updates = _updates.Values.OrderBy(u => u.Package).Select(u => new { where = u.Where, kind = u.Kind, package = u.Package, version = u.Version, latest = u.Latest }),
            images = _images.Values.OrderBy(i => i.Reference).Select(i => new { where = i.Where, image = i.Reference, file = i.File }),
        };
        File.WriteAllText(path, JsonSerializer.Serialize(document, Json) + "\n");
    }

    public static void WriteFailure(string path, ProjectFile project, string error) =>
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            project = project.Name,
            repository = project.Repository,
            @checked = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            error,
        }, Json) + "\n");
}

/// <summary>Every finding ever made, by the day it was first seen and the day it was gone.</summary>
sealed class History
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public List<Entry> Entries { get; set; } = [];

    public static History Load(string path) =>
        File.Exists(path) ? JsonSerializer.Deserialize<History>(File.ReadAllText(path), Json) ?? new() : new();

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, Json) + "\n");

    /// <summary>Today's findings for a project: the open ones kept, the new ones opened, the gone ones closed. Returns the new ones.</summary>
    public List<Finding> Record(string project, IEnumerable<Finding> findings, string today)
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
                    Project = project, Key = finding.Key, Kind = finding.Kind, Package = finding.Package, Version = finding.Version,
                    Advisory = finding.Advisory, Cve = finding.Cve, Severity = finding.Severity, FixedIn = finding.FixedIn, Url = finding.Url, Opened = today,
                };
                Entries.Add(entry);
                opened.Add(finding);
            }

            entry.LastSeen = today;
            entry.Where = [.. finding.Where];
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
            .Append("Open ones are still in at least one of the branches or releases it watches; ")
            .Append("an old release stays open until it is no longer among them.\n\n")
            .Append("| Opened | Closed | Project | Package | Version | Advisory | Severity | Where | Fixed in |\n")
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
        public string Kind { get; set; } = "";
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
    /// <summary>One issue for a blocking finding first seen today: the mail GitHub sends for it is the alarm.</summary>
    public static async Task OpenAsync(ProjectFile project, Finding finding, string? token)
    {
        if (token is not { Length: > 0 })
        {
            return;
        }

        var body = $"""
            **{finding.Package} {finding.Version}** in [{project.Repository}](https://github.com/{project.Repository}), at {string.Join(", ", finding.Where)}.

            - Advisory: [{finding.Advisory}]({finding.Url}) {finding.Cve}
            - Severity: {finding.Severity}
            - Fixed in: {(finding.FixedIn.Length > 0 ? finding.FixedIn : "not yet")}

            {finding.Summary}
            """;
        var start = new ProcessStartInfo("gh") { RedirectStandardOutput = true };
        foreach (var argument in new[] { "issue", "create", "--title", $"{project.Name}: {finding.Package} {finding.Version}, {finding.Severity} ({finding.Advisory})", "--body", body })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        await process.WaitForExitAsync();
    }
}
