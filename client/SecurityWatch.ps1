<#
.SYNOPSIS
    security-watch from a project's builds: asked before every build, told
    after one. Each project keeps a copy of this file and dot-sources it,
    with its name set first:

        $SecurityWatchProject = "keyplus"
        . (Join-Path $PSScriptRoot "SecurityWatch.ps1")

.DESCRIPTION
    Berpiztu/security-watch checks the libraries Berpiztu's projects use,
    each one once for all of them, and reads no project: every project sends
    its own list (inventories/<project>/<ref>.json) and reads its own status
    (status/<project>.json). This is the one copy every project takes;
    client/AGENTS.md in security-watch says how it is kept.

    Test-SecurityWatch, first thing in a build: the status of the ref being
    built. A finding moderate or worse stops the build; a lower one is
    written as a warning. When security-watch cannot be reached, the person
    is asked whether to go on; a build on GitHub Actions stops.

    Send-SecurityWatchInventory, once a build succeeded: the list of every
    library the checkout uses, sent only when it differs from the one
    security-watch has, and only for main, develop and release tags, as an
    issue in security-watch opened by whoever gh is signed in as on this
    machine, as they would open it by hand: no token of its own. On GitHub
    Actions it sends nothing: a project's release script sends each
    release's list when it tags it.
#>

if (-not (Get-Variable -Name SecurityWatchProject -ValueOnly -ErrorAction SilentlyContinue)) {
    throw "Set `$SecurityWatchProject to the project's name in security-watch's projects.txt before dot-sourcing SecurityWatch.ps1."
}
$SecurityWatchRepository = "Berpiztu/security-watch"

function Get-SecurityWatchRoot {
    <# The project's repository: the one this copy of the file lives in. #>
    return (git -C $PSScriptRoot rev-parse --show-toplevel)
}

function Get-SecurityWatchRef {
    <# The ref this checkout is: the release tag on a release's build on GitHub, the branch otherwise. #>
    if ($env:GITHUB_REF_TYPE -eq "tag") {
        return [pscustomobject]@{ Name = $env:GITHUB_REF_NAME; Type = "release" }
    }
    $branch = git -C (Get-SecurityWatchRoot) branch --show-current
    if (-not $branch) { $branch = $env:GITHUB_HEAD_REF }
    return [pscustomobject]@{ Name = "$branch"; Type = "branch" }
}

function Test-SecurityWatch {
    <#
    Asks security-watch about the ref being built, or the one named, before
    anything is built: stops on a finding moderate or worse, warns on a lower
    one, and asks whether to go on when security-watch cannot be reached.
    #>
    param([string]$Ref)
    if (-not $Ref) { $Ref = (Get-SecurityWatchRef).Name }
    $url = "https://raw.githubusercontent.com/$SecurityWatchRepository/main/status/$SecurityWatchProject.json"
    try {
        $status = Invoke-RestMethod -Uri $url -TimeoutSec 20
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-Host "security-watch: no status for $SecurityWatchProject yet; its list is sent after this build." -ForegroundColor Yellow
            return
        }
        $reason = $_.Exception.Message
        if ($env:GITHUB_ACTIONS -eq "true") {
            throw "security-watch could not be reached ($reason): the build stops, since nothing says its libraries are safe."
        }
        $answer = Read-Host "security-watch could not be reached ($reason). Build anyway, without knowing of a new vulnerability? (y/n)"
        if ($answer -notmatch '^(y|yes|s|si)$') { throw "Stopped: security-watch could not be reached ($reason)." }
        Write-Warning "security-watch could not be reached ($reason); built without asking it."
        return
    }

    $mine = @($status.refs) | Where-Object { $_.ref -eq $Ref } | Select-Object -First 1
    if (-not $mine) {
        Write-Host "security-watch: no list of $Ref yet; it is sent after this build." -ForegroundColor Yellow
        return
    }

    $findings = @($mine.findings)
    foreach ($finding in $findings | Where-Object { -not $_.blocking }) {
        Write-Warning "security-watch: $($finding.package) $($finding.version) ($($finding.ecosystem)), $($finding.severity): $($finding.advisory) $($finding.cve), fixed in $(if ($finding.fixedIn) { $finding.fixedIn } else { 'no version yet' })."
    }
    $blocking = @($findings | Where-Object { $_.blocking })
    if ($blocking.Count -gt 0) {
        $lines = $blocking | ForEach-Object { "  $($_.package) $($_.version) ($($_.ecosystem)), $($_.severity): $($_.advisory) $($_.cve), fixed in $(if ($_.fixedIn) { $_.fixedIn } else { 'no version yet' })" }
        throw "security-watch: $Ref uses $($blocking.Count) librar$(if ($blocking.Count -eq 1) { 'y' } else { 'ies' }) with a vulnerability moderate or worse:`n$($lines -join "`n")`nPatch it and build again."
    }
    Write-Host "security-watch: $Ref has no known vulnerability that stops a build." -ForegroundColor Green
}

function Get-SecurityWatchInventory {
    <#
    Every library this checkout uses, at the version it resolves: the NuGet
    packages of every project restored here (project.assets.json, transitive
    ones included), the versions the project asks for of the ones not
    restored here (central in Directory.Packages.props, or in each project
    file), the pinned lines of every tracked requirements file, the .NET SDK
    (global.json's, or the one installed when there is none) and the
    container images.
    #>
    param([Parameter(Mandatory = $true)]$Ref)
    $root = Get-SecurityWatchRoot
    $tracked = @(git -C $root ls-files)
    $packages = @{}
    function Add-Package([string]$Ecosystem, [string]$Name, [string]$Version, [bool]$Direct) {
        $key = "$Ecosystem|$($Name.ToLowerInvariant())|$Version"
        if (-not $packages.ContainsKey($key)) {
            $packages[$key] = [ordered]@{ ecosystem = $Ecosystem; name = $Name; version = $Version; direct = $Direct }
        } elseif ($Direct) {
            $packages[$key].direct = $true
        }
    }

    # What the project asks for itself: central versions, or each project file's.
    $asked = @{}
    $central = Join-Path $root "Directory.Packages.props"
    $declarations = if (Test-Path -LiteralPath $central) {
        ([xml][IO.File]::ReadAllText($central)).SelectNodes("//*[local-name()='PackageVersion']")
    } else {
        $tracked | Where-Object { $_ -like "*.csproj" } | ForEach-Object {
            ([xml][IO.File]::ReadAllText((Join-Path $root $_))).SelectNodes("//*[local-name()='PackageReference'][@Version]")
        }
    }
    foreach ($node in $declarations) {
        $asked[$node.Include.ToLowerInvariant()] = $node.Version
    }

    foreach ($project in $tracked | Where-Object { $_ -like "*.csproj" }) {
        # A project at the repository's root has no folder of its own: its obj\ is the root's.
        $folder = Split-Path -Parent $project
        $assets = Join-Path $root (Join-Path $(if ($folder) { $folder } else { "." }) "obj\project.assets.json")
        if (-not (Test-Path -LiteralPath $assets)) { continue }
        foreach ($library in ([IO.File]::ReadAllText($assets) | ConvertFrom-Json).libraries.PSObject.Properties) {
            if ($library.Value.type -ne "package") { continue }
            $name, $version = $library.Name -split "/", 2
            Add-Package "NuGet" $name $version ($asked.ContainsKey($name.ToLowerInvariant()) -and $asked[$name.ToLowerInvariant()] -eq $version)
        }
    }
    foreach ($node in $declarations) {
        Add-Package "NuGet" $node.Include $node.Version $true
    }

    foreach ($file in $tracked | Where-Object { (Split-Path -Leaf $_) -like "*requirements*.txt" }) {
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $root $file))) {
            if ($line -match '^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([^\s;#]+)') { Add-Package "PyPI" $Matches[1] $Matches[3] $true }
        }
    }

    $images = [System.Collections.Generic.SortedSet[string]]::new()
    foreach ($file in $tracked | Where-Object { (Split-Path -Leaf $_) -like "Dockerfile*" }) {
        $stages = @{}
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $root $file))) {
            if ($line -match '^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?') {
                $image = $Matches[1]
                if ($Matches[2]) { $stages[$Matches[2].ToLowerInvariant()] = $true }
                if ($image -ne "scratch" -and $image -notmatch '\$' -and -not $stages.ContainsKey($image.ToLowerInvariant())) { [void]$images.Add($image) }
            }
        }
    }
    foreach ($file in $tracked | Where-Object { (Split-Path -Leaf $_) -match '^(docker-)?compose.*\.ya?ml$' }) {
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $root $file))) {
            if ($line -match '^\s*image:\s*["'']?([^"''\s#]+)' -and $Matches[1] -notmatch '\$') { [void]$images.Add($Matches[1]) }
        }
    }

    # The SDK the build uses: global.json's, or the newest installed when it names none.
    $globalJson = Join-Path $root "global.json"
    $sdk = if (Test-Path -LiteralPath $globalJson) {
        ([IO.File]::ReadAllText($globalJson) | ConvertFrom-Json).sdk.version
    } elseif (Get-Command dotnet -ErrorAction SilentlyContinue) {
        Push-Location $root
        try { dotnet --version } finally { Pop-Location }
    }

    return [ordered]@{
        project = $SecurityWatchProject
        ref = $Ref.Name
        type = $Ref.Type
        commit = (git -C $root rev-parse --short HEAD)
        sent = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        packages = @($packages.Values | Sort-Object { $_.ecosystem }, { $_.name.ToLowerInvariant() }, { $_.version })
        dotnetSdk = if ($sdk) { "$sdk" } else { $null }
        images = @($images)
    }
}

function Send-SecurityWatchInventory {
    <#
    Sends this checkout's list of libraries to security-watch, when it is not
    the list security-watch already has: for main, develop and release tags
    alone, a working branch being nobody's install.
    #>
    param($Ref)
    if (-not $Ref) { $Ref = Get-SecurityWatchRef }
    if ($Ref.Type -ne "release" -and $Ref.Name -notin @("main", "develop")) {
        Write-Host "security-watch: lists are sent for main, develop and releases; $($Ref.Name) is not sent." -ForegroundColor DarkGray
        return
    }
    if ($env:GITHUB_ACTIONS -eq "true") {
        Write-Host "security-watch: GitHub Actions only asks; the lists are sent by the builds and releases made on a machine." -ForegroundColor DarkGray
        return
    }

    $inventory = Get-SecurityWatchInventory -Ref $Ref

    # The same libraries, whenever and from whichever commit they were sent, are the same list.
    $sameness = { param($list) ConvertTo-Json -Compress -Depth 5 @{ packages = @($list.packages | ForEach-Object { "$($_.ecosystem)|$($_.name)|$($_.version)|$($_.direct)" }); dotnetSdk = "$($list.dotnetSdk)"; images = @($list.images) } }
    $known = "https://raw.githubusercontent.com/$SecurityWatchRepository/main/inventories/$SecurityWatchProject/$($Ref.Name).json"
    try {
        if ((& $sameness (Invoke-RestMethod -Uri $known -TimeoutSec 20)) -eq (& $sameness $inventory)) {
            Write-Host "security-watch already has this list of $($Ref.Name): nothing sent." -ForegroundColor DarkGray
            return
        }
    } catch {
        if (-not ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 404)) {
            Write-Warning "security-watch could not be read ($($_.Exception.Message)): the list of $($Ref.Name) was not sent."
            return
        }
    }

    # Opened as the person signed in to gh here, as they would open it by
    # hand: security-watch takes it from the accounts in its submitters.txt.
    $login = if (Get-Command gh -ErrorAction SilentlyContinue) { gh auth token 2>$null }
    if (-not $login) {
        Write-Warning "The list of $($Ref.Name) changed, and gh is not signed in on this machine (gh auth login): it was not sent to security-watch."
        return
    }

    # Sent as an issue: no project writes a file in security-watch. Its
    # watcher takes the list in, answers the issue with the result and closes it.
    $issue = [ordered]@{
        title = "inventory: $SecurityWatchProject@$($Ref.Name)"
        body = "Libraries of $SecurityWatchProject at $($Ref.Name) ($($inventory.commit)), sent by its build.`n`n``````json`n$(ConvertTo-Json -Compress -Depth 5 $inventory)`n``````"
    }
    if ($issue.body.Length -gt 65000) {
        Write-Warning "security-watch: the list of $($Ref.Name) is longer than an issue holds ($($issue.body.Length) characters): it was not sent."
        return
    }
    $headers = @{ Accept = "application/vnd.github+json"; "User-Agent" = $SecurityWatchProject; Authorization = "Bearer $login" }
    try {
        $opened = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$SecurityWatchRepository/issues" -Headers $headers `
            -ContentType "application/json; charset=utf-8" -Body ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $issue))) -TimeoutSec 30
        Write-Host "security-watch: the list of $($Ref.Name) was sent ($(@($inventory.packages).Count) libraries, $($opened.html_url)); it is checked within minutes." -ForegroundColor Green
    } catch {
        Write-Warning "security-watch: the list of $($Ref.Name) could not be sent ($($_.Exception.Message))."
    }
}
