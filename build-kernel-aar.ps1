# Rebuilds build\kernel.aar from ./mobile.
#
# Local runs pick up the toolchain env.ps1 and the desktop proxy; CI sets
# ANDROID_HOME / ANDROID_NDK_HOME itself, has gomobile on PATH and needs no
# proxy. Everything below therefore only fills the gaps.
param(
    # gomobile targets. android/arm64 covers phones, android/amd64 is x86_64
    # (emulators, Chromebooks). Comma separated.
    #
    # gomobile only honours a single architecture per invocation (a list or a
    # bare "android" silently builds arm64 only), so each target is built on its
    # own and the results are merged into one AAR below.
    [string[]]$Target = @('android/arm64')
)
$ErrorActionPreference = 'Stop'

$localEnv = 'C:\Users\Nobody\android-toolchain\env.ps1'
if (Test-Path $localEnv) {
    . $localEnv
    $env:GOPROXY = 'https://goproxy.cn,direct'
    $env:HTTPS_PROXY = 'http://127.0.0.1:31181'
}

if (-not $env:ANDROID_HOME) {
    $fallback = 'C:\Users\Nobody\android-toolchain\android-sdk'
    if (Test-Path $fallback) { $env:ANDROID_HOME = $fallback }
}
if (-not $env:ANDROID_HOME) { throw 'ANDROID_HOME is not set' }

# gomobile shells out to javac when it generates the Java bindings. setup-java
# puts it on PATH, but a bare JAVA_HOME does not, so add it explicitly.
if ($env:JAVA_HOME) { $env:PATH = "$env:JAVA_HOME\bin;$env:PATH" }

# NDK: an explicit ANDROID_NDK_HOME wins, otherwise the newest one under the SDK.
if (-not $env:ANDROID_NDK_HOME) {
    $ndk = Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $ndk) { throw "NO-NDK under $env:ANDROID_HOME\ndk (set ANDROID_NDK_HOME)" }
    $env:ANDROID_NDK_HOME = $ndk.FullName
}
$env:ANDROID_NDK = $env:ANDROID_NDK_HOME
Write-Host "NDK=$($env:ANDROID_NDK_HOME)"

Set-Location $PSScriptRoot
# A fresh clone has no build\ (it is git-ignored) and gomobile will not create
# the output file's parent directory; it fails with a bare "cannot find the path".
New-Item -ItemType Directory -Path build -Force | Out-Null

$parts = @()
foreach ($t in $Target) {
    $name = ($t -replace '^android/', '') -replace '[^A-Za-z0-9]', '-'
    $part = "build\kernel-$name.aar"
    Write-Host "gomobile bind -target=$t"
    # "-target=$t" must be built first: PowerShell passes the `-target=$t` token`r`n    # through to native commands without expanding $t.
    gomobile bind "-target=$t" -androidapi=35 -o $part ./mobile
    if ($LASTEXITCODE) {
        Write-Host "GOMOBILE-FAILED target=$t exit=$LASTEXITCODE"
        exit 1
    }
    $parts += $part
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
# The first AAR is the base (classes.jar and the manifest are identical for
# every architecture); the rest only contribute their lib/<abi>/libgojni.so.
$final = 'build\kernel.aar'
Copy-Item $parts[0] $final -Force

if ($parts.Count -gt 1) {
    $zip = [System.IO.Compression.ZipFile]::Open((Resolve-Path $final), 'Update')
    try {
        foreach ($part in $parts[1..($parts.Count - 1)]) {
            $tmp = Join-Path $env:TEMP ('aar-' + [guid]::NewGuid())
            [System.IO.Compression.ZipFile]::ExtractToDirectory((Resolve-Path $part), $tmp)
            try {
                foreach ($so in Get-ChildItem $tmp -Recurse -Filter libgojni.so) {
                    $abi = Split-Path $so.DirectoryName -Leaf
                    $entry = "jni/$abi/libgojni.so"
                    if ($zip.GetEntry($entry)) { continue }
                    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $so.FullName, $entry) | Out-Null
                    Write-Host "merged $entry"
                }
            } finally {
                Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    } finally {
        $zip.Dispose()
    }
}

$abis = & "$env:JAVA_HOME\bin\jar.exe" tf $final 2>&1 | Select-String 'libgojni' | ForEach-Object { $_.Line.Trim() }
Write-Host ("ABIS: " + ($abis -join ', '))
Write-Host 'GOMOBILE-OK'

