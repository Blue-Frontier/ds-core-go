# Rebuilds build\kernel.aar for arm64 from ./mobile.
#
# Local runs pick up the toolchain env.ps1 and the desktop proxy; CI sets
# ANDROID_HOME / ANDROID_NDK_HOME itself, has gomobile on PATH and needs no
# proxy. Everything below therefore only fills the gaps.
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
gomobile bind -target=android/arm64 -androidapi=35 -o build\kernel.aar ./mobile
if ($LASTEXITCODE) {
    Write-Host "GOMOBILE-FAILED exit=$LASTEXITCODE"
    exit 1
}
Write-Host 'GOMOBILE-OK'
