# Rebuilds build\kernel.aar for arm64 from ./mobile.
# Prereqs: android toolchain env, gomobile on PATH (env.ps1).
. C:\Users\Nobody\android-toolchain\env.ps1
# NDK lives under the SDK's side-by-side dir; pick the newest installed.
$ndkRoot = 'C:\Users\Nobody\android-toolchain\android-sdk\ndk'
$ndk = Get-ChildItem $ndkRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $ndk) { Write-Host "NO-NDK under $ndkRoot"; exit 1 }
$env:ANDROID_NDK = $ndk.FullName
Write-Host "NDK=$($env:ANDROID_NDK)"
$env:ANDROID_HOME = 'C:\Users\Nobody\android-toolchain\android-sdk'
$env:GOPROXY = 'https://goproxy.cn,direct'
$env:HTTPS_PROXY = 'http://127.0.0.1:31181'
Set-Location $PSScriptRoot
gomobile bind -target=android/arm64 -androidapi=35 -o build\kernel.aar ./mobile
if ($LASTEXITCODE) {
    Write-Host "GOMOBILE-FAILED exit=$LASTEXITCODE"
    exit 1
}
Write-Host 'GOMOBILE-OK'
