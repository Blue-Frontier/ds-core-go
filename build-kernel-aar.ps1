# Rebuilds build\kernel.aar for arm64 from ./mobile.
# Prereqs: android toolchain env, gomobile on PATH (env.ps1).
. C:\Users\Nobody\android-toolchain\env.ps1
$env:ANDROID_NDK = 'C:\Users\Nobody\android-toolchain\ndk'
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
