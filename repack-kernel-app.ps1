# Repackages the ds-kernel companion app using the newest build\kernel.aar:
# extracts classes.jar + libgojni.so into kernel-app\libs\, updates the
# extracted classes dir, runs build-kernel.ps1, then prints install hints.
$ErrorActionPreference = 'Stop'
$repo = 'D:\dev-sidecar-core-go'
$kapp = 'D:\dev-sidecar-android\kernel-app'
$aar = Join-Path $repo 'build\kernel.aar'
if (-not (Test-Path $aar)) { throw "kernel.aar not built yet: $aar" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$tmp = Join-Path $env:TEMP ('aar-' + [guid]::NewGuid())
[System.IO.Compression.ZipFile]::ExtractToDirectory($aar, $tmp)

Copy-Item (Join-Path $tmp 'classes.jar') (Join-Path $kapp 'libs\classes.jar') -Force
# jniLibs keeps whatever layout the aar ships; find libgojni.so recursively.
$so = Get-ChildItem $tmp -Recurse -Filter libgojni.so | Select-Object -First 1
if (-not $so) { throw 'libgojni.so missing from aar' }
Copy-Item $so.FullName (Join-Path $kapp 'libs\libgojni.so') -Force
Remove-Item $tmp -Recurse -Force

# refresh the kotlinc classpath dir (build-kernel.ps1 skips stale extraction)
if (Test-Path (Join-Path $kapp 'libs\classes')) {
    Remove-Item (Join-Path $kapp 'libs\classes') -Recurse -Force
}

& powershell -NoProfile -File (Join-Path $kapp 'build-kernel.ps1')
Write-Host 'NEXT: adb uninstall com.bluefrontier.dscore.kernel; adb install kernel-app\build\ds-kernel.apk; then relaunch kernel + main apps'
