[CmdletBinding()]
param([ValidateSet('Release', 'Debug')][string]$Configuration = 'Release')

$ErrorActionPreference = 'Stop'
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or $env:OS -ne 'Windows_NT') {
    throw 'Publica la distribución win-x64 desde Windows x64.'
}
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$artifacts = New-Item -ItemType Directory -Path (Join-Path $root 'artifacts') -Force
$stage = New-Item -ItemType Directory -Path (Join-Path $artifacts.FullName ('publish-' + [guid]::NewGuid().ToString('N')))
$package = Join-Path $artifacts.FullName 'SentinelSecurity-win-x64.zip'
$temporaryPackage = Join-Path $artifacts.FullName ($stage.Name + '.zip')
try {
    $project = Join-Path $root 'SentinelSecurity.UI\SentinelSecurity.UI.csproj'
    dotnet publish $project --configuration $Configuration --no-restore --no-self-contained --output $stage.FullName `
        --disable-build-servers -m:1 -p:UseSharedCompilation=false
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish falló con código $LASTEXITCODE." }
    if (!(Test-Path -LiteralPath (Join-Path $stage.FullName 'SentinelSecurity.UI.exe') -PathType Leaf)) {
        throw 'El ejecutable WPF no se incluyó en la publicación.'
    }
    Copy-Item -LiteralPath (Join-Path $root 'docs\manual.md') -Destination (Join-Path $stage.FullName 'Manual.md')
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($stage.FullName, $temporaryPackage)
    Move-Item -LiteralPath $temporaryPackage -Destination $package -Force
    $digest = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
    "$digest  SentinelSecurity-win-x64.zip" | Set-Content -LiteralPath "$package.sha256" -Encoding ascii
    Write-Output $package
}
finally {
    $resolved = (Resolve-Path -LiteralPath $stage.FullName).ProviderPath
    if ([IO.Path]::GetDirectoryName($resolved) -eq $artifacts.FullName -and $stage.Name -match '^publish-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    if (Test-Path -LiteralPath $temporaryPackage) {
        Remove-Item -LiteralPath $temporaryPackage -Force
    }
}
