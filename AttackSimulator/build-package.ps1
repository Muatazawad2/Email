<#
.SYNOPSIS
    Builds the ready-to-run zip for the portal's "Publish files" deployment.

.DESCRIPTION
    The portal's Manual Deployment > Publish files option does not install Python
    packages, so the zip must already contain them, built for the Function App's
    platform (Linux x86-64, Python 3.12). Run from the AttackSimulator folder.

.EXAMPLE
    .\build-package.ps1            # creates .\dist\ast-sync-ready-to-run.zip

.NOTES
    Developer: Dr. Muataz Awad
#>
param([string] $Output = "dist\ast-sync-ready-to-run.zip")

$ErrorActionPreference = 'Stop'
$stage = Join-Path ([IO.Path]::GetTempPath()) "ast-sync-pkg-$(Get-Random)"
New-Item -ItemType Directory $stage | Out-Null
try {
    Copy-Item function_app.py, ast_sync.py, requirements.txt, host.json $stage
    python -m pip install -q -r requirements.txt `
        --target "$stage\.python_packages\lib\site-packages" `
        --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 `
        --python-version 3.12 --implementation cp --only-binary=:all:
    if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }
    Get-ChildItem $stage -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force

    New-Item -ItemType Directory -Force (Split-Path $Output) | Out-Null
    $zip = Join-Path (Get-Location) $Output
    Remove-Item $zip -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
    try {
        # Forward slashes in entry names: Linux hosts don't treat '\' as a separator.
        Get-ChildItem $stage -Recurse -File | ForEach-Object {
            $name = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, $name, 'Optimal')
        }
    } finally { $archive.Dispose() }
    Write-Host ("Created {0} ({1:N1} MB)" -f $Output, ((Get-Item $zip).Length / 1MB))
} finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
