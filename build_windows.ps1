Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CheckedPython {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & python @Arguments
    if ($LASTEXITCODE -ne 0) {
        $Command = "python " + ($Arguments -join " ")
        throw "$Command ist mit Exitcode $LASTEXITCODE fehlgeschlagen."
    }
}

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Invoke-CheckedPython -Arguments @("-m", "pip", "install", ".[dev,build]")
Invoke-CheckedPython -Arguments @("-m", "pytest")
Invoke-CheckedPython -Arguments @("-m", "ruff", "check", ".")
Invoke-CheckedPython -Arguments @(
    "-m", "PyInstaller", "--clean", "--noconfirm", "BitTorrentBeobachter.spec"
)

$PackageDirectory = Join-Path $ProjectRoot "dist/BitTorrent-Beobachter"
if (-not (Test-Path -LiteralPath $PackageDirectory -PathType Container)) {
    throw "PyInstaller hat das erwartete Paketverzeichnis nicht erstellt: $PackageDirectory"
}
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") `
    -Destination (Join-Path $PackageDirectory "README.md") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "LICENSE") `
    -Destination (Join-Path $PackageDirectory "LICENSE") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "THIRD_PARTY_NOTICES.md") `
    -Destination (Join-Path $PackageDirectory "THIRD_PARTY_NOTICES.md") -Force

$Archive = Join-Path $ProjectRoot "dist/BitTorrent-Beobachter-Windows-x64.zip"
if (Test-Path $Archive) {
    Remove-Item -LiteralPath $Archive -Force
}
Compress-Archive -Path "dist/BitTorrent-Beobachter/*" -DestinationPath $Archive
$Hash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
"$Hash  BitTorrent-Beobachter-Windows-x64.zip" |
    Set-Content -Encoding ascii "$Archive.sha256"

Write-Host "Erstellt: $Archive"
Write-Host "SHA-256: $Hash"
