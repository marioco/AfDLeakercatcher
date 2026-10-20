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
$PdfName = "Cybercrime-E-Mail-Kontakte_BKA-und-LKA_Deutschland_Stand-2026-10-20.pdf"
$PdfSource = Join-Path $ProjectRoot "assets/$PdfName"
$ExpectedPdfHash = "75585bb562b705f5644734299f78d1b26f1bd083a4acd962d21704041feb2f12"
$ActualPdfHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $PdfSource
).Hash.ToLowerInvariant()
if ($ActualPdfHash -ne $ExpectedPdfHash) {
    throw "Die Prüfsumme der Kontakt-PDF stimmt nicht."
}
Copy-Item -LiteralPath $PdfSource `
    -Destination (Join-Path $PackageDirectory $PdfName) -Force
$Checksums = @("BitTorrent-Beobachter.exe", $PdfName) | ForEach-Object {
    $FilePath = Join-Path $PackageDirectory $_
    $FileHash = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath
    ).Hash.ToLowerInvariant()
    "$FileHash  $_"
}
$Checksums | Set-Content -Encoding ascii (
    Join-Path $PackageDirectory "SHA256SUMS.txt"
)

$Archive = Join-Path $ProjectRoot "dist/AfDLeakercatcher-Windows-x64.zip"
if (Test-Path $Archive) {
    Remove-Item -LiteralPath $Archive -Force
}
Compress-Archive -Path "dist/BitTorrent-Beobachter/*" -DestinationPath $Archive
$Hash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
"$Hash  AfDLeakercatcher-Windows-x64.zip" |
    Set-Content -Encoding ascii "$Archive.sha256"

Write-Host "Erstellt: $Archive"
Write-Host "SHA-256: $Hash"
