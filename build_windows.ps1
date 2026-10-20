Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedPythonVersion = "3.12.10"
$ExpectedTclTkVersion = "8.6.15"
$ExpectedOpenSslVersion = "OpenSSL 3.0.16 11 Feb 2025"
$ThirdPartyLicenseNames = @(
    "Python-3.12.10.txt",
    "Tcl-8.6.15.txt",
    "Tk-8.6.15.txt",
    "OpenSSL-3.0.16-LICENSE.txt",
    "OpenSSL-3.0.16-ACKNOWLEDGEMENTS.md",
    "ReportLab-4.5.1.txt",
    "Pillow-13.0.0.txt",
    "charset-normalizer-3.5.2.txt",
    "PyInstaller-6.22.3.txt"
)

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

function Assert-BundledRuntimeVersions {
    $RuntimeCheck = @"
import platform
import ssl
import tkinter as tk

expected_python = "$ExpectedPythonVersion"
expected_tcl_tk = "$ExpectedTclTkVersion"
expected_openssl = "$ExpectedOpenSslVersion"
actual_python = platform.python_version()
actual_openssl = ssl.OPENSSL_VERSION
if actual_python != expected_python:
    raise SystemExit(
        f"Python {actual_python} gefunden; für diesen Build ist "
        f"Python {expected_python} erforderlich."
    )
if actual_openssl != expected_openssl:
    raise SystemExit(
        f"{actual_openssl} gefunden; für diesen Build ist "
        f"{expected_openssl} erforderlich."
    )

root = tk.Tk()
try:
    root.withdraw()
    root.update_idletasks()
    actual_tcl = str(root.tk.call("info", "patchlevel"))
    actual_tk = str(root.tk.call("package", "provide", "Tk"))
finally:
    root.destroy()

if actual_tcl != expected_tcl_tk or actual_tk != expected_tcl_tk:
    raise SystemExit(
        f"Tcl/Tk {actual_tcl}/{actual_tk} gefunden; für diesen Build ist "
        f"Tcl/Tk {expected_tcl_tk}/{expected_tcl_tk} erforderlich."
    )
print(
    f"Python {actual_python} mit Tcl/Tk {actual_tcl}/{actual_tk} und "
    f"{actual_openssl} geprüft."
)
"@

    $RuntimeCheck | python -
    if ($LASTEXITCODE -ne 0) {
        throw "Die Prüfung der gebündelten Laufzeitversionen ist fehlgeschlagen."
    }
}

function Assert-BundledOpenSslLibraries {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PackageDirectory
    )

    $InternalDirectory = Join-Path $PackageDirectory "_internal"
    if (-not (Test-Path -LiteralPath $InternalDirectory -PathType Container)) {
        throw "Das interne PyInstaller-Verzeichnis fehlt: $InternalDirectory"
    }

    $CryptoLibraries = @(
        Get-ChildItem -LiteralPath $InternalDirectory -File |
            Where-Object { $_.Name -like "libcrypto-3*.dll" }
    )
    $SslLibraries = @(
        Get-ChildItem -LiteralPath $InternalDirectory -File |
            Where-Object { $_.Name -like "libssl-3*.dll" }
    )
    if ($CryptoLibraries.Count -ne 1 -or $SslLibraries.Count -ne 1) {
        throw "Das Windows-Paket enthält nicht genau eine OpenSSL-3-Crypto- und SSL-Bibliothek."
    }
    foreach ($Library in @($CryptoLibraries + $SslLibraries)) {
        if ($Library.Length -le 0) {
            throw "Das Windows-Paket enthält eine leere OpenSSL-Bibliothek: $($Library.FullName)"
        }
    }
}

function Assert-ThirdPartyLicenseDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Directory
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "Der Drittanbieter-Lizenzordner fehlt: $Directory"
    }

    $ExpectedNames = @($ThirdPartyLicenseNames | Sort-Object)
    $ActualNames = @(
        Get-ChildItem -LiteralPath $Directory -File |
            Select-Object -ExpandProperty Name |
            Sort-Object
    )
    $UnexpectedDirectories = @(
        Get-ChildItem -LiteralPath $Directory -Directory
    )
    $Differences = @(
        Compare-Object -ReferenceObject $ExpectedNames -DifferenceObject $ActualNames
    )
    if ($Differences.Count -ne 0 -or $UnexpectedDirectories.Count -ne 0) {
        throw "Der Drittanbieter-Lizenzordner ist unvollständig oder enthält unerwartete Dateien."
    }

    foreach ($Name in $ExpectedNames) {
        $LicensePath = Join-Path $Directory $Name
        if ((Get-Item -LiteralPath $LicensePath).Length -le 0) {
            throw "Der Drittanbieter-Lizenztext ist leer: $LicensePath"
        }
    }
}

function Assert-ReleaseArchiveLicenses {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ArchivePath
    )

    $ExpectedEntries = @(
        $ThirdPartyLicenseNames |
            ForEach-Object { "THIRD_PARTY_LICENSES/$_" } |
            Sort-Object
    )
    $ZipArchive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $LicenseEntries = @(
            $ZipArchive.Entries |
                Where-Object {
                    -not [string]::IsNullOrEmpty($_.Name) -and
                    $_.FullName.Replace("\", "/").StartsWith(
                        "THIRD_PARTY_LICENSES/",
                        [StringComparison]::Ordinal
                    )
                }
        )
        $ActualEntries = @(
            $LicenseEntries |
                ForEach-Object { $_.FullName.Replace("\", "/") } |
                Sort-Object
        )
        $Differences = @(
            Compare-Object -ReferenceObject $ExpectedEntries -DifferenceObject $ActualEntries
        )
        if ($Differences.Count -ne 0) {
            throw "Das Release-ZIP enthält nicht genau die erwarteten Drittanbieter-Lizenztexte."
        }
        foreach ($Entry in $LicenseEntries) {
            if ($Entry.Length -le 0) {
                throw "Das Release-ZIP enthält einen leeren Lizenztext: $($Entry.FullName)"
            }
        }
    } finally {
        $ZipArchive.Dispose()
    }
}

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Assert-BundledRuntimeVersions

Invoke-CheckedPython -Arguments @(
    "-m", "pip", "install", "--require-hashes", "-r", "requirements-build.lock"
)
Invoke-CheckedPython -Arguments @("-m", "pytest")
Invoke-CheckedPython -Arguments @("-m", "ruff", "check", ".")
Invoke-CheckedPython -Arguments @(
    "-m", "PyInstaller", "--clean", "--noconfirm", "BitTorrentBeobachter.spec"
)

$PackageDirectory = Join-Path $ProjectRoot "dist/BitTorrent-Beobachter"
if (-not (Test-Path -LiteralPath $PackageDirectory -PathType Container)) {
    throw "PyInstaller hat das erwartete Paketverzeichnis nicht erstellt: $PackageDirectory"
}
Assert-BundledOpenSslLibraries -PackageDirectory $PackageDirectory
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") `
    -Destination (Join-Path $PackageDirectory "README.md") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "LICENSE") `
    -Destination (Join-Path $PackageDirectory "LICENSE") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "THIRD_PARTY_NOTICES.md") `
    -Destination (Join-Path $PackageDirectory "THIRD_PARTY_NOTICES.md") -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "requirements-build.lock") `
    -Destination (Join-Path $PackageDirectory "requirements-build.lock") -Force
$ThirdPartyLicensesSource = Join-Path $ProjectRoot "THIRD_PARTY_LICENSES"
$ThirdPartyLicensesDestination = Join-Path $PackageDirectory "THIRD_PARTY_LICENSES"
Assert-ThirdPartyLicenseDirectory -Directory $ThirdPartyLicensesSource
Copy-Item -LiteralPath $ThirdPartyLicensesSource `
    -Destination $ThirdPartyLicensesDestination -Recurse -Force
Assert-ThirdPartyLicenseDirectory -Directory $ThirdPartyLicensesDestination
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
if (Test-Path -LiteralPath $Archive) {
    Remove-Item -LiteralPath $Archive -Force
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $PackageDirectory,
    $Archive,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
)
Assert-ReleaseArchiveLicenses -ArchivePath $Archive
$Hash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $Archive
).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(
    "$Archive.sha256",
    "$Hash  AfDLeakercatcher-Windows-x64.zip`n",
    [Text.Encoding]::ASCII
)

Write-Host "Erstellt: $Archive"
Write-Host "SHA-256: $Hash"
