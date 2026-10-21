"""Statische Tests für das einmal entpackbare Windows-Paket."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_NAME = "AfDLeakerCatcher"
EXE_NAME = f"{PRODUCT_NAME}.exe"
PACKAGE_DIRECTORY = f"dist/{PRODUCT_NAME}"
PDF_NAME = "Cybercrime-E-Mail-Kontakte_BKA-und-LKA_Deutschland_Stand-2026-10-20.pdf"
PDF_SHA256 = "75585bb562b705f5644734299f78d1b26f1bd083a4acd962d21704041feb2f12"
ARCHIVE_NAME = f"{PRODUCT_NAME}-Windows-x64.zip"
CHECKSUM_NAME = f"{ARCHIVE_NAME}.sha256"
RELEASE_ARTIFACT_NAME = f"{PRODUCT_NAME}-Windows-x64-release"
EXPECTED_LICENSE_HASHES = {
    "Python-3.14.8.txt": "935cf13e19f8c31b497d20b05d73623431a226b230c3599bc30fa3348979bc68",
    "Tcl-9.0.4.txt": "c0a69a2bfd757361ec7e6143973b103c90409316b49e9c88db26ad6388e79f16",
    "Tk-9.0.4.txt": "2cde822b93ca16ae535c954b7dfe658b4ad10df2a193628d1b358f1765e8b198",
    "OpenSSL-3.5.9-LICENSE.txt": (
        "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"
    ),
    "OpenSSL-3.5.9-ACKNOWLEDGEMENTS.md": (
        "58dee45791f007ced048114717f86672778fe75c551827c57e760861446ce3c3"
    ),
    "ReportLab-4.5.1.txt": "ef831761646313921375fc2cb888e8eeaf7da213d0b92852c10c42f3a0b4d138",
    "Pillow-13.0.0.txt": "dda12a98c1979cf3d94df1cff45d27a4cb3f04a60c76f76902ac54cac03ec0ce",
    "charset-normalizer-3.5.2.txt": (
        "6d0d41bfe170ac6c7dc248c9a63e254d0fb45a60d50a8257d0af92c6e249b887"
    ),
    "PyInstaller-6.22.3.txt": "0598064c7d2718e38d7914a7d08343b2fa008e3bea9ebba2aa7a6ffa5900dd64",
}


def _text(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def _app_version() -> str:
    init_source = _text("bittorrent_beobachter/__init__.py")
    match = re.search(r'^VERSION = "([^"]+)"$', init_source, flags=re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_public_product_name_is_consistent_in_program_and_release() -> None:
    init_source = _text("bittorrent_beobachter/__init__.py")
    cli_source = _text("bittorrent_beobachter/cli.py")
    gui_source = _text("bittorrent_beobachter/gui.py")
    reports_source = _text("bittorrent_beobachter/reports.py")
    spec = _text("BitTorrentBeobachter.spec")
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")
    readme = _text("README.md")
    project = tomllib.loads(_text("pyproject.toml"))

    assert f'APP_NAME = "{PRODUCT_NAME}"' in init_source
    assert "prog=APP_NAME" in cli_source
    assert 'root.title(f"{APP_NAME} {VERSION}")' in gui_source
    assert 'ttk.Label(hero, text=APP_NAME, style="Hero.TLabel")' in gui_source
    assert reports_source.count("canvas.setCreator(APP_NAME)") == 2
    assert spec.count(f'name="{PRODUCT_NAME}"') == 2
    assert f'"{PACKAGE_DIRECTORY}/{EXE_NAME}"' in workflow
    assert f'"{EXE_NAME}"' in local_build
    assert readme.startswith(f"# {PRODUCT_NAME}\n")
    assert f"`{EXE_NAME}`" in readme
    assert project["project"]["name"] == "bittorrent-beobachter"
    assert "afdleakercatcher" in project["project"]["scripts"]
    assert "bittorrent-beobachter" in project["project"]["scripts"]

    for public_source in (
        init_source,
        cli_source,
        gui_source,
        reports_source,
        spec,
        workflow,
        local_build,
        readme,
    ):
        assert "BitTorrent-Beobachter" not in public_source


def test_reference_pdf_is_the_reviewed_document() -> None:
    pdf_path = PROJECT_ROOT / "assets" / PDF_NAME
    payload = pdf_path.read_bytes()

    assert payload.startswith(b"%PDF-1.4")
    assert hashlib.sha256(payload).hexdigest() == PDF_SHA256


def test_complete_third_party_license_texts_are_present_unchanged() -> None:
    license_directory = PROJECT_ROOT / "THIRD_PARTY_LICENSES"
    entries = list(license_directory.iterdir())

    assert {entry.name for entry in entries} == set(EXPECTED_LICENSE_HASHES)
    assert all(entry.is_file() for entry in entries)
    for filename, expected_hash in EXPECTED_LICENSE_HASHES.items():
        payload = (license_directory / filename).read_bytes()
        assert payload
        assert hashlib.sha256(payload).hexdigest() == expected_hash


def test_third_party_licenses_are_documented_packaged_and_zip_checked() -> None:
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")
    spec = _text("BitTorrentBeobachter.spec")
    notices = _text("THIRD_PARTY_NOTICES.md")

    for filename in EXPECTED_LICENSE_HASHES:
        assert f"THIRD_PARTY_LICENSES/{filename}" in notices
        assert filename in workflow
        assert filename in local_build
    assert 'THIRD_PARTY_LICENSES_DIR = PROJECT_ROOT / "THIRD_PARTY_LICENSES"' in spec
    assert '(str(THIRD_PARTY_LICENSES_DIR), "THIRD_PARTY_LICENSES")' in spec
    assert "Copy-Item -LiteralPath $licenseSource" in workflow
    assert '"dist/AfDLeakerCatcher/THIRD_PARTY_LICENSES"' in workflow
    assert "[System.IO.Compression.ZipFile]::OpenRead($archive)" in workflow
    assert '"THIRD_PARTY_LICENSES/"' in workflow
    assert 'Join-Path $ProjectRoot "THIRD_PARTY_LICENSES"' in local_build
    assert "Assert-ThirdPartyLicenseDirectory" in local_build
    assert "Assert-ReleaseArchiveLicenses -ArchivePath $Archive" in local_build
    assert '"THIRD_PARTY_LICENSES/$_"' in local_build


def test_bundled_runtime_versions_match_the_shipped_license_texts() -> None:
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")

    assert workflow.count('python-version: "3.14.8"') == 2
    assert 'expected_python = "3.14.8"' in workflow
    assert 'expected_tcl_tk = "9.0.4"' in workflow
    assert 'expected_openssl = "OpenSSL 3.5.9 29 Sep 2026"' in workflow
    assert "actual_openssl = ssl.OPENSSL_VERSION" in workflow
    assert '$ExpectedPythonVersion = "3.14.8"' in local_build
    assert '$ExpectedTclTkVersion = "9.0.4"' in local_build
    assert '$ExpectedOpenSslVersion = "OpenSSL 3.5.9 29 Sep 2026"' in local_build
    assert "actual_openssl = ssl.OPENSSL_VERSION" in local_build
    assert 'root.tk.call("package", "provide", "Tk")' in workflow
    assert 'root.tk.call("package", "provide", "Tk")' in local_build
    assert "EXPECTED_PYTHON_VERSION = (3, 14, 8)" in _text("BitTorrentBeobachter.spec")
    assert 'EXPECTED_OPENSSL_VERSION = "OpenSSL 3.5.9 29 Sep 2026"' in _text(
        "BitTorrentBeobachter.spec"
    )
    assert 'EXPECTED_TCL_VERSION = "9.0.4"' in _text("BitTorrentBeobachter.spec")
    assert 'EXPECTED_TK_VERSION = "9.0.4"' in _text("BitTorrentBeobachter.spec")
    assert 'root.tk.call("package", "provide", "Tk")' in _text("BitTorrentBeobachter.spec")
    for runtime_name in (
        "python314.dll",
        "tcl90.dll",
        "tcl9tk90.dll",
        "libcrypto-3.dll",
        "libssl-3.dll",
    ):
        assert runtime_name in workflow
        assert runtime_name in local_build
    assert "Runtime-Inventar:" in workflow
    assert "Runtime-Inventar:" in local_build
    assert "Get-FileHash -Algorithm SHA256" in workflow
    assert "Get-FileHash -Algorithm SHA256" in local_build
    assert 'Where-Object { $_.Name -like "libcrypto-3*.dll" }' in workflow
    assert 'Where-Object { $_.Name -like "libssl-3*.dll" }' in workflow
    assert "Assert-BundledRuntimeInventory" in local_build
    assert '"libcrypto-3*.dll"' in local_build
    assert '"libssl-3*.dll"' in local_build


def test_windows_build_places_pdf_beside_executable() -> None:
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")

    assert PDF_NAME in workflow
    assert PDF_NAME in local_build
    assert "dist/AfDLeakerCatcher/" + PDF_NAME in workflow
    assert PDF_SHA256 in workflow
    assert PDF_SHA256 in local_build


def test_package_exposes_the_exact_build_dependency_lock() -> None:
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")
    spec = _text("BitTorrentBeobachter.spec")

    assert 'PROJECT_ROOT / "requirements-build.lock"' in spec
    assert "dist/AfDLeakerCatcher/requirements-build.lock" in workflow
    assert 'Join-Path $PackageDirectory "requirements-build.lock"' in local_build


def test_windows_job_builds_one_final_zip_and_preserves_raw_app_artifact() -> None:
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")

    assert "path: dist/AfDLeakerCatcher\n" in workflow
    assert "System.IO.Compression.ZipFile]::CreateFromDirectory(" in workflow
    assert "System.IO.Compression.ZipFile]::CreateFromDirectory(" in local_build
    assert f"name: {RELEASE_ARTIFACT_NAME}" in workflow
    assert f"dist/release/{ARCHIVE_NAME}" in workflow
    assert f"dist/release/{CHECKSUM_NAME}" in workflow
    assert "path: release/package" not in workflow
    assert "zip -r ../AfDLeakerCatcher-Windows-x64.zip ." not in workflow
    assert '-ArgumentList "--gui-smoke-test"' in workflow
    assert "Gebündelte Tkinter-GUI erfolgreich gestartet und beendet." in workflow


def test_local_windows_build_smokes_bundled_executable_before_archiving() -> None:
    local_build = _text("build_windows.ps1")

    version_smoke = local_build.index('-Arguments @("--version")')
    gui_smoke = local_build.index('-Arguments @("--gui-smoke-test")')
    archive_creation = local_build.index("[System.IO.Compression.ZipFile]::CreateFromDirectory(")

    assert "function Invoke-BundledExecutableSmokeTest" in local_build
    assert "$Process.WaitForExit($TimeoutMilliseconds)" in local_build
    assert "$Process.Kill()" in local_build
    assert "[int] $TimeoutMilliseconds = 30000" in local_build
    assert version_smoke < gui_smoke < archive_creation


def test_ci_and_local_windows_build_use_hash_locked_dependencies() -> None:
    workflow = _text(".github/workflows/build.yml")
    local_build = _text("build_windows.ps1")
    lock = _text("requirements-build.lock")

    assert workflow.count("python -m pip install --require-hashes -r requirements-build.lock") == 2
    assert "cache-dependency-path: requirements-build.lock" in workflow
    assert '"--require-hashes", "-r", "requirements-build.lock"' in local_build
    for package in (
        "reportlab==4.5.1",
        "pyinstaller==6.22.3",
        "pytest==9.1.1",
        "ruff==0.17.1",
        'colorama==0.4.6 ; sys_platform == "win32"',
        'pefile==2024.8.26 ; sys_platform == "win32"',
        'pywin32-ctypes==0.2.3 ; sys_platform == "win32"',
    ):
        assert package in lock
    assert "--hash=sha256:" in lock
    assert "pip-compile for Python 3.14 builds" in lock


def test_exact_final_zip_is_attested_and_published() -> None:
    workflow = _text(".github/workflows/build.yml")
    readme = _text("README.md")

    assert f"subject-path: attest/{ARCHIVE_NAME}" in workflow
    assert "subject-path: attest/AfDLeakerCatcher.exe" not in workflow
    assert f"gh attestation verify {ARCHIVE_NAME}" in workflow
    assert "attestations: read" in workflow
    assert workflow.count(f"name: {RELEASE_ARTIFACT_NAME}") >= 3
    assert f"gh attestation verify {ARCHIVE_NAME}" in readme
    assert "gh attestation verify AfDLeakerCatcher.exe" not in readme


def test_version_sources_tag_checks_and_direct_download_are_consistent() -> None:
    workflow = _text(".github/workflows/build.yml")
    readme = _text("README.md")
    project = tomllib.loads(_text("pyproject.toml"))
    version = project["project"]["version"]

    assert version == _app_version() == "0.3.5"
    assert f"Windows-Download \N{EN DASH} Version {version}" in readme
    release_path = f"releases/download/afdleakercatcher-v{version}/"
    assert readme.count(release_path) >= 2
    assert '"v${version}"' in workflow
    assert '"afdleakercatcher-v${version}"' in workflow
    assert '"bittorrent-beobachter-v${version}"' in workflow
    assert "from bittorrent_beobachter import VERSION" in workflow


def test_existing_release_is_serialized_and_fully_validated() -> None:
    workflow = _text(".github/workflows/build.yml")

    assert "group: afdleakercatcher-github-release" in workflow
    assert "cancel-in-progress: false" in workflow
    assert '"repos/$GITHUB_REPOSITORY/commits/$RELEASE_TAG"' in workflow
    assert "--json isDraft" in workflow
    assert "expected_assets" in workflow
    assert f'"{ARCHIVE_NAME}"' in workflow
    assert f'"{CHECKSUM_NAME}"' in workflow
    assert f"sha256sum --check --strict {CHECKSUM_NAME}" in workflow
    assert "permissions:\n      attestations: read\n      contents: write" in workflow


def test_readme_explains_checksum_and_optional_signature() -> None:
    readme = _text("README.md")
    normalized_readme = " ".join(readme.split())

    assert f"]({release_url(CHECKSUM_NAME)})" in readme
    assert f"Get-FileHash .\\{ARCHIVE_NAME} -Algorithm SHA256" in readme
    assert "**unsigniert**" in readme
    assert "Unbekannter Herausgeber" in readme
    assert "ersetzen aber keine Windows-Herausgebersignatur" in normalized_readme


def release_url(filename: str) -> str:
    version = tomllib.loads(_text("pyproject.toml"))["project"]["version"]
    return (
        "https://github.com/marioco/AfDLeakercatcher/releases/download/"
        f"afdleakercatcher-v{version}/{filename}"
    )
