@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║  Chrome Recovery v1.0 — Rust / App-Bound Bypass  ║
echo ║  Build Script (Windows MSVC)                     ║
echo ╚══════════════════════════════════════════════════╝
echo.

REM ── Check Rust ──────────────────────────────────────────────────────────────
echo [*] Vérification de Rust...
rustc --version >nul 2>&1
if errorlevel 1 (
    echo [✗] Rust n'est pas installé!
    echo     Installez: winget install -e --id Rustlang.Rustup
    pause
    exit /b 1
)
echo [✓] Rust trouvé

REM ── Activate MSVC environment if VS is installed ────────────────────────────
echo [*] Configuration MSVC...
set "VCVARS="
for %%E in (BuildTools Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if defined VCVARS (
    echo [✓] Visual Studio trouvé — activation vcvars64
    call "!VCVARS!" >nul
    goto :build
)

where link >nul 2>&1
if not errorlevel 1 (
    echo [✓] link.exe dans PATH
    goto :build
)

echo [!] MSVC introuvable — installation Visual C++ Build Tools...
echo     (peut prendre 5-10 minutes, ne fermez pas la fenêtre)
where winget >nul 2>&1
if not errorlevel 1 (
    winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements --accept-source-agreements --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
)

REM Re-scan after install
for %%E in (BuildTools Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)
if defined VCVARS (
    echo [✓] Build Tools installés — activation vcvars64
    call "!VCVARS!" >nul
    goto :build
)

echo.
echo [✗] Visual C++ Build Tools toujours introuvable.
echo.
echo Option A — installe manuellement puis relance BUILD.bat:
echo   1. Ouvre https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo   2. Télécharge "Build Tools for Visual Studio 2022"
echo   3. Coche "Desktop development with C++"
echo   4. Relance BUILD.bat
echo.
echo Option B — commande admin en une ligne:
echo   winget install -e --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
echo.
pause
exit /b 1

:build
cd /d "%~dp0"

echo.
echo [*] Compilation chrome_payload.dll...
cargo build --release -p chrome-payload
if errorlevel 1 goto :build_fail

echo [✓] chrome_payload.dll compilé

echo [*] Compilation chrome-recovery.exe...
cargo build --release -p chrome-recovery
if errorlevel 1 goto :build_fail

echo [✓] chrome-recovery.exe compilé

set OUT=target\release
if not exist release mkdir release
copy /Y "%OUT%\chrome-recovery.exe" release\ >nul
copy /Y "%OUT%\chrome_payload.dll" release\ >nul

echo.
echo [✓] Binaires dans release\
echo     - release\chrome-recovery.exe
echo     - release\chrome_payload.dll
echo.

echo [*] Lancement de chrome-recovery.exe chrome...
echo.
release\chrome-recovery.exe chrome
echo.
pause
exit /b 0

:build_fail
echo.
echo [✗] Erreur compilation.
echo     Si le message mentionne "link.exe" ou "cl.exe":
echo     installe Visual C++ Build Tools (Desktop development with C++)
echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo.
pause
exit /b 1
