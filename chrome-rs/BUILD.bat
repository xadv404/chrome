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
    echo     Installez depuis: https://rustup.rs
    pause
    exit /b 1
)
echo [✓] Rust trouvé

REM ── Check MSVC linker (Visual Studio Build Tools) ───────────────────────────
echo [*] Vérification MSVC (Visual C++ Build Tools)...
where link >nul 2>&1
if errorlevel 1 (
    echo [!] MSVC introuvable — tentative d'installation...
    where winget >nul 2>&1
    if not errorlevel 1 (
        winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements --accept-source-agreements --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    )
    where link >nul 2>&1
    if errorlevel 1 (
        echo.
        echo [✗] Visual C++ Build Tools requis.
        echo     Installez: https://visualstudio.microsoft.com/visual-cpp-build-tools/
        echo     Cochez "Desktop development with C++" puis relancez BUILD.bat
        echo.
        pause
        exit /b 1
    )
)
echo [✓] MSVC disponible

cd /d "%~dp0"

REM ── Build (native Windows MSVC — pas de MinGW) ──────────────────────────────
echo.
echo [*] Compilation chrome_payload.dll...
cargo build --release -p chrome-payload
if errorlevel 1 (
    echo [✗] Erreur compilation payload!
    pause
    exit /b 1
)
echo [✓] chrome_payload.dll compilé

echo [*] Compilation chrome-recovery.exe...
cargo build --release -p chrome-recovery
if errorlevel 1 (
    echo [✗] Erreur compilation injector!
    pause
    exit /b 1
)
echo [✓] chrome-recovery.exe compilé

REM ── Copy artifacts ────────────────────────────────────────────────────────────
set OUT=target\release
if not exist release mkdir release
copy /Y "%OUT%\chrome-recovery.exe" release\ >nul
copy /Y "%OUT%\chrome_payload.dll" release\ >nul

echo.
echo [✓] Binaires copiés dans: release\
echo     - release\chrome-recovery.exe
echo     - release\chrome_payload.dll
echo.

REM ── Run ───────────────────────────────────────────────────────────────────────
echo [*] Lancement de chrome-recovery.exe chrome...
echo.
release\chrome-recovery.exe chrome

echo.
pause
