@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║  Chrome Recovery v1.0 — Rust / App-Bound Bypass  ║
echo ║  Build Script                                    ║
echo ╚══════════════════════════════════════════════════╝
echo.

set TARGET=x86_64-pc-windows-gnu

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

REM ── Check MinGW target ────────────────────────────────────────────────────────
echo [*] Vérification du target %TARGET%...
rustup target list --installed | findstr /C:"%TARGET%" >nul 2>&1
if errorlevel 1 (
    echo [*] Installation du target %TARGET%...
    rustup target add %TARGET%
    if errorlevel 1 (
        echo [✗] Impossible d'installer le target %TARGET%
        echo     Installez MinGW-w64: https://www.mingw-w64.org
        pause
        exit /b 1
    )
)
echo [✓] Target %TARGET% disponible

cd /d "%~dp0"

REM ── Build payload DLL ─────────────────────────────────────────────────────────
echo.
echo [*] Compilation chrome_payload.dll...
cargo build --release -p chrome-payload --target %TARGET%
if errorlevel 1 (
    echo [✗] Erreur compilation payload!
    pause
    exit /b 1
)
echo [✓] chrome_payload.dll compilé

REM ── Build injector ────────────────────────────────────────────────────────────
echo [*] Compilation chrome-recovery.exe...
cargo build --release -p chrome-recovery --target %TARGET%
if errorlevel 1 (
    echo [✗] Erreur compilation injector!
    pause
    exit /b 1
)
echo [✓] chrome-recovery.exe compilé

REM ── Copy artifacts to release dir ────────────────────────────────────────────
set OUT=target\%TARGET%\release
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
