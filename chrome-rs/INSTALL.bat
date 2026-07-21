@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║  Chrome Recovery — Installation complète           ║
echo ╚══════════════════════════════════════════════════╝
echo.

REM ── Git ───────────────────────────────────────────────────────────────────────
where git >nul 2>&1
if errorlevel 1 (
    echo [*] Installation Git...
    winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
)

REM ── Rust ──────────────────────────────────────────────────────────────────────
where rustc >nul 2>&1
if errorlevel 1 (
    echo [*] Installation Rust...
    winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
    echo [!] Fermez et rouvrez le terminal, puis relancez INSTALL.bat
    pause
    exit /b 0
)

REM ── MSYS2 + MinGW ─────────────────────────────────────────────────────────────
where x86_64-w64-mingw32-gcc >nul 2>&1
if errorlevel 1 (
    if not exist "C:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe" (
        echo [*] Installation MSYS2...
        winget install -e --id MSYS2.MSYS2 --accept-package-agreements --accept-source-agreements
    )
    if exist "C:\msys64\usr\bin\bash.exe" (
        echo [*] Installation MinGW gcc...
        C:\msys64\usr\bin\bash.exe -lc "pacman -Sy --noconfirm mingw-w64-x86_64-gcc"
    )
)

set "PATH=C:\msys64\mingw64\bin;%PATH%"
rustup default stable
rustup target add x86_64-pc-windows-gnu

cd /d "%~dp0"
call BUILD.bat
