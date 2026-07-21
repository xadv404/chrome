@echo off
chcp 65001 >nul
setlocal

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║  Chrome Recovery — Installation Windows            ║
echo ╚══════════════════════════════════════════════════╝
echo.

where git >nul 2>&1
if errorlevel 1 (
    echo [*] Installation Git...
    winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
)

where rustc >nul 2>&1
if errorlevel 1 (
    echo [*] Installation Rust...
    winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
    echo [!] Fermez et rouvrez le terminal, puis relancez INSTALL.bat
    pause
    exit /b 0
)

where link >nul 2>&1
if errorlevel 1 (
    echo [*] Installation Visual C++ Build Tools...
    winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements --accept-source-agreements --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
)

rustup default stable

cd /d "%~dp0"
call BUILD.bat
