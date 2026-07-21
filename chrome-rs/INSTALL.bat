@echo off
setlocal

echo.
echo ====================================================
echo   Chrome Recovery - Full Install (Windows)
echo ====================================================
echo.

where git >nul 2>&1
if errorlevel 1 (
    echo [*] Installing Git...
    winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
)

where rustc >nul 2>&1
if errorlevel 1 (
    echo [*] Installing Rust...
    winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
    echo [!] Restart terminal then run INSTALL.bat again
    pause
    exit /b 0
)

where link >nul 2>&1
if errorlevel 1 (
    for %%E in (BuildTools Community Professional Enterprise) do (
        if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" goto have_vs
    )
    echo [*] Installing Visual C++ Build Tools...
    winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements --accept-source-agreements --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
)
:have_vs

rustup default stable

cd /d "%~dp0"
call BUILD.bat
