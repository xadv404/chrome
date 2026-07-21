@echo off
setlocal enabledelayedexpansion

echo.
echo ====================================================
echo   Chrome Recovery v1.0 - Build Script (MSVC)
echo ====================================================
echo.

echo [*] Checking Rust...
rustc --version >nul 2>&1
if errorlevel 1 (
    echo [X] Rust not found. Install: winget install -e --id Rustlang.Rustup
    pause
    exit /b 1
)
echo [OK] Rust found

echo [*] Setting up MSVC...
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
    echo [OK] Visual Studio found
    call "!VCVARS!" >nul
    goto build
)

where link >nul 2>&1
if not errorlevel 1 (
    echo [OK] link.exe in PATH
    goto build
)

echo [!] MSVC not found - installing Build Tools...
echo     This may take 5-10 minutes.
where winget >nul 2>&1
if not errorlevel 1 (
    winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements --accept-source-agreements --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
)

set "VCVARS="
for %%E in (BuildTools Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)
if defined VCVARS (
    echo [OK] Build Tools installed
    call "!VCVARS!" >nul
    goto build
)

echo.
echo [X] Visual C++ Build Tools required.
echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo     Select "Desktop development with C++"
echo.
pause
exit /b 1

:build
cd /d "%~dp0"

echo.
echo [*] Building chrome_payload.dll...
cargo build --release -p chrome-payload
if errorlevel 1 goto build_fail
echo [OK] chrome_payload.dll

echo [*] Building chrome-recovery.exe...
cargo build --release -p chrome-recovery
if errorlevel 1 goto build_fail
echo [OK] chrome-recovery.exe

if not exist release mkdir release
copy /Y "target\release\chrome-recovery.exe" "release\" >nul
copy /Y "target\release\chrome_payload.dll" "release\" >nul

echo.
echo [OK] Output in release\
echo     release\chrome-recovery.exe
echo     release\chrome_payload.dll
echo.

echo [*] Running chrome-recovery.exe chrome...
echo.
release\chrome-recovery.exe chrome
echo.
pause
exit /b 0

:build_fail
echo.
echo [X] Build failed.
echo     If link.exe or cl.exe is missing, install Visual C++ Build Tools.
echo.
pause
exit /b 1
