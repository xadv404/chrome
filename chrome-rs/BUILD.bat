@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Chrome Recovery - Auto Setup + Build + Run
echo ============================================================
echo.

set "PATH=%USERPROFILE%\.cargo\bin;C:\Program Files\Git\cmd;C:\Program Files\Git\bin;%PATH%"

call :ensure_rust
if errorlevel 1 exit /b 1

call :ensure_msvc
if errorlevel 1 exit /b 1

call :do_build
if errorlevel 1 exit /b 1

call :do_run
exit /b 0

REM ============================================================
:ensure_rust
where rustc >nul 2>&1
if not errorlevel 1 (
    echo [OK] Rust found
    rustc --version
    goto rust_ok
)

echo [*] Rust not found - downloading rustup...
if not exist "%TEMP%\rustup-init.exe" (
    curl -fsSL -o "%TEMP%\rustup-init.exe" https://win.rustup.rs/x86_64
    if errorlevel 1 (
        echo [X] Download failed. Get Rust manually: https://rustup.rs
        pause
        exit /b 1
    )
)

echo [*] Installing Rust...
"%TEMP%\rustup-init.exe" -y --default-toolchain stable
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

where rustc >nul 2>&1
if errorlevel 1 (
    echo [X] Rust install failed.
    pause
    exit /b 1
)

:rust_ok
rustup default stable >nul 2>&1
echo [OK] Rust ready
exit /b 0

REM ============================================================
:ensure_msvc
call :find_vcvars
if defined VCVARS (
    echo [OK] Visual Studio found
    call "!VCVARS!" >nul 2>&1
    exit /b 0
)

where link >nul 2>&1
if not errorlevel 1 (
    echo [OK] link.exe in PATH
    exit /b 0
)

echo [*] MSVC not found - downloading Build Tools...
echo     This takes 5-15 minutes. Do not close this window.

net session >nul 2>&1
if errorlevel 1 (
    echo [!] Admin rights required for Build Tools install.
    echo     Right-click BUILD.bat - Run as administrator
    pause
    exit /b 1
)

if not exist "%TEMP%\vs_buildtools.exe" (
    curl -fsSL -o "%TEMP%\vs_buildtools.exe" https://aka.ms/vs/17/release/vs_buildtools.exe
    if errorlevel 1 (
        echo [X] Download failed.
        echo     Manual: https://visualstudio.microsoft.com/visual-cpp-build-tools/
        pause
        exit /b 1
    )
)

echo [*] Installing Visual C++ Build Tools...
"%TEMP%\vs_buildtools.exe" --wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
if errorlevel 1 (
    echo [X] Build Tools install failed.
    pause
    exit /b 1
)

call :find_vcvars
if defined VCVARS (
    echo [OK] Build Tools installed
    call "!VCVARS!" >nul 2>&1
    exit /b 0
)

where link >nul 2>&1
if not errorlevel 1 exit /b 0

echo [X] MSVC still not found. Install "Desktop development with C++" manually.
pause
exit /b 1

REM ============================================================
:find_vcvars
set "VCVARS="
for %%E in (BuildTools Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)
exit /b 0

REM ============================================================
:do_build
cd /d "%~dp0"

echo.
echo [*] Building chrome_payload.dll...
cargo build --release -p chrome-payload
if errorlevel 1 (
    echo [X] Payload build failed.
    pause
    exit /b 1
)
echo [OK] chrome_payload.dll

echo [*] Building chrome-recovery.exe...
cargo build --release -p chrome-recovery
if errorlevel 1 (
    echo [X] Injector build failed.
    pause
    exit /b 1
)
echo [OK] chrome-recovery.exe

if not exist release mkdir release
copy /Y "target\release\chrome-recovery.exe" "release\" >nul
copy /Y "target\release\chrome_payload.dll" "release\" >nul

echo.
echo [OK] Binaries in release\
exit /b 0

REM ============================================================
:do_run
echo.
echo [*] Running chrome-recovery.exe chrome...
echo     Chrome must be open.
echo.
release\chrome-recovery.exe chrome
echo.
pause
exit /b 0
