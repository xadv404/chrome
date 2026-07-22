@echo off
setlocal enabledelayedexpansion

set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
set "CARGO_TERM_COLOR=never"
set "CARGO_TERM_PROGRESS=never"

call :ensure_rust
if errorlevel 1 exit /b 1

call :ensure_msvc
if errorlevel 1 exit /b 1

call :do_build
if errorlevel 1 exit /b 1

exit /b 0

:ensure_rust
where rustc >nul 2>&1
if not errorlevel 1 exit /b 0
curl -fsSL -o "%TEMP%\rustup-init.exe" https://win.rustup.rs/x86_64 >nul 2>&1
"%TEMP%\rustup-init.exe" -y --default-toolchain stable >nul 2>&1
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where rustc >nul 2>&1 || exit /b 1
exit /b 0

:ensure_msvc
call :find_vcvars
if defined VCVARS (
    if exist "!VCVARS!" (
        call "!VCVARS!" >nul 2>&1
        where cl >nul 2>&1
        if not errorlevel 1 exit /b 0
    )
)
where link >nul 2>&1
if not errorlevel 1 exit /b 0
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

:do_build
cd /d "%~dp0"

cargo build --release -q -p chrome-payload >nul 2>&1 || goto build_fail
if not exist "target\release\chrome_payload.dll" goto build_fail

rem LTO + codegen-units=1: final link can take several minutes — expected.
cargo build --release -q -p jewish >nul 2>&1 || goto build_fail
if not exist "target\release\jewish.exe" goto build_fail

if not exist release mkdir release >nul 2>&1
copy /Y "target\release\jewish.exe" "release\" >nul 2>&1
exit /b 0

:build_fail
exit /b 1
