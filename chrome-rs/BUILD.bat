@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║  Chrome Recovery v1.0 — Rust / App-Bound Bypass  ║
echo ║  Build Script                                    ║
echo ╚══════════════════════════════════════════════════╝
echo.

set TARGET=x86_64-pc-windows-gnu

REM ── Check Rust ──────────────────────────────────────────────────────────────
echo [*] Vérification de Rust...
rustc --version >nul 2>&1
if errorlevel 1 (
    echo [✗] Rust n'est pas installé!
    echo     Installez depuis: https://rustup.rs
    pause
    exit /b 1
)
echo [✓] Rust trouvé

REM ── Check MinGW target ────────────────────────────────────────────────────────
echo [*] Vérification du target %TARGET%...
rustup target list --installed | findstr /C:"%TARGET%" >nul 2>&1
if errorlevel 1 (
    echo [*] Installation du target %TARGET%...
    rustup target add %TARGET%
    if errorlevel 1 (
        echo [✗] Impossible d'installer le target %TARGET%
        pause
        exit /b 1
    )
)
echo [✓] Target %TARGET% disponible

REM ── Check MinGW gcc (required for libsqlite3-sys) ───────────────────────────
echo [*] Vérification de MinGW gcc...

set "MINGW_BIN="
if exist "C:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe" set "MINGW_BIN=C:\msys64\mingw64\bin"
if exist "C:\tools\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe" set "MINGW_BIN=C:\tools\msys64\mingw64\bin"
if exist "C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin\gcc.exe" (
    set "MINGW_BIN=C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin"
)

where x86_64-w64-mingw32-gcc >nul 2>&1
if not errorlevel 1 (
    echo [✓] MinGW gcc trouvé dans PATH
    goto :mingw_ok
)

if defined MINGW_BIN (
    echo [✓] MinGW trouvé: !MINGW_BIN!
    set "PATH=!MINGW_BIN!;%PATH%"
    goto :mingw_ok
)

echo [!] MinGW gcc introuvable — tentative d'installation via MSYS2...
where winget >nul 2>&1
if errorlevel 1 goto :mingw_manual

winget install -e --id MSYS2.MSYS2 --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto :mingw_manual

if exist "C:\msys64\usr\bin\bash.exe" (
    echo [*] Installation mingw-w64-x86_64-gcc via pacman...
    C:\msys64\usr\bin\bash.exe -lc "pacman -Sy --noconfirm mingw-w64-x86_64-gcc"
    set "MINGW_BIN=C:\msys64\mingw64\bin"
    set "PATH=!MINGW_BIN!;%PATH%"
)

where x86_64-w64-mingw32-gcc >nul 2>&1
if not errorlevel 1 (
    echo [✓] MinGW installé
    goto :mingw_ok
)

:mingw_manual
echo.
echo [✗] MinGW gcc requis mais introuvable.
echo.
echo Installez MSYS2 puis gcc:
echo   winget install -e --id MSYS2.MSYS2
echo   C:\msys64\usr\bin\bash.exe -lc "pacman -Sy --noconfirm mingw-w64-x86_64-gcc"
echo   set PATH=C:\msys64\mingw64\bin;%%PATH%%
echo.
echo Puis relancez BUILD.bat
pause
exit /b 1

:mingw_ok
set "CC=x86_64-w64-mingw32-gcc"
set "AR=x86_64-w64-mingw32-ar"
set "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc"

cd /d "%~dp0"

REM ── Build payload DLL ─────────────────────────────────────────────────────────
echo.
echo [*] Compilation chrome_payload.dll...
cargo build --release -p chrome-payload --target %TARGET%
if errorlevel 1 (
    echo [✗] Erreur compilation payload!
    pause
    exit /b 1
)
echo [✓] chrome_payload.dll compilé

REM ── Build injector ────────────────────────────────────────────────────────────
echo [*] Compilation chrome-recovery.exe...
cargo build --release -p chrome-recovery --target %TARGET%
if errorlevel 1 (
    echo [✗] Erreur compilation injector!
    pause
    exit /b 1
)
echo [✓] chrome-recovery.exe compilé

REM ── Copy artifacts to release dir ────────────────────────────────────────────
set OUT=target\%TARGET%\release
if not exist release mkdir release
copy /Y "%OUT%\chrome-recovery.exe" release\ >nul
copy /Y "%OUT%\chrome_payload.dll" release\ >nul

echo.
echo [✓] Binaires copiés dans: release\
echo     - release\chrome-recovery.exe
echo     - release\chrome_payload.dll
echo.

REM ── Run ───────────────────────────────────────────────────────────────────────
echo [*] Lancement de chrome-recovery.exe chrome...
echo.
release\chrome-recovery.exe chrome

echo.
pause
