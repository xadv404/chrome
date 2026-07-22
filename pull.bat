@echo off
cd /d "%~dp0"

echo.
echo [*] Git pull...
git pull
if errorlevel 1 (
    echo.
    echo [X] Pull failed
    pause
    exit /b 1
)

echo.
echo [OK] Pull complete
pause
